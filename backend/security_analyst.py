"""
security_analyst.py

Ollama 기반(또는 임의의 BaseAIProvider 기반) 방어적 보안 분석 모듈.

이 모듈은 Rule Engine 이 산출한 finding/스캔 결과를 '읽기 전용'으로 받아서,
LLM 에게 방어적 해석(오탐 가능성, 비즈니스 영향, 조치 우선순위 등)을 요청한다.

설계 원칙
---------
1. finding 의 어떤 필드도 변경하지 않는다(read-only).
   severity / confidence_score / judgment / finding_type / count 등은 절대 건드리지 않는다.
2. LLM 은 '새로운 취약점 생성', '개수/severity 변경', 'evidence 없는 단정',
   '공격 실행/익스플로잇/파괴 절차 설명' 을 하지 못하도록 프롬프트에서 강하게 제약한다.
3. LLM 미사용(NoneProvider) / 파싱 실패 / 예외 시 항상 동일한 스키마의
   fallback dict 를 반환한다. (report.py 가 키 접근 시 깨지지 않도록.)
4. ai_provider 는 함수 내부에서 지연 import 한다(순환참조 방지).

provider 인터페이스
-------------------
- `await provider.complete(prompt) -> str`
- `provider.name` (예: "ollama/llama3.2", "claude/...", "none")
"""

import json
from typing import Optional


# ── 반환 스키마 정의 (fallback 안정성용 단일 진실원) ────────────────────────────

# analyze_finding_with_ollama 가 반환하는 모든 키.
FINDING_KEYS = (
    "provider",
    "model",
    "used_rag",
    "false_positive_assessment",
    "business_impact",
    "attack_chain_analysis",
    "remediation_priority_reason",
    "additional_verification_steps",
    "report_text",
)

# analyze_scan_with_ollama 가 반환하는 모든 키.
SCAN_KEYS = (
    "provider",
    "model",
    "used_rag",
    "executive_summary",
    "overall_risk_commentary",
    "top_priorities",
    "attack_chain_summary",
    "operation_team_actions",
    "developer_team_actions",
)

# 리스트로 강제 정규화할 필드.
_FINDING_LIST_FIELDS = {"additional_verification_steps"}
_SCAN_LIST_FIELDS = {"top_priorities", "operation_team_actions", "developer_team_actions"}

_RULE_BASED_NOTE = (
    "AI 분석 미사용 / 규칙 기반 분석 사용. Rule Engine 판정 결과를 참고하세요."
)

# 프롬프트에 항상 포함되는 방어적 제한사항 블록.
_CONSTRAINTS_BLOCK = """[분석 제한사항 — 반드시 준수]
- 새로운 취약점 생성 금지: 입력에 없는 취약점을 만들어내지 마라.
- severity, confidence_score, 취약점 개수, attack_surface 개수 변경 금지.
- evidence 없는 단정 금지: 제공된 evidence 와 matched_knowledge 에 근거한 내용만 기술하라.
- 불확실하면 '수동 검토 필요' 로 표현하라.
- 공격 실행, 익스플로잇, 파괴적 절차 설명 금지: 익스플로잇 코드/PoC/실제 공격 수행 방법을 적지 마라.
- 방어적 분석, 조치 우선순위, 오탐(false positive) 가능성 평가에 집중하라.
- 제공된 evidence 와 matched_knowledge 만 근거로 해석하라. 예를 들어 TRACE 메서드 허용 같은
  항목에서 PUT 파일 업로드/RCE 등 검증되지 않은 시나리오를 단정해 만들어내지 마라.
- 출력은 반드시 JSON 한 개만 출력하라(설명 텍스트 없이)."""


# ── 내부 헬퍼 ──────────────────────────────────────────────────────────────────

def _has_rag(rag_context) -> bool:
    """rag_context 에 매칭된 지식이 있는지."""
    if not isinstance(rag_context, dict):
        return False
    mk = rag_context.get("matched_knowledge")
    return bool(mk)


def _parse_provider_name(name: str) -> tuple[str, str]:
    """provider.name 에서 (provider, model) 추출.

    "ollama/llama3.2" -> ("ollama", "llama3.2")
    "none"            -> ("none", "")
    """
    name = (name or "").strip()
    if not name:
        return "", ""
    if "/" in name:
        prov, _, model = name.partition("/")
        return prov.strip(), model.strip()
    return name, ""


def _rag_remediations(rag_context) -> list[str]:
    """matched_knowledge 에서 remediation 문구를 추출."""
    out: list[str] = []
    if not isinstance(rag_context, dict):
        return out
    for item in rag_context.get("matched_knowledge") or []:
        if not isinstance(item, dict):
            continue
        rem = item.get("remediation") or item.get("remediations")
        if isinstance(rem, str) and rem.strip():
            out.append(rem.strip())
        elif isinstance(rem, (list, tuple)):
            out.extend(str(r).strip() for r in rem if str(r).strip())
    return out


def _extract_json(text: str) -> Optional[dict]:
    """LLM 응답 텍스트에서 첫 번째 JSON 오브젝트를 추출·파싱."""
    if not text or not isinstance(text, str):
        return None
    # 1) 통째로 파싱 시도
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, ValueError):
        pass
    # 2) 코드펜스/본문에서 첫 { ... } 블록을 균형 괄호로 추출
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                blob = text[start:i + 1]
                try:
                    obj = json.loads(blob)
                    if isinstance(obj, dict):
                        return obj
                except (json.JSONDecodeError, ValueError):
                    return None
    return None


def _as_list(val) -> list:
    if val is None:
        return []
    if isinstance(val, list):
        return [v for v in val if v is not None]
    if isinstance(val, tuple):
        return list(val)
    return [val]


def _as_text(val) -> str:
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, (list, tuple)):
        return " / ".join(str(v) for v in val)
    return str(val)


# 프롬프트 JSON 스키마의 예시 문구 — 소형 모델이 채우지 않고 그대로 echo 하는 경우
# 보고서에 노출되지 않도록 제거한다(미충전 플레이스홀더 필터).
_PLACEHOLDER_VALUES = {
    "오탐 가능성 평가 (근거 포함)", "비즈니스 영향 평가",
    "evidence 에 근거한 방어 관점 공격 체인 해석", "조치 우선순위 판단 사유",
    "추가 수동 검증/조치 단계", "보고서에 넣을 한국어 서술 요약", "...",
    "경영진용 요약 (한국어)", "전반적 위험 코멘트", "최우선 조치 항목",
    "공격 체인 요약 (방어 관점)", "운영팀 조치", "개발팀 조치",
}


def _strip_placeholder(val):
    """스키마 예시 문구가 그대로 들어온 경우 제거한다."""
    if isinstance(val, str):
        return "" if val.strip() in _PLACEHOLDER_VALUES else val
    if isinstance(val, list):
        return [x for x in val
                if not (isinstance(x, str) and x.strip() in _PLACEHOLDER_VALUES)]
    return val


def _finding_is_confirmed(finding: dict) -> bool:
    """finding 이 실증/검증된(CONFIRMED) 항목인지 판정."""
    finding = finding or {}
    c = str(finding.get("confidence") or "").upper()
    if c == "CONFIRMED":
        return True
    if c in ("POSSIBLE", "LIKELY", "MANUAL_REVIEW", "INFO"):
        return False
    score = finding.get("confidence_score")
    if isinstance(score, (int, float)) and score >= 85:
        return True
    if finding.get("probe_confirmed") is True:
        return True
    return False


def _normalize(parsed: dict, keys, list_fields, provider: str, model: str,
               used_rag: bool) -> dict:
    """파싱된 dict 를 고정 스키마로 정규화. 누락 필드는 기본값. 플레이스홀더는 제거."""
    out: dict = {}
    for k in keys:
        if k == "provider":
            out[k] = provider
            continue
        if k == "model":
            out[k] = model
            continue
        if k == "used_rag":
            out[k] = bool(used_rag)
            continue
        if k in list_fields:
            out[k] = _strip_placeholder(_as_list(parsed.get(k)))
        else:
            out[k] = _strip_placeholder(_as_text(parsed.get(k)))
    return out


# ── fallback 빌더 (스키마의 모든 키 보장) ──────────────────────────────────────

def _finding_fallback(rag_context) -> dict:
    used_rag = _has_rag(rag_context)
    steps = list(_rag_remediations(rag_context))
    if not steps:
        steps = ["Rule Engine 판정 결과와 evidence 를 직접 검토하세요."]
    return {
        "provider": "fallback",
        "model": "",
        "used_rag": used_rag,
        "false_positive_assessment": _RULE_BASED_NOTE,
        "business_impact": _RULE_BASED_NOTE,
        "attack_chain_analysis": _RULE_BASED_NOTE,
        "remediation_priority_reason": _RULE_BASED_NOTE,
        "additional_verification_steps": steps,
        "report_text": (
            "AI 분석 미사용 / 규칙 기반 분석 사용. "
            "Rule Engine 의 severity/confidence_score 판정 결과를 참고하세요."
        ),
    }


def _scan_fallback(rag_context) -> dict:
    used_rag = _has_rag(rag_context)
    rems = list(_rag_remediations(rag_context))
    ops = rems[:] if rems else ["Rule Engine 판정 결과를 우선순위에 따라 검토하세요."]
    dev = rems[:] if rems else ["취약 항목의 evidence 를 확인하고 패치 적용 여부를 검토하세요."]
    return {
        "provider": "fallback",
        "model": "",
        "used_rag": used_rag,
        "executive_summary": _RULE_BASED_NOTE,
        "overall_risk_commentary": _RULE_BASED_NOTE,
        "top_priorities": ["Rule Engine 판정 severity 가 높은 항목부터 검토하세요."],
        "attack_chain_summary": _RULE_BASED_NOTE,
        "operation_team_actions": ops,
        "developer_team_actions": dev,
    }


# ── 프롬프트 빌더 (테스트 가능하도록 분리) ─────────────────────────────────────

def _fmt_rag(rag_context) -> str:
    if not _has_rag(rag_context):
        return "(매칭된 보안 지식 없음)"
    lines = []
    for item in rag_context.get("matched_knowledge") or []:
        if not isinstance(item, dict):
            lines.append(f"- {item}")
            continue
        title = item.get("title") or item.get("id") or item.get("name") or "지식"
        desc = item.get("description") or item.get("summary") or ""
        rem = item.get("remediation") or ""
        piece = f"- {title}"
        if desc:
            piece += f": {desc}"
        if rem:
            piece += f" (권고: {rem})"
        lines.append(piece)
    return "\n".join(lines)


def build_finding_prompt(finding: dict, rag_context: dict,
                         technologies: list = None,
                         attack_chains: list = None) -> str:
    """단일 finding 에 대한 방어적 분석 프롬프트를 생성한다(읽기 전용)."""
    finding = finding or {}
    technologies = technologies or []
    attack_chains = attack_chains or []

    title = finding.get("title") or finding.get("name") or "(제목 없음)"
    severity = finding.get("severity", "")
    confidence = finding.get("confidence_score", "")
    finding_type = finding.get("finding_type", "")
    judgment = finding.get("judgment", "")
    evidence = finding.get("evidence")
    if evidence is None:
        evidence = finding.get("evidences")
    evidence_text = _as_text(evidence) or "(제공된 evidence 없음)"

    tech_text = ", ".join(str(t) for t in technologies) if technologies else "(없음)"

    # 이 항목(finding) 하나만 분석한다 — 다른 취약점/공격 체인 내용을 섞지 않도록
    # attack_chains 는 프롬프트에 포함하지 않는다(교차 오염 방지).
    confirmed = _finding_is_confirmed(finding)
    if confirmed:
        grade_guidance = (
            "이 항목은 이미 실증/검증된(CONFIRMED) 취약점이다. "
            "false_positive_assessment 는 '실증 확인됨 — 오탐 가능성 낮음' 취지로 간결히 적고, "
            "불필요한 오탐 의심이나 '수동 검토 필요' 를 만들지 마라."
        )
    else:
        grade_guidance = (
            "이 항목은 가능성(POSSIBLE/LIKELY) 단계로 아직 최종 검증되지 않았다. "
            "additional_verification_steps 에 이 항목을 확정하기 위한 구체적 수동 검증 절차를 제시하라."
        )

    return f"""당신은 방어 측(Blue Team) 보안 분석가다. 아래 '단일 탐지 항목(finding) 하나만'을
Rule Engine 의 판정 결과와 evidence, 매칭된 보안 지식(matched_knowledge)에
근거하여 방어적으로 해석하라. 다른 취약점·다른 항목의 내용을 절대 섞지 마라.

{_CONSTRAINTS_BLOCK}

[분석 지침]
{grade_guidance}

[탐지 항목 (읽기 전용 — 값 변경 금지)]
- 제목: {title}
- severity: {severity}
- confidence_score: {confidence}
- finding_type: {finding_type}
- judgment: {judgment}
- evidence:
{evidence_text}

[탐지된 기술 스택]
{tech_text}

[매칭된 보안 지식 (matched_knowledge)]
{_fmt_rag(rag_context)}

[요청]
위 evidence 와 matched_knowledge 만을 근거로, '이 항목에 한정해서' 다음을 JSON 으로 작성하라.
근거가 부족하면 해당 필드에 "수동 검토 필요" 라고 적어라. 다른 취약점 내용을 포함하지 마라.
{{
  "false_positive_assessment": "<이 항목의 오탐 가능성 평가>",
  "business_impact": "<이 항목의 비즈니스 영향>",
  "attack_chain_analysis": "<이 항목 evidence 에 근거한 방어 관점 해석>",
  "remediation_priority_reason": "<이 항목의 조치 우선순위 사유>",
  "additional_verification_steps": ["<이 항목 검증/조치 단계>"],
  "report_text": "<이 항목 한국어 서술 요약>"
}}
출력은 위 JSON 하나만."""


def build_scan_prompt(findings: list, attack_surface_items: list,
                      discovery_items: list, technologies: list,
                      attack_chains: list, rag_context: dict = None) -> str:
    """스캔 전체에 대한 방어적 요약 분석 프롬프트를 생성한다(읽기 전용)."""
    findings = findings or []
    attack_surface_items = attack_surface_items or []
    discovery_items = discovery_items or []
    technologies = technologies or []
    attack_chains = attack_chains or []

    def _summ(items, limit=20):
        lines = []
        for f in items[:limit]:
            if isinstance(f, dict):
                t = f.get("title") or f.get("name") or "(제목 없음)"
                sev = f.get("severity", "")
                lines.append(f"- [{sev}] {t}")
            else:
                lines.append(f"- {f}")
        if len(items) > limit:
            lines.append(f"- ... 외 {len(items) - limit}건")
        return "\n".join(lines) if lines else "(없음)"

    tech_text = ", ".join(str(t) for t in technologies) if technologies else "(없음)"
    chain_text = (
        "\n".join(f"- {c}" for c in attack_chains) if attack_chains else "(없음)"
    )

    return f"""당신은 방어 측(Blue Team) 보안 분석가다. 아래 스캔 결과 전체를
Rule Engine 판정과 각 항목의 evidence, 매칭된 보안 지식에 근거하여
방어적으로 요약·해석하라.

{_CONSTRAINTS_BLOCK}

[집계 (읽기 전용 — 개수/severity 변경 금지)]
- 취약점(findings) 개수: {len(findings)}
- attack_surface 항목 개수: {len(attack_surface_items)}
- discovery 항목 개수: {len(discovery_items)}

[취약점(findings)]
{_summ(findings)}

[Attack Surface]
{_summ(attack_surface_items)}

[Discovery]
{_summ(discovery_items)}

[탐지된 기술 스택]
{tech_text}

[관련 공격 체인(참고용, 입력)]
{chain_text}

[매칭된 보안 지식 (matched_knowledge)]
{_fmt_rag(rag_context)}

[요청]
위 입력만을 근거로 다음 항목을 JSON 으로 작성하라. 개수와 severity 는 절대 바꾸지 마라.
근거가 부족하면 "수동 검토 필요" 로 표현하라.
{{
  "executive_summary": "경영진용 요약 (한국어)",
  "overall_risk_commentary": "전반적 위험 코멘트",
  "top_priorities": ["최우선 조치 항목", "..."],
  "attack_chain_summary": "공격 체인 요약 (방어 관점)",
  "operation_team_actions": ["운영팀 조치", "..."],
  "developer_team_actions": ["개발팀 조치", "..."]
}}
출력은 위 JSON 하나만."""


# ── 공개 분석 함수 ─────────────────────────────────────────────────────────────

def _resolve_provider(provider):
    """provider 가 None 이면 지연 import 로 기본 프로바이더를 얻는다."""
    if provider is not None:
        return provider
    # 순환참조 방지를 위한 함수 내부 지연 import.
    from ai_provider import get_ai_provider
    return get_ai_provider()


async def analyze_finding_with_ollama(finding: dict, rag_context: dict,
                                      technologies: list = None,
                                      attack_chains: list = None,
                                      provider=None) -> dict:
    """단일 finding 을 방어적으로 분석한다. finding 은 읽기 전용으로만 사용한다."""
    rag_context = rag_context or {}
    used_rag = _has_rag(rag_context)

    try:
        provider = _resolve_provider(provider)
    except Exception:
        return _finding_fallback(rag_context)

    prov_name, model = _parse_provider_name(getattr(provider, "name", ""))
    if prov_name in ("", "none"):
        return _finding_fallback(rag_context)

    prompt = build_finding_prompt(finding, rag_context, technologies, attack_chains)

    try:
        raw = await provider.complete(prompt)
    except Exception:
        return _finding_fallback(rag_context)

    parsed = _extract_json(raw)
    if parsed is None:
        return _finding_fallback(rag_context)

    result = _normalize(
        parsed, FINDING_KEYS, _FINDING_LIST_FIELDS, prov_name, model, used_rag
    )

    # CONFIRMED/POSSIBLE 정책 후처리
    confirmed = _finding_is_confirmed(finding)
    fp = (result.get("false_positive_assessment") or "").strip()
    if confirmed:
        # 실증 항목엔 오탐 의심/수동검토 문구를 만들지 않는다.
        if (not fp) or ("수동 검토" in fp) or ("검토 필요" in fp):
            result["false_positive_assessment"] = "실증/검증으로 확인된 항목으로 오탐 가능성은 낮습니다."
    else:
        # 가능성 단계는 수동 검증 권고를 보장한다.
        if not result.get("additional_verification_steps"):
            result["additional_verification_steps"] = [
                "evidence 를 수동으로 재현하여 취약 여부를 확정하세요.",
            ]
        if not fp:
            result["false_positive_assessment"] = "가능성 단계 — 수동 검증으로 확정이 필요합니다."
    return result


async def analyze_scan_with_ollama(findings: list, attack_surface_items: list,
                                   discovery_items: list, technologies: list,
                                   attack_chains: list, provider=None) -> dict:
    """스캔 전체를 방어적으로 요약 분석한다. 입력은 읽기 전용으로만 사용한다."""
    # 스캔 단위 호출에서는 rag_context 를 별도로 받지 않으므로 매칭 없음으로 둔다.
    rag_context: dict = {}
    used_rag = False

    try:
        provider = _resolve_provider(provider)
    except Exception:
        return _scan_fallback(rag_context)

    prov_name, model = _parse_provider_name(getattr(provider, "name", ""))
    if prov_name in ("", "none"):
        return _scan_fallback(rag_context)

    prompt = build_scan_prompt(
        findings, attack_surface_items, discovery_items,
        technologies, attack_chains, rag_context
    )

    try:
        raw = await provider.complete(prompt)
    except Exception:
        return _scan_fallback(rag_context)

    parsed = _extract_json(raw)
    if parsed is None:
        return _scan_fallback(rag_context)

    return _normalize(
        parsed, SCAN_KEYS, _SCAN_LIST_FIELDS, prov_name, model, used_rag
    )
