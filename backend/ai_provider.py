"""
ai_provider.py

AI 분석 보강 모듈 — none / ollama / claude 프로바이더 패턴.

환경변수:
  AI_PROVIDER       : "none" | "ollama" | "claude"  (기본값: "none")
  OLLAMA_BASE_URL   : Ollama 서버 주소               (기본값: "http://localhost:11434")
  OLLAMA_MODEL      : 사용할 Ollama 모델명           (기본값: "llama3.2")
  ANTHROPIC_API_KEY : Claude API 키                  (claude 프로바이더 필수)

사용:
  from ai_provider import enhance_analysis
  analysis = await enhance_analysis(domain, analysis, vuln_findings)
"""

import asyncio
import hashlib
import json
import os
from abc import ABC, abstractmethod

# ── AI 속도 팩: finding 분석 결과 캐시 (제목+severity+evidence 시그니처 기준) ──────
#   동일 취약점/재스캔은 LLM 재호출 없이 즉시 재사용(프로세스 메모리).
_AI_FINDING_CACHE: dict = {}
_AI_CACHE_MAX = 500


def _finding_signature(f: dict) -> str:
    title = str(f.get("title", ""))
    sev = str(f.get("severity", "") or f.get("report_severity", ""))
    ev = f.get("evidence_detail") or f.get("evidence") or ""
    raw = f"{title}|{sev}|{str(ev)[:500]}"
    return hashlib.md5(raw.encode("utf-8", "ignore")).hexdigest()


def _should_analyze_finding(f: dict) -> bool:
    """트리아지: 고위험·실증만 AI 분석(저위험/정보성은 건너뛰어 속도 확보).
    AI_ANALYZE_ALL=true 면 전부 분석."""
    if os.getenv("AI_ANALYZE_ALL", "false").lower() in ("1", "true", "yes"):
        return True
    if f.get("probe_confirmed") is True:
        return True
    sev = str(f.get("report_severity") or f.get("severity") or "").upper()
    return sev in ("CRITICAL", "HIGH", "MEDIUM")
from dataclasses import dataclass, field
from typing import Optional

import aiohttp

# ── 환경변수 ───────────────────────────────────────────────────────────────────
_AI_PROVIDER    = os.getenv("AI_PROVIDER", "none").lower().strip()
_OLLAMA_BASE    = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
_OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
_ANTHROPIC_KEY  = os.getenv("ANTHROPIC_API_KEY", "")
_CLAUDE_MODEL   = os.getenv("CLAUDE_MODEL", "claude-haiku-4-5-20251001")
# AI_TIMEOUT 우선, 하위호환으로 AI_TIMEOUT_SEC 도 인정. 기본 30초.
_AI_TIMEOUT     = int(os.getenv("AI_TIMEOUT", os.getenv("AI_TIMEOUT_SEC", "30")))


# ── 결과 구조체 ────────────────────────────────────────────────────────────────

# AI 를 실제로 사용하지 않은(=규칙 기반) 상태를 나타내는 provider 값.
# 이 경우 사용자에게는 'AI 분석 미사용 / 규칙 기반 분석 사용'으로 표기한다.
_RULE_BASED_PROVIDERS = {"fallback", "none"}
_RULE_BASED_LABEL = "AI 분석 미사용 / 규칙 기반 분석 사용"


@dataclass
class AIAnalysisResult:
    provider: str = "none"
    executive_summary: str = ""
    top_attack_chain: str = ""
    remediation_priority: list[dict] = field(default_factory=list)
    risk_assessment: str = ""
    error: Optional[str] = None

    @property
    def ai_used(self) -> bool:
        """실제 AI(LLM)가 분석에 사용되었는지 여부."""
        return self.provider not in _RULE_BASED_PROVIDERS

    @property
    def provider_label(self) -> str:
        """사용자 노출용 프로바이더 라벨.

        provider 가 fallback/none 이면 AI 미사용 사실을 명확히 표시하고,
        그 외에는 실제 프로바이더명을 그대로 노출한다.
        """
        if not self.ai_used:
            return _RULE_BASED_LABEL
        return self.provider

    def to_dict(self) -> dict:
        return {
            "ai_provider": self.provider,
            "ai_used": self.ai_used,
            "ai_provider_label": self.provider_label,
            "ai_executive_summary": self.executive_summary,
            "ai_top_attack_chain": self.top_attack_chain,
            "ai_remediation_priority": self.remediation_priority,
            "ai_risk_assessment": self.risk_assessment,
            "ai_error": self.error,
        }


# ── 프롬프트 빌더 ──────────────────────────────────────────────────────────────

def _build_attack_graph(vuln_findings: list[dict], discovered_assets: dict) -> str:
    """발견된 자산과 취약점을 기반으로 공격 그래프 텍스트를 생성합니다."""
    lines = []

    # 정찰 단계: 발견된 자산 나열
    recon_items = []
    if discovered_assets.get("admin_pages"):
        recon_items.append(f"관리자 페이지 {len(discovered_assets['admin_pages'])}개")
    if discovered_assets.get("admin_apis"):
        recon_items.append(f"내부 API {len(discovered_assets['admin_apis'])}개")
    if discovered_assets.get("swagger_found"):
        recon_items.append(f"Swagger/OpenAPI {len(discovered_assets['swagger_found'])}개")
    if discovered_assets.get("graphql_found"):
        recon_items.append(f"GraphQL {len(discovered_assets['graphql_found'])}개")
    if recon_items:
        lines.append(f"[정찰] {', '.join(recon_items)} 발견")

    # 취약점 단계: severity 순으로 체인 구성
    high = [f for f in vuln_findings if f.get("severity") == "HIGH"]
    med  = [f for f in vuln_findings if f.get("severity") == "MEDIUM"]
    low  = [f for f in vuln_findings if f.get("severity") == "LOW"]

    ordered = high[:2] + med[:2] + low[:1]
    for i, f in enumerate(ordered):
        arrow = "→" if i > 0 else "↓"
        lines.append(f"{arrow} [{f.get('severity', '')}] {f.get('title', '')}")

    if not lines:
        return "발견된 공격 체인 없음"

    return "\n".join(lines)


def _build_prompt(domain: str, analysis: dict, vuln_findings: list[dict],
                  discovered_assets: dict | None = None) -> str:
    high   = [f for f in vuln_findings if f.get("severity") == "HIGH"]
    medium = [f for f in vuln_findings if f.get("severity") == "MEDIUM"]
    low    = [f for f in vuln_findings if f.get("severity") == "LOW"]

    findings_lines = []
    for i, f in enumerate(vuln_findings[:15], 1):
        sev   = f.get("severity", "")
        title = f.get("title", "")
        owasp = f.get("owasp", "")
        conf  = f.get("confidence", "")
        rec   = (f.get("recommendation") or "")[:120]
        findings_lines.append(
            f"{i}. [{sev}] {title}"
            + (f" ({owasp})" if owasp else "")
            + (f" — Confidence: {conf}" if conf else "")
            + (f"\n   권고: {rec}" if rec else "")
        )

    findings_text = "\n".join(findings_lines) if findings_lines else "취약점 없음"
    overall_risk  = analysis.get("overall_risk", "GOOD")
    attack_chain  = analysis.get("attack_chain", {})
    chain_recon   = attack_chain.get("recon", "")
    chain_pen     = attack_chain.get("penetration", "")

    # 발견된 자산 섹션 (Phase 6)
    assets = discovered_assets or {}
    attack_graph = _build_attack_graph(vuln_findings, assets)

    assets_lines = []
    if assets.get("admin_pages"):
        pages = [p.get("url", str(p)) if isinstance(p, dict) else str(p)
                 for p in assets["admin_pages"][:3]]
        assets_lines.append(f"- 관리자 페이지: {', '.join(pages)}")
    if assets.get("admin_apis"):
        apis = [a.get("url", str(a)) if isinstance(a, dict) else str(a)
                for a in assets["admin_apis"][:3]]
        assets_lines.append(f"- 내부/관리 API: {', '.join(apis)}")
    if assets.get("swagger_found"):
        sw = assets["swagger_found"]
        sw_info = []
        for s in sw[:2]:
            cnt = s.get("api_count", 0) if isinstance(s, dict) else 0
            url = s.get("url", "") if isinstance(s, dict) else str(s)
            sw_info.append(f"{url}({cnt}개 API)")
        assets_lines.append(f"- Swagger/OpenAPI: {', '.join(sw_info)}")
    if assets.get("graphql_found"):
        gql_info = []
        for g in assets["graphql_found"][:2]:
            url = g.get("url", "") if isinstance(g, dict) else str(g)
            admin_mut = g.get("admin_mutations", []) if isinstance(g, dict) else []
            info = url
            if admin_mut:
                info += f"(관리 Mutation: {', '.join(admin_mut[:2])})"
            gql_info.append(info)
        assets_lines.append(f"- GraphQL: {', '.join(gql_info)}")
    if assets.get("framework_hints"):
        fw_names = list({f.get("framework", "") for f in assets["framework_hints"]})[:3]
        assets_lines.append(f"- 프레임워크: {', '.join(fw_names)}")

    assets_section = "\n".join(assets_lines) if assets_lines else "발견된 자산 없음"

    prompt = f"""당신은 보안 취약점 분석 전문가입니다. 아래 스캔 결과를 분석하고 반드시 JSON만 응답하세요. JSON 외 텍스트 없이 순수 JSON만 출력하세요.

[스캔 대상]
도메인: {domain}
전체 위험도: {overall_risk}
취약점: HIGH {len(high)}개, MEDIUM {len(medium)}개, LOW {len(low)}개

[발견된 자산 (URL Discovery 결과)]
{assets_section}

[공격 그래프 (발견된 자산 → 취약점 연결)]
{attack_graph}

[룰 엔진 공격 체인]
정찰: {chain_recon}
침투: {chain_pen}

[발견된 취약점 목록]
{findings_text}

중요: AI는 위에 나열된 발견된 취약점과 자산만을 기반으로 설명합니다. evidence 없는 취약점을 새로 생성하거나 추측하지 마세요.

위 정보를 바탕으로 다음 JSON 형식으로 한국어로 응답하세요:
{{
  "executive_summary": "경영진·비기술 담당자를 위한 요약 (3~4문장). 발견된 취약점이 비즈니스에 미치는 실질적 영향 중심으로 서술.",
  "top_attack_chain": "발견된 자산과 취약점을 연결한 가장 위험한 공격 시나리오 (2~4문장). 정찰→침투→목표 달성 순서로 서술. 관리자 페이지나 API가 발견된 경우 이를 활용한 시나리오 포함.",
  "remediation_priority": [
    {{"rank": 1, "title": "취약점명", "reason": "우선 처리해야 하는 이유 (1문장)"}},
    {{"rank": 2, "title": "취약점명", "reason": "이유"}},
    {{"rank": 3, "title": "취약점명", "reason": "이유"}}
  ],
  "risk_assessment": "전체 보안 수준 평가 및 개선 방향 제언 (2~3문장)."
}}"""
    return prompt


import re as _re

def _extract_json_candidate(raw: str) -> str:
    """다양한 형태의 AI 응답에서 JSON 후보 문자열을 추출합니다."""
    raw = raw.strip()

    # 1) ```json ... ``` 블록
    m = _re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
    if m:
        return m.group(1).strip()

    # 2) { ... } 범위 추출 — 가장 바깥쪽 중괄호 기준
    try:
        start = raw.index("{")
        # 중첩 depth 추적으로 닫는 } 찾기
        depth = 0
        for i, ch in enumerate(raw[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return raw[start:i + 1]
    except ValueError:
        pass

    return raw


def _parse_ai_response(raw: str, provider: str) -> AIAnalysisResult:
    """AI 응답에서 JSON을 추출하고 AIAnalysisResult로 변환합니다."""
    if not raw:
        return AIAnalysisResult(provider=provider, error="empty_response")

    candidate = _extract_json_candidate(raw)

    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        # 후처리: 후행 쉼표, 단일 따옴표, 제어문자 제거 후 재시도
        fixed = _re.sub(r",\s*([}\]])", r"\1", candidate)
        fixed = fixed.replace("'", '"')
        fixed = _re.sub(r"[\x00-\x1f\x7f]", " ", fixed)
        try:
            data = json.loads(fixed)
        except json.JSONDecodeError:
            return AIAnalysisResult(provider=provider, error="json_parse_error")

    return AIAnalysisResult(
        provider=provider,
        executive_summary=data.get("executive_summary", ""),
        top_attack_chain=data.get("top_attack_chain", ""),
        remediation_priority=data.get("remediation_priority", []),
        risk_assessment=data.get("risk_assessment", ""),
    )


def _build_fallback_summary(domain: str, vuln_findings: list[dict],
                            discovered_assets: dict | None = None) -> AIAnalysisResult:
    """AI 호출 실패 시 규칙 기반 fallback 요약을 생성합니다."""
    high   = [f for f in vuln_findings if f.get("severity") == "HIGH"]
    medium = [f for f in vuln_findings if f.get("severity") == "MEDIUM"]
    low    = [f for f in vuln_findings if f.get("severity") == "LOW"]
    assets = discovered_assets or {}

    asset_parts = []
    if assets.get("admin_pages"):
        asset_parts.append(f"관리자 페이지 {len(assets['admin_pages'])}개")
    if assets.get("admin_apis"):
        asset_parts.append(f"내부 API {len(assets['admin_apis'])}개")
    if assets.get("swagger_found"):
        asset_parts.append(f"Swagger/OpenAPI {len(assets['swagger_found'])}개")
    if assets.get("graphql_found"):
        asset_parts.append(f"GraphQL {len(assets['graphql_found'])}개")

    asset_text = f" {', '.join(asset_parts)}이 외부에 노출되어 있으며," if asset_parts else ""

    summary = (
        f"{domain} 도메인에서 총 {len(vuln_findings)}건의 취약점이 발견되었습니다.{asset_text} "
        f"높은 위험도 {len(high)}건, 중간 위험도 {len(medium)}건, 낮은 위험도 {len(low)}건입니다. "
        "발견된 취약점을 심각도 순으로 즉시 조치하시기 바랍니다."
    )

    # 관리자 페이지 + 취약점이 함께 발견된 경우 더 구체적인 체인 설명
    if assets.get("admin_pages") and high:
        admin_url = (assets["admin_pages"][0].get("url", "관리자 페이지")
                     if isinstance(assets["admin_pages"][0], dict)
                     else str(assets["admin_pages"][0]))
        top_chain = (
            f"공격자는 먼저 노출된 관리자 페이지({admin_url})를 통해 대상을 식별하고, "
            f"'{high[0]['title']}' 취약점을 이용한 초기 침투 후 관리자 권한 획득을 시도할 수 있습니다."
        )
    elif assets.get("swagger_found") and (high or medium):
        first_vuln = (high + medium)[0]
        top_chain = (
            f"Swagger/OpenAPI 문서가 공개되어 전체 API 구조가 노출된 상황에서, "
            f"'{first_vuln['title']}' 취약점과 결합하면 체계적인 API 공격이 가능합니다."
        )
    else:
        top_chain = (
            f"가장 위험한 취약점은 '{high[0]['title']}'으로, 즉각적인 조치가 필요합니다."
            if high else
            f"발견된 취약점 중 '{medium[0]['title']}'에 대한 조치를 우선 진행하십시오."
            if medium else "발견된 취약점에 대한 조치를 진행하십시오."
        )
    priority = [
        {"rank": i + 1, "title": f["title"], "reason": f.get("recommendation", "조치 필요")[:80]}
        for i, f in enumerate((high + medium + low)[:3])
    ]
    return AIAnalysisResult(
        provider="fallback",
        executive_summary=f"[{_RULE_BASED_LABEL}] {summary}",
        top_attack_chain=top_chain,
        remediation_priority=priority,
        risk_assessment=(
            f"{_RULE_BASED_LABEL}: AI(LLM) 분석을 사용하지 않고 규칙 기반으로 요약을 생성했습니다. "
            "취약점 개수·심각도는 규칙 엔진 탐지 결과이며 AI가 변경하지 않습니다. "
            "상세 분석은 각 취약점 항목을 참고하세요."
        ),
    )


# ── 프로바이더 추상 클래스 ─────────────────────────────────────────────────────

class BaseAIProvider(ABC):
    @abstractmethod
    async def complete(self, prompt: str, timeout: int | None = None) -> str:
        """프롬프트를 전달하고 응답 텍스트를 반환합니다.

        timeout: 이 호출에만 적용할 응답 대기 상한(초). None 이면 전역 _AI_TIMEOUT.
                 대형 요약(전체 서사)처럼 무거운 모델(예: 32b, 부분 CPU offload)로 오래
                 걸리는 단일 호출에 넉넉한 상한을 주어 불필요한 규칙기반 fallback 을 막는다.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...


# ── None 프로바이더 ────────────────────────────────────────────────────────────

class NoneProvider(BaseAIProvider):
    @property
    def name(self) -> str:
        return "none"

    async def complete(self, prompt: str, timeout: int | None = None) -> str:
        return ""


# ── Ollama 프로바이더 ──────────────────────────────────────────────────────────

class OllamaProvider(BaseAIProvider):
    def __init__(self, base_url: str = _OLLAMA_BASE, model: str = _OLLAMA_MODEL):
        self.base_url = base_url.rstrip("/")
        self.model = model

    @property
    def name(self) -> str:
        return f"ollama/{self.model}"

    async def complete(self, prompt: str, timeout: int | None = None) -> str:
        url = f"{self.base_url}/api/chat"
        _t = int(timeout) if timeout else _AI_TIMEOUT
        try:
            # 512 는 취약점 다수(10건+) JSON 응답에 부족해 '절단→json_parse_error' 를 유발했다.
            # 기본을 1536 으로 상향(필요 시 AI_NUM_PREDICT 로 조절).
            num_predict = int(os.getenv("AI_NUM_PREDICT", "1536"))
        except (TypeError, ValueError):
            num_predict = 1536
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            # 모델 상주 — 호출 사이 언로드/재로딩 제거(속도)
            "keep_alive": os.getenv("OLLAMA_KEEP_ALIVE", "30m"),
            "options": {
                "temperature": 0.2,
                "num_predict": num_predict,
            },
        }
        # 프롬프트가 JSON 출력을 요구하면 Ollama 구조화 출력(format=json)으로 '유효한 JSON'을 강제한다.
        # → 마크다운(```json) 감싸기·서두/후미 잡텍스트·절단으로 인한 json_parse_error 를 원천 차단.
        if "json" in prompt.lower():
            payload["format"] = "json"
        _cto = aiohttp.ClientTimeout(total=_t)
        try:
            async with aiohttp.ClientSession(timeout=_cto) as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        raise RuntimeError(f"Ollama HTTP {resp.status}: {text[:200]}")
                    data = await resp.json()
                    return data.get("message", {}).get("content", "")
        except aiohttp.ClientConnectorError:
            raise RuntimeError(f"Ollama 서버 연결 실패: {self.base_url}")
        except asyncio.TimeoutError:
            raise RuntimeError(f"Ollama 응답 시간 초과 ({_t}s)")

    async def is_available(self) -> bool:
        """Ollama 서버 및 모델 가용 여부 확인."""
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"{self.base_url}/api/tags") as resp:
                    if resp.status != 200:
                        return False
                    data = await resp.json()
                    models = [m.get("name", "") for m in data.get("models", [])]
                    return any(self.model in m for m in models)
        except Exception:
            return False


# ── Claude 프로바이더 ──────────────────────────────────────────────────────────

class ClaudeProvider(BaseAIProvider):
    def __init__(self, api_key: str = _ANTHROPIC_KEY, model: str = _CLAUDE_MODEL):
        self.api_key = api_key
        self.model = model
        self._api_url = "https://api.anthropic.com/v1/messages"

    @property
    def name(self) -> str:
        return f"claude/{self.model}"

    async def complete(self, prompt: str, timeout: int | None = None) -> str:
        if not self.api_key:
            raise RuntimeError("ANTHROPIC_API_KEY 환경변수가 설정되지 않았습니다.")
        _t = int(timeout) if timeout else _AI_TIMEOUT

        # anthropic SDK 우선 시도
        try:
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=self.api_key)
            msg = await client.messages.create(
                model=self.model,
                max_tokens=1024,
                temperature=0.2,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text if msg.content else ""
        except ImportError:
            pass  # SDK 없으면 직접 HTTP 호출

        # 직접 HTTP 호출 (SDK 미설치 환경)
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }
        _cto = aiohttp.ClientTimeout(total=_t)
        async with aiohttp.ClientSession(timeout=_cto) as session:
            async with session.post(self._api_url, json=payload, headers=headers) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(f"Claude API HTTP {resp.status}: {text[:400]}")
                data = await resp.json()
                return data.get("content", [{}])[0].get("text", "")


# ── 프로바이더 팩토리 ──────────────────────────────────────────────────────────

def get_ai_provider() -> BaseAIProvider:
    """AI_PROVIDER 환경변수에 따라 적절한 프로바이더를 반환합니다."""
    provider_name = _AI_PROVIDER
    if provider_name == "ollama":
        return OllamaProvider()
    if provider_name == "claude":
        return ClaudeProvider()
    return NoneProvider()


# ── 역할→모델 라우터 + 오탐 앙상블 판정 (설정 파일 ai_roles.json — 계속 업데이트 가능) ──
_ROLES_PATH = os.getenv("AI_ROLES_CONFIG",
                        os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai_roles.json"))
_ROLES_CACHE: dict = {"mtime": 0.0, "data": None}


def load_ai_roles() -> dict:
    """ai_roles.json 로드(파일 수정 시 자동 반영 — mtime 기반). 파일 없거나 오류면 기본값."""
    default = {"enabled": True, "fallback_model": _OLLAMA_MODEL, "roles": {},
               "fp_judge_ensemble": {"enabled": False, "panel": [], "fp_votes_to_downgrade": 2}}
    try:
        mt = os.path.getmtime(_ROLES_PATH)
        if _ROLES_CACHE["data"] is not None and mt == _ROLES_CACHE["mtime"]:
            return _ROLES_CACHE["data"]
        import json as _json
        with open(_ROLES_PATH, encoding="utf-8") as f:
            data = _json.load(f)
        _ROLES_CACHE.update(mtime=mt, data=data)
        return data
    except Exception:
        return _ROLES_CACHE["data"] or default


def role_model(role: str | None) -> str | None:
    """역할에 매핑된 모델명. 라우팅 비활성/미지정이면 None(→ 기본 모델 사용)."""
    if not role:
        return None
    cfg = load_ai_roles()
    if not cfg.get("enabled", True):
        return None
    r = (cfg.get("roles") or {}).get(role) or {}
    return r.get("model") or None


def _provider_with_model(model: str | None) -> BaseAIProvider:
    """지정 모델로 Ollama 프로바이더 생성(ollama 일 때만). 그 외엔 기본 프로바이더."""
    if _AI_PROVIDER == "ollama" and model:
        return OllamaProvider(model=model)
    return get_ai_provider()


def _is_model_missing(exc) -> bool:
    s = str(exc).lower()
    return any(k in s for k in ("not found", "404", "try pulling", "no such model"))


def make_sync_ai_fn(max_calls: int | None = None, role: str | None = None):
    """동기 ai_fn(prompt:str)->str 를 만든다.

    role 을 주면 ai_roles.json 의 역할→모델 라우팅을 적용한다(예: role="poc" → 코드 특화 모델).
    역할 모델이 없으면 fallback_model 로 자동 대체(개발/단일GPU 환경 안전).

    attack_graph/ai_exploit_planning/poc_generator 등 '동기' 빌더가 AI 를 쓰도록 하는 브리지.
    - 반드시 **워커 스레드**(asyncio.to_thread 등)에서 호출해야 한다. 자체적으로 asyncio.run 을
      돌리므로, 이미 실행 중인 이벤트 루프 스레드에서 직접 호출하면 안 된다.
    - **스캔당 호출 예산**(max_calls)을 둬 느린 로컬 LLM 이 폭주하지 않게 한다. 예산 소진/실패/
      미가용 시 "" 반환 → 호출부의 결정적 백스톱이 유지된다(판정·증거는 절대 바꾸지 않음).
    provider 가 none 이면 None 을 반환(호출부는 ai_fn 미주입과 동일하게 동작)."""
    provider = get_ai_provider()
    if isinstance(provider, NoneProvider):
        return None
    if max_calls is None:
        try:
            max_calls = int(os.getenv("AI_MAX_CALLS_PER_SCAN", "16"))
        except (TypeError, ValueError):
            max_calls = 16

    # 역할→모델 라우팅 + 폴백
    rm = role_model(role)
    primary = _provider_with_model(rm) if rm else provider
    _fb_model = (load_ai_roles().get("fallback_model") or _OLLAMA_MODEL)
    fallback = (_provider_with_model(_fb_model)
                if (rm and _fb_model and _fb_model != rm and _AI_PROVIDER == "ollama") else None)
    state = {"used": 0}

    def _fn(prompt: str) -> str:
        if state["used"] >= max_calls:
            return ""   # 예산 소진 → 결정적 백스톱
        state["used"] += 1
        import asyncio as _a
        try:
            return _a.run(primary.complete(prompt)) or ""
        except Exception as e:
            # 역할 모델이 아직 없으면(pull 전) 기본 모델로 1회 폴백 — 그 외 오류는 백스톱
            if fallback is not None and _is_model_missing(e):
                try:
                    return _a.run(fallback.complete(prompt)) or ""
                except Exception:
                    return ""
            return ""
    return _fn


# ── 오탐 앙상블 판정(advisory 전용) ────────────────────────────────────────────
# 원칙: 룰이 1차, AI 는 2차 보조. AI 는 CONFIRMED 를 '삭제'하지 않는다 —
#       confidence 하향 + 검토표시(flag)까지만. 진짜 취약점을 숨기는 미탐을 방지한다.
_JUDGE_PROMPT = (
    "너는 웹 보안 전문가다. 아래는 스캐너가 '확인(CONFIRMED)'으로 보고한 취약점 항목이다.\n"
    "이 판정이 실제 취약점(REAL)인지 오탐(FP)인지 판단하라.\n"
    "반드시 첫 줄에 REAL 또는 FP 만 쓰고, 둘째 줄에 한 줄 이유만 써라.\n\n"
    "제목: {title}\n유형: {type}\n근거: {evidence}\n")


def _parse_vote(text: str) -> str:
    """모델 응답 → 'real' / 'fp' / 'uncertain'."""
    if not text:
        return "uncertain"
    head = text.strip().splitlines()[0]
    head_u = head.upper()
    # 부정 표현 우선 처리 — '취약하지 않음' / '정탐 아님' / '해당 없음' 등은 FP 로 해석.
    # (기존엔 '취약' 문자열만 보고 REAL 로 오독했음)
    if (any(neg in head for neg in ("않", "아님", "아니", "없")) and
            any(kw in head for kw in ("취약", "정탐")) or "NOT VULN" in head_u):
        return "fp"
    if "FP" in head_u or "오탐" in head or "FALSE" in head_u:
        return "fp"
    if "REAL" in head_u or "정탐" in head or "취약" in head or "TRUE" in head_u:
        return "real"
    low = text.lower()
    if "오탐" in text or "false positive" in low:
        return "fp"
    return "uncertain"


def _aggregate_votes(votes: list[str], threshold: int, action: str) -> dict:
    """투표 집계(순수). 유효표 2 미만이면 판단 보류(action 없음 — 미탐 방지)."""
    valid = [v for v in votes if v in ("real", "fp")]
    total = len(valid)
    fp = valid.count("fp")
    if total < 2:
        return {"verdict": "uncertain", "fp_votes": fp, "total_votes": total, "action": "none"}
    if fp >= threshold:
        return {"verdict": "fp", "fp_votes": fp, "total_votes": total, "action": action}
    return {"verdict": "real", "fp_votes": fp, "total_votes": total, "action": "none"}


async def ensemble_fp_judge(finding: dict, base_url: str | None = None) -> dict | None:
    """CONFIRMED 취약점을 다계열 판정 패널이 투표해 오탐 여부를 advisory 로 판단.

    반환 None = 앙상블 비활성/미가용(=아무 조치 안 함). dict = {verdict, action, reasons, ...}.
    action="downgrade_and_flag" 여도 호출부는 confidence 하향/플래그만 하고 삭제하지 않는다.
    """
    cfg = load_ai_roles()
    ens = cfg.get("fp_judge_ensemble") or {}
    if not (cfg.get("enabled", True) and ens.get("enabled") and _AI_PROVIDER == "ollama"):
        return None
    panel = ens.get("panel") or []
    threshold = int(ens.get("fp_votes_to_downgrade", 2))
    action = ens.get("action", "downgrade_and_flag")
    base = (base_url or _OLLAMA_BASE).rstrip("/")
    prompt = _JUDGE_PROMPT.format(
        title=finding.get("title", ""),
        type=finding.get("type") or finding.get("family") or "",
        evidence=(finding.get("evidence_detail") or finding.get("evidence") or "")[:600])

    votes: list[str] = []
    reasons: list[str] = []
    for model in panel:
        prov = OllamaProvider(base_url=base, model=model)
        try:
            if not await prov.is_available():
                continue                       # 아직 pull 안 된 모델은 건너뜀(폴백)
            resp = await prov.complete(prompt)
        except Exception:
            continue
        v = _parse_vote(resp)
        if v in ("real", "fp"):
            votes.append(v)
            reasons.append(f"{model}: {v} — {(resp or '').strip().splitlines()[-1][:80]}")
    result = _aggregate_votes(votes, threshold, action)
    result["reasons"] = reasons
    result["panel_used"] = len([v for v in votes if v in ("real", "fp")])
    return result


async def apply_fp_ensemble(analysis: dict, base_url: str | None = None,
                            max_checks: int | None = None) -> dict:
    """CONFIRMED 취약점에 앙상블 오탐 판정을 advisory 로 적용한다(룰 판정·데이터 불변 원칙).

    조치는 오직: finding['ai_fp_flag']=True + 근거 노트 추가 + confidence 표시 하향(POSSIBLE).
    **삭제/judgment 변경 금지** — 진짜 취약점을 숨기는 미탐을 방지한다. 패널 미가용이면 no-op.
    반환: {'checked': n, 'flagged': m} 요약.
    """
    cfg = load_ai_roles()
    ens = cfg.get("fp_judge_ensemble") or {}
    if not (cfg.get("enabled", True) and ens.get("enabled") and _AI_PROVIDER == "ollama"):
        return {"checked": 0, "flagged": 0, "skipped": "ensemble_disabled"}
    if max_checks is None:
        try:
            max_checks = int(os.getenv("AI_FP_ENSEMBLE_MAX", "20"))
        except (TypeError, ValueError):
            max_checks = 20
    findings = analysis.get("findings") or []
    confirmed = [f for f in findings
                 if f.get("probe_confirmed") is True or str(f.get("confidence", "")).upper().startswith("CONFIRMED")]
    checked = flagged = 0
    for f in confirmed[:max_checks]:
        verdict = await ensemble_fp_judge(f, base_url=base_url)
        if not verdict or verdict.get("verdict") == "uncertain":
            continue
        checked += 1
        if verdict.get("verdict") == "fp" and verdict.get("action") != "none":
            flagged += 1
            f["ai_fp_flag"] = True
            f["ai_fp_reasons"] = verdict.get("reasons", [])
            f["ai_fp_votes"] = f"{verdict.get('fp_votes')}/{verdict.get('total_votes')}"
            note = (f"\n⚠ AI 앙상블 오탐 의심({f['ai_fp_votes']}표) — 수동 확인 권장. "
                    "룰 판정은 유지(자동 삭제 안 함).")
            f["evidence_detail"] = (f.get("evidence_detail") or "") + note
            # 표시 confidence 만 하향(판정·심각도·버킷 불변)
            f["ai_review_confidence"] = "POSSIBLE"
    return {"checked": checked, "flagged": flagged}


# ── 메인 진입점 ────────────────────────────────────────────────────────────────

async def enhance_analysis(
    domain: str,
    analysis: dict,
    vuln_findings: list[dict] | None = None,
    discovered_assets: dict | None = None,
) -> dict:
    """
    rule_engine의 analysis dict를 AI로 보강합니다.
    분석 결과를 analysis dict에 직접 추가하고 반환합니다.

    vuln_findings가 None이면 analysis["findings"]에서 취약 항목을 추출합니다.
    discovered_assets: URL Discovery 결과 (admin_pages, admin_apis, swagger_found, graphql_found 등)
    """
    if vuln_findings is None:
        vuln_findings = [
            f for f in analysis.get("findings", [])
            if f.get("judgment") == "취약"
        ]

    # 역할 라우팅: 취약점 보강 분석도 'analysis' 역할 모델(예: qwen2.5:32b)을 사용.
    # (enrich_with_security_analyst 와 동일 — 두 AI 경로 모두 무거운 추론 모델로 통일)
    provider = _provider_with_model(role_model("analysis"))

    # NoneProvider 또는 취약점 없으면 AI 호출 생략
    if isinstance(provider, NoneProvider) or not vuln_findings:
        analysis["ai_analysis"] = AIAnalysisResult(provider=provider.name).to_dict()
        return analysis

    prompt = _build_prompt(domain, analysis, vuln_findings, discovered_assets)

    ai_result: AIAnalysisResult | None = None
    _fb_reason = ""   # fallback 사유(타임아웃/파싱실패 등) — 보고서·상태 정직성 위해 기록
    # 전체 서사 요약은 취약점 다수(10건+)를 한 프롬프트로 처리해 무겁다. 무거운 모델(analysis=32b,
    # 부분 CPU offload)에서 전역 _AI_TIMEOUT(예: 120s)을 넘겨 불필요하게 규칙기반으로 떨어지던
    # 문제를 막기 위해, 이 단일 호출에는 넉넉한 요약 전용 상한(AI_SUMMARY_TIMEOUT, 기본 600s)을 준다.
    try:
        _summary_timeout = int(os.getenv("AI_SUMMARY_TIMEOUT", "600"))
    except (TypeError, ValueError):
        _summary_timeout = 600
    for attempt in range(2):  # 최대 1회 재시도
        try:
            raw_response = await provider.complete(prompt, timeout=_summary_timeout)
            result = _parse_ai_response(raw_response, provider.name)
            if result.error:
                # 파싱 실패 → 1회 재시도 후 fallback
                _fb_reason = result.error   # empty_response / json_parse_error
                if attempt == 0:
                    continue
                ai_result = _build_fallback_summary(domain, vuln_findings, discovered_assets)
            else:
                ai_result = result
            break
        except Exception as _e:
            # 타임아웃/연결오류 등 — 유형을 사유로 남긴다.
            _msg = str(_e)
            _fb_reason = (FALLBACK_TIMEOUT if ("시간 초과" in _msg or "timeout" in _msg.lower())
                          else f"{type(_e).__name__}: {_msg[:80]}")
            if attempt == 1:
                ai_result = _build_fallback_summary(domain, vuln_findings, discovered_assets)

    if ai_result is None:
        ai_result = _build_fallback_summary(domain, vuln_findings)

    # fallback(규칙기반)으로 떨어졌으면 '왜' 를 error 로 기록 — 과거엔 사유 없이 '완료(fallback)' 로만
    # 표기돼 원인 파악이 불가했다. 이제 로그/상태/보고서에 사유(TIMEOUT/json_parse_error 등)가 남는다.
    if ai_result.provider in _RULE_BASED_PROVIDERS and _fb_reason and not ai_result.error:
        ai_result.error = _fb_reason

    analysis["ai_analysis"] = ai_result.to_dict()
    return analysis


# ── Security Analyst + RAG 보강 (Ollama 기반) ──────────────────────────────────

def _ai_analysis_enabled() -> bool:
    return os.getenv("ENABLE_AI_ANALYSIS", "false").lower().strip() in ("true", "1", "yes")


def _ai_require_json() -> bool:
    return os.getenv("AI_REQUIRE_JSON", "true").lower().strip() in ("true", "1", "yes")


# fallback_reason 표준 값 (보고서 표기·테스트 계약).
FALLBACK_ENABLE_FALSE   = "ENABLE_AI_ANALYSIS_FALSE"
FALLBACK_CONN_FAILED    = "OLLAMA_CONNECTION_FAILED"
FALLBACK_MODEL_NOT_FOUND = "MODEL_NOT_FOUND"
FALLBACK_JSON_PARSE     = "JSON_PARSE_FAILED"
FALLBACK_NOT_CONFIGURED = "PROVIDER_NOT_CONFIGURED"
FALLBACK_TIMEOUT        = "TIMEOUT"
FALLBACK_INTERNAL       = "INTERNAL_ERROR"


def _empty_ai_status() -> dict:
    """ai_status 의 모든 키를 가진 기본 구조(보고서 KeyError 방지용)."""
    return {
        "enabled": False,
        "provider": "",
        "model": "",
        "base_url": "",
        "available": False,
        "used": False,
        "fallback": True,
        "fallback_reason": "",
        "last_error": "",
        "analyzed_findings": 0,
        "rag_mode": "keyword",
        "embed_model": "",
    }


def _classify_error(exc: Exception) -> str:
    """예외를 fallback_reason 으로 분류한다."""
    msg = str(exc).lower()
    if "시간 초과" in str(exc) or "timeout" in msg:
        return FALLBACK_TIMEOUT
    if "연결 실패" in str(exc) or "connect" in msg or "connection" in msg:
        return FALLBACK_CONN_FAILED
    if "model" in msg and ("not found" in msg or "없" in str(exc)):
        return FALLBACK_MODEL_NOT_FOUND
    return FALLBACK_INTERNAL


async def enrich_with_security_analyst(domain: str, analysis: dict) -> dict:
    """
    Rule Engine / finding_normalizer 결과를 'AI 보안 분석가 의견'으로 보강한다.
    - ENABLE_AI_ANALYSIS=true 이고 Ollama 가 실제 사용 가능할 때만 finding 에 ai_analysis 를 부여한다.
    - analysis["ai_status"] 에 AI 사용/미사용 상태를 1회 기록한다(보고서가 1회만 표시).
    - finding 의 title/severity/confidence/confidence_score/judgment/finding_type/개수는
      절대 변경하지 않는다 (ai_analysis 하위에만 저장 — 읽기 전용).
    - AI 비활성/실패 시 finding 에 fallback ai_analysis 를 붙이지 않는다(used=False).
    """
    status = _empty_ai_status()

    # ── 1) AI 비활성 ──
    if not _ai_analysis_enabled():
        status["fallback_reason"] = FALLBACK_ENABLE_FALSE
        analysis["ai_status"] = status
        return analysis

    status["enabled"] = True

    # 지연 import (순환참조 방지)
    import security_rag
    import security_analyst

    # 역할 라우팅: 취약점 분석은 'analysis' 역할 모델(예: qwen2.5:32b)을 사용한다.
    # role_model 이 None(라우팅 비활성/미설정)이면 _provider_with_model 이 기본 모델로 폴백.
    provider = _provider_with_model(role_model("analysis"))
    prov_name = getattr(provider, "name", "") or ""
    base_url = getattr(provider, "base_url", "") or ""
    model = getattr(provider, "model", "") or ""
    status["provider"] = prov_name
    status["model"] = model
    status["base_url"] = base_url

    # ── 2) 프로바이더 미설정(none) ──
    if isinstance(provider, NoneProvider) or prov_name.startswith("none"):
        status["fallback_reason"] = FALLBACK_NOT_CONFIGURED
        analysis["ai_status"] = status
        return analysis

    # ── 3) Ollama 가용성 확인 ──
    if isinstance(provider, OllamaProvider):
        try:
            available = await provider.is_available()
        except Exception as e:
            available = False
            status["last_error"] = str(e)[:200]
        status["available"] = available
        if not available:
            # 서버 미응답/모델 없음 — 둘을 세분화하기 어려우므로 연결 실패로 분류
            status["fallback_reason"] = status["fallback_reason"] or FALLBACK_CONN_FAILED
            analysis["ai_status"] = status
            return analysis
    else:
        status["available"] = True

    findings  = analysis.get("findings", []) or []
    techs     = analysis.get("technologies", []) or []
    chains    = analysis.get("attack_chains", []) or []
    surface   = analysis.get("attack_surface_items", []) or []
    discovery = analysis.get("discovery_items", []) or []

    require_json = _ai_require_json()
    analyzed = 0
    last_error = ""
    last_reason = ""

    # ── 속도 팩: 트리아지 → 병렬 호출 → 캐시 ──────────────────────────────────
    try:
        _concurrency = max(1, int(os.getenv("AI_CONCURRENCY", "3")))
    except (TypeError, ValueError):
        _concurrency = 3
    sem = asyncio.Semaphore(_concurrency)
    errors: list = []

    # 분석 대상 선별(고위험·실증만; 나머지는 LLM 호출 생략)
    targets = [f for f in findings if _should_analyze_finding(f)]

    # 임베딩 RAG 활성 시 의미 검색(비활성/실패 시 키워드 RAG 폴백)
    try:
        import security_embed as _se
        _use_embed = _se.embed_enabled()
    except Exception:
        _use_embed = False
    # 보고서 정직성: 어떤 RAG 모드를 사용했는지 기록(embedding 의미검색 / keyword 매칭)
    status["rag_mode"] = "embedding" if _use_embed else "keyword"
    if _use_embed:
        try:
            status["embed_model"] = _se.embed_model()
        except Exception:
            pass

    async def _analyze_one(f: dict):
        sig = _finding_signature(f)
        cached = _AI_FINDING_CACHE.get(sig)
        if cached is not None:
            f["ai_analysis"] = dict(cached)
            return "cache_hit"
        try:
            if _use_embed:
                rag = await security_rag.retrieve_knowledge_semantic(f, techs, chains)
            else:
                rag = security_rag.retrieve_knowledge(f, techs, chains)
        except Exception:
            rag = {"matched_knowledge": []}
        async with sem:
            try:
                result = await security_analyst.analyze_finding_with_ollama(
                    f, rag, techs, chains, provider=provider,
                )
            except Exception as e:
                errors.append(e)
                return "error"
        if (result.get("provider") or "").lower() == "ollama":
            # RAG 매칭 지식을 finding 에 각인(보고서 투명성 — 대응방안 근거 제시).
            # 상위 3개의 CWE/제목/유사도만 저장(경량).
            try:
                _mk = (rag or {}).get("matched_knowledge") or []
                if _mk:
                    result["matched_knowledge"] = [
                        {"cwe": m.get("cwe"), "title": m.get("title"),
                         "similarity": m.get("similarity")}
                        for m in _mk[:3]
                    ]
            except Exception:
                pass
            f["ai_analysis"] = result
            if len(_AI_FINDING_CACHE) < _AI_CACHE_MAX:
                _AI_FINDING_CACHE[sig] = dict(result)
            return "ok"
        return "fallback"

    # 개별 finding 병렬 + 스캔 전체 분석을 동시에 실행(동시성 캡 내)
    finding_tasks = [_analyze_one(f) for f in targets]
    scan_task = security_analyst.analyze_scan_with_ollama(
        findings, surface, discovery, techs, chains, provider=provider,
    )
    gathered = await asyncio.gather(*finding_tasks, scan_task, return_exceptions=True)
    finding_outcomes = gathered[:-1]
    scan_outcome = gathered[-1]

    analyzed = sum(1 for o in finding_outcomes if o in ("ok", "cache_hit"))
    if errors:
        last_error = str(errors[0])[:200]
        last_reason = _classify_error(errors[0])
    elif require_json and any(o == "fallback" for o in finding_outcomes):
        last_reason = FALLBACK_JSON_PARSE

    # 스캔 전체 분석 결과 반영
    if isinstance(scan_outcome, dict):
        if (scan_outcome.get("provider") or "").lower() == "ollama":
            analysis["ai_scan_analysis"] = scan_outcome
        elif require_json and not last_reason:
            last_reason = FALLBACK_JSON_PARSE
    elif isinstance(scan_outcome, Exception):
        last_error = last_error or str(scan_outcome)[:200]
        last_reason = last_reason or _classify_error(scan_outcome)

    # ── ai_status 확정 ──
    if analyzed > 0:
        status["used"] = True
        status["fallback"] = False
        status["analyzed_findings"] = analyzed
        status["fallback_reason"] = ""
    else:
        status["used"] = False
        status["fallback"] = True
        status["analyzed_findings"] = 0
        status["last_error"] = last_error
        # findings 가 없으면 사용할 대상이 없었던 것 — 내부 오류로 표기하지 않음.
        if not findings:
            status["fallback_reason"] = status["fallback_reason"] or FALLBACK_NOT_CONFIGURED
        else:
            status["fallback_reason"] = last_reason or FALLBACK_INTERNAL

    analysis["ai_status"] = status
    return analysis


async def check_provider_health() -> dict:
    """현재 설정된 AI 프로바이더의 상태를 확인합니다.

    프로바이더 가용성뿐 아니라 역할→모델 라우팅, 앙상블/솔로 모드,
    오탐 판정 패널, 신규 프로브 토글 상태까지 반환한다(프론트 표시용).
    """
    provider = get_ai_provider()
    result = {
        "provider": provider.name,
        "configured": not isinstance(provider, NoneProvider),
        "available": False,
        "error": None,
    }

    if isinstance(provider, NoneProvider):
        result["available"] = True
    elif isinstance(provider, OllamaProvider):
        result["available"] = await provider.is_available()
        if not result["available"]:
            result["error"] = f"Ollama 서버({provider.base_url})에 모델 '{provider.model}'이 없거나 서버 미응답"
    elif isinstance(provider, ClaudeProvider):
        if not provider.api_key:
            result["error"] = "ANTHROPIC_API_KEY 미설정"
        else:
            result["available"] = True

    # ── 역할 라우터 + 앙상블/솔로 모드 정보 ──────────────────────────────
    try:
        roles = load_ai_roles()
        ens = roles.get("fp_judge_ensemble") or {}
        result["routing_enabled"] = bool(roles.get("enabled", True))
        result["fallback_model"] = roles.get("fallback_model") or ""
        result["roles"] = {k: (v or {}).get("model") for k, v in (roles.get("roles") or {}).items()}
        result["mode"] = "ensemble" if ens.get("enabled") else "solo"
        result["fp_judge_ensemble"] = {
            "enabled": bool(ens.get("enabled")),
            "panel": ens.get("panel") or [],
            "votes_to_downgrade": ens.get("fp_votes_to_downgrade", 2),
        }
    except Exception:
        result["mode"] = "solo"
        result["roles"] = {}
        result["fp_judge_ensemble"] = {"enabled": False, "panel": [], "votes_to_downgrade": 2}

    # ── 신규 프로브 토글 상태(기본값 포함) ───────────────────────────────
    def _b(name: str, default: str = "false") -> bool:
        return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")

    result["probes"] = {
        "sqlmap": _b("ENABLE_SQLMAP"),
        "oob": _b("ENABLE_OOB"),
        "unauth_write_bac": _b("ENABLE_UNAUTH_WRITE_BAC", "true"),
        "cve_intel": _b("ENABLE_CVE_INTEL", "true"),
    }
    return result
