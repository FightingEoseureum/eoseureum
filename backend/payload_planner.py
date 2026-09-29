"""
payload_planner.py — AI 기반 Payload Planner + 조합형 Technique Planner.

역할:
  - 입력점 분류 결과를 받아, 취약점 유형별 'payload 후보'와 'technique 순서'를 계획한다.
  - AI(온프레미스)는 '제안'만 한다. 생성된 payload 는 그대로 실행하지 않으며, 반드시
    payload_validator 를 통과해야 한다. AI 는 '취약 판정(CONFIRMED)'을 만들 수 없다.
  - 최종 판정은 Rule Engine(proof_mode 경유) 전담. 여기서는 계획/후보/검증 결과만 산출.

핵심:
  - AI 미가용/실패 시에도 동작하도록 '결정적 안전 payload 베이스라인'을 내장(테스트 결정성).
  - 모든 payload 는 validate 단계를 거쳐 실행 허용 여부(execution_plan)가 결정된다.
"""
from __future__ import annotations

import json
import re

import payload_validator as pv

# 지원 취약점 유형(후보)
VULN_TYPES = [
    "xss", "sqli", "idor", "csrf", "open_redirect", "ssrf",
    "path_traversal", "file_upload", "ssti", "command_injection",
    "business_logic", "auth_bypass",
]

# RCE 증거용 고정 echo marker (validator 가 RCE_PROOF_MODE 에서만 허용)
RCE_ECHO_MARKER = "EOSEUREUM_RCE_PROOF_7F3A"

# ── 결정적 안전 payload 베이스라인(검증 통과 보장 설계) ───────────────────────
_BASE_PAYLOADS: dict[str, list[str]] = {
    "xss": ["<script>alert('EOSEUREUM_XSS_PROOF')</script>",
            "\"><svg onload=alert('EOSEUREUM_XSS_PROOF')>",
            "' onmouseover=alert('EOSEUREUM_XSS_PROOF') x='",
            "<img src=x onerror=alert('EOSEUREUM_XSS_PROOF')>",
            "\" autofocus onfocus=alert('EOSEUREUM_XSS_PROOF') x=\"",
            "';alert('EOSEUREUM_XSS_PROOF');//",
            "</script><svg onload=alert('EOSEUREUM_XSS_PROOF')>",
            "<sVg/oNloAd=alert('EOSEUREUM_XSS_PROOF')>"],
    "sqli": ["'", "\"", "' OR '1'='1", "' OR '1'='1'-- -", "' AND '1'='1", "' AND '1'='2",
             "1' ORDER BY 1-- -", "' UNION SELECT NULL-- -", "') OR ('1'='1",
             "1' AND SLEEP_DISABLED--"],
    "idor": ["{neighbor_id}"],            # 값 치환은 교차계정 검증에서 수행(비파괴)
    "csrf": ["<no-token-request>"],       # 후보 분석/위험도 평가만(요청 미전송)
    "open_redirect": ["//evil.example.com", "https://evil.example.com", "/\\evil.example.com"],
    "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80/"],  # 후보(자동 전송 안 함)
    "path_traversal": ["../../../../etc/hostname", "..%2f..%2f..%2fetc%2fhostname"],
    "file_upload": ["eoseureum_probe.txt:hello world", "eoseureum_probe.png"],  # 무해 파일(후보 분석)
    "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
    "command_injection": [f";echo {RCE_ECHO_MARKER}", f"|echo {RCE_ECHO_MARKER}"],
    "business_logic": ["{tampered_value}"],   # 값 변조는 수동 검토(자동 조작 안 함)
    "auth_bypass": ["' OR '1'='1", "admin'-- -"],
}

# 유형별 기대 신호 / 기본 위험도 / 안전 메모
_EXPECTED_SIGNAL = {
    "xss": "Playwright 브라우저 alert 발생(미발생 시 반사만→POSSIBLE)",
    "sqli": "SQLMap injectable 확인 또는 DB 에러 원문 반사",
    "idor": "교차 계정 응답에 타 사용자 식별정보 노출",
    "csrf": "토큰/SameSite/상태변경성 기반 위험도(자동 확정 없음)",
    "open_redirect": "Location 헤더에 외부 도메인 반환",
    "ssrf": "내부 메타데이터/내부망 응답(자동 전송 없음 — 후보)",
    "path_traversal": "응답에 파일 내용 노출(후보 — 무해 파일만)",
    "file_upload": "서버측 확장자/콘텐츠 검증 부재(업로드는 승인 시에만)",
    "ssti": "응답에 수식 평가 결과(예: 49) 출력",
    "command_injection": "RCE Proof Mode 에서 고정 echo marker 반사만",
    "business_logic": "서버측 재검증 부재(값 변조는 수동 검토)",
    "auth_bypass": "로그인 폼 우회 신호(안전 응답 비교, 잠금 금지)",
}
_RISK = {
    "xss": "HIGH", "sqli": "HIGH", "idor": "HIGH", "command_injection": "HIGH",
    "ssrf": "HIGH", "file_upload": "MEDIUM", "ssti": "HIGH", "path_traversal": "MEDIUM",
    "open_redirect": "MEDIUM", "csrf": "MEDIUM", "business_logic": "MEDIUM", "auth_bypass": "HIGH",
}
_SAFETY_NOTE = {
    "command_injection": "OS 명령 실행 기본 금지 — RCE_PROOF_MODE 승인 시 무해 echo marker 만.",
    "sqli": "Time-based/DML/stacked/덤프/파일 I/O 금지. SQLMap 안전 옵션만.",
    "file_upload": "실제 웹쉘/실행파일 업로드 금지. 무해 hello-world 는 승인 시에만.",
    "ssrf": "자동 외부/내부 요청 전송 안 함 — 후보 분류만.",
    "idor": "읽기 전용 교차계정 검증, 상태 변경 금지.",
    "csrf": "상태 변경 요청 미수행 — 위험도 평가만.",
}

# 입력 컨텍스트 → technique 조합 순서(조합형 Planner)
_CONTEXT_TECHNIQUES = {
    "login": ["auth_bypass", "sqli"],
    "search": ["xss", "sqli", "ssti"],
    "file": ["idor", "path_traversal"],
    "redirect": ["open_redirect"],
    "url": ["ssrf", "open_redirect"],
    "business": ["business_logic"],
    "object_ref": ["idor"],
    "generic": ["xss", "sqli"],
}

_REDIRECT_PARAMS = re.compile(r"(redirect|next|url|return|returnurl|goto|dest|target|continue)", re.I)
_URL_PARAMS = re.compile(r"(url|uri|webhook|callback|fetch|proxy|site|host|link)", re.I)
_FILE_PARAMS = re.compile(r"(file|filename|path|doc|document|download|attachment|fileid|page)", re.I)
_OBJ_PARAMS = re.compile(r"(^id$|uid|userid|accountid|seq|^no$|idx|memberid|orderid|boardid)", re.I)
_BIZ_PARAMS = re.compile(r"(price|amount|discount|point|balance|role|admin|isadmin|permission|approval|qty|quantity)", re.I)


def _classify_techniques(point: dict) -> list[str]:
    """입력점 컨텍스트로 technique 조합 순서를 결정(조합형 planner의 결정적 코어)."""
    ctx = (point.get("context") or "generic").lower()
    param = (point.get("param") or "")
    techs: list[str] = []

    def add(*ts):
        for t in ts:
            if t not in techs:
                techs.append(t)

    if ctx == "login" or _is_login(point):
        add("auth_bypass", "sqli")
    if ctx == "search":
        add("xss", "sqli", "ssti")
    if _OBJ_PARAMS.search(param):
        add("idor")
    if _FILE_PARAMS.search(param):
        add("idor", "path_traversal", "file_upload")
    if _REDIRECT_PARAMS.search(param):
        add("open_redirect")
    if _URL_PARAMS.search(param):
        add("ssrf", "open_redirect")
    if _BIZ_PARAMS.search(param):
        add("business_logic")
    if not techs:
        add(*_CONTEXT_TECHNIQUES.get(ctx, _CONTEXT_TECHNIQUES["generic"]))
    return techs


def _is_login(point: dict) -> bool:
    it = (point.get("input_type") or "").lower()
    return it == "password" or (point.get("context") or "").lower() == "login"


# ── AI 출력 정화: AI 는 판정(verdict/confirmed)을 만들 수 없다 ───────────────────
_AI_FORBIDDEN_KEYS = {"verdict", "confirmed", "confirmed_browser", "confirmed_response",
                      "judgment", "is_vulnerable", "vulnerable", "final_verdict", "severity_final"}


def sanitize_ai_plan(raw: dict) -> dict:
    """AI 가 반환한 계획에서 '판정' 류 필드를 제거한다(AI 는 취약 확정 불가).
    허용 필드만 남기고, payload 는 문자열만 수용한다."""
    if not isinstance(raw, dict):
        return {}
    out: dict = {}
    pls = raw.get("recommended_payloads") or raw.get("payloads") or []
    out["recommended_payloads"] = [str(p) for p in pls if isinstance(p, (str, int, float))][:20]
    for k in ("technique", "expected_signal", "reason", "safety_notes", "risk_level"):
        if k in raw and isinstance(raw[k], (str, int, float)):
            out[k] = str(raw[k])
    out["ai_cannot_confirm"] = True
    out["_stripped"] = sorted(set(raw.keys()) & _AI_FORBIDDEN_KEYS)
    return out


def _safe_ai_call(ai_fn, prompt: str) -> dict:
    """AI 호출 래퍼(실패/미가용 시 빈 dict). 반환 JSON 을 정화."""
    if ai_fn is None:
        return {}
    try:
        text = ai_fn(prompt)
        if not text:
            return {}
        m = re.search(r"\{.*\}", text, re.DOTALL)
        raw = json.loads(m.group(0)) if m else {}
        return sanitize_ai_plan(raw)
    except Exception:
        return {}


# ── 단일 (입력점 × 취약유형) 계획 ─────────────────────────────────────────────
def plan_payloads(point: dict, vuln_type: str, *, ai_fn=None,
                  tech: list[str] | None = None) -> dict:
    """입력점+취약유형에 대한 payload 후보 계획.
    출력: recommended_payloads/technique/expected_signal/risk_level/reason/safety_notes.
    AI 가 있으면 후보를 보강하되, 최종은 베이스라인 ∪ AI(정화) 이고 판정은 만들지 않는다.
    """
    vt = (vuln_type or "").lower()
    base = list(_BASE_PAYLOADS.get(vt, []))
    ai_part = {}
    if ai_fn is not None:
        prompt = _build_prompt(point, vt, tech or [])
        ai_part = _safe_ai_call(ai_fn, prompt)
        for pl in ai_part.get("recommended_payloads", []):
            if pl not in base:
                base.append(pl)

    return {
        "vuln_type": vt,
        "recommended_payloads": base[:20],
        "technique": ai_part.get("technique") or vt,
        "expected_signal": ai_part.get("expected_signal") or _EXPECTED_SIGNAL.get(vt, ""),
        "risk_level": (ai_part.get("risk_level") or _RISK.get(vt, "MEDIUM")).upper(),
        "reason": ai_part.get("reason") or f"{vt} 후보 — 입력 컨텍스트 기반 계획",
        "safety_notes": ai_part.get("safety_notes") or _SAFETY_NOTE.get(vt, "비파괴·안전 페이로드만 사용."),
        "ai_used": bool(ai_part),
        "ai_cannot_confirm": True,
    }


def _build_prompt(point: dict, vt: str, tech: list[str]) -> str:
    return (
        "You are a security testing payload planner. Suggest SAFE, non-destructive payload "
        "candidates ONLY. Never include reverse shells, destructive commands, DB dumps, or "
        "time-based SQLi. You MUST NOT decide whether the target is vulnerable. "
        f"Context: input_type={point.get('input_type')}, param={point.get('param')}, "
        f"endpoint={point.get('url')}, method={point.get('method')}, "
        f"authenticated={point.get('authenticated')}, vuln_type={vt}. "
        'Return JSON: {"recommended_payloads":[...],"technique":"","expected_signal":"",'
        '"risk_level":"LOW|MEDIUM|HIGH","reason":"","safety_notes":""}'
    )


# ── 입력점 단위 통합 계획(조합형 + 검증 + 실행계획) ───────────────────────────
def _input_id(point: dict, idx: int) -> str:
    return f"IP-{idx:03d}:{(point.get('method') or 'GET')}:{point.get('param') or '-'}"


def plan_for_input(point: dict, idx: int = 0, *, ai_fn=None) -> dict:
    """단일 입력점에 대한 조합형 계획 + payload 검증 + 실행계획 산출.

    반환: {input_id, endpoint, param, context, authenticated, selected_techniques,
           payload_candidates[], validator_result{}, execution_plan[], skipped_reason,
           evidence_required[]}.
    실행 자체는 하지 않는다(계획·검증만). 실행은 Eoseureum 정책/probe 엔진이 수행.
    """
    techs = _classify_techniques(point)
    method = (point.get("method") or "GET").upper()
    is_upload_ctx = bool(_FILE_PARAMS.search(point.get("param") or "")) and "file_upload" in techs

    payload_candidates: list[dict] = []
    validator_results: list[dict] = []
    execution_plan: list[dict] = []
    evidence_required: list[str] = []

    for vt in techs:
        plan = plan_payloads(point, vt, ai_fn=ai_fn, tech=techs)
        evidence_required.append(f"{vt}: {plan['expected_signal']}")
        for pl in plan["recommended_payloads"]:
            v = pv.validate_payload(
                pl, vuln_type=vt, method=method,
                is_upload=(vt == "file_upload"),
            )
            entry = {"vuln_type": vt, "payload": pl, "verdict": v["verdict"],
                     "reason": v["reason"], "technique": plan["technique"],
                     "risk_level": plan["risk_level"]}
            payload_candidates.append(entry)
            validator_results.append(v)
            if pv.is_allowed(v["verdict"]):
                execution_plan.append({"vuln_type": vt, "payload": pl,
                                       "technique": plan["technique"],
                                       "expected_signal": plan["expected_signal"]})

    vsum = pv.summarize(validator_results)
    skipped_reason = ""
    if not execution_plan:
        skipped_reason = "안전 실행 가능한 payload 없음(전부 차단/승인 필요)"

    return {
        "input_id": _input_id(point, idx),
        "endpoint": point.get("url", ""),
        "param": point.get("param", ""),
        "context": point.get("context", "generic"),
        "authenticated": bool(point.get("authenticated")),
        "selected_techniques": techs,
        "payload_candidates": payload_candidates,
        "validator_result": vsum,
        "execution_plan": execution_plan,
        "skipped_reason": skipped_reason,
        "evidence_required": evidence_required,
        "ai_cannot_confirm": True,
    }
