"""
false_positive_filter.py — 오탐 억제(자문 + 억제) v2.

soft-404 / WAF 반사 / 동적 콘텐츠 / 일반 에러 반사 등 오탐 유발 패턴을 유형별로 분류해
finding 에 '오탐 위험(fp_risk)' 자문 신호를 부여한다.

v2 추가(억제 게이트 — 물리적으로 불가능하거나 판정 근거가 자기모순인 경우):
  A. 정적 에셋(.woff/.js/.css/.png …)에 대한 인젝션(SSTI/SQLi/XSS 등) 발견 → 자동 억제.
     정적 바이너리/에셋에는 서버측 템플릿·쿼리 실행 경로가 없어 원천적으로 불가.
  B. family↔검증방법 불일치: 능동 인젝션 계열이 'CONFIRMED(실증)'인데 실제 수행한 검증이
     배너 관찰 등 수동 관찰뿐 → 실증 근거 부재로 판단, 자동 억제(inconsistent_confirmed).

중요: Rule Engine 의 최종 판정·Severity·Confidence 필드는 절대 변경하지 않는다. 본 모듈은
'자문(_fp_risk)'과 '표현/집계용 억제 플래그(_fp_suppressed)'만 부여하며, 보고서/점수 계층이
이를 반영한다(억제 항목은 점수·분포 산정에서 제외하고 '오탐 후보'로 표기).
"""
from __future__ import annotations

import re as _re

_SOFT404 = _re.compile(r"(soft.?404|not\s*found|페이지를?\s*찾을\s*수\s*없|does not exist|404\b)", _re.I)
_WAF = _re.compile(r"(waf|mod_?security|cloudflare|incapsula|forbidden|blocked|access denied|"
                   r"request rejected|차단되었습니다)", _re.I)
_GENERIC_ERR = _re.compile(r"(internal server error|500\b|잠시 후 다시|일시적인 오류|unexpected error)", _re.I)
_CONFIRMED = ("CONFIRMED", "CONFIRMED_BROWSER", "CONFIRMED_RESPONSE")

# ── A. 정적 에셋 판별 ─────────────────────────────────────────────────────────
_STATIC_EXT = (
    ".woff", ".woff2", ".ttf", ".otf", ".eot",           # 폰트
    ".css", ".js", ".mjs", ".map",                        # 스타일/스크립트
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",      # 이미지
    ".webp", ".bmp", ".avif",
    ".mp4", ".mp3", ".webm", ".woff", ".pdf", ".zip",     # 미디어/기타
)
# 서버측 실행/주입이 성립하려면 동적 처리 경로가 필요한 계열
_INJECTION_FAMS = {
    "ssti", "sqli", "sql_injection", "xss", "rce", "command_injection", "cmdi",
    "lfi", "rfi", "xxe", "ssrf", "open_redirect", "crlf", "nosqli", "code_injection",
}
# 능동 인젝션 실증에 필요한 계열별 '유효 검증' 키워드(하나라도 있어야 실증 인정)
_ACTIVE_PROOF_TOKENS = {
    "ssti": ("ssti", "arithmetic", "template", "7*7", "49"),
    "sqli": ("sqli", "boolean", "union", "error", "time", "blind"),
    "sql_injection": ("sqli", "boolean", "union", "error", "time", "blind"),
    "xss": ("xss", "alert", "browser", "dom", "script"),
    "rce": ("rce", "command", "exec", "shell", "echo"),
    "command_injection": ("command", "exec", "echo", "shell"),
    "lfi": ("lfi", "traversal", "file", "etc/passwd", "path"),
    "xxe": ("xxe", "entity", "dtd"),
    "ssrf": ("ssrf", "callback", "oob", "collaborator"),
    "open_redirect": ("redirect", "location"),
}
# 수동 관찰(능동 인젝션 실증으로 인정 불가) 검증 기법
_PASSIVE_TECH = {
    "banner_observe", "response_header_analysis", "response_evidence_analysis",
    "header_analysis", "passive_observe", "safe_observe", "안전 관찰", "안전관찰",
}
# 접근통제(인증/인가) 계열 — 정적 에셋 대상이면 오탐(정적 파일은 서버측 인증 로직이 없어 공개가 정상)
_ACCESS_CONTROL_FAMS = {
    "unauth_privileged_content", "missing_auth", "missing_function_level_auth",
    "function_level_auth", "bfla", "bola", "idor", "broken_access_control",
    "unauth_write", "access_control", "authz", "privilege_escalation",
}
_ACCESS_CONTROL_TITLE = _re.compile(
    r'(미인증|무인증|인증\s*없이|특권\s*(?:콘텐츠|기능|접근)|관리\s*기능\s*접근|'
    r'function[\-\s]?level|missing\s*(?:function|auth)|권한\s*상승|접근\s*통제|'
    r'access\s*control|idor|bfla|bola)', _re.I)


def _is_access_control_finding(finding: dict, fam: str) -> bool:
    if fam in _ACCESS_CONTROL_FAMS:
        return True
    t = f"{finding.get('title', '')} {finding.get('type', '')} {finding.get('vuln_type', '')}"
    return bool(_ACCESS_CONTROL_TITLE.search(t))


def _is_static_asset(url: str) -> bool:
    if not url:
        return False
    path = url.split("?", 1)[0].split("#", 1)[0].lower().rstrip("/")
    return path.endswith(_STATIC_EXT)


def _finding_url(finding: dict) -> str:
    # evidence_url 포함 — 일부 finding 은 url 대신 evidence_url 에만 대상 URL 을 담는다.
    return str(finding.get("url") or finding.get("evidence_url") or finding.get("endpoint")
               or finding.get("path") or finding.get("affected_url") or "")


# title 기반 family 유도(family/vuln_type 이 비어있는 finding 대비)
_TITLE_FAM = [
    ("ssti", ("ssti", "템플릿 인젝션", "template inject")),
    ("sqli", ("sql injection", "sqli", "sql 인젝션")),
    ("xss", ("xss", "크로스", "스크립트 삽입")),
    ("rce", ("command inject", "명령", "rce", "코드 실행")),
    ("lfi", ("lfi", "path traversal", "경로 순회", "파일 포함")),
    ("xxe", ("xxe", "xml external")),
    ("ssrf", ("ssrf", "요청 위조")),
    ("open_redirect", ("open redirect", "오픈 리다이렉트")),
]


def _family(finding: dict) -> str:
    fam = (finding.get("family") or finding.get("vuln_type") or "").lower().strip()
    if fam:
        return fam
    # proof_evidence 의 family 매퍼 우선 사용
    try:
        import proof_evidence as _pe
        fam = (_pe._family(finding) or "").lower().strip()
        if fam and fam != "generic":
            return fam
    except Exception:
        pass
    title = (finding.get("title") or "").lower()
    for f, keys in _TITLE_FAM:
        if any(k in title for k in keys):
            return f
    return fam


def assess(finding: dict, proof_rec: dict | None = None) -> dict:
    """단일 finding 의 오탐 위험 자문 + 억제 판정.
    반환: {fp_risk, reasons, advisory, inconsistent_confirmed, suppress, suppress_reason}."""
    conf = (finding.get("confidence") or "").upper()
    fam = _family(finding)
    ev = " ".join(str(finding.get(k, "")) for k in
                  ("evidence_detail", "observed_result", "detail", "title")).strip()
    url = _finding_url(finding)
    reasons, risk = [], "low"
    suppress, suppress_reason = False, None

    # ── A. 정적 에셋에 인젝션 → 물리적으로 불가(즉시 억제) ──────────────────────
    if fam in _INJECTION_FAMS and _is_static_asset(url):
        return {"fp_risk": "high",
                "reasons": [f"정적 에셋({_ext(url)})에 대한 {fam.upper()} 발견 — 서버측 실행 경로 부재로 물리적 불가(오탐)"],
                "advisory": True, "inconsistent_confirmed": conf in _CONFIRMED,
                "suppress": True,
                "suppress_reason": f"정적 에셋 인젝션(오탐): {_ext(url) or 'static'} 리소스에는 템플릿/쿼리 실행 경로가 없음"}

    # ── A2. 정적 에셋 대상 접근통제(무인증/인가) → 오탐(정적 파일 공개는 정상) ──────
    # 예: /_nuxt/pages/admin/api.<hash>.js 같은 SPA 빌드 번들. 경로에 'admin' 이 있고 번들 안에
    # 관리 UI 문자열이 들어있다고 '무인증 관리기능 접근'으로 오판되던 것 차단(서버측 인증 로직 부재).
    if _is_static_asset(url) and _is_access_control_finding(finding, fam):
        return {"fp_risk": "high",
                "reasons": [f"정적 에셋({_ext(url)}) 대상 무인증/인가 finding — 정적 파일 공개 서빙은 정상(서버측 인증 로직 없음)"],
                "advisory": True, "inconsistent_confirmed": conf in _CONFIRMED,
                "suppress": True,
                "suppress_reason": f"정적 에셋 접근통제(오탐): {_ext(url) or 'static'} 는 공개 서빙이 정상 — 특권/인가 대상 아님"}

    # ── B. family↔검증방법 불일치: 능동 인젝션 CONFIRMED 인데 수동 관찰만 수행 ──
    if proof_rec is not None and fam in _INJECTION_FAMS and conf in _CONFIRMED:
        techs = [str(t).lower() for t in (proof_rec.get("performed_techniques") or [])]
        if techs:
            need = _ACTIVE_PROOF_TOKENS.get(fam, (fam,))
            has_active = any(any(tok in t for tok in need) for t in techs)
            only_passive = all(t in _PASSIVE_TECH for t in techs)
            if only_passive and not has_active:
                return {"fp_risk": "high",
                        "reasons": [f"{fam.upper()} '실증(CONFIRMED)' 이나 실제 수행 검증이 수동 관찰뿐"
                                    f"({', '.join(techs)}) — 능동 실증 근거 부재"],
                        "advisory": True, "inconsistent_confirmed": True,
                        "suppress": True,
                        "suppress_reason": f"검증방법 불일치: {fam.upper()} 실증 주장 대비 능동 증거 없음(수행: {', '.join(techs)})"}

    # ── 기존 자문 패턴 ────────────────────────────────────────────────────────
    if _SOFT404.search(ev):
        risk = "high"; reasons.append("soft-404/미존재 페이지 반사 가능성")
    if _WAF.search(ev):
        risk = "high"; reasons.append("WAF/차단 응답 반사 가능성")
    if _GENERIC_ERR.search(ev) and fam in ("sqli", "ssti"):
        risk = _max(risk, "medium"); reasons.append("일반 서버 오류 반사(주입 오탐 주의)")
    if fam == "xss" and conf not in _CONFIRMED and "alert" not in ev.lower():
        risk = _max(risk, "medium"); reasons.append("스크립트 실행 미확인(반사만) — 비실행 반사 여지")
    if len((finding.get("evidence_detail") or "").strip()) < 8 and conf not in _CONFIRMED:
        risk = _max(risk, "medium"); reasons.append("증거 근거가 빈약(동적 콘텐츠 차이 가능)")

    inconsistent = conf in _CONFIRMED and risk == "high"
    if conf in _CONFIRMED and not inconsistent:
        risk = "low"; reasons = reasons or ["실증 확인됨 — 오탐 위험 낮음"]
    return {"fp_risk": risk, "reasons": reasons or ["특이 오탐 신호 없음"],
            "advisory": True, "inconsistent_confirmed": inconsistent,
            "suppress": False, "suppress_reason": None}


def _ext(url: str) -> str:
    path = url.split("?", 1)[0].split("#", 1)[0].lower().rstrip("/")
    for e in _STATIC_EXT:
        if path.endswith(e):
            return e
    return ""


def _max(a: str, b: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    return a if order[a] >= order[b] else b


def _proof_rec_for(analysis: dict, f: dict) -> dict | None:
    recs = analysis.get("proof_validation") or []
    uid = f.get("finding_uid") or f.get("_idx")
    return (next((r for r in recs if r.get("finding_uid") == uid or r.get("finding_id") == uid), None)
            or next((r for r in recs if r.get("finding_title") == f.get("title")), None))


def annotate(analysis: dict) -> dict:
    """findings 에 _fp_risk 자문 + _fp_suppressed 억제 플래그 부여(원본 판정 불변) + 요약 반환."""
    findings = [f for f in (analysis.get("findings") or []) if f.get("judgment") != "양호"]
    counts = {"low": 0, "medium": 0, "high": 0}
    inconsistent, suppressed = [], []
    for f in findings:
        a = assess(f, _proof_rec_for(analysis, f))
        f["_fp_risk"] = a["fp_risk"]
        f["_fp_reasons"] = a["reasons"]
        f["_fp_suppressed"] = bool(a.get("suppress"))
        if a.get("suppress"):
            f["_fp_suppress_reason"] = a.get("suppress_reason")
            suppressed.append({"title": f.get("title", ""), "reason": a.get("suppress_reason")})
        counts[a["fp_risk"]] += 1
        if a["inconsistent_confirmed"]:
            inconsistent.append(f.get("title", ""))
    return {"fp_risk_summary": {
        "high": counts["high"], "medium": counts["medium"], "low": counts["low"],
        "inconsistent_confirmed": inconsistent,
        "suppressed": suppressed,
        "suppressed_count": len(suppressed),
        "note": "오탐 위험은 참고용 자문입니다. 억제(suppressed) 항목은 물리적 불가/검증 불일치로 "
                "판단해 점수·분포 산정에서 제외하고 '오탐 후보'로 표기합니다(Rule Engine 원본 판정은 보존).",
    }}


def is_suppressed(f: dict) -> bool:
    """점수·분포·표현 계층에서 억제 여부 확인용."""
    return bool(f.get("_fp_suppressed"))
