"""
critical_prioritizer.py — Critical 취약점 후보 우선순위 점수화.

크리티컬일수록 먼저 점검하도록 입력점/후보를 점수화한다(순수 함수). 점수는 '쉘 획득'이
아니라 '운영 영향 가능성·접근통제 민감도' 기준이며, 자동 공격 강도와 무관하다.
"""
from __future__ import annotations

import re

_SENSITIVE_FUNC = re.compile(
    r"(password|passwd|account|delete|remove|grant|role|permission|privilege|admin|"
    r"approve|approval|transfer|payment|withdraw|reset|deactivate|비밀번호|권한|결제|승인|삭제)",
    re.IGNORECASE)
_PRIVILEGE = re.compile(r"(role|admin|isadmin|is_admin|permission|privilege|grant|sudo|superuser|권한)", re.I)
_OBJECT_ID = re.compile(r"(^id$|uid|userid|accountid|seq|^no$|idx|memberid|orderid|boardid|objectid)", re.I)
_FILE_CMD_API = re.compile(r"(file|upload|cmd|command|exec|api|/api/|\.json|webhook|callback|url|ssrf)", re.I)
_STATE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

# 후보 유형별 가중치(우선순위 높은 항목)
_TYPE_WEIGHT = {
    "command_injection": 5, "rce": 5, "ssrf": 4, "file_upload": 4,
    "idor": 4, "auth_bypass": 4, "business_logic": 3, "path_traversal": 3,
    "sqli": 4, "ssti": 4, "xss": 2, "open_redirect": 2, "csrf": 2,
}


def score_candidate(cand: dict) -> dict:
    """단일 후보/입력점 점수화. 반환: {score, level, factors[]}.

    cand 기대 키(있으면 사용): vuln_type, param, url, method, context,
      authenticated(bool), is_admin_area(bool).
    """
    vt = (cand.get("vuln_type") or "").lower()
    param = cand.get("param") or ""
    url = cand.get("url") or ""
    method = (cand.get("method") or "GET").upper()
    text = f"{param} {url}"
    authed = bool(cand.get("authenticated"))

    score = _TYPE_WEIGHT.get(vt, 1)
    factors: list[str] = [f"유형 가중치({vt or 'generic'})={_TYPE_WEIGHT.get(vt,1)}"]

    if authed:
        score += 3
        factors.append("인증 후(+3)")
    if cand.get("is_admin_area") or re.search(r"(admin|관리자|manage|console)", text, re.I):
        score += 3
        factors.append("관리자 기능(+3)")
    if _PRIVILEGE.search(text):
        score += 3
        factors.append("권한 관련(+3)")
    if _SENSITIVE_FUNC.search(text):
        score += 2
        factors.append("민감 기능(+2)")
    if _OBJECT_ID.search(param):
        score += 2
        factors.append("객체 식별자(+2)")
    if method in _STATE_METHODS:
        score += 1
        factors.append(f"상태 변경 가능({method})(+1)")
    if _FILE_CMD_API.search(text):
        score += 2
        factors.append("파일/명령/API 관련(+2)")
    # 인증 후 IDOR / API 객체참조 가중
    if authed and vt == "idor":
        score += 2
        factors.append("인증 후 IDOR(+2)")

    if score >= 11:
        level = "CRITICAL"
    elif score >= 8:
        level = "HIGH"
    elif score >= 5:
        level = "MEDIUM"
    else:
        level = "LOW"
    return {"score": score, "level": level, "factors": factors}


def prioritize(candidates: list[dict]) -> list[dict]:
    """후보 목록을 점수 내림차순 정렬 + 점수 메타 부여."""
    scored = []
    for c in candidates or []:
        s = score_candidate(c)
        scored.append({**c, "priority_score": s["score"], "priority_level": s["level"],
                       "priority_factors": s["factors"]})
    scored.sort(key=lambda x: x["priority_score"], reverse=True)
    return scored


def count_critical(scored: list[dict]) -> int:
    return sum(1 for c in (scored or []) if c.get("priority_level") in ("CRITICAL", "HIGH"))
