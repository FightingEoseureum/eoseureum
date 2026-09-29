"""
business_impact_engine.py — 기술적 결과 → 비즈니스 영향 변환(순수 로직).

새 탐지/판정 없음. 기존 analysis(Finding/Attack Path/Evidence Level/Solver/Agent/
Attack Surface)를 받아 비즈니스 영향·규제 관련 가능성·Executive Risk Score 로 변환한다.
AI 는 설명 보강만 가능하며 Risk Score/Evidence Level/판정을 변경할 수 없다.

규제 관련 표시는 '관련 가능성' 수준만 제시하며 실제 법률 판정은 하지 않는다.
"""
from __future__ import annotations

import re

import evidence_levels as evl

# Impact Category (복수 선택 가능)
CONFIDENTIALITY = "Confidentiality"
INTEGRITY = "Integrity"
AVAILABILITY = "Availability"
ACCESS_CONTROL = "Access Control"
AUTHENTICATION = "Authentication"
AUTHORIZATION = "Authorization"
DATA_EXPOSURE = "Data Exposure"
BUSINESS_LOGIC = "Business Logic"
OPERATIONAL_RISK = "Operational Risk"
COMPLIANCE_RISK = "Compliance Risk"

# 패밀리 → 비즈니스 영향 매핑
_IMPACT_MAP: dict[str, dict] = {
    "idor": {
        "categories": [ACCESS_CONTROL, DATA_EXPOSURE, CONFIDENTIALITY, COMPLIANCE_RISK],
        "affected_asset": "고객/사용자 데이터",
        "business_risk": "타 사용자 데이터 접근으로 고객 정보 노출 가능",
        "consequences": ["고객 정보 노출 가능", "타 사용자 데이터 접근 가능성", "개인정보보호 규정 영향"],
        "regulatory": ["개인정보"],
    },
    "xss": {
        "categories": [INTEGRITY, AUTHENTICATION, CONFIDENTIALITY],
        "affected_asset": "사용자 세션/브라우저",
        "business_risk": "세션 탈취·관리자 계정 악용으로 권한 오남용 가능",
        "consequences": ["세션 탈취 가능성", "관리자 계정 악용 가능성", "악성 코드 전달 가능성"],
        "regulatory": ["인증 정보"],
    },
    "sqli": {
        "categories": [CONFIDENTIALITY, INTEGRITY, DATA_EXPOSURE, COMPLIANCE_RISK],
        "affected_asset": "데이터베이스",
        "business_risk": "DB 데이터 노출·변조 가능",
        "consequences": ["데이터베이스 정보 노출 가능", "데이터 무결성 훼손 가능"],
        "regulatory": ["개인정보", "금융 정보"],
    },
    "csrf": {
        "categories": [INTEGRITY, AUTHORIZATION],
        "affected_asset": "상태 변경 기능",
        "business_risk": "피해자 권한으로 임의 상태 변경 가능",
        "consequences": ["권한 도용 상태 변경 가능", "비밀번호/설정 변경 악용 가능"],
        "regulatory": ["접근 통제"],
    },
    "business_logic": {
        "categories": [BUSINESS_LOGIC, INTEGRITY, OPERATIONAL_RISK],
        "affected_asset": "거래/권한 로직",
        "business_risk": "가격 조작·승인 우회로 금전적 손실 가능",
        "consequences": ["가격 조작 가능성", "승인 절차 우회 가능성", "금전적 손실 가능성"],
        "regulatory": ["금융 정보"],
    },
    "upload": {
        "categories": [INTEGRITY, OPERATIONAL_RISK, AVAILABILITY],
        "affected_asset": "파일 저장/처리 시스템",
        "business_risk": "악성 파일 처리로 운영 위험 가능(자동 업로드 미수행)",
        "consequences": ["악성 파일 처리 위험", "저장소 노출 가능성"],
        "regulatory": ["내부 시스템 정보"],
    },
    "ssrf": {
        "categories": [CONFIDENTIALITY, ACCESS_CONTROL, OPERATIONAL_RISK],
        "affected_asset": "내부망/클라우드 메타데이터",
        "business_risk": "서버측 요청으로 내부 자산 노출 가능",
        "consequences": ["내부 자산 노출 가능성", "클라우드 메타데이터 접근 위험"],
        "regulatory": ["내부 시스템 정보"],
    },
    "redirect": {
        "categories": [INTEGRITY, AUTHENTICATION],
        "affected_asset": "사용자 신뢰/세션",
        "business_risk": "피싱·세션 우회에 악용 가능",
        "consequences": ["피싱 유도 가능성", "인증 우회 경유 가능성"],
        "regulatory": [],
    },
    "auth": {
        "categories": [AUTHENTICATION, ACCESS_CONTROL],
        "affected_asset": "인증 체계",
        "business_risk": "인증 우회 시 비인가 접근 가능",
        "consequences": ["인증 우회 가능성", "비인가 접근 가능성"],
        "regulatory": ["인증 정보", "접근 통제"],
    },
    "path_traversal": {
        "categories": [CONFIDENTIALITY, DATA_EXPOSURE],
        "affected_asset": "서버 파일 시스템",
        "business_risk": "서버 파일 노출 가능",
        "consequences": ["서버 파일 노출 가능성"],
        "regulatory": ["내부 시스템 정보"],
    },
    "ssti": {
        "categories": [INTEGRITY, OPERATIONAL_RISK],
        "affected_asset": "서버 템플릿 엔진",
        "business_risk": "서버측 표현식 평가로 무결성 위험",
        "consequences": ["서버측 표현식 평가 가능성"],
        "regulatory": ["내부 시스템 정보"],
    },
    "cmdi": {
        "categories": [INTEGRITY, AVAILABILITY, OPERATIONAL_RISK],
        "affected_asset": "서버 운영체제",
        "business_risk": "OS 명령 실행 시 운영 위험(기본 미수행, 승인 시 무해 증거만)",
        "consequences": ["서버 명령 실행 가능성(증거 한정)"],
        "regulatory": ["내부 시스템 정보"],
    },
}

# 규제 관련 가능성 매핑(데이터 유형 → 관련 영역). 실제 법률 판정 아님.
_REGULATORY_AREA = {
    "개인정보": "개인정보 보호(관련 가능성)",
    "인증 정보": "접근 통제·인증 보호(관련 가능성)",
    "금융 정보": "금융 정보 보호·감사 추적(관련 가능성)",
    "내부 시스템 정보": "내부 시스템 접근 통제(관련 가능성)",
    "접근 통제": "접근 통제(관련 가능성)",
}

_FAMILY_KW = [
    ("idor", ("idor", "객체 참조", "object reference")),
    ("sqli", ("sql 인젝션", "sql injection", "sqli")),
    ("xss", ("xss", "스크립트")),
    ("csrf", ("csrf",)),
    ("business_logic", ("비즈니스 로직", "business logic")),
    ("upload", ("업로드", "upload")),
    ("ssrf", ("ssrf",)),
    ("redirect", ("리다이렉트", "redirect", "open redirect")),
    ("auth", ("인증 우회", "auth bypass", "로그인 우회", "인증")),
    ("path_traversal", ("경로 추적", "path traversal", "lfi")),
    ("ssti", ("ssti", "템플릿")),
    ("cmdi", ("명령", "command injection", "rce")),
]


def family_of(text: str) -> str | None:
    t = (text or "").lower()
    for fam, kws in _FAMILY_KW:
        if any(k in t for k in kws):
            return fam
    return None


_SENSITIVE = re.compile(r"(관리자|admin|비밀번호|password|계정|account|결제|payment|권한|role|개인정보)", re.I)


def executive_risk_score(*, evidence_level: int, path_priority: str = "",
                         authenticated: bool = False, admin: bool = False,
                         sensitive: bool = False, categories: list[str] | None = None) -> dict:
    """Executive Risk Score(기술 점수와 별도). 반환 {score, level, factors}."""
    cats = categories or []
    score = 0
    factors: list[str] = []
    lvl_w = {3: 4, 2: 2, 1: 1}.get(int(evidence_level or 0), 0)
    if lvl_w:
        score += lvl_w; factors.append(f"검증 수준 L{evidence_level}(+{lvl_w})")
    pp = (path_priority or "").lower()
    pw = 4 if "critical" in pp else 3 if "high" in pp else 2 if "medium" in pp else 0
    if pw:
        score += pw; factors.append(f"경로 우선순위({path_priority})(+{pw})")
    if authenticated:
        score += 2; factors.append("인증 후(+2)")
    if admin:
        score += 3; factors.append("관리자 기능(+3)")
    if sensitive:
        score += 2; factors.append("민감 기능(+2)")
    if any(c in (DATA_EXPOSURE, COMPLIANCE_RISK, BUSINESS_LOGIC) for c in cats):
        score += 2; factors.append("고영향 범주(+2)")

    if score >= 10:
        level = "Critical"
    elif score >= 7:
        level = "High"
    elif score >= 4:
        level = "Medium"
    else:
        level = "Low"
    return {"score": score, "level": level, "factors": factors}


def assess_finding(finding: dict, *, path: dict | None = None) -> dict | None:
    """단일 finding → 비즈니스 영향 평가. 매핑 불가(패밀리 미상)면 None."""
    title = finding.get("title", "")
    fam = family_of(title)
    if not fam:
        return None
    m = _IMPACT_MAP[fam]
    level = evl.level_of(finding, finding_type="vulnerability")
    text = title + " " + (finding.get("evidence_detail") or "")
    authed = bool(finding.get("authenticated") or finding.get("is_verified_idor")
                  or (path and "인증 후" in (path.get("title") or "")))
    admin = bool(re.search(r"관리자|admin", text, re.I))
    sensitive = bool(_SENSITIVE.search(text))
    er = executive_risk_score(evidence_level=level, path_priority=(path or {}).get("risk_grade", ""),
                              authenticated=authed, admin=admin, sensitive=sensitive,
                              categories=m["categories"])
    reg = [_REGULATORY_AREA.get(r, r) for r in m.get("regulatory", [])]
    return {
        "family": fam,
        "title": title,
        "impact_category": list(m["categories"]),
        "business_risk": m["business_risk"],
        "affected_asset": m["affected_asset"],
        "impact_description": m["business_risk"],
        "potential_consequence": list(m["consequences"]),
        "regulatory_risk": reg,
        "evidence_level": level,
        "executive_risk_score": er["score"],
        "priority": er["level"],
        "priority_factors": er["factors"],
    }


def build_business_impact(analysis: dict) -> dict:
    """analysis 의 findings(+공격 경로 컨텍스트)를 비즈니스 영향 목록으로 변환."""
    analysis = analysis or {}
    paths_by_fam: dict = {}
    for p in (analysis.get("attack_paths") or []):
        fam = family_of(p.get("title", ""))
        if fam and fam not in paths_by_fam:
            paths_by_fam[fam] = p

    items: list[dict] = []
    for f in (analysis.get("findings") or []):
        # 확정 취약점만 비즈니스 영향에 반영 — 양호/오탐 억제 항목은 제외(집계 부풀림 방지)
        if f.get("judgment") == "양호" or f.get("_fp_suppressed"):
            continue
        fam = family_of(f.get("title", ""))
        imp = assess_finding(f, path=paths_by_fam.get(fam))
        if imp:
            items.append(imp)
    # 참고(discovery) 후보도 영향 가능성으로 포함(낮은 우선순위)
    for d in (analysis.get("discovery_items") or []):
        fam = family_of(d.get("title", ""))
        if fam and not any(it["title"] == d.get("title") for it in items):
            imp = assess_finding(d, path=paths_by_fam.get(fam))
            if imp:
                items.append(imp)

    items.sort(key=lambda x: x["executive_risk_score"], reverse=True)
    summary = _summarize(items)
    return {"items": items, "summary": summary, "ai_cannot_confirm": True}


def _summarize(items: list[dict]) -> dict:
    def lvl(n):
        return sum(1 for x in items if x["priority"] == n)
    cat_count: dict = {}
    reg_count: dict = {}
    for it in items:
        for c in it["impact_category"]:
            cat_count[c] = cat_count.get(c, 0) + 1
        for r in it["regulatory_risk"]:
            reg_count[r] = reg_count.get(r, 0) + 1
    return {
        "total": len(items),
        "critical": lvl("Critical"), "high": lvl("High"),
        "medium": lvl("Medium"), "low": lvl("Low"),
        "by_category": cat_count,
        "by_regulatory": reg_count,
    }
