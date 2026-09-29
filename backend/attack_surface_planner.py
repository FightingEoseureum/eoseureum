"""
attack_surface_planner.py — 입력점 '의미 분석 → 공격 표면 점수화 → 추천 technique → 우선순위'.

Technique Planner(payload_planner) 앞단에 위치한다. 입력점의 의미/비즈니스 역할을 파악하고,
Technique Knowledge Base(technique_kb)에서 추천 technique 을 도출하며, 공격 표면 점수로
우선순위를 매겨 Probe 예산을 최적화한다. AI Reasoning Trace 를 함께 저장한다.

중복 금지: payload 생성/검증/판정은 기존 계층(payload_planner/validator/proof_mode/
critical_prioritizer)이 담당한다. 이 모듈은 '무엇을 먼저, 왜 점검할지'만 결정한다.
"""
from __future__ import annotations

import re

import technique_kb as kb

# ── semantic 분류 규칙 ────────────────────────────────────────────────────────
_RX_SEARCH = re.compile(r"^(q|s|query|keyword|kw|search|term|find|word)$", re.I)
_RX_OBJECT = re.compile(r"(^id$|uid|userid|accountid|memberid|orderid|boardid|objectid|fileid|seq|^no$|idx|^pid$|num)", re.I)
_RX_BUSINESS = re.compile(r"(price|amount|discount|point|balance|role|admin|isadmin|permission|approval|grade|qty|quantity|cost|total)", re.I)
_RX_REDIRECT = re.compile(r"(redirect|next|return|returnurl|goto|dest|target|continue)", re.I)
_RX_URLFETCH = re.compile(r"(url|uri|webhook|callback|fetch|proxy|site|host|link|feed|src)", re.I)
_RX_FILE = re.compile(r"(file|filename|path|doc|document|download|attachment|upload|image|img)", re.I)
_RX_ADMIN = re.compile(r"(admin|관리자|manage|console|dashboard|superuser)", re.I)
_RX_SENSITIVE = re.compile(r"(password|passwd|account|delete|remove|grant|role|permission|privilege|payment|transfer|withdraw|approve|reset|비밀번호|권한|결제|승인|삭제)", re.I)
_RX_API = re.compile(r"(/api/|/v\d+/|\.json|graphql|/rest/)", re.I)

_STATE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

# semantic_role → (attack_surface_type, business_role 설명)
_ROLE_META = {
    kb.ROLE_SEARCH:    ("Search", "검색 기능"),
    kb.ROLE_OBJECT_REF:("Object Reference", "객체 참조(권한 검증 대상)"),
    kb.ROLE_BUSINESS:  ("Business Logic", "비즈니스 로직(금액/권한/포인트)"),
    kb.ROLE_AUTH:      ("Authentication", "인증/로그인"),
    kb.ROLE_REDIRECT:  ("Redirect", "리다이렉트 대상"),
    kb.ROLE_URL_FETCH: ("URL Fetch", "서버측 URL 페치(SSRF 표면)"),
    kb.ROLE_FILE:      ("File Handling", "파일 처리"),
    kb.ROLE_GENERIC:   ("Generic", "일반 입력"),
}


def classify_semantic(point: dict) -> str:
    """입력점의 semantic_role 분류(의미 분석)."""
    param = str(point.get("param") or "")
    url = str(point.get("url") or "")
    itype = (point.get("input_type") or "").lower()
    ctx = (point.get("context") or "").lower()

    if itype == "password" or ctx == "login":
        return kb.ROLE_AUTH
    if _RX_OBJECT.search(param):
        return kb.ROLE_OBJECT_REF
    if _RX_BUSINESS.search(param):
        return kb.ROLE_BUSINESS
    if _RX_REDIRECT.search(param):
        return kb.ROLE_REDIRECT
    if _RX_FILE.search(param):
        return kb.ROLE_FILE
    if _RX_URLFETCH.search(param):
        return kb.ROLE_URL_FETCH
    if ctx == "search" or _RX_SEARCH.search(param):
        return kb.ROLE_SEARCH
    return kb.ROLE_GENERIC


def _score_surface(point: dict, role: str) -> dict:
    """공격 표면 점수화. 요소: 인증후/관리자/객체식별자/API/파일/상태변경/민감기능."""
    param = str(point.get("param") or "")
    url = str(point.get("url") or "")
    text = f"{param} {url}"
    method = (point.get("method") or "GET").upper()
    authed = bool(point.get("authenticated"))

    score = 0
    factors: list[str] = []
    # 역할 기본 가중
    role_weight = {kb.ROLE_OBJECT_REF: 4, kb.ROLE_URL_FETCH: 4, kb.ROLE_FILE: 4,
                   kb.ROLE_AUTH: 4, kb.ROLE_BUSINESS: 3, kb.ROLE_SEARCH: 2,
                   kb.ROLE_REDIRECT: 2, kb.ROLE_GENERIC: 1}.get(role, 1)
    score += role_weight
    factors.append(f"역할 가중({role})={role_weight}")

    if authed:
        score += 3; factors.append("인증 후(+3)")
    if _RX_ADMIN.search(text):
        score += 3; factors.append("관리자 기능(+3)")
    if _RX_OBJECT.search(param):
        score += 2; factors.append("객체 식별자(+2)")
    if _RX_API.search(url):
        score += 2; factors.append("API 엔드포인트(+2)")
    if _RX_FILE.search(param):
        score += 2; factors.append("파일 처리(+2)")
    if method in _STATE_METHODS:
        score += 1; factors.append(f"상태 변경 가능({method})(+1)")
    if _RX_SENSITIVE.search(text):
        score += 2; factors.append("민감 기능(+2)")
    if authed and role == kb.ROLE_OBJECT_REF:
        score += 2; factors.append("인증 후 객체참조(+2)")

    if score >= 11:
        level = "Critical"
    elif score >= 8:
        level = "High"
    elif score >= 5:
        level = "Medium"
    else:
        level = "Low"
    return {"score": score, "level": level, "factors": factors}


def analyze_input_point(point: dict) -> dict:
    """단일 입력점 분석 → semantic/business/surface_type/추천technique/점수/reasoning."""
    role = classify_semantic(point)
    surface_type, business_role = _ROLE_META.get(role, ("Generic", "일반 입력"))
    recommended = kb.techniques_for_role(role) or ["xss", "sqli"]
    sc = _score_surface(point, role)

    # ── Detection Intelligence 결선 — 컨텍스트 기반 기법 우선순위 + 점수 boost ──
    # active_probing raw_point_score 정렬(실제 점검 우선순위) 및 계획 선별에 반영.
    # 신규 payload/실행 없음(기법 라벨 병합 + 점수 가중만, payload 는 여전히 게이트 통과).
    di_boost, di_reason = 0, ""
    try:
        import detection_intelligence as _di
        sig = _di.point_signal(point)
        di_boost = sig.get("boost", 0)
        di_reason = sig.get("reason", "")
        for t in reversed(sig.get("techniques", [])):   # DI 추천 기법을 앞쪽으로 병합
            if t not in recommended:
                recommended = [t] + recommended
    except Exception:
        pass
    score = min(100, sc["score"] + di_boost)

    reasoning = _reason(point, role, surface_type, recommended, sc)
    if di_reason:
        reasoning += f"  [탐지지능: {di_reason} (+{di_boost})]"
    factors = list(sc["factors"]) + ([f"탐지지능 boost +{di_boost}"] if di_boost else [])
    return {
        "param": point.get("param", ""),
        "endpoint": point.get("url", ""),
        "method": (point.get("method") or "GET").upper(),
        "authenticated": bool(point.get("authenticated")),
        "semantic_role": role,
        "business_role": business_role,
        "attack_surface_type": surface_type,
        "recommended_techniques": recommended,
        "priority_score": score,
        "priority_level": sc["level"],
        "reasoning": reasoning,
        "reasoning_factors": factors,
    }


def _reason(point, role, surface_type, recommended, sc) -> str:
    param = point.get("param", "") or "(파라미터)"
    authed = "인증 후 " if point.get("authenticated") else ""
    return (f"{authed}'{param}' 는 {surface_type}({role}) 의미를 가지며, "
            f"추천 기법: {', '.join(recommended)}. "
            f"공격 표면 점수 {sc['score']}({sc['level']}) — {', '.join(sc['factors'][:4])}.")


def plan_attack_surface(input_points: list[dict], *, budget: int = 0,
                        min_level: str | None = None) -> dict:
    """입력점 전체를 분석·점수화·정렬하고, 예산(budget) 만큼 상위를 선별한다.

    budget=0 → 무제한(MAX_PROBE_INPUTS 환경에서 별도 제한). min_level 지정 시 그 이상만 선별.
    반환: {analyzed[], selected[], reasoning_trace[], summary{}}.
    """
    analyzed = [analyze_input_point(p) for p in (input_points or [])]
    analyzed.sort(key=lambda x: x["priority_score"], reverse=True)

    _LV = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    pool = analyzed
    if min_level:
        thr = _LV.get(min_level, 1)
        pool = [a for a in analyzed if _LV.get(a["priority_level"], 1) >= thr]
    selected = pool[:budget] if budget and budget > 0 else pool

    reasoning_trace = [{
        "input": a["param"], "endpoint": a["endpoint"],
        "semantic_role": a["semantic_role"], "recommended": a["recommended_techniques"],
        "priority": a["priority_level"], "reason": a["reasoning"],
    } for a in selected]

    auth_surfaces = sum(1 for a in analyzed if a["authenticated"])
    crit = sum(1 for a in analyzed if a["priority_level"] in ("Critical", "High"))
    summary = {
        "total_surfaces": len(analyzed),
        "selected_surfaces": len(selected),
        "auth_after_surfaces": auth_surfaces,
        "critical_high_surfaces": crit,
        "by_type": _count_by(analyzed, "attack_surface_type"),
        "by_level": _count_by(analyzed, "priority_level"),
    }
    return {"analyzed": analyzed, "selected": selected,
            "reasoning_trace": reasoning_trace, "summary": summary}


def _count_by(items, key) -> dict:
    out: dict = {}
    for it in items:
        out[it.get(key)] = out.get(it.get(key), 0) + 1
    return out


def raw_point_score(point: dict) -> int:
    """주입 지점(params dict 보유, {method,url,params,...})의 공격 표면 점수(파라미터 최댓값).

    active_probing 의 Probe Budget Optimization 용 — 상위 점수 지점을 우선 점검하도록 정렬.
    """
    params = (point.get("params") or {})
    if not params:
        single = {"param": "", "url": point.get("url", ""),
                  "method": point.get("method", "GET"),
                  "authenticated": point.get("authenticated", False),
                  "input_type": "", "context": ""}
        return analyze_input_point(single)["priority_score"]
    best = 0
    for pname in params:
        single = {"param": pname, "url": point.get("url", ""),
                  "method": point.get("method", "GET"),
                  "authenticated": point.get("authenticated", False),
                  "input_type": "password" if "pass" in str(pname).lower() else "",
                  "context": ""}
        best = max(best, analyze_input_point(single)["priority_score"])
    return best


def selected_points(plan: dict, original_points: list[dict]) -> list[dict]:
    """plan.selected 에 대응하는 '원본 입력점'을 반환(Payload Planner 입력으로 전달)."""
    keys = {(s["method"], s["endpoint"], s["param"]) for s in plan.get("selected", [])}
    out = []
    for p in original_points or []:
        k = ((p.get("method") or "GET").upper(), p.get("url", ""), p.get("param", ""))
        if k in keys:
            out.append(p)
    return out
