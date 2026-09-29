"""
attack_path_prioritizer.py — Attack Graph 경로 중 '실제 가치 높은' 경로를 선별.

Attack Graph 의 attack_paths + nodes 를 입력받아 경로별 점수/우선순위/신뢰도/증거강도/
추천 Solver/실행예산/근거를 산출한다. 점수/신뢰도는 증거 수준 기반(Rule Engine)으로만
결정하며, AI 는 근거 설명만 보강한다(판정/신뢰도 변경 금지).
"""
from __future__ import annotations

import attack_graph as ag
import solver_registry as registry

# ── Path Scoring 가중치 — Evidence 중심(실증 경로가 관찰 경로보다 항상 우선) ──────
# 증거 수준 가중(강화): Level3 +15 / Level2 +8 / Level1 +2
_W_LEVEL3 = 15
_W_LEVEL2 = 8
_W_LEVEL1 = 2
# 경로 신뢰도(Rule Engine 산출) 가중: Confirmed +10 / Evidence +5 / Observed +0
_W_CONF = {"Confirmed Path": 10, "Evidence Path": 5, "Observed Path": 0,
           "Informational Path": 0}
_NODE_WEIGHT = {
    ag.N_AUTH: 5, ag.N_ADMIN: 8, ag.N_SENSITIVE: 6, ag.N_OBJREF: 4,
    ag.N_BIZ: 4, ag.N_FILE: 4, ag.N_STATE: 3, ag.N_API: 2,
}

# node_type → 추천 solver 라우팅 키
_NODE_SOLVER_KEY = {
    ag.N_OBJREF: "object_reference", ag.N_FILE: "file_handling",
    ag.N_STATE: "state_change", ag.N_BIZ: "business_logic",
    ag.N_FETCH: "url_fetch", ag.N_LOGIN: "authentication",
    ag.N_ADMIN: "authentication", ag.N_PARAM: "search_function",
}
# semantic_role → 추천 solver 라우팅 키(보조)
_ROLE_SOLVER_KEY = {
    "object_reference": "idor", "search_function": "xss", "state_change": "csrf",
    "business_logic": "business_logic", "file_handling": "file_upload",
    "url_fetch": "ssrf", "redirect": "open_redirect", "authentication": "auth_bypass",
}


def _nodes_index(nodes: list[dict]) -> dict:
    return {n["node_id"]: n for n in (nodes or [])}


def score_path(path: dict, nodes_idx: dict) -> dict:
    """단일 경로 점수화 → {score, priority, evidence_strength, factors}."""
    seq = path.get("node_ids") or []
    pnodes = [nodes_idx.get(nid, {}) for nid in seq]
    level = int(path.get("evidence_level", 0) or 0)

    score = 0
    factors: list[str] = []
    # 1) 증거 수준 가중(Rule Engine 산출 — AI 개입 없음)
    if level >= 3:
        score += _W_LEVEL3; factors.append(f"Level 3 증거(+{_W_LEVEL3})")
    elif level == 2:
        score += _W_LEVEL2; factors.append(f"Level 2 증거(+{_W_LEVEL2})")
    elif level == 1:
        score += _W_LEVEL1; factors.append(f"Level 1 관찰(+{_W_LEVEL1})")
    # 2) 경로 신뢰도 가중(실증/증거 경로 우대)
    pconf = path.get("path_confidence", "")
    cw = _W_CONF.get(pconf, 0)
    if cw:
        score += cw; factors.append(f"{pconf}(+{cw})")

    seen_types = set()
    for n in pnodes:
        nt = n.get("node_type")
        if nt in _NODE_WEIGHT and nt not in seen_types:
            score += _NODE_WEIGHT[nt]
            factors.append(f"{nt}(+{_NODE_WEIGHT[nt]})")
            seen_types.add(nt)
    # Path Length(+1)
    if len(seq) >= 5:
        score += 1; factors.append("경로 길이(+1)")

    # 등급 임계값 — 증거 가중 강화에 맞춰 상향(실증 경로가 Critical/High 로 수렴)
    if score >= 25:
        priority = "Critical"
    elif score >= 16:
        priority = "High"
    elif score >= 8:
        priority = "Medium"
    else:
        priority = "Low"

    evidence_strength = {3: "strong", 2: "moderate", 1: "weak"}.get(level, "informational")
    return {"score": score, "priority": priority,
            "evidence_strength": evidence_strength, "factors": factors}


def _recommend_solver(path: dict, nodes_idx: dict) -> str | None:
    """경로의 노드/의미역할로 적합한 Solver 선택(레지스트리 기반)."""
    seq = path.get("node_ids") or []
    # 노드 타입 우선
    for nid in seq:
        n = nodes_idx.get(nid, {})
        key = _NODE_SOLVER_KEY.get(n.get("node_type"))
        role = (n.get("semantic_role") or "")
        rkey = _ROLE_SOLVER_KEY.get(role)
        s = registry.select_solver(rkey, key, role)
        if s:
            return s.name
    # 제목 키워드 폴백
    title = (path.get("title") or "").lower()
    for kw, rkey in (("idor", "idor"), ("객체", "idor"), ("xss", "xss"),
                     ("인젝션", "sqli"), ("csrf", "csrf"), ("리다이렉트", "open_redirect"),
                     ("ssrf", "ssrf"), ("업로드", "file_upload"), ("파일", "file_upload"),
                     ("비즈니스", "business_logic"), ("인증", "auth_bypass")):
        if kw in title:
            s = registry.select_solver(rkey)
            if s:
                return s.name
    return None


_BUDGET = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}


def prioritize(attack_paths: list[dict], nodes: list[dict], *,
               max_paths: int = 0, ai_fn=None) -> dict:
    """경로 우선순위화 → {prioritized[], summary{}}.

    max_paths>0 이면 상위 N 경로만 Solver 배정 대상으로 선별(Probe 예산 2단계).
    """
    nodes_idx = _nodes_index(nodes)
    scored: list[dict] = []
    for p in (attack_paths or []):
        sc = score_path(p, nodes_idx)
        rec = _recommend_solver(p, nodes_idx)
        reasoning = (f"{p.get('title','경로')} — {sc['priority']}({sc['score']}점), "
                     f"증거강도 {sc['evidence_strength']}, 추천 Solver: {rec or '없음'}. "
                     f"근거: {', '.join(sc['factors'][:4])}")
        if ai_fn:
            reasoning = _ai_reason(ai_fn, reasoning) or reasoning
        scored.append({
            "path_id": p.get("path_id"),
            "title": p.get("title"),
            "score": sc["score"],
            "priority": sc["priority"],
            "confidence": p.get("path_confidence"),       # Rule Engine 기반(변경 불가)
            "evidence_strength": sc["evidence_strength"],
            "evidence_level": p.get("evidence_level", 0),
            "recommended_solver": rec,
            "execution_budget": _BUDGET.get(sc["priority"], 0),
            "reasoning": reasoning,
        })
    scored.sort(key=lambda x: x["score"], reverse=True)
    selected = scored[:max_paths] if max_paths and max_paths > 0 else scored

    summary = {
        "total_paths": len(scored),
        "prioritized_paths": len(selected),
        "critical": sum(1 for x in scored if x["priority"] == "Critical"),
        "high": sum(1 for x in scored if x["priority"] == "High"),
        "medium": sum(1 for x in scored if x["priority"] == "Medium"),
        "low": sum(1 for x in scored if x["priority"] == "Low"),
    }
    return {"prioritized": scored, "selected": selected, "summary": summary,
            "ai_cannot_confirm": True}


def _ai_reason(ai_fn, base: str) -> str | None:
    """AI 는 근거 설명만 보강. 점수/우선순위/신뢰도 변경 불가(반환의 해당 키는 무시)."""
    try:
        text = ai_fn("Improve only the human-readable reasoning. Do NOT change score, "
                     f"priority, or confidence. Context: {base}")
        return str(text).strip() if text else None
    except Exception:
        return None
