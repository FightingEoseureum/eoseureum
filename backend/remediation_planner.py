"""
remediation_planner.py — 발견 사항을 '실제 조치 계획'으로 변환.

business_impact_engine 결과 + remediation_kb 를 결합해 조치 항목과 우선 조치 계획(Top N)을
생성한다. 우선순위는 Executive Risk Score(증거 기반)로만 결정하며 AI 는 설명만 보강한다.
"""
from __future__ import annotations

import remediation_kb as kb

_PRIORITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def plan_remediation(impact: dict) -> dict:
    """business_impact_engine.build_business_impact() 결과 → 조치 계획.

    반환: {items[], priority_action_plan[], summary{}}.
    """
    impact = impact or {}
    items: list[dict] = []
    for idx, imp in enumerate(impact.get("items", [])):
        fam = imp.get("family", "")
        rem = kb.get_remediation(fam)
        items.append({
            "family": fam,
            "finding_title": imp.get("title", ""),
            "remediation_title": rem["title"],
            "remediation_description": rem["description"],
            "estimated_effort": rem["effort"],
            "responsible_team": rem["team"],
            "expected_benefit": rem["benefit"],
            "implementation_priority": imp.get("priority", "Low"),
            "executive_risk_score": imp.get("executive_risk_score", 0),
            "impact_category": imp.get("impact_category", []),
            "regulatory_risk": imp.get("regulatory_risk", []),
        })

    # 정렬: 우선순위 등급 → Executive Risk Score → KB 가중
    def _key(it):
        return (_PRIORITY_RANK.get(it["implementation_priority"], 0),
                it["executive_risk_score"],
                kb.get_remediation(it["family"]).get("weight", 1))
    items.sort(key=_key, reverse=True)

    # 우선 조치 계획(Top 10) — 같은 family 중복은 1개로 병합
    plan: list[dict] = []
    seen_fam: set = set()
    for it in items:
        if it["family"] in seen_fam:
            continue
        seen_fam.add(it["family"])
        plan.append({
            "rank": f"P{len(plan) + 1}",
            "title": it["remediation_title"],
            "team": it["responsible_team"],
            "effort": it["estimated_effort"],
            "benefit": it["expected_benefit"],
            "priority": it["implementation_priority"],
            "family": it["family"],
        })
        if len(plan) >= 10:
            break

    summary = {
        "total_remediations": len(items),
        "priority_actions": len(plan),
        "by_team": _count(items, "responsible_team"),
        "by_priority": _count(items, "implementation_priority"),
    }
    return {"items": items, "priority_action_plan": plan, "summary": summary,
            "ai_cannot_confirm": True}


def _count(items, key) -> dict:
    out: dict = {}
    for it in items:
        out[it.get(key)] = out.get(it.get(key), 0) + 1
    return out
