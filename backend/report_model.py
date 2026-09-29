"""
report_model.py — 단일 정규화 리포트 모델(파사드).

여러 렌더러(DOCX/HTML/인앱)가 제각각 analysis 를 파헤치던 것을 하나의 정규화 모델로 모은다.
Finding 별로 proof 카드·오탐 위험·그래프 우선순위·스크린샷을 '안정 식별자(finding_uid)'로
결합해 렌더러가 그대로 소비하게 한다(교차 오염·중복 로직 방지).

이 단계는 파사드(facade)다: 기존 렌더러 로직을 즉시 갈아엎지 않고, HTML 렌더러부터 이 모델을
소비하도록 이관한다. DOCX 렌더러의 전면 이관과 3종 그래프(attack_graph/attack_path_graph/
security_knowledge_graph) 물리 병합은 회귀 위험이 커 후속 단계로 둔다(아키텍처 노트 참조).
판정/데이터 변경 없음 — 표현 결합만 한다.
"""
from __future__ import annotations


def _uid(f: dict):
    return f.get("finding_uid") or f.get("_idx") or ("T:" + (f.get("title") or ""))


def normalized_findings(analysis: dict) -> list:
    """Finding + proof card + 오탐위험 + 그래프 우선순위를 uid 기준으로 결합한 단일 목록."""
    findings = [f for f in (analysis.get("findings") or []) if f.get("judgment") != "양호"]
    cards = analysis.get("proof_evidence_cards") or []
    card_by_uid = {}
    for c in cards:
        for k in (c.get("finding_uid"), c.get("finding_id")):
            if k is not None:
                card_by_uid.setdefault(k, c)
    card_by_title = {c.get("finding_title"): c for c in cards}
    rc = (analysis.get("graph_risk_context") or {}).get("by_finding", {})

    out = []
    for f in findings:
        uid = _uid(f)
        card = card_by_uid.get(uid) or card_by_title.get(f.get("title")) or {}
        out.append({
            "uid": uid,
            "title": f.get("title", ""),
            "severity": f.get("severity", "Info"),
            "family": card.get("vulnerability_type") or f.get("family", ""),
            "confidence": f.get("confidence", ""),
            "card": card,
            "fp_risk": f.get("_fp_risk", "low"),
            "fp_reasons": f.get("_fp_reasons", []),
            "graph_why": rc.get(uid, {}),
            "screenshot": f.get("evidence_screenshot") or None,
            "raw": f,
        })
    return out


def build_report_model(scan: dict) -> dict:
    """렌더러 공용 정규화 모델(cover/summary/dashboard/findings/graph/coverage/qa)."""
    analysis = scan.get("analysis") or {}
    try:
        import report as _r
        score = _r._v3_security_score(analysis)
        sev = _r._eff_severity_counts(analysis)
        levels = _r._eff_levels(analysis)
    except Exception:
        score, sev, levels = 0, {}, {}
    return {
        "cover": {"domain": scan.get("domain", ""), "created_at": scan.get("created_at", ""),
                  "scope": "Web · Service · Network"},
        "summary": {"security_score": score, "severity": sev, "levels": levels,
                    "findings": len([f for f in (analysis.get("findings") or [])
                                     if f.get("judgment") != "양호"])},
        "findings": normalized_findings(analysis),
        "knowledge_graph": (analysis.get("security_knowledge_graph") or {}).get("summary") or {},
        "attack_paths": analysis.get("attack_path_graph") or {},
        "detection_coverage": analysis.get("detection_coverage") or {},
        "browser_discovery": analysis.get("browser_discovery_summary") or {},
        "proof_validation": analysis.get("proof_validation_summary") or {},
        "fp_risk": analysis.get("fp_risk_summary") or {},
        "report_qa": analysis.get("report_qa") or {},
    }
