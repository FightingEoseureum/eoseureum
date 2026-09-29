"""
evaluate.py — 스캔 결과(analysis) ↔ 골든셋 대조 → 정탐/오탐/누락 + precision/recall/F1.

정탐(TP): 기대 유형이 실제 발견됨. 누락(FN): 기대했으나 미발견.
오탐 후보(potential FP): 기대에 없는데 발견됨(골든셋이 exhaustive 일 때만 FP 로 엄격 계산).
Confirmed 여부(Rule Engine level)도 함께 보고해 '실증까지 됐는지' 구분한다.
"""
from __future__ import annotations


def _family_of(f: dict) -> str:
    try:
        import proof_evidence as pe
        return pe._family(f)
    except Exception:
        return (f.get("family") or f.get("vuln_type") or "").lower()


def _confirmed(f: dict) -> bool:
    return (f.get("confidence") or "").upper().startswith("CONFIRMED") or f.get("probe_confirmed") is True


def _all_scored_items(analysis: dict) -> list:
    """채점 대상 항목: findings(취약) + discovery_items(참고) + attack_surface_items.
    (예전엔 findings 만 봐서 IDOR/Swagger/CSRF 후보 등 discovery·attack_surface 로 분류되는
    유형이 전부 '누락(FN)'으로 잘못 채점됐다.) '양호'만 제외한다."""
    items = []
    for bucket in ("findings", "discovery_items", "attack_surface_items"):
        for f in (analysis.get(bucket) or []):
            if isinstance(f, dict) and f.get("judgment") != "양호":
                items.append(f)
    return items


def evaluate(analysis: dict, golden: dict) -> dict:
    """analysis(dict) 를 골든셋과 대조. 반환: 지표 + per-family 상세."""
    findings = _all_scored_items(analysis)
    found_by_fam: dict = {}
    for f in findings:
        fam = _family_of(f)
        found_by_fam.setdefault(fam, {"count": 0, "confirmed": 0})
        found_by_fam[fam]["count"] += 1
        if _confirmed(f):
            found_by_fam[fam]["confirmed"] += 1

    expected_fams = []
    seen = set()
    for e in golden.get("expected", []):
        if e["family"] not in seen:
            seen.add(e["family"]); expected_fams.append(e)

    detail, tp, fn = [], 0, 0
    for e in expected_fams:
        fam = e["family"]
        hit = found_by_fam.get(fam)
        status = "TP(정탐)" if hit else "FN(누락)"
        if hit:
            tp += 1
            if hit["confirmed"]:
                status = "TP(실증 확인)"
        else:
            fn += 1
        detail.append({"family": fam, "note": e.get("note", ""), "status": status,
                       "found": hit["count"] if hit else 0,
                       "confirmed": hit["confirmed"] if hit else 0})

    # 기대에 없는데 발견된 유형 → 오탐 후보. allowed_extra(정보노출/헤더 등 알려진 정상 부가발견)는
    # 제외해 '유의미한' 오탐만 남긴다 → exhaustive 가 아니어도 precision 을 의미있게 측정.
    allowed_extra = {a.lower() for a in (golden.get("allowed_extra") or [])}
    unexpected = [{"family": fam, "found": v["count"]} for fam, v in found_by_fam.items()
                  if fam not in seen and fam not in ("generic", "")]
    unexpected_significant = [u for u in unexpected if u["family"] not in allowed_extra]
    exhaustive = bool(golden.get("exhaustive"))
    # FP: exhaustive 면 모든 unexpected, 아니면 allowed_extra 를 뺀 '유의미한' unexpected 만.
    fp = len(unexpected) if exhaustive else len(unexpected_significant)

    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else (1.0 if tp else 0.0)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "label": golden.get("label", ""),
        "expected": len(expected_fams),
        "true_positive": tp, "false_negative": fn,
        "potential_false_positive": len(unexpected),
        "significant_false_positive": len(unexpected_significant),
        "false_positive": fp,
        "recall": round(recall, 3), "precision": round(precision, 3), "f1": round(f1, 3),
        "detail": detail,
        "unexpected": unexpected,
        "unexpected_significant": unexpected_significant,
        "exhaustive": exhaustive,
        "verdict": _verdict(recall, len(unexpected_significant)),
    }


def _verdict(recall: float, unexpected: int) -> str:
    if recall >= 0.8 and unexpected <= 1:
        return "양호 — 기대 취약점 대부분 탐지, 오탐 후보 적음"
    if recall >= 0.5:
        return "보통 — 일부 기대 취약점 누락 또는 오탐 후보 존재"
    return "미흡 — 기대 취약점 다수 누락(탐지 커버리지 점검 필요)"


def format_report(result: dict) -> str:
    """사람이 읽는 텍스트 리포트."""
    lines = [f"=== 벤치마크: {result['label']} ===",
             f"정탐 {result['true_positive']}/{result['expected']} · "
             f"누락 {result['false_negative']} · 오탐후보 {result['potential_false_positive']}",
             f"Recall {result['recall']} · Precision {result['precision']} · F1 {result['f1']}",
             f"판정: {result['verdict']}", "", "[유형별]"]
    for d in result["detail"]:
        lines.append(f"  - {d['family']:<16} {d['status']:<12} 발견 {d['found']} "
                     f"(실증 {d['confirmed']})  {d['note']}")
    if result["unexpected"]:
        lines.append("[기대 외 발견(검토 필요)]")
        for u in result["unexpected"]:
            lines.append(f"  - {u['family']} × {u['found']}")
    return "\n".join(lines)
