"""
validation_readiness.py — 검증(Validation) 중심 레이어.

관찰(Level1) → 증거(Level2) → 실증(Level3) 으로 '승격 가능한 후보'를 선별하고
검증 우선순위·필요 증거·추천 검증 방법을 제시한다.

새 탐지/실행 없음. 기존 analysis(Finding/후보/Evidence Level)만 사용한다.
Level/Confidence/판정 변경은 하지 않으며(최종 판정 Rule Engine), AI 는 설명 보강만 가능.
"""
from __future__ import annotations

import evidence_levels as evl
import business_impact_engine as bie   # family_of 재사용(중복 구현 방지)

# 자동 안전 검증으로 Level3(실증)까지 승격 가능한 패밀리
_PROMOTABLE_L3 = {"idor", "xss", "sqli", "open_redirect", "ssti", "path_traversal"}
# 수동/승인 기반 — 자동 실증 불가, 최대 Level2(증거)까지
_PROMOTABLE_L2 = {"csrf", "business_logic", "upload", "ssrf", "auth", "cmdi"}

# 패밀리별 추천 검증 방법 / 필요 증거
_VALIDATION = {
    "idor": ("인증 세션 A/B 교차 계정 비교(읽기 전용)", "교차 계정 접근 결과(타 사용자 식별정보 노출)"),
    "xss": ("Playwright 브라우저 alert 실증", "브라우저 스크립트 실행(alert) 발생"),
    "sqli": ("SQLMap 안전 옵션 추가 검증(파라미터 확대)", "SQLMap injectable 확인"),
    "open_redirect": ("Location 헤더 외부 도메인 반환 확인", "외부 도메인 리다이렉트 응답"),
    "ssti": ("산술식 평가 결과 반사 확인", "응답 내 수식 평가 결과"),
    "path_traversal": ("무해 파일 경로 노출 확인", "응답 내 파일 내용(무해 파일)"),
    "csrf": ("상태 변경 검증(수동) — 토큰/Origin 검증 여부", "토큰/Origin 검증 결과(자동 확정 금지)"),
    "business_logic": ("서버측 재검증 수동 확인(가격/권한/포인트)", "서버측 값 재검증 동작 여부"),
    "upload": ("무해 txt/png 업로드 가능 여부(별도 승인)", "서버측 확장자/콘텐츠 검증 동작"),
    "ssrf": ("OOB 콜백 검증(별도 승인)", "서버측 아웃바운드 요청 도달 여부"),
    "auth": ("로그인 폼 안전 응답 비교 재검증(잠금 금지)", "안전 페이로드 응답 차이"),
    "cmdi": ("RCE Proof Mode 고정 echo marker 검증(승인 시)", "고정 marker 반사(무해)"),
}


def _target_level(family: str) -> int:
    if family in _PROMOTABLE_L3:
        return 3
    if family in _PROMOTABLE_L2:
        return 2
    return 2


def _validation_priority(family: str, current_level: int, target: int) -> str:
    """승격 우선순위 — 실증(L3) 도달 가능 + 고영향 패밀리일수록 높음."""
    high_impact = family in ("idor", "sqli", "xss", "ssti", "cmdi")
    reaches_l3 = target >= 3
    if reaches_l3 and high_impact:
        return "High"          # 실증 도달 가능 + 고영향 → 최우선
    if reaches_l3:
        return "Medium"        # 실증 도달 가능
    return "Low"               # 수동/증거 단계까지만


def _candidate_from(item: dict, bucket_type: str) -> dict | None:
    title = item.get("title", "")
    fam = bie.family_of(title)
    if not fam:
        return None
    current = evl.level_of(item, finding_type=bucket_type)
    if current >= 3:
        return None                      # 이미 실증(Validated) — 후보 아님
    target = _target_level(fam)
    if current >= target:
        return None                      # 이미 도달 가능 상한(예: CSRF L2) — 승격 여지 없음
    rec, req = _VALIDATION.get(fam, ("수동 검증", "추가 증거"))
    prio = _validation_priority(fam, current, target)
    reason = (f"현재 {evl.label_of(current)} → {evl.label_of(target)} 승격 가능. "
              f"부족 증거: {req}.")
    return {
        "family": fam,
        "validation_candidate": title,
        "current_level": current,
        "target_level": target,
        "validation_priority": prio,
        "validation_reason": reason,
        "recommended_validation": rec,
        "required_evidence": req,
        "promotable_to_level3": target >= 3,
    }


_PRIO_RANK = {"High": 3, "Medium": 2, "Low": 1}


def build_validation_readiness(analysis: dict) -> dict:
    """승격 후보 + 우선순위 + Backlog + 요약 산출."""
    analysis = analysis or {}
    cands: list[dict] = []
    seen: set = set()
    for bucket, bt in (("findings", "vulnerability"),
                       ("attack_surface_items", "attack_surface"),
                       ("discovery_items", "discovery")):
        for it in (analysis.get(bucket) or []):
            c = _candidate_from(it, bt)
            if not c:
                continue
            key = (c["family"], c["validation_candidate"])
            if key in seen:
                continue
            seen.add(key)
            cands.append(c)

    cands.sort(key=lambda c: (_PRIO_RANK.get(c["validation_priority"], 0),
                              c["current_level"], c["promotable_to_level3"]),
               reverse=True)

    ev = analysis.get("evidence_levels") or {}
    current_confirmed = ev.get("level3_proven", 0)
    l1_to_l2 = sum(1 for c in cands if c["current_level"] == 1)
    l2_to_l3 = sum(1 for c in cands if c["current_level"] == 2 and c["target_level"] >= 3)
    promotable_l3 = sum(1 for c in cands if c["promotable_to_level3"])
    by_family: dict = {}
    for c in cands:
        by_family[c["family"]] = by_family.get(c["family"], 0) + 1

    summary = {
        "validation_candidates": len(cands),
        "level1_to_level2": l1_to_l2,
        "level2_to_level3": l2_to_l3,
        "by_family": by_family,
        "current_confirmed": current_confirmed,          # 현재 Level3
        "potential_confirmed": current_confirmed + promotable_l3,  # 추가 검증 시 Level3 가능
        "expected_promotions": promotable_l3,
    }
    return {"validation_candidates": cands, "validation_summary": summary,
            "validation_backlog": cands, "ai_cannot_confirm": True}
