"""
evidence_levels.py — 증거 중심 '검증 수준(Level 0~3)' 매핑/요약.

기존 confidence(CONFIRMED/CONFIRMED_BROWSER/CONFIRMED_RESPONSE/POSSIBLE/MANUAL_REVIEW)와
finding_type(vulnerability/attack_surface/discovery/good)을 '재사용'하여 검증 수준으로 환산한다.
새 판정을 만들지 않는다(최종 판정은 Rule Engine 전담).

Level 0 정보 / Level 1 관찰됨 / Level 2 증거 확보 / Level 3 실증 확인
"""
from __future__ import annotations

LEVEL_LABEL = {
    0: "Level 0 · 정보",
    1: "Level 1 · 관찰됨",
    2: "Level 2 · 증거 확보",
    3: "Level 3 · 실증 확인",
}

_LEVEL3 = {"CONFIRMED", "CONFIRMED_BROWSER", "CONFIRMED_RESPONSE"}
_LEVEL2 = {"POSSIBLE", "CONFIG_CONFIRMED"}
_LEVEL1 = {"MANUAL_REVIEW"}


def level_of(finding: dict, *, finding_type: str | None = None) -> int:
    """단일 finding 의 검증 수준(0~3) 산정."""
    conf = (finding.get("confidence") or "").upper()
    ft = (finding_type or finding.get("finding_type") or "").lower()

    # B10: 공격 표면은 '관찰' 성격 → CONFIRMED 계열만 상위 레벨, POSSIBLE/MANUAL_REVIEW 여도 Level 1 상한
    # (finding_type 을 confidence 보다 우선 적용해, POSSIBLE 공격표면이 Level 2 로 과대평가되던 문제 수정)
    if ft == "attack_surface":
        return 3 if conf in _LEVEL3 else 1

    if conf in _LEVEL3:
        return 3
    if conf in _LEVEL2:
        return 2
    if conf in _LEVEL1:
        return 1
    # confidence 가 없을 때 finding_type 으로 보정
    # (attack_surface 는 위 31행에서 이미 반환되므로 여기서 다시 다루지 않는다)
    if ft == "vulnerability":
        return 3                 # 정규화에서 취약점으로 승격된 항목(근거 확인됨)
    return 0


def label_of(level: int) -> str:
    return LEVEL_LABEL.get(level, LEVEL_LABEL[0])


def observed_view(finding: dict, *, finding_type: str | None = None) -> dict:
    """취약점 finding 을 '보안 관찰' 관점 구조로 환산(보고서용).
    관찰된 현상 / 검증 수준 / 확보된 증거 / 가능한 영향 / 권고사항.
    """
    lvl = level_of(finding, finding_type=finding_type)
    evidence = finding.get("evidence_detail") or ""
    if not evidence:
        steps = finding.get("detection_steps") or []
        evidence = " / ".join(str(s) for s in steps[:3])
    impact = (finding.get("business_impact") or finding.get("attack_scenario")
              or finding.get("attack_vector") or "")
    return {
        "observed_phenomenon": finding.get("title", ""),
        "verification_level": lvl,
        "verification_label": label_of(lvl),
        "evidence": evidence,
        "possible_impact": impact,
        "recommendation": finding.get("recommendation", ""),
        "not_performed": finding.get("safe_not_performed", ""),
    }


def summarize_levels(findings: list[dict] | None,
                     attack_surface: list[dict] | None = None,
                     discovery: list[dict] | None = None,
                     good: list[dict] | None = None) -> dict:
    """검증 수준별 카운트 요약(Executive Summary 용)."""
    counts = {0: 0, 1: 0, 2: 0, 3: 0}
    for f in (findings or []):
        counts[level_of(f, finding_type="vulnerability")] += 1
    for f in (attack_surface or []):
        counts[level_of(f, finding_type="attack_surface")] += 1
    for f in (discovery or []):
        counts[level_of(f, finding_type="discovery")] += 1
    # good 은 검증수준으로 집계하지 않는다(정보 항목). 파라미터는 호출부 호환을 위해 유지.
    return {
        "level3_proven": counts[3],
        "level2_evidence": counts[2],
        "level1_observed": counts[1],
        "level0_info": counts[0],
        "priority_actions": counts[3] + counts[2],   # 우선 조치(증거 이상)
    }
