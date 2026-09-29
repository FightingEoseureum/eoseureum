"""
evidence_correlation.py — 여러 증거를 하나의 경로/체인으로 묶어 상관분석한다.

예: IDOR Candidate + IDOR Verification + Authenticated Area → IDOR Evidence Chain.

신뢰도 변화(confidence_change)는 증거 수준(evidence_levels, Rule Engine)으로만 계산하며,
이 모듈은 새 판정/Level 을 만들지 않는다(상관·요약만).

출력(체인별): evidence_chain / supporting_findings / supporting_paths /
            confidence_change / validation_summary
"""
from __future__ import annotations

import evidence_levels as evl

# 패밀리 → (체인명, 제목 키워드)
_FAMILIES = [
    ("idor", "IDOR Evidence Chain", ("idor", "객체 참조", "object reference")),
    ("xss", "XSS Evidence Chain", ("xss", "스크립트")),
    ("sqli", "SQLi Evidence Chain", ("sql 인젝션", "sql injection", "sqli")),
    ("csrf", "CSRF Risk Chain", ("csrf",)),
    ("upload", "File Upload Chain", ("업로드", "upload")),
    ("logic", "Business Logic Chain", ("비즈니스 로직", "business logic")),
    ("redirect", "Open Redirect Chain", ("리다이렉트", "redirect")),
    ("ssrf", "SSRF Chain", ("ssrf",)),
    ("auth", "Auth Bypass Chain", ("인증 우회", "auth bypass", "로그인 우회", "인증 우회")),
]


def _family_of(title: str) -> str | None:
    t = (title or "").lower()
    for fam, _name, kws in _FAMILIES:
        if any(k in t for k in kws):
            return fam
    return None


def correlate(analysis: dict) -> dict:
    """analysis 의 finding/후보/검증/경로를 패밀리별 증거 체인으로 묶는다."""
    analysis = analysis or {}
    chains: dict[str, dict] = {}

    def _chain(fam):
        meta = next((c for c in _FAMILIES if c[0] == fam), None)
        name = meta[1] if meta else f"{fam} chain"
        return chains.setdefault(fam, {
            "family": fam, "evidence_chain": name,
            "supporting_findings": [], "supporting_paths": [],
            "levels": [], "authenticated": False,
        })

    # 1) findings / attack_surface / discovery
    for bucket, ft in (("findings", "vulnerability"),
                       ("attack_surface_items", "attack_surface"),
                       ("discovery_items", "discovery")):
        for f in (analysis.get(bucket) or []):
            fam = _family_of(f.get("title", ""))
            if not fam:
                continue
            ch = _chain(fam)
            ch["supporting_findings"].append({
                "title": f.get("title", ""), "bucket": bucket,
                "level": evl.level_of(f, finding_type=ft),
                "url": f.get("evidence_url", ""),
            })
            ch["levels"].append(evl.level_of(f, finding_type=ft))
            if f.get("authenticated") or f.get("is_verified_idor"):
                ch["authenticated"] = True

    # 2) IDOR 교차검증 결과(있으면 idor 체인 보강)
    cv = analysis.get("candidate_verification") or {}
    idor = cv.get("idor") or {}
    if idor.get("promoted"):
        ch = _chain("idor")
        ch["levels"].append(3)
        ch["supporting_findings"].append({
            "title": f"IDOR 교차검증 승격 {idor.get('promoted')}건",
            "bucket": "candidate_verification", "level": 3, "url": "",
        })

    # 3) attack_paths 연결
    for p in (analysis.get("attack_paths") or []):
        fam = _family_of(p.get("title", ""))
        if not fam:
            continue
        ch = _chain(fam)
        ch["supporting_paths"].append({
            "path_id": p.get("path_id"), "title": p.get("title"),
            "confidence": p.get("path_confidence"),
            "level": p.get("evidence_level", 0),
        })
        ch["levels"].append(int(p.get("evidence_level", 0) or 0))

    # 4) 체인별 신뢰도 변화/요약 산출
    out_chains = []
    for fam, ch in chains.items():
        levels = ch.pop("levels", []) or [0]
        max_level = max(levels)
        min_level = min(levels)
        ch["max_level"] = max_level
        ch["confidence_change"] = _confidence_change(min_level, max_level, len(ch["supporting_findings"]))
        ch["validation_summary"] = _validation_summary(ch, max_level)
        out_chains.append(ch)

    out_chains.sort(key=lambda c: c["max_level"], reverse=True)
    summary = {
        "evidence_chains": len(out_chains),
        "confirmed_chains": sum(1 for c in out_chains if c["max_level"] >= 3),
        "evidence_chains_level2": sum(1 for c in out_chains if c["max_level"] == 2),
        "observed_chains": sum(1 for c in out_chains if c["max_level"] == 1),
    }
    return {"chains": out_chains, "summary": summary, "ai_cannot_confirm": True}


def _confidence_change(min_level: int, max_level: int, n: int) -> str:
    if max_level > min_level and max_level >= 2:
        return (f"{evl.label_of(min_level)} → {evl.label_of(max_level)} 로 강화"
                f"(상관 증거 {n}건)")
    if max_level >= 3:
        return f"{evl.label_of(max_level)} 유지(실증 확인)"
    return f"{evl.label_of(max_level)} (상관 증거 {n}건)"


def _validation_summary(ch: dict, max_level: int) -> str:
    auth = "인증 후 영역 포함 · " if ch.get("authenticated") else ""
    nf = len(ch.get("supporting_findings", []))
    np = len(ch.get("supporting_paths", []))
    return (f"{auth}{ch['evidence_chain']}: 지지 발견 {nf}건 · 연결 경로 {np}건 · "
            f"최고 검증 수준 {evl.label_of(max_level)} (Rule Engine 기준)")
