"""
probes/adapter.py — ProbeResult <-> 레거시 finding 구조 변환.

finding_normalizer / report / UI 가 기대하는 finding dict 구조와 호환을 보장한다.
(레거시 finding 핵심 키: title, judgment, severity(HIGH/MEDIUM/LOW), confidence,
 confidence_score, owasp, cwe, evidence_url, evidence_detail, recommendation,
 finding_type, host, port, tags, probe_confirmed)
"""
from __future__ import annotations

from .base import ProbeResult

# ProbeResult.severity(High/Medium/Low/Info) -> 레거시 severity(대문자)
_SEV_TO_LEGACY = {"CRITICAL": "HIGH", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
                  "LOW": "LOW", "INFO": "INFO", "INFORMATIONAL": "INFO"}
_SEV_FROM_LEGACY = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}
# finding_type -> judgment
_JUDGMENT = {"good": "양호"}


def convert_probe_result_to_legacy_finding(pr: ProbeResult, host: str = "", port: int = 0) -> dict:
    sev = _SEV_TO_LEGACY.get((pr.severity or "").upper(), "MEDIUM")
    evidence_detail = pr.reproduction or "\n".join(str(e) for e in (pr.evidence or []))
    finding = {
        "title": pr.title,
        "judgment": _JUDGMENT.get(pr.finding_type, "취약"),
        "severity": sev,
        "confidence": pr.confidence,
        "confidence_score": pr.confidence_score,
        "finding_type": pr.finding_type,
        "owasp": pr.owasp,
        "cwe": pr.cwe,
        "evidence_url": pr.affected_url,
        "evidence_detail": evidence_detail,
        "recommendation": pr.recommendation,
        "tags": list(pr.tags or []),
        "host": host or "",
        "port": port or 0,
        "safe_check": pr.safe_check,
        "probe_category": pr.category,
        "probe_confirmed": (pr.confidence or "").upper() == "CONFIRMED",
    }
    if pr.affected_endpoint:
        finding["affected_endpoints"] = [pr.affected_endpoint]
    # 위임 원본(active_probing 결과)이 있으면 보존 (probe_detail 호환)
    if pr.raw:
        finding["probe_detail"] = pr.raw
        finding["_probe_key"] = pr.probe_key
    return finding


def convert_legacy_finding_to_probe_result(f: dict) -> ProbeResult:
    sev = _SEV_FROM_LEGACY.get((f.get("severity") or "").upper(), "Medium")
    return ProbeResult(
        title=f.get("title", ""),
        category=f.get("probe_category", ""),
        finding_type=f.get("finding_type", "vulnerability" if f.get("judgment") != "양호" else "good"),
        severity=sev,
        confidence=f.get("confidence", "MANUAL_REVIEW") or "MANUAL_REVIEW",
        confidence_score=int(f.get("confidence_score", 0) or 0),
        affected_url=f.get("evidence_url", ""),
        affected_endpoint=(f.get("affected_endpoints") or [""])[0] if f.get("affected_endpoints") else "",
        evidence=[f.get("evidence_detail", "")] if f.get("evidence_detail") else [],
        recommendation=f.get("recommendation", ""),
        cwe=f.get("cwe", "") or "",
        owasp=f.get("owasp", "") or "",
        tags=list(f.get("tags") or []),
        safe_check=bool(f.get("safe_check", True)),
        probe_key=f.get("_probe_key", ""),
        raw=f.get("probe_detail") or {},
    )


def probe_results_to_findings(results: list[ProbeResult], host: str = "", port: int = 0) -> list[dict]:
    return [convert_probe_result_to_legacy_finding(r, host, port) for r in (results or [])]
