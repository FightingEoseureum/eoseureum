"""
inventory.py — 기술 스택 / 보고서 목록 집계 (순수 함수, I/O 없음).

이미 수집된 스캔 결과(analysis/results)만 가공한다. 새로운 점검/네트워크 호출 없음.
- build_techstack(scans): analysis["technologies"](fingerprint) + nmap -sV discovery +
  adaptive_recon 추천 점검을 호스트별로 집계.
- build_report_list(scans): scan history 기반 보고서 목록(기존 export API 재사용).

scans 는 get_scans_for_user() 형식의 dict 리스트(최신순). 각 항목:
  {scan_id, domain, status, created_at, analysis(dict|None), results(list|None), ...}
"""
from __future__ import annotations

import re

_RISK_KR = {"HIGH": "높음", "MEDIUM": "중간", "LOW": "낮음", "GOOD": "양호"}

# 기술명 기반 최소 추천 점검 (recommended_probes/adaptive 가 없을 때 폴백)
_MINIMAL_CHECKS = {
    "apache tomcat": ["/manager/html", "/host-manager/html", "/docs", "/examples"],
    "spring": ["/actuator", "/actuator/health", "/actuator/env"],
    "spring boot": ["/actuator", "/actuator/health", "/actuator/env"],
    "jenkins": ["/script", "/api/json"],
    "nginx": ["/", "/status"],
    "apache": ["/server-status", "/server-info"],
    "wordpress": ["/wp-login.php", "/wp-json"],
    "phpmyadmin": ["/phpmyadmin"],
}


def _conf_label(score) -> str:
    """confidence 점수(0~100) → high/medium/low. 없으면 medium."""
    if isinstance(score, bool):
        return "medium"
    if isinstance(score, (int, float)):
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        return "low"
    s = str(score or "").strip().lower()
    if s in ("high", "medium", "low"):
        return s
    return "medium"


def _primary_http_port(host_data: dict):
    services = host_data.get("services") or []
    for svc in services:
        if svc.get("http_info") and svc.get("port"):
            return svc.get("port")
    for svc in services:
        if svc.get("port"):
            return svc.get("port")
    return None


def _vuln_count_by_host(analysis: dict) -> dict:
    out: dict = {}
    for f in (analysis.get("findings") or []):
        if not isinstance(f, dict):
            continue
        is_vuln = (f.get("finding_type") == "vulnerability") or (f.get("judgment") == "취약")
        if not is_vuln:
            continue
        h = f.get("host") or ""
        out[h] = out.get(h, 0) + 1
    return out


def _adaptive_checks_for(name: str, adaptive: list) -> list:
    """adaptive_recon suggested_checks 에서 기술명과 관련된 점검 경로를 모은다."""
    nl = (name or "").lower()
    paths: list = []
    for c in adaptive or []:
        if not isinstance(c, dict):
            continue
        reason = str(c.get("reason") or "").lower()
        if nl and (nl in reason):
            for p in (c.get("paths") or []):
                if p not in paths:
                    paths.append(p)
    return paths


def _recommended_checks(name: str, tech: dict, adaptive: list) -> list:
    probes = tech.get("recommended_probes") or tech.get("probes") or []
    if probes:
        return list(probes)
    ad = _adaptive_checks_for(name, adaptive)
    if ad:
        return ad
    return list(_MINIMAL_CHECKS.get((name or "").lower(), []))


_NMAP_PAREN_RE = re.compile(r"\(([^)]+)\)")
_VERSION_TAIL_RE = re.compile(r"\s+(\d[\w.\-]*)\s*$")


def _parse_nmap_item(d: dict) -> tuple[str, str]:
    """nmap -sV discovery 항목에서 (제품명, 버전) 을 추출한다."""
    ev = d.get("evidence") or []
    text = ev[0] if ev else (d.get("title") or "")
    m = _NMAP_PAREN_RE.search(str(text))
    product = m.group(1).strip() if m else ""
    if not product:
        # title: "서비스/버전 식별: <label> (포트 N)" 형태 폴백
        title = str(d.get("title") or "")
        if ":" in title:
            product = title.split(":", 1)[1].split("(")[0].strip()
    version = "-"
    vm = _VERSION_TAIL_RE.search(product)
    if vm:
        version = vm.group(1)
        product = product[:vm.start()].strip()
    return (product or (d.get("service") or "unknown"), version)


def _merge_nmap_version(items: list, host, tech_name: str, version: str, port) -> bool:
    """기존 fingerprint 항목과 nmap 제품명이 겹치면 버전/출처를 보강한다. 보강 성공 시 True."""
    tl = (tech_name or "").lower()
    for it in items:
        if it["host"] != host:
            continue
        il = (it["technology"] or "").lower()
        if il and (il in tl or tl in il):
            if version and version != "-" and (not it.get("version") or it["version"] == "-"):
                it["version"] = version
            if "nmap" not in it["source"]:
                it["source"] = it["source"] + ",nmap"
            if port and (not it.get("port") or it["port"] in ("-", None)):
                it["port"] = port
            return True
    return False


def build_techstack(scans: list) -> dict:
    items: list = []
    seen: set = set()  # (host, tech_lower)

    for s in (scans or []):
        analysis = s.get("analysis") or {}
        if not isinstance(analysis, dict):
            continue
        results = s.get("results") or []
        created_at = s.get("created_at") or "-"
        adaptive = analysis.get("adaptive_recon") or []
        vuln_by_host = _vuln_count_by_host(analysis)

        # 1) fingerprint 기술 (results 의 호스트별 technologies)
        for host_data in results:
            if not isinstance(host_data, dict):
                continue
            host = host_data.get("host") or ""
            port = _primary_http_port(host_data)
            for t in (host_data.get("technologies") or []):
                if not isinstance(t, dict):
                    continue
                name = t.get("name")
                if not name:
                    continue
                key = (host, name.lower())
                if key in seen:
                    continue
                seen.add(key)
                items.append({
                    "host": host,
                    "port": port if port is not None else "-",
                    "service": "http",
                    "technology": name,
                    "version": "-",
                    "source": t.get("source") or "fingerprint",
                    "confidence": _conf_label(t.get("confidence")),
                    "last_seen": created_at,
                    "recommended_checks": _recommended_checks(name, t, adaptive),
                    "related_findings": vuln_by_host.get(host, 0),
                })

        # 2) nmap -sV 버전 식별 (analysis.discovery_items)
        for d in (analysis.get("discovery_items") or []):
            if not isinstance(d, dict):
                continue
            tags = d.get("tags") or []
            if not ({"nmap", "version-detection"} & set(tags)):
                continue
            host = d.get("host") or ""
            port = d.get("port")
            service = d.get("service") or "-"
            product, version = _parse_nmap_item(d)
            # 기존 fingerprint 항목과 겹치면 버전 보강 후 종료
            if _merge_nmap_version(items, host, product, version, port):
                continue
            key = (host, product.lower())
            if key in seen:
                continue
            seen.add(key)
            items.append({
                "host": host,
                "port": port if port is not None else "-",
                "service": service,
                "technology": product,
                "version": version,
                "source": "nmap",
                "confidence": "high" if version != "-" else "medium",
                "last_seen": created_at,
                "recommended_checks": list(_MINIMAL_CHECKS.get(product.lower(), [])),
                "related_findings": vuln_by_host.get(host, 0),
            })

    hosts = {it["host"] for it in items if it["host"]}
    summary = {
        "total_hosts": len(hosts),
        "total_technologies": len(items),
        "high_confidence": sum(1 for it in items if it["confidence"] == "high"),
        "medium_confidence": sum(1 for it in items if it["confidence"] == "medium"),
        "low_confidence": sum(1 for it in items if it["confidence"] == "low"),
    }
    return {"items": items, "summary": summary}


def _confirmed_count(analysis: dict) -> int:
    summ = analysis.get("summary") or {}
    if isinstance(summ.get("confirmed_count"), int):
        return summ["confirmed_count"]
    n = 0
    for f in (analysis.get("findings") or []):
        if not isinstance(f, dict):
            continue
        if str(f.get("confidence") or "").upper() == "CONFIRMED" or f.get("probe_confirmed") is True:
            n += 1
    return n


def build_report_list(scans: list) -> dict:
    items: list = []
    high_risk = 0
    latest = "-"

    for s in (scans or []):
        analysis = s.get("analysis") or {}
        if not isinstance(analysis, dict):
            analysis = {}
        summ = analysis.get("summary") or {}
        sev = summ.get("by_severity") or {}
        status = s.get("status")
        risk = analysis.get("overall_risk")
        available = bool(analysis) and status in ("complete", "stopped")

        total = summ.get("vulnerability_count")
        if not isinstance(total, int):
            total = sum(
                1 for f in (analysis.get("findings") or [])
                if isinstance(f, dict) and (
                    f.get("finding_type") == "vulnerability" or f.get("judgment") == "취약"
                )
            )
        high_count = (sev.get("Critical", 0) or 0) + (sev.get("High", 0) or 0)
        medium_count = sev.get("Medium", 0) or 0
        low_count = sev.get("Low", 0) or 0

        scan_id = s.get("scan_id")
        items.append({
            "scan_id": scan_id,
            "target": s.get("domain"),
            "created_at": s.get("created_at") or "-",
            "status": status,
            "risk_level": _RISK_KR.get(risk, "-"),
            "total_findings": total,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "confirmed_count": _confirmed_count(analysis),
            "report_available": available,
            "download_url": f"/api/scans/{scan_id}/export",
        })
        if available:
            if risk == "HIGH":
                high_risk += 1
            if latest == "-" and s.get("created_at"):
                latest = s.get("created_at")  # scans 최신순 → 첫 available 이 최신

    total_reports = sum(1 for it in items if it["report_available"])
    return {
        "items": items,
        "summary": {
            "total_reports": total_reports,
            "high_risk_reports": high_risk,
            "latest_report_at": latest,
        },
    }
