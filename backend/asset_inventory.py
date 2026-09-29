"""
asset_inventory.py — Host 단위 자산 인벤토리 + 분류 + risk_tags.

기존 포트 스캔/서비스 식별 결과(host_results)만으로 자산 메타데이터를 구성한다.
새 탐색/공격 없음. service_surface_planner 의 분류를 재사용한다.
"""
from __future__ import annotations

import ipaddress

import service_surface_planner as ssp

# 자산 유형
A_WEB = "Web Server"
A_DB = "Database Server"
A_AUTH = "Authentication Server"
A_FILE = "File Server"
A_MAIL = "Mail Server"
A_CONTAINER = "Container/Platform Node"
A_NETDEV = "Network Device"
A_UNKNOWN = "Unknown"

_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}
_NETDEV_PORTS = {161, 162, 23}   # SNMP/telnet (네트워크 장비 단서)
_NETDEV_HOST_RE = ("router", "switch", "gw", "gateway", "firewall", "ap-", "-sw", "-rtr")


def _is_internet_exposed(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def classify_asset(asset: dict) -> str:
    """open_ports/services/hostname 으로 자산 유형 분류."""
    ports = set(asset.get("open_ports") or [])
    svcs = asset.get("detected_services") or []
    families = {s.get("family") for s in svcs}
    surfaces = {s.get("attack_surface_type") for s in svcs}
    host = (asset.get("hostname") or asset.get("reverse_dns") or "").lower()

    if ports & _WEB_PORTS or asset.get("web_endpoints"):
        # 웹이 있으면 웹 서버(다른 서비스 동반 가능하나 대표 분류)
        web_only = not (families - {None})
        if web_only or (surfaces and surfaces <= {ssp.S_OTHER}):
            return A_WEB
    if ssp.S_DB in surfaces or ssp.S_DATA in surfaces:
        return A_DB
    if ssp.S_AUTH in surfaces:
        return A_AUTH
    if ssp.S_FILE in surfaces:
        return A_FILE
    if ssp.S_MESSAGING in surfaces:
        return A_MAIL
    if ssp.S_CONTAINER in surfaces:
        return A_CONTAINER
    if (ports & _NETDEV_PORTS) or any(h in host for h in _NETDEV_HOST_RE):
        return A_NETDEV
    if ports & _WEB_PORTS:
        return A_WEB
    return A_UNKNOWN


def _risk_tags(asset: dict, surfaces: set, families: set) -> list[str]:
    tags: list[str] = []
    if ssp.S_AUTH in surfaces:
        tags.append("exposed_auth_service")
    if ssp.S_DB in surfaces or ssp.S_DATA in surfaces:
        tags.append("exposed_database")
    if ssp.S_FILE in surfaces:
        tags.append("exposed_file_sharing")
    if ssp.S_CONTAINER in surfaces:
        tags.append("exposed_container")
    if asset.get("has_admin"):
        tags.append("exposed_admin")
    if not families or families == {None}:
        if not asset.get("web_endpoints"):
            tags.append("unknown_service")
    if _is_internet_exposed(asset.get("ip", "")):
        tags.append("internet_exposed")
    return tags


def _priority(asset_type: str, tags: list[str], n_ports: int) -> str:
    score = {"Container/Platform Node": 4, "Database Server": 4, "Authentication Server": 3,
             "File Server": 3, "Mail Server": 2, "Web Server": 2, "Network Device": 2,
             "Unknown": 1}.get(asset_type, 1)
    if "internet_exposed" in tags:
        score += 2
    if "exposed_database" in tags or "exposed_container" in tags:
        score += 2
    if "exposed_admin" in tags:
        score += 1
    score += min(n_ports, 5) // 3
    return "Critical" if score >= 8 else "High" if score >= 6 else "Medium" if score >= 4 else "Low"


def build_inventory(host_results: list[dict]) -> dict:
    """host_results → 자산 인벤토리 목록 + 요약."""
    assets: list[dict] = []
    for hr in (host_results or []):
        host = hr.get("host", "")
        ip = hr.get("ip") or hr.get("address") or host
        services = hr.get("services", []) or []
        open_ports = sorted({p for p in (hr.get("open_ports") or
                             [s.get("port") for s in services]) if p})
        # 서비스 분류(service_surface_planner 재사용)
        detected = []
        for s in services:
            c = ssp.classify_service(s)
            if c:
                detected.append({"port": c["port"], "service": c["service"],
                                 "family": c["family"], "attack_surface_type": c["attack_surface_type"],
                                 "version": c.get("version", "")})
        # 웹 엔드포인트
        web_eps = []
        for p in open_ports:
            if p in (443, 8443):
                web_eps.append(f"https://{ip}:{p}")
            elif p in (80, 8080, 8000, 8888):
                web_eps.append(f"http://{ip}:{p}")
        # 관리자 노출 단서(discovery_result admin_hits)
        has_admin = any((svc.get("discovery_result") or {}).get("admin_hits")
                        for svc in services)
        # OS/MAC/vendor (있으면 사용)
        asset = {
            "ip": ip, "hostname": hr.get("hostname", host),
            "reverse_dns": hr.get("reverse_dns", ""),
            "os_guess": hr.get("os_guess") or hr.get("os", "") or "unknown",
            "mac_address": hr.get("mac_address", ""),
            "vendor": hr.get("vendor", ""),
            "open_ports": open_ports, "detected_services": detected,
            "web_endpoints": web_eps, "has_admin": has_admin,
        }
        surfaces = {s["attack_surface_type"] for s in detected}
        families = {s["family"] for s in detected}
        asset["asset_type"] = classify_asset(asset)
        asset["risk_tags"] = _risk_tags(asset, surfaces, families)
        asset["priority"] = _priority(asset["asset_type"], asset["risk_tags"], len(open_ports))
        asset.pop("has_admin", None)
        assets.append(asset)

    assets.sort(key=lambda a: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
                .get(a["priority"], 0), reverse=True)
    return {"assets": assets, "summary": _summary(assets)}


def _summary(assets: list[dict]) -> dict:
    def type_cnt(t):
        return sum(1 for a in assets if a["asset_type"] == t)
    total_ports = sum(len(a["open_ports"]) for a in assets)
    total_svcs = sum(len(a["detected_services"]) for a in assets)
    web_cand = sum(len(a["web_endpoints"]) for a in assets)
    return {
        "total_assets": len(assets),
        "open_ports": total_ports,
        "services": total_svcs,
        "web_candidates": web_cand,
        "web_servers": type_cnt(A_WEB),
        "database_servers": type_cnt(A_DB),
        "auth_servers": type_cnt(A_AUTH),
        "file_servers": type_cnt(A_FILE),
        "mail_servers": type_cnt(A_MAIL),
        "container_nodes": type_cnt(A_CONTAINER),
        "network_devices": type_cnt(A_NETDEV),
        "unknown": type_cnt(A_UNKNOWN),
        "internet_exposed": sum(1 for a in assets if "internet_exposed" in a["risk_tags"]),
        "high_priority": sum(1 for a in assets if a["priority"] in ("Critical", "High")),
    }
