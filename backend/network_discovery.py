"""
network_discovery.py — Network Discovery Engine (Network Discovery Framework v1).

CIDR/IP 대역에서 살아있는 호스트를 '안전하게' 식별한다.

중요 원칙(보수적 기본값):
  - 승인된 대역만. 대량 고속 스캔 금지. 브루트포스/Exploit/destructive 금지.
  - 기본 Discovery(ICMP/TCP ping) 만. 큰 대역(/16 이상)은 기본 차단 또는 명시 승인 필요.
  - 호스트 수/포트 수/속도/타임아웃 상한 적용.

네트워크 I/O 는 주입 가능한 ping_fn 으로 분리(테스트에서 monkeypatch). 모듈 로드 시
네트워크 호출 없음.
"""
from __future__ import annotations

import ipaddress
import os

import target_input as ti


# ── 안전 정책 기본값(보수적) ──────────────────────────────────────────────────
def _int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def network_policy() -> dict:
    return {
        "max_hosts": _int("NETWORK_MAX_HOSTS", 256),          # 기본 /24
        "max_ports_per_host": _int("NETWORK_MAX_PORTS_PER_HOST", 100),
        "discovery_rate": _int("NETWORK_DISCOVERY_RATE", 10),  # 초당 호스트(권장 상한)
        "timeout": _int("NETWORK_TIMEOUT", 2),                 # 호스트당 초
        "block_prefix": _int("NETWORK_BLOCK_PREFIX", 16),      # 이보다 큰 대역(prefix < 16)은 차단
        "allow_large": os.getenv("NETWORK_ALLOW_LARGE", "false").strip().lower()
                       in ("1", "true", "yes", "on"),
    }


# ── Scope Guard ───────────────────────────────────────────────────────────────
def scope_guard(normalized: dict, policy: dict | None = None) -> dict:
    """정규화 대상에 안전 정책을 적용해 허용/차단을 판정한다.

    반환: {allowed[], blocked[], total_hosts, blocked_reasons[], within_limit, summary}
    """
    pol = policy or network_policy()
    items = (normalized or {}).get("normalized_targets") or []
    allowed: list[dict] = []
    blocked: list[dict] = []
    reasons: list[str] = []
    total = 0

    for it in items:
        t = it.get("type")
        if t == ti.T_CIDR:
            net = ipaddress.ip_network(it["value"], strict=False)
            # /16 이상 대역(prefix < block_prefix) 차단(명시 승인 없으면)
            if net.prefixlen < pol["block_prefix"] and not pol["allow_large"]:
                blocked.append({**it, "reason": f"대역이 너무 큼(/{net.prefixlen}) — "
                                f"/{pol['block_prefix']} 이상만 기본 허용. NETWORK_ALLOW_LARGE 승인 필요"})
                reasons.append(f"{it['value']}: 큰 대역 기본 차단")
                continue
            hc = it.get("host_count", 0)
            if total + hc > pol["max_hosts"] and not pol["allow_large"]:
                blocked.append({**it, "reason": f"호스트 수 상한 초과(누적 {total+hc} > "
                                f"NETWORK_MAX_HOSTS {pol['max_hosts']})"})
                reasons.append(f"{it['value']}: 호스트 상한 초과")
                continue
            total += hc
            allowed.append(it)
        elif t == ti.T_IP:
            total += 1
            allowed.append(it)
        else:
            # url/domain 은 네트워크 디스커버리 대상 아님(기존 파이프라인)
            allowed.append(it)

    summary = {
        "allowed_count": len(allowed), "blocked_count": len(blocked),
        "total_discovery_hosts": total, "max_hosts": pol["max_hosts"],
        "block_prefix": pol["block_prefix"], "within_limit": len(blocked) == 0,
    }
    return {"allowed": allowed, "blocked": blocked, "blocked_reasons": reasons,
            "total_hosts": total, "within_limit": len(blocked) == 0, "summary": summary,
            "policy": pol}


# ── CIDR/IP → 호스트 목록 ────────────────────────────────────────────────────
def expand_targets(allowed_items: list[dict], max_hosts: int) -> list[str]:
    """허용된 CIDR/IP 를 개별 호스트 IP 목록으로 펼친다(상한 적용)."""
    ips: list[str] = []
    seen: set = set()
    for it in (allowed_items or []):
        t = it.get("type")
        if t == ti.T_CIDR:
            net = ipaddress.ip_network(it["value"], strict=False)
            hosts = net.hosts() if net.num_addresses > 2 else iter(net)
            for h in hosts:
                s = str(h)
                if s not in seen:
                    seen.add(s); ips.append(s)
                    if len(ips) >= max_hosts:
                        return ips
        elif t == ti.T_IP:
            s = it["value"]
            if s not in seen:
                seen.add(s); ips.append(s)
                if len(ips) >= max_hosts:
                    return ips
    return ips


# ── 라이브 호스트 탐지(주입형) ────────────────────────────────────────────────
def _default_tcp_ping(ip: str, timeout: float = 2.0) -> bool:
    """안전 기본 탐지: 공통 포트에 TCP connect(비대량). 응답 있으면 live.
    실제 스캔 시에만 호출(테스트는 ping_fn 주입)."""
    import socket
    for port in (80, 443, 22, 445, 3389):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            rc = s.connect_ex((ip, port))
            s.close()
            if rc == 0:
                return True
        except Exception:
            continue
    return False


def discover_live_hosts(ips: list[str], *, ping_fn=None, timeout: float = 2.0,
                        method: str = "tcp_ping") -> dict:
    """호스트 목록에서 살아있는 호스트 식별. ping_fn(ip, timeout)->bool 주입 가능.

    반환: {live_hosts[], unreachable_hosts[], discovery_method, discovery_summary}.
    """
    fn = ping_fn or _default_tcp_ping
    # rate 거버너(동기): 서브넷 sweep 의 host별 TCP 핑도 SAFE 상한에 맞춰 페이싱(버스트 방지)
    try:
        import adaptive_throttle as _gov
        _glim = _gov.stage("host_sweep")
    except Exception:
        _glim = None
    live: list[str] = []
    unreachable: list[str] = []
    for ip in (ips or []):
        if _glim is not None:
            _glim.before_sync()
        try:
            ok = bool(fn(ip, timeout))
        except Exception:
            ok = False
        if _glim is not None:
            _glim.after_sync(0.0, 0, None)
        (live if ok else unreachable).append(ip)
    summary = {
        "scanned": len(ips or []), "live": len(live), "unreachable": len(unreachable),
        "method": method,
    }
    return {"live_hosts": live, "unreachable_hosts": unreachable,
            "discovery_method": method, "discovery_summary": summary}


def run_discovery(raw_target: str, *, ping_fn=None, policy: dict | None = None) -> dict:
    """입력 → 정규화 → scope guard → 펼치기 → 라이브 탐지. (라이브 탐지는 ping_fn 주입 시
    테스트에서 네트워크 없이 동작). 반환에 가드/차단 정보 포함."""
    pol = policy or network_policy()
    norm = ti.normalize_targets(raw_target)
    guard = scope_guard(norm, pol)
    ips = expand_targets(guard["allowed"], pol["max_hosts"])
    disc = discover_live_hosts(ips, ping_fn=ping_fn, timeout=float(pol["timeout"]))
    return {
        "target_type": norm["target_type"],
        "normalized_targets": norm["normalized_targets"],
        "scope_guard": guard,
        "expanded_hosts": ips,
        "network_discovery": disc,
        "blocked": guard["blocked"],
    }
