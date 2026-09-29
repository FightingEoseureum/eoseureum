"""
target_input.py — 입력 대상 확장(URL/Domain/IP/IP List/CIDR 자동 판별·정규화).

Network Discovery Framework v1. 순수 함수(네트워크 없음).
"""
from __future__ import annotations

import ipaddress
import re

T_URL = "url"
T_DOMAIN = "domain"
T_IP = "ip"
T_IP_LIST = "ip_list"
T_CIDR = "cidr"

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$", re.IGNORECASE)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _is_cidr(s: str) -> bool:
    if "/" not in s:
        return False
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def _classify_one(s: str) -> str:
    s = s.strip()
    if not s:
        return ""
    if s.startswith(("http://", "https://")):
        return T_URL
    if _is_cidr(s):
        return T_CIDR
    if _is_ip(s):
        return T_IP
    if _DOMAIN_RE.match(s):
        return T_DOMAIN
    # host:port 또는 경로 포함 → url 로 간주(스킴 없이)
    if "/" in s or ":" in s:
        return T_URL
    return T_DOMAIN


def detect_target_type(raw: str) -> str:
    """단일/복수 입력의 대표 target_type 판별."""
    parts = _split(raw)
    if not parts:
        return ""
    types = [_classify_one(p) for p in parts]
    types = [t for t in types if t]
    if not types:
        return ""
    uniq = set(types)
    if len(parts) > 1:
        # 복수 — IP/CIDR 위주면 ip_list, 그 외 첫 유형
        if uniq <= {T_IP, T_CIDR}:
            return T_CIDR if T_CIDR in uniq else T_IP_LIST
        return types[0]
    # 단일
    return types[0]


def _split(raw: str) -> list[str]:
    if not raw:
        return []
    return [p.strip() for p in re.split(r"[\s,;]+", raw) if p.strip()]


def normalize_targets(raw: str, *, max_hosts: int | None = None) -> dict:
    """입력을 정규화. CIDR 은 호스트로 펼치지 않고(가드는 network_discovery 담당)
    구성요소만 분해한다.

    반환: {target_type, normalized_targets[], scan_scope_summary{}}.
      normalized_targets 항목: {value, type, is_private(IP/CIDR), host_count(CIDR)}
    """
    parts = _split(raw)
    ttype = detect_target_type(raw)
    out: list[dict] = []
    total_hosts = 0
    private_n = public_n = 0
    for p in parts:
        t = _classify_one(p)
        item = {"value": p, "type": t}
        if t == T_CIDR:
            net = ipaddress.ip_network(p, strict=False)
            hc = max(net.num_addresses - (2 if net.num_addresses > 2 else 0), 1)
            item["host_count"] = hc
            item["is_private"] = net.is_private
            total_hosts += hc
            private_n += hc if net.is_private else 0
            public_n += 0 if net.is_private else hc
        elif t == T_IP:
            ip = ipaddress.ip_address(p)
            item["host_count"] = 1
            item["is_private"] = ip.is_private
            total_hosts += 1
            private_n += 1 if ip.is_private else 0
            public_n += 0 if ip.is_private else 1
        else:
            item["host_count"] = 1
        out.append(item)

    summary = {
        "target_type": ttype,
        "target_count": len(out),
        "estimated_hosts": total_hosts,
        "private_hosts": private_n,
        "public_hosts": public_n,
        "has_network_range": any(i["type"] == T_CIDR for i in out),
        "note": "승인된 사내/고객 대상 대역만 점검합니다.",
    }
    return {"target_type": ttype, "normalized_targets": out, "scan_scope_summary": summary}
