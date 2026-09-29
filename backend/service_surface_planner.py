"""
service_surface_planner.py — Service Attack Surface Planner (Service Security Framework v1).

웹 중심 플랫폼을 Web + Service 로 확장한다. 새 능동 탐색 없이 기존 포트 스캔/서비스 식별
결과(포트/프로토콜/배너/서비스/버전/TLS/인증)만으로 서비스 공격 표면을 분류·점수화하고,
서비스 공격 경로·증거·보안 통제·비즈니스 영향을 도출한다.

판정/검증 수준은 기존 증거 기준(Rule Engine)만 사용하며 AI 는 설명 보강만 가능.
"""
from __future__ import annotations

# Surface 타입
S_AUTH = "Authentication Surface"
S_FILE = "File Sharing Surface"
S_DB = "Database Surface"
S_DATA = "Data Exposure Surface"
S_CONTAINER = "Container Surface"
S_MESSAGING = "Messaging Surface"
S_OTHER = "Service Surface"

# 서비스명 키워드 → (surface, family, solver, role)
_SERVICE_MAP = [
    (("ssh",), (S_AUTH, "ssh", "ssh_solver", "원격 관리 인증")),
    (("rdp", "ms-wbt"), (S_AUTH, "rdp", "ssh_solver", "원격 데스크톱 인증")),
    (("ldap",), (S_AUTH, "ldap", "ssh_solver", "디렉터리 인증")),
    (("telnet",), (S_AUTH, "telnet", "ssh_solver", "평문 원격 접속")),
    (("smb", "microsoft-ds", "netbios"), (S_FILE, "smb", "smb_solver", "파일 공유")),
    (("nfs",), (S_FILE, "nfs", "smb_solver", "네트워크 파일 시스템")),
    (("ftp",), (S_FILE, "ftp", "ftp_solver", "파일 전송")),
    (("mysql", "mariadb"), (S_DB, "mysql", "mysql_solver", "관계형 DB")),
    (("postgres", "postgresql"), (S_DB, "postgresql", "mysql_solver", "관계형 DB")),
    (("mssql", "ms-sql", "sqlserver"), (S_DB, "mssql", "mysql_solver", "관계형 DB")),
    (("mongo",), (S_DB, "mongodb", "mysql_solver", "문서 DB")),
    (("oracle",), (S_DB, "oracle", "mysql_solver", "관계형 DB")),
    (("redis",), (S_DATA, "redis", "redis_solver", "인메모리 데이터")),
    (("memcache",), (S_DATA, "memcached", "redis_solver", "인메모리 캐시")),
    (("elastic", "elasticsearch"), (S_DATA, "elasticsearch", "redis_solver", "검색 데이터")),
    (("docker",), (S_CONTAINER, "docker", "docker_solver", "컨테이너 데몬")),
    (("kubernetes", "kube", "k8s", "kubelet"), (S_CONTAINER, "k8s", "k8s_solver", "컨테이너 오케스트레이션")),
    (("smtp",), (S_MESSAGING, "smtp", "smtp_solver", "메일 전송")),
    (("imap",), (S_MESSAGING, "imap", "smtp_solver", "메일 수신")),
    (("pop3",), (S_MESSAGING, "pop3", "smtp_solver", "메일 수신")),
]
# 포트 → 폴백 매핑(서비스명이 없을 때)
_PORT_MAP = {
    22: "ssh", 23: "telnet", 3389: "rdp", 389: "ldap", 636: "ldap",
    445: "smb", 139: "smb", 2049: "nfs", 21: "ftp",
    3306: "mysql", 5432: "postgres", 1433: "mssql", 27017: "mongo", 1521: "oracle",
    6379: "redis", 11211: "memcache", 9200: "elasticsearch",
    2375: "docker", 2376: "docker", 6443: "kubernetes", 10250: "kubernetes",
    25: "smtp", 587: "smtp", 143: "imap", 993: "imap", 110: "pop3", 995: "pop3",
}

_SURFACE_WEIGHT = {S_DB: 8, S_DATA: 8, S_CONTAINER: 9, S_FILE: 6, S_AUTH: 7,
                   S_MESSAGING: 4, S_OTHER: 2}


def classify_service(service: dict) -> dict | None:
    """단일 서비스 → 의미 분류 + 표면/솔버/점수/증거/근거. 식별 불가 시 None."""
    name = (service.get("service") or service.get("name") or "").lower()
    port = service.get("port")
    banner = (service.get("banner") or "") or ""
    version = (service.get("version") or service.get("product") or "") or ""
    text = f"{name} {banner}".lower()

    fam = None
    surface = solver = role = None
    for kws, (sf, family, slv, rl) in _SERVICE_MAP:
        if any(k in text or k == name for k in kws):
            surface, fam, solver, role = sf, family, slv, rl
            break
    if not fam and port in _PORT_MAP:
        key = _PORT_MAP[port]
        for kws, (sf, family, slv, rl) in _SERVICE_MAP:
            if family == key or key in kws:
                surface, fam, solver, role = sf, family, slv, rl
                break
    if not fam:
        # HTTP/HTTPS 는 웹 파이프라인이 담당 — 서비스 표면에서 제외
        if name in ("http", "https") or port in (80, 443, 8080, 8443):
            return None
        return None

    evidence = _collect_evidence(fam, service, banner, version)
    elvl = _evidence_level(fam, service, evidence)
    weight = _SURFACE_WEIGHT.get(surface, 2)
    score = weight + (3 if elvl >= 2 else 1 if elvl == 1 else 0)
    if surface in (S_DB, S_DATA, S_CONTAINER):
        score += 2   # 민감/고위험 표면 가중
    pr = "Critical" if score >= 12 else "High" if score >= 9 else "Medium" if score >= 6 else "Low"

    reasoning = (f"{port}/tcp {name or fam} → {surface}({role}). "
                 f"증거 수준 {elvl}, 추천 Solver {solver}.")
    return {
        "port": port, "service": name or fam, "family": fam,
        "service_role": role, "attack_surface_type": surface,
        "recommended_solver": solver, "priority_score": score, "priority": pr,
        "evidence_level": elvl, "evidence": evidence, "reasoning": reasoning,
        "version": version,
    }


def _collect_evidence(fam: str, service: dict, banner: str, version: str) -> dict:
    """기존 수집 정보(배너/버전/TLS)에서 서비스 증거 추출(능동 점검 없음)."""
    ssl_info = service.get("ssl_info") or {}
    ev: dict = {"version": version or _ver_from_banner(banner)}
    low = (banner or "").lower()
    if ssl_info:
        ev["tls"] = ssl_info.get("protocol") or ssl_info.get("version") or "TLS"
    if fam == "ssh":
        ev["auth_hint"] = "password" if "password" in low else ("publickey" if "publickey" in low else "")
        ev["algorithms"] = ssl_info.get("ciphers") if ssl_info else ""
    if fam == "smb":
        ev["signing"] = "enabled" if "signing" in low and "enabled" in low else ""
        ev["guest"] = "allowed" if "guest" in low else ""
    if fam in ("mysql", "postgresql", "mssql", "mongodb", "oracle"):
        ev["external_exposed"] = True   # 외부 포트 스캔에서 보였다는 것 자체가 외부 노출
    if fam in ("redis", "memcached", "elasticsearch"):
        ev["auth_required"] = "no" if ("noauth" in low or "no password" in low) else "unknown"
        ev["protected_mode"] = "off" if "protected mode" in low and "off" in low else "unknown"
    return {k: v for k, v in ev.items() if v not in ("", None)}


def _ver_from_banner(banner: str) -> str:
    import re
    m = re.search(r"[\d]+\.[\d.]+", banner or "")
    return m.group(0) if m else ""


def _evidence_level(fam: str, service: dict, evidence: dict) -> int:
    """기존 증거 기준 검증 수준(보수적). 능동 점검 없이 단순 노출은 Level 1(관찰)."""
    # service_scan 등에서 부여된 confidence 가 있으면 그것을 우선
    conf = (service.get("confidence") or "").upper()
    if conf in ("CONFIRMED", "CONFIRMED_RESPONSE"):
        return 3
    if conf == "POSSIBLE":
        return 2
    # 무인증/보호모드 off 같은 명확 노출 단서 → Level 2(증거)
    if evidence.get("auth_required") == "no" or evidence.get("protected_mode") == "off" \
            or evidence.get("guest") == "allowed":
        return 2
    return 1   # 단순 외부 노출/배너 = 관찰


# ── 서비스 공격 경로(Internet → Service → 조건 → 위험) ─────────────────────────
_PATH_TEMPLATE = {
    S_AUTH: ("약한 인증 정책", "권한 있는 접근 위험(Privileged Access Risk)"),
    S_FILE: ("익명/Guest 접근", "민감 파일 노출 위험(Sensitive File Exposure)"),
    S_DB: ("외부 노출", "데이터 노출 위험(Data Exposure Risk)"),
    S_DATA: ("무인증 접근", "데이터 노출 위험(Data Exposure Risk)"),
    S_CONTAINER: ("무인증 API 접근", "컨테이너 탈취 위험(Container Compromise Risk)"),
    S_MESSAGING: ("개방 릴레이/노출", "스팸·정보 노출 위험(Mail Abuse Risk)"),
    S_OTHER: ("서비스 노출", "공격 표면 증가"),
}
_PCONF = {3: "Confirmed Path", 2: "Evidence Path", 1: "Observed Path", 0: "Informational Path"}


def _service_path(host: str, surf: dict, idx: int) -> dict:
    cond, risk = _PATH_TEMPLATE.get(surf["attack_surface_type"], _PATH_TEMPLATE[S_OTHER])
    elvl = surf["evidence_level"]
    steps = [
        "Entry Point: 인터넷(Internet)",
        f"{surf['attack_surface_type']}: {surf['port']}/tcp {surf['service']}",
        f"조건: {cond}",
        f"Report Impact: {risk}",
    ]
    pgrade = ("Critical Path" if elvl >= 2 and surf["attack_surface_type"] in (S_DB, S_DATA, S_CONTAINER)
              else "High Path" if elvl >= 2 else "Medium Path" if surf["priority"] in ("Critical", "High")
              else "Observed Path")
    return {
        "path_id": f"SVC-{idx:03d}",
        "title": f"서비스 경로 — {surf['attack_surface_type']} ({surf['service']})",
        "steps": steps, "node_ids": [],
        "evidence_level": elvl, "path_confidence": _PCONF.get(elvl, "Observed Path"),
        "risk_grade": pgrade, "possible_impact": risk,
        "scan_category": "service", "service_family": surf["family"],
        "host": host, "evidence_refs": [f"{host}:{surf['port']}"],
        "blocked_actions": "서비스 무차별 인증/익스플로잇은 수행하지 않음(기존 정보 분석만)",
    }


def plan_service_surfaces(host_results: list[dict]) -> dict:
    """모든 호스트의 서비스 → 표면/경로/요약 산출."""
    surfaces: list[dict] = []
    paths: list[dict] = []
    seen: set = set()
    for hr in (host_results or []):
        host = hr.get("host", "")
        for svc in hr.get("services", []):
            c = classify_service(svc)
            if not c:
                continue
            key = (host, c["port"], c["family"])
            if key in seen:
                continue
            seen.add(key)
            c["host"] = host
            surfaces.append(c)
            paths.append(_service_path(host, c, len(paths) + 1))

    surfaces.sort(key=lambda x: x["priority_score"], reverse=True)
    summary = _summary(surfaces)
    return {"service_surfaces": surfaces, "service_attack_paths": paths,
            "service_surface_summary": summary, "ai_cannot_confirm": True}


def _summary(surfaces: list[dict]) -> dict:
    def cnt(s):
        return sum(1 for x in surfaces if x["attack_surface_type"] == s)
    return {
        "total_service_surfaces": len(surfaces),
        "authentication_surfaces": cnt(S_AUTH),
        "file_sharing_surfaces": cnt(S_FILE),
        "database_surfaces": cnt(S_DB),
        "data_exposure_surfaces": cnt(S_DATA),
        "container_surfaces": cnt(S_CONTAINER),
        "messaging_surfaces": cnt(S_MESSAGING),
        "critical_high": sum(1 for x in surfaces if x["priority"] in ("Critical", "High")),
        "by_family": _by_family(surfaces),
    }


def _by_family(surfaces):
    out: dict = {}
    for s in surfaces:
        out[s["family"]] = out.get(s["family"], 0) + 1
    return out


# ── 서비스 비즈니스 영향(기존 business_impact_engine 형식과 호환) ────────────────
_SVC_IMPACT = {
    S_AUTH: (["Access Control", "Authentication"], "관리자/원격 접근 위험",
             "인증 체계", ["관리자 접근 위험", "비인가 원격 접근 가능성"], ["인증 정보", "접근 통제"]),
    S_FILE: (["Confidentiality", "Data Exposure"], "파일 노출 위험",
             "파일 공유 시스템", ["민감 파일 노출 가능성", "익명 접근 가능성"], ["내부 시스템 정보"]),
    S_DB: (["Confidentiality", "Data Exposure", "Compliance Risk"], "민감 정보 노출 위험",
           "데이터베이스", ["민감 정보 노출 가능성", "DB 외부 노출"], ["개인정보", "금융 정보"]),
    S_DATA: (["Confidentiality", "Data Exposure"], "데이터 노출 위험",
             "인메모리/검색 데이터", ["무인증 데이터 노출 가능성"], ["개인정보"]),
    S_CONTAINER: (["Operational Risk", "Integrity", "Access Control"], "인프라 장악 위험",
                  "컨테이너 인프라", ["컨테이너/노드 장악 가능성", "무인증 API 접근"], ["내부 시스템 정보"]),
    S_MESSAGING: (["Operational Risk"], "메일 남용/정보 노출 위험",
                  "메일 서비스", ["오픈 릴레이 악용 가능성", "사용자 열거 가능성"], []),
}
_REG_AREA = {
    "개인정보": "개인정보 보호(관련 가능성)", "인증 정보": "접근 통제·인증 보호(관련 가능성)",
    "금융 정보": "금융 정보 보호·감사 추적(관련 가능성)", "접근 통제": "접근 통제(관련 가능성)",
    "내부 시스템 정보": "내부 시스템 접근 통제(관련 가능성)",
}


def service_business_impact(surfaces: list[dict]) -> list[dict]:
    """서비스 표면 → 비즈니스 영향 항목(business_impact_engine 항목 형식)."""
    import business_impact_engine as bie
    out: list[dict] = []
    for s in surfaces:
        m = _SVC_IMPACT.get(s["attack_surface_type"])
        if not m:
            continue
        cats, risk, asset, cons, regs = m
        er = bie.executive_risk_score(
            evidence_level=s["evidence_level"], path_priority=s["priority"],
            authenticated=False, admin=(s["attack_surface_type"] == S_AUTH),
            sensitive=(s["attack_surface_type"] in (S_DB, S_DATA, S_CONTAINER)),
            categories=cats)
        out.append({
            "family": s["family"],
            "title": f"[서비스] {s['attack_surface_type']} — {s['port']}/tcp {s['service']}",
            "impact_category": cats, "business_risk": risk, "affected_asset": asset,
            "impact_description": risk, "potential_consequence": cons,
            "regulatory_risk": [_REG_AREA.get(r, r) for r in regs],
            "evidence_level": s["evidence_level"],
            "executive_risk_score": er["score"], "priority": er["level"],
            "priority_factors": er["factors"], "scan_category": "service",
        })
    return out


def service_controls(surfaces: list[dict]) -> list[str]:
    """서비스 증거에서 '정상 동작 보안 통제'(✓) 도출(증거 있을 때만 — 오탐 방지)."""
    controls: list[str] = []
    for s in surfaces:
        ev = s.get("evidence") or {}
        if ev.get("signing") == "enabled":
            controls.append("SMB Signing 활성")
        if ev.get("protected_mode") == "on":
            controls.append("Redis Protected Mode 활성")
        if s["family"] == "ssh" and ev.get("auth_hint") == "publickey":
            controls.append("SSH Password Login 비활성(키 기반)")
        tls = str(ev.get("tls") or "")
        if tls and any(v in tls for v in ("1.2", "1.3", "TLSv1.2", "TLSv1.3")):
            controls.append("서비스 전송 구간 TLS1.2 이상 사용")
    # 중복 제거
    seen, out = set(), []
    for c in controls:
        if c not in seen:
            seen.add(c); out.append(c)
    return out
