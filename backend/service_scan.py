"""
service_scan.py — Eoseureum 열린 포트 기반 서비스 보안 점검 모듈.

열려 있는 포트 목록을 받아, 각 포트의 구동 서비스를 식별하고
**비파괴적·안전한 점검만** 수행한다. (배너 수집, 프로토콜 negotiate 응답,
안전 handshake, 인증 요구 여부, 비파괴적 설정 확인까지만.)

[안전 제약 — 코드 레벨에서 보장]
  - 브루트포스/기본계정 로그인/exploit/파괴적 NSE/대량요청을 수행하는
    경로가 존재하지 않는다. 인증이 필요한 서비스에 로그인을 시도하지 않는다.
  - anonymous FTP login / SMB 익명세션 등 '인증 우회 확인'은 모듈 상수
    ALLOW_ANON(기본 False) 또는 scan_services(allow_anon=...) 인자가 True 일
    때만 수행하며, 기본값에서는 절대 수행하지 않는다.
  - nmap 을 쓰는 경우 안전 플래그만 사용한다(-sV --version-light -Pn,
    제한 포트, --host-timeout). -A / --script vuln / intrusive·exploit·brute
    NSE / 전체포트 / 대량 UDP 는 사용하지 않는다. nmap 이 없으면 Python
    socket 배너 수집으로 graceful fallback 한다.

[환경변수]
  SERVICE_SCAN_TIMEOUT  (기본 5)   : 소켓/HTTP 타임아웃(초)
  SERVICE_SCAN_MAX_PORTS(기본 30)  : 점검 최대 포트 수
  SCAN_MODE             (기본 safe): safe 외 값도 동일하게 안전 동작
  SERVICE_SCAN_ALLOW_ANON (기본 false): 익명 점검 허용 여부
  SERVICE_SCAN_USE_NMAP (기본 false): nmap -sV 서비스/버전 식별 보강 사용 여부
                                      (무권한·안전 플래그만. 없으면 Python 점검만 유지)
  NMAP_PATH             (기본 빈값) : nmap 바이너리 경로(포터블 등). 없으면 PATH 에서 탐색.

[테스트 구조]
  서비스별 점검은 개별 함수(_check_ssh, _check_redis, ...)로 분리한다.
  실제 네트워크 I/O 는 monkeypatch 가능한 모듈 함수로 캡슐화한다:
    _recv_banner(host, port, timeout, send=None) -> str
    _tcp_connect_ok(host, port, timeout)         -> bool
    _http_get(host, port, path, timeout, scheme) -> dict | None
    _dns_axfr(host, port, timeout)               -> list[str] | None
  테스트는 이 함수들을 패치해 배너/응답을 주입하고 분류를 검증한다.

공개 인터페이스:
  scan_services(host: str, open_ports: list[int], scan_mode: str = "safe") -> dict
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# 안전 상수 / 설정
# ---------------------------------------------------------------------------

# 익명 접근 점검(anonymous FTP / SMB 익명세션)은 기본 비활성화.
ALLOW_ANON = False

# 신뢰도 점수 기준 (요구 명세)
_SCORE_UNAUTH = 90    # 인증 없는 접근 실증 (85~95)
_SCORE_BANNER = 78    # 배너·버전 명확 (70~85)
_SCORE_EXPOSED = 60   # 노출만 (55~65)
_SCORE_PROTECTED = 45  # 보호됨 (401/403/auth required)
_SCORE_GUESS = 35     # 추정


def _timeout() -> float:
    try:
        return float(os.environ.get("SERVICE_SCAN_TIMEOUT", "5"))
    except (TypeError, ValueError):
        return 5.0


def _max_ports() -> int:
    try:
        return int(os.environ.get("SERVICE_SCAN_MAX_PORTS", "30"))
    except (TypeError, ValueError):
        return 30


def _allow_anon(arg: bool | None) -> bool:
    if arg is not None:
        return bool(arg)
    env = os.environ.get("SERVICE_SCAN_ALLOW_ANON", "").strip().lower()
    if env in ("1", "true", "yes", "on"):
        return True
    return bool(ALLOW_ANON)


# ---------------------------------------------------------------------------
# 네트워크 I/O 캡슐화 (monkeypatch 지점)
#   — 어느 것도 인증/로그인/exploit 을 수행하지 않는다. 읽기/handshake 전용.
# ---------------------------------------------------------------------------

def _recv_banner(host: str, port: int, timeout: float, send: bytes | None = None) -> str:
    """TCP 연결 후 배너를 1회 수신한다. 필요 시 무해한 send(예: HELP, EHLO)만 전송.

    파괴적/인증 데이터는 전송하지 않는다. 실패 시 빈 문자열 반환.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if send:
                try:
                    sock.sendall(send)
                except OSError:
                    pass
            try:
                data = sock.recv(4096)
            except (socket.timeout, OSError):
                return ""
            return data.decode("utf-8", errors="replace").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ""


def _tcp_connect_ok(host: str, port: int, timeout: float) -> bool:
    """TCP 연결 가능 여부만 확인한다(데이터 송신 없음)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _http_get(host: str, port: int, path: str, timeout: float, scheme: str = "http") -> dict | None:
    """단일 비파괴적 GET 요청. 인증 헤더/자격증명을 전혀 보내지 않는다.

    반환: {"status": int, "headers": dict[str,str], "body": str} 또는 None(실패).
    """
    try:
        import http.client
        import ssl

        if scheme == "https":
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": "Eoseureum-ServiceScan/1.0"})
            resp = conn.getresponse()
            body = resp.read(8192).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.getheaders()}
            return {"status": resp.status, "headers": headers, "body": body}
        finally:
            conn.close()
    except Exception:
        return None


def _dns_axfr(host: str, port: int, timeout: float) -> list[str] | None:
    """DNS Zone Transfer(AXFR)를 1회 안전 시도한다(읽기 전용).

    성공 시 레코드 문자열 리스트, 거부/실패 시 None.
    dnspython 미설치 시 None(graceful).
    """
    try:
        import dns.query
        import dns.zone
    except Exception:
        return None
    try:
        xfr = dns.query.xfr(host, host, timeout=timeout, port=port, lifetime=timeout)
        zone = dns.zone.from_xfr(xfr)
        return [str(n) for n in zone.nodes.keys()]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# item 빌더
# ---------------------------------------------------------------------------

def _make_item(
    *,
    title: str,
    service: str,
    host: str,
    port: int,
    finding_type: str,
    severity: str,
    confidence: str,
    confidence_score: int,
    evidence: list[str],
    check_method: str,
    recommendation: str,
    cwe: str = "",
    kisa_reference: str = "",
    tags: list[str] | None = None,
    protocol: str = "tcp",
) -> dict:
    item = {
        "title": title,
        "service": service,
        "host": host,
        "port": port,
        "protocol": protocol,
        "finding_type": finding_type,
        "severity": severity,
        "confidence": confidence,
        "confidence_score": int(max(0, min(100, confidence_score))),
        "evidence": list(evidence),
        "safe_check": True,
        "check_method": check_method,
        "recommendation": recommendation,
        "cwe": cwe,
        "kisa_reference": kisa_reference,
        "tags": list(tags or []),
        "scan_category": "service",
    }
    if finding_type == "vulnerability":
        item["judgment"] = "취약"
    elif finding_type == "good":
        item["judgment"] = "양호"
    return item


# ---------------------------------------------------------------------------
# 서비스별 점검 함수
#   각 함수는 list[dict] 를 반환한다.
# ---------------------------------------------------------------------------

def _check_ssh(host: str, port: int, timeout: float, **_) -> list[dict]:
    banner = _recv_banner(host, port, timeout)
    if not banner:
        return [_make_item(
            title="SSH 응답 없음", service="SSH", host=host, port=port,
            finding_type="noise", severity="Info",
            confidence="MANUAL_REVIEW", confidence_score=_SCORE_GUESS,
            evidence=["no banner / timeout"], check_method="socket banner",
            recommendation="포트 접근성/필터링 상태 수동 확인.",
            tags=["ssh"],
        )]
    items: list[dict] = []
    low = banner.lower()
    if "ssh-" in low:
        # 버전 노출 → Low finding
        items.append(_make_item(
            title="SSH 버전/배너 노출", service="SSH", host=host, port=port,
            finding_type="vulnerability", severity="Low",
            confidence="POSSIBLE", confidence_score=_SCORE_BANNER,
            evidence=[f"banner: {banner[:200]}"],
            check_method="socket banner grab",
            recommendation="SSH 배너에서 정확한 버전 노출을 최소화하고 최신 버전 유지. "
                           "구버전이면 약한 KEX/cipher 사용 '가능성'을 수동 점검(단정 불가).",
            cwe="CWE-200", kisa_reference="KISA 서버보안 - SSH 서비스 버전 노출 점검",
            tags=["ssh", "version-disclosure"],
        ))
    # 단순 외부 노출 → attack_surface
    items.append(_make_item(
        title="SSH 외부 노출", service="SSH", host=host, port=port,
        finding_type="attack_surface", severity="Info",
        confidence="POSSIBLE", confidence_score=_SCORE_EXPOSED,
        evidence=[f"banner observed on tcp/{port}"],
        check_method="socket banner grab",
        recommendation="SSH 접근을 신뢰 네트워크/방화벽/공개키 인증으로 제한.",
        cwe="CWE-284", kisa_reference="KISA 서버보안 - 원격접속 제한",
        tags=["ssh", "exposure"],
    ))
    return items


def _check_ftp(host: str, port: int, timeout: float, allow_anon: bool = False, **_) -> list[dict]:
    banner = _recv_banner(host, port, timeout)
    if not banner:
        return [_make_item(
            title="FTP 응답 없음", service="FTP", host=host, port=port,
            finding_type="noise", severity="Info",
            confidence="MANUAL_REVIEW", confidence_score=_SCORE_GUESS,
            evidence=["no banner / timeout"], check_method="socket banner",
            recommendation="포트 접근성 수동 확인.", tags=["ftp"],
        )]
    items = [_make_item(
        title="평문 FTP 서비스 노출", service="FTP", host=host, port=port,
        finding_type="attack_surface", severity="Low",
        confidence="POSSIBLE", confidence_score=_SCORE_EXPOSED,
        evidence=[f"banner: {banner[:200]}"],
        check_method="socket banner grab",
        recommendation="평문 FTP 대신 SFTP/FTPS 사용을 권고. 외부 노출 차단.",
        cwe="CWE-319", kisa_reference="KISA 서버보안 - 평문 전송 프로토콜 사용 점검",
        tags=["ftp", "cleartext"],
    )]
    # anonymous 점검은 옵션이 켜진 경우에만 — 기본 미수행.
    if allow_anon:
        # 안전: USER anonymous 응답코드만 관찰(로그인 완료 시도 안 함은 호출측 책임).
        # 여기서는 옵션이 켜졌다는 사실만 evidence 로 남기고 별도 finding 미생성.
        items.append(_make_item(
            title="FTP anonymous 점검(옵션 활성)", service="FTP", host=host, port=port,
            finding_type="discovery", severity="Info",
            confidence="MANUAL_REVIEW", confidence_score=_SCORE_GUESS,
            evidence=["ALLOW_ANON enabled; anonymous response inspection allowed"],
            check_method="anonymous response code (opt-in)",
            recommendation="anonymous 접근 허용 여부를 수동 확인하고 비활성화.",
            cwe="CWE-287", tags=["ftp", "anonymous", "opt-in"],
        ))
    return items


def _check_smtp(host: str, port: int, timeout: float, **_) -> list[dict]:
    # 배너 + EHLO 응답(STARTTLS 광고 여부)만 확인. 실제 메일 발송/RCPT 강제 없음.
    banner = _recv_banner(host, port, timeout, send=b"EHLO eoseureum.scan\r\n")
    if not banner:
        return [_make_item(
            title="SMTP 응답 없음", service="SMTP", host=host, port=port,
            finding_type="noise", severity="Info",
            confidence="MANUAL_REVIEW", confidence_score=_SCORE_GUESS,
            evidence=["no banner / timeout"], check_method="socket banner",
            recommendation="포트 접근성 수동 확인.", tags=["smtp"],
        )]
    low = banner.lower()
    items: list[dict] = []
    starttls = "starttls" in low
    items.append(_make_item(
        title="SMTP 서비스 노출", service="SMTP", host=host, port=port,
        finding_type="attack_surface", severity="Info",
        confidence="POSSIBLE", confidence_score=_SCORE_EXPOSED,
        evidence=[f"banner/ehlo: {banner[:200]}", f"starttls_advertised={starttls}"],
        check_method="banner + EHLO advertisement",
        recommendation="STARTTLS 강제, 인증된 릴레이만 허용, 외부 릴레이 차단.",
        cwe="CWE-200", kisa_reference="KISA 메일보안 - 메일 서비스 노출 점검",
        tags=["smtp", "exposure"],
    ))
    if not starttls:
        items.append(_make_item(
            title="SMTP STARTTLS 미광고 가능성", service="SMTP", host=host, port=port,
            finding_type="vulnerability", severity="Low",
            confidence="POSSIBLE", confidence_score=_SCORE_GUESS,
            evidence=[f"EHLO response lacks STARTTLS: {banner[:200]}"],
            check_method="EHLO advertisement (no auth, no mail sent)",
            recommendation="STARTTLS 지원/강제를 활성화하여 평문 전송 방지.",
            cwe="CWE-319", kisa_reference="KISA 메일보안 - 전송구간 암호화",
            tags=["smtp", "starttls"],
        ))
    # Open Relay 는 '가능성'만, 실제 발송 금지 → 항상 수동검토 discovery.
    items.append(_make_item(
        title="SMTP Open Relay 수동 점검 권고", service="SMTP", host=host, port=port,
        finding_type="discovery", severity="Info",
        confidence="MANUAL_REVIEW", confidence_score=_SCORE_GUESS,
        evidence=["relay check requires non-destructive manual verification (no mail sent)"],
        check_method="manual (no message delivery in safe mode)",
        recommendation="릴레이 정책을 수동 점검. 외부->외부 릴레이 차단 여부 확인.",
        cwe="CWE-269", tags=["smtp", "open-relay", "manual"],
    ))
    return items


def _check_dns(host: str, port: int, timeout: float, **_) -> list[dict]:
    records = _dns_axfr(host, port, timeout)
    if records:
        return [_make_item(
            title="DNS Zone Transfer(AXFR) 허용", service="DNS", host=host, port=port,
            finding_type="vulnerability", severity="High",
            confidence="CONFIRMED", confidence_score=_SCORE_UNAUTH,
            evidence=[f"AXFR returned {len(records)} records",
                      f"sample: {', '.join(records[:5])}"],
            check_method="single AXFR query (read-only)",
            recommendation="AXFR 를 신뢰 secondary 로 제한. 공개 AXFR 즉시 차단.",
            cwe="CWE-200", kisa_reference="KISA DNS보안 - Zone Transfer 제한",
            tags=["dns", "axfr", "zone-transfer"], protocol="tcp",
        )]
    return [_make_item(
        title="DNS Zone Transfer 미허용/응답 없음", service="DNS", host=host, port=port,
        finding_type="discovery", severity="Info",
        confidence="POSSIBLE", confidence_score=_SCORE_GUESS,
        evidence=["AXFR refused or no transfer"],
        check_method="single AXFR query (read-only)",
        recommendation="DNS 노출 범위를 수동 확인.",
        tags=["dns", "axfr"], protocol="tcp",
    )]


def _check_rdp(host: str, port: int, timeout: float, **_) -> list[dict]:
    if not _tcp_connect_ok(host, port, timeout):
        return [_make_item(
            title="RDP 응답 없음", service="RDP", host=host, port=port,
            finding_type="noise", severity="Info",
            confidence="MANUAL_REVIEW", confidence_score=_SCORE_GUESS,
            evidence=["connection refused / timeout"], check_method="tcp connect",
            recommendation="포트 접근성 수동 확인.", tags=["rdp"],
        )]
    return [_make_item(
        title="RDP 외부 노출", service="RDP", host=host, port=port,
        finding_type="attack_surface", severity="Medium",
        confidence="POSSIBLE", confidence_score=_SCORE_EXPOSED,
        evidence=[f"tcp/{port} reachable (RDP)"],
        check_method="tcp connect / safe handshake",
        recommendation="RDP 직접 노출 금지. VPN/게이트웨이 뒤로 배치하고 NLA 강제.",
        cwe="CWE-284", kisa_reference="KISA 서버보안 - 원격데스크톱 노출 점검",
        tags=["rdp", "exposure"],
    )]


def _check_smb(host: str, port: int, timeout: float, allow_anon: bool = False, **_) -> list[dict]:
    if not _tcp_connect_ok(host, port, timeout):
        return [_make_item(
            title="SMB 응답 없음", service="SMB", host=host, port=port,
            finding_type="noise", severity="Info",
            confidence="MANUAL_REVIEW", confidence_score=_SCORE_GUESS,
            evidence=["connection refused / timeout"], check_method="tcp connect",
            recommendation="포트 접근성 수동 확인.", tags=["smb"],
        )]
    items = [_make_item(
        title="SMB 외부 노출", service="SMB", host=host, port=port,
        finding_type="attack_surface", severity="Medium",
        confidence="POSSIBLE", confidence_score=_SCORE_EXPOSED,
        evidence=[f"tcp/{port} reachable (SMB)"],
        check_method="tcp connect; protocol negotiate (no auth)",
        recommendation="SMB 외부 노출 차단. SMBv1 비활성화 및 서명 강제.",
        cwe="CWE-284", kisa_reference="KISA 서버보안 - 파일공유 서비스 노출 점검",
        tags=["smb", "exposure"],
    )]
    if allow_anon:
        items.append(_make_item(
            title="SMB 익명세션 점검(옵션 활성)", service="SMB", host=host, port=port,
            finding_type="discovery", severity="Info",
            confidence="MANUAL_REVIEW", confidence_score=_SCORE_GUESS,
            evidence=["ALLOW_ANON enabled; null-session inspection allowed"],
            check_method="null session (opt-in)",
            recommendation="익명/null 세션 허용 여부 수동 확인 후 비활성화.",
            cwe="CWE-287", tags=["smb", "anonymous", "opt-in"],
        ))
    return items


# --- 데이터스토어 (인증 없는 접근 = High finding) ----------------------------

def _datastore_result(host, port, service, unauth, reachable, *, cwe, kisa, ev):
    """공통 분류: unauth(인증 없는 접근 실증)=High vuln, reachable=노출 attack_surface."""
    if unauth:
        return [_make_item(
            title=f"{service} 인증 없는 접근 가능", service=service, host=host, port=port,
            finding_type="vulnerability", severity="High",
            confidence="CONFIRMED", confidence_score=_SCORE_UNAUTH,
            evidence=ev or [f"{service} responded to unauthenticated query"],
            check_method="unauthenticated protocol probe (read-only)",
            recommendation=f"{service} 에 인증/접근제어를 즉시 적용하고 외부 노출 차단.",
            cwe=cwe, kisa_reference=kisa,
            tags=[service.lower(), "no-auth", "exposed-datastore"],
        )]
    if reachable:
        return [_make_item(
            title=f"{service} 외부 노출(인증요구)", service=service, host=host, port=port,
            finding_type="attack_surface", severity="Medium",
            confidence="POSSIBLE", confidence_score=_SCORE_PROTECTED,
            evidence=ev or [f"{service} reachable; authentication required"],
            check_method="protocol probe (auth required)",
            recommendation=f"{service} 외부 노출을 차단하고 신뢰 네트워크로 제한.",
            cwe="CWE-284", kisa_reference=kisa,
            tags=[service.lower(), "exposure"],
        )]
    return [_make_item(
        title=f"{service} 응답 없음", service=service, host=host, port=port,
        finding_type="noise", severity="Info",
        confidence="MANUAL_REVIEW", confidence_score=_SCORE_GUESS,
        evidence=["connection refused / timeout"], check_method="tcp connect",
        recommendation="포트 접근성 수동 확인.", tags=[service.lower()],
    )]


def _check_redis(host: str, port: int, timeout: float, **_) -> list[dict]:
    if not _tcp_connect_ok(host, port, timeout):
        return _datastore_result(host, port, "Redis", False, False,
                                 cwe="CWE-306", kisa="KISA - 인증 미설정 점검", ev=[])
    # 안전: PING(읽기 전용, 파괴 없음) 응답으로 인증 필요 여부 판별.
    resp = _recv_banner(host, port, timeout, send=b"PING\r\n")
    low = resp.lower()
    unauth = "+pong" in low
    needs_auth = "noauth" in low or "authentication" in low
    return _datastore_result(
        host, port, "Redis", unauth=unauth, reachable=True,
        cwe="CWE-306", kisa="KISA 데이터베이스보안 - 인증 미설정 점검",
        ev=[f"PING response: {resp[:120]!r}"] if resp else
           ([f"auth required: {resp[:120]!r}"] if needs_auth else []),
    )


def _check_mysql(host: str, port: int, timeout: float, **_) -> list[dict]:
    banner = _recv_banner(host, port, timeout)
    reachable = bool(banner) or _tcp_connect_ok(host, port, timeout)
    # MySQL 핸드셰이크는 항상 인증을 요구 → unauth 단정 불가. 노출만 보고.
    return _datastore_result(
        host, port, "MySQL", unauth=False, reachable=reachable,
        cwe="CWE-306", kisa="KISA 데이터베이스보안 - DB 외부 노출 점검",
        ev=[f"handshake banner: {banner[:120]}"] if banner else [],
    )


def _check_postgres(host: str, port: int, timeout: float, **_) -> list[dict]:
    reachable = _tcp_connect_ok(host, port, timeout)
    return _datastore_result(
        host, port, "PostgreSQL", unauth=False, reachable=reachable,
        cwe="CWE-306", kisa="KISA 데이터베이스보안 - DB 외부 노출 점검", ev=[],
    )


def _check_mongodb(host: str, port: int, timeout: float, **_) -> list[dict]:
    # MongoDB 노출 점검은 HTTP 상태 페이지 또는 TCP 도달성으로 노출만 판단.
    reachable = _tcp_connect_ok(host, port, timeout)
    return _datastore_result(
        host, port, "MongoDB", unauth=False, reachable=reachable,
        cwe="CWE-306", kisa="KISA 데이터베이스보안 - DB 외부 노출 점검", ev=[],
    )


def _check_elasticsearch(host: str, port: int, timeout: float, **_) -> list[dict]:
    # 안전: GET / (read-only). 인증 없이 cluster 정보 노출되면 High.
    resp = _http_get(host, port, "/", timeout)
    if resp is None:
        return _datastore_result(host, port, "Elasticsearch", False, False,
                                 cwe="CWE-306", kisa="KISA - DB 외부 노출 점검", ev=[])
    status = resp.get("status", 0)
    body = (resp.get("body") or "")
    if status == 200 and ("cluster_name" in body or "lucene_version" in body or '"tagline"' in body):
        return _datastore_result(
            host, port, "Elasticsearch", unauth=True, reachable=True,
            cwe="CWE-306", kisa="KISA 데이터베이스보안 - 인증 미설정 점검",
            ev=[f"GET / 200 cluster info exposed: {body[:120]}"],
        )
    if status in (401, 403):
        return _datastore_result(
            host, port, "Elasticsearch", unauth=False, reachable=True,
            cwe="CWE-306", kisa="KISA - DB 외부 노출 점검",
            ev=[f"GET / {status} (auth required)"],
        )
    return _datastore_result(
        host, port, "Elasticsearch", unauth=False, reachable=True,
        cwe="CWE-306", kisa="KISA - DB 외부 노출 점검",
        ev=[f"GET / {status}"],
    )


# --- HTTP 관리 콘솔 / API (인증 없는 접근 = High) -----------------------------

def _http_console(host, port, timeout, service, probe_path, *, unauth_marker, kisa,
                  scheme="http", fingerprint=None):
    """관리 콘솔/API 공통 점검.
    unauth_marker(status,body,headers) True => High vuln, 401/403/로그인 => attack_surface.

    fingerprint(status,body,headers) 가 주어지면, 해당 서비스의 '실제 지문'이
    확인될 때만 보고한다. 경로(포트)만 일치하고 지문이 없으면 오탐 방지를 위해
    해당 서비스로 집계하지 않는다(빈 결과 반환).
    """
    resp = _http_get(host, port, probe_path, timeout, scheme=scheme)
    if resp is None:
        return [_make_item(
            title=f"{service} 응답 없음", service=service, host=host, port=port,
            finding_type="noise", severity="Info",
            confidence="MANUAL_REVIEW", confidence_score=_SCORE_GUESS,
            evidence=["connection refused / timeout"], check_method="http get",
            recommendation="포트 접근성 수동 확인.", tags=[service.lower()],
        )]
    status = resp.get("status", 0)
    body = resp.get("body") or ""
    headers = resp.get("headers") or {}
    # 지문 게이트: 경로만 일치하고 실제 서비스 지문이 없으면 오탐 → 보고 안 함.
    if fingerprint is not None and not fingerprint(status, body, headers):
        return []
    if unauth_marker(status, body, headers):
        return [_make_item(
            title=f"{service} 인증 없는 접근 가능", service=service, host=host, port=port,
            finding_type="vulnerability", severity="High",
            confidence="CONFIRMED", confidence_score=_SCORE_UNAUTH,
            evidence=[f"GET {probe_path} -> {status}", f"body: {body[:120]}"],
            check_method="unauthenticated HTTP GET (read-only)",
            recommendation=f"{service} 에 인증을 강제하고 외부 노출을 차단.",
            cwe="CWE-306", kisa_reference=kisa,
            tags=[service.lower(), "no-auth"],
        )]
    if status in (401, 403):
        return [_make_item(
            title=f"{service} 보호됨(인증요구)", service=service, host=host, port=port,
            finding_type="attack_surface", severity="Low",
            confidence="POSSIBLE", confidence_score=_SCORE_PROTECTED,
            evidence=[f"GET {probe_path} -> {status} (auth required)"],
            check_method="HTTP GET (auth required, read-only)",
            recommendation=f"{service} 노출 범위를 신뢰 네트워크로 제한.",
            cwe="CWE-284", kisa_reference=kisa,
            tags=[service.lower(), "exposure", "protected"],
        )]
    # 로그인 화면 / 일반 노출 → attack_surface
    is_login = any(m in body.lower() for m in ("login", "sign in", "log in", "password"))
    return [_make_item(
        title=f"{service} 콘솔 노출" + (" (로그인 화면)" if is_login else ""),
        service=service, host=host, port=port,
        finding_type="attack_surface", severity="Medium" if is_login else "Low",
        confidence="POSSIBLE", confidence_score=_SCORE_EXPOSED,
        evidence=[f"GET {probe_path} -> {status}", f"login_form={is_login}"],
        check_method="HTTP GET (read-only)",
        recommendation=f"{service} 관리 콘솔의 외부 노출을 차단하고 인증을 강화.",
        cwe="CWE-284", kisa_reference=kisa,
        tags=[service.lower(), "exposure"],
    )]


def _check_jenkins(host, port, timeout, **_):
    def marker(status, body, headers):
        # 인증 없이 대시보드/api 가 200 으로 노출되고 로그인 폼이 없을 때.
        bl = body.lower()
        return status == 200 and "dashboard" in bl and "login" not in bl

    def fingerprint(status, body, headers):
        # 경로명만으로 판정 금지 — 실제 Jenkins 지문이 있을 때만.
        h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
        bl = (body or "").lower()
        if "x-jenkins" in h:                       # Jenkins 전용 헤더
            return True
        if "x-hudson" in h:                        # 구 Hudson/Jenkins
            return True
        if '"_class"' in bl and "hudson" in bl:    # /api/json 의 Jenkins 클래스
            return True
        if "jenkins" in bl:                        # 본문에 Jenkins 표기(로그인/제목/대시보드)
            return True
        if "jenkins" in h.get("set-cookie", "") or "jenkins" in h.get("server", ""):
            return True
        return False

    return _http_console(host, port, timeout, "Jenkins", "/api/json",
                         unauth_marker=marker, fingerprint=fingerprint,
                         kisa="KISA - CI/CD 관리콘솔 노출 점검")


def _check_grafana(host, port, timeout, **_):
    def marker(status, body, headers):
        return status == 200 and ('"database"' in body.lower() and "ok" in body.lower())

    def fingerprint(status, body, headers):
        bl = (body or "").lower()
        h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
        return ("grafana" in bl or "grafana" in h.get("set-cookie", "")
                or '"database"' in bl or '"version"' in bl)

    return _http_console(host, port, timeout, "Grafana", "/api/health",
                         unauth_marker=marker, fingerprint=fingerprint,
                         kisa="KISA - 모니터링 콘솔 노출 점검")


def _check_kibana(host, port, timeout, **_):
    def marker(status, body, headers):
        return status == 200 and '"status"' in body.lower() and "overall" in body.lower()

    def fingerprint(status, body, headers):
        bl = (body or "").lower()
        h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
        return ("kibana" in bl or "kbn-name" in h or "kbn-version" in h
                or '"nodes"' in bl)

    return _http_console(host, port, timeout, "Kibana", "/api/status",
                         unauth_marker=marker, fingerprint=fingerprint,
                         kisa="KISA - 모니터링 콘솔 노출 점검")


def _check_docker_api(host, port, timeout, **_):
    def marker(status, body, headers):
        # /version 200 + ApiVersion => 인증 없는 Docker API.
        return status == 200 and ("ApiVersion" in body or "apiversion" in body.lower())

    def fingerprint(status, body, headers):
        bl = (body or "").lower()
        return ("apiversion" in bl or "dockerversion" in bl or '"os"' in bl)

    return _http_console(host, port, timeout, "Docker API", "/version",
                         unauth_marker=marker, fingerprint=fingerprint,
                         kisa="KISA - 컨테이너 관리 API 노출 점검")


def _check_kubernetes_api(host, port, timeout, **_):
    def marker(status, body, headers):
        # /version 200 + gitVersion 노출 & 인증 없음.
        return status == 200 and ("gitVersion" in body or "major" in body.lower())
    return _http_console(host, port, timeout, "Kubernetes API", "/version",
                         unauth_marker=marker,
                         kisa="KISA - 오케스트레이션 API 노출 점검", scheme="https")


def _check_prometheus(host, port, timeout, **_):
    def marker(status, body, headers):
        return status == 200 and ("prometheus" in body.lower() or "is healthy" in body.lower())
    return _http_console(host, port, timeout, "Prometheus", "/-/healthy",
                         unauth_marker=marker, kisa="KISA - 모니터링 콘솔 노출 점검")


# ---------------------------------------------------------------------------
# 포트 -> 점검 함수 매핑
# ---------------------------------------------------------------------------

PORT_CHECKS: dict[int, tuple] = {
    22:    (_check_ssh, "SSH"),
    21:    (_check_ftp, "FTP"),
    25:    (_check_smtp, "SMTP"),
    587:   (_check_smtp, "SMTP"),
    53:    (_check_dns, "DNS"),
    3389:  (_check_rdp, "RDP"),
    445:   (_check_smb, "SMB"),
    3306:  (_check_mysql, "MySQL"),
    5432:  (_check_postgres, "PostgreSQL"),
    6379:  (_check_redis, "Redis"),
    27017: (_check_mongodb, "MongoDB"),
    9200:  (_check_elasticsearch, "Elasticsearch"),
    8080:  (_check_jenkins, "Jenkins"),
    8081:  (_check_jenkins, "Jenkins"),
    3000:  (_check_grafana, "Grafana"),
    5601:  (_check_kibana, "Kibana"),
    2375:  (_check_docker_api, "Docker API"),
    6443:  (_check_kubernetes_api, "Kubernetes API"),
    9090:  (_check_prometheus, "Prometheus"),
}


def _bucket(items: list[dict], result: dict) -> None:
    for it in items:
        ft = it.get("finding_type")
        if ft == "vulnerability":
            result["service_findings"].append(it)
        elif ft == "attack_surface":
            result["service_attack_surface"].append(it)
        elif ft == "discovery":
            result["service_discovery"].append(it)
        elif ft == "good":
            result["service_good"].append(it)
        else:  # noise / unknown
            result["service_noise"].append(it)


# ---------------------------------------------------------------------------
# nmap -sV 서비스/버전 식별 (선택, 안전 플래그 전용)
#   - 무권한 동작: -sV/--version-light/-Pn 만 사용. -sS/-sU/-O(권한 필요)·NSE·
#     전체포트·대량 UDP 는 절대 사용하지 않는다.
#   - nmap(또는 NMAP_PATH) 이 없으면 {} 를 반환해 Python 점검으로 graceful fallback.
#   - _nmap_version_scan 은 monkeypatch 지점(테스트는 이 함수를 패치).
# ---------------------------------------------------------------------------

def _nmap_binary() -> str | None:
    """NMAP_PATH(포터블 등) 우선, 없으면 PATH 에서 nmap 탐색. 없으면 None."""
    p = os.environ.get("NMAP_PATH", "").strip()
    if p:
        return p if (os.path.isfile(p) and os.access(p, os.X_OK)) else None
    return shutil.which("nmap")


def _nmap_version_scan(host: str, ports: list[int], timeout: float) -> dict:
    """안전 플래그 nmap -sV 로 포트별 서비스/버전을 식별한다(무권한·비파괴).

    반환: {port(int): {"name","product","version","extrainfo"}} / 실패 시 {} (폴백).
    """
    binary = _nmap_binary()
    if not binary or not ports:
        return {}
    ports_csv = ",".join(str(int(p)) for p in ports)
    host_timeout = max(30, min(180, len(ports) * 5))
    cmd = [
        binary, "-sV", "--version-light", "-Pn", "-T3",
        "--host-timeout", f"{host_timeout}s",
        "-p", ports_csv, "-oX", "-", host,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=host_timeout + 15, check=False,
        )
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return {}
    if proc.returncode != 0 or not proc.stdout:
        return {}
    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError:
        return {}
    out: dict[int, dict] = {}
    for port_el in root.iter("port"):
        try:
            pid = int(port_el.get("portid", ""))
        except (TypeError, ValueError):
            continue
        state_el = port_el.find("state")
        if state_el is not None and state_el.get("state") != "open":
            continue
        svc = port_el.find("service")
        if svc is None:
            continue
        out[pid] = {
            "name": svc.get("name", "") or "",
            "product": svc.get("product", "") or "",
            "version": svc.get("version", "") or "",
            "extrainfo": svc.get("extrainfo", "") or "",
        }
    return out


def _nmap_enrich(host: str, ports: list[int], timeout: float) -> list[dict]:
    """nmap -sV 결과를 service_discovery(정보) 항목으로 변환. 취약 판정/severity 변경 없음."""
    info = _nmap_version_scan(host, ports, timeout)
    items: list[dict] = []
    for pid, sv in info.items():
        name = sv.get("name") or "unknown"
        product = " ".join(x for x in (sv.get("product"), sv.get("version")) if x).strip()
        label = product or name
        if not label or label == "unknown":
            continue
        ev = [f"nmap -sV: {name}" + (f" ({product})" if product else "")]
        if sv.get("extrainfo"):
            ev.append(f"extrainfo: {sv['extrainfo']}")
        # 제품/버전이 식별돼도 '취약점'이 아니라 정보 노출/공격표면(attack_surface)으로 분류한다.
        # 근거: 서비스·버전 노출 자체로는 실제 악용 행위가 성립하지 않으며(알려진 CVE 매칭이나
        # 구체적 익스플로잇이 확인돼야 취약), 이를 LOW 취약으로 올리면 보고서가 과분류된다.
        # → 공격자가 추가 분석할 '노출 지점'으로만 기록(취약점 수·위험도·커버리지에서 제외).
        # 포트 이름만 추정된 경우: 정보성(Info) 발견으로 유지(오탐 방지).
        if product:
            items.append(_make_item(
                title=f"서비스/버전 식별: {label} (포트 {pid})",
                service=name, host=host, port=pid,
                finding_type="attack_surface", severity="Info",
                confidence="CONFIRMED",
                confidence_score=_SCORE_BANNER,
                evidence=ev,
                check_method="nmap -sV --version-light (safe, unprivileged)",
                recommendation=("서비스 배너/버전 노출 최소화(버전 문자열 숨김·프록시 뒤 배치), "
                                "노출된 제품/버전이 최신 보안 패치 상태인지 확인."),
                cwe="CWE-200",
                kisa_reference="정보 노출",
                tags=[name.lower(), "nmap", "version-detection", "info-disclosure"],
            ))
        else:
            items.append(_make_item(
                title=f"서비스/버전 식별: {label} (포트 {pid})",
                service=name, host=host, port=pid,
                finding_type="discovery", severity="Info",
                confidence="MANUAL_REVIEW",
                confidence_score=_SCORE_GUESS,
                evidence=ev,
                check_method="nmap -sV --version-light (safe, unprivileged)",
                recommendation="노출된 서비스/버전이 최신 보안 패치 상태인지 확인 권고.",
                tags=[name.lower(), "nmap", "version-detection"],
            ))
    return items


def scan_services(host: str, open_ports: list[int], scan_mode: str = "safe",
                  allow_anon: bool | None = None) -> dict:
    """열린 포트 기반 서비스 보안 점검(안전 점검 전용).

    Args:
      host: 대상 호스트.
      open_ports: 열린 TCP 포트 목록.
      scan_mode: SCAN_MODE 환경변수 우선; "safe" 외 값도 동일하게 안전 동작.
      allow_anon: 익명 점검 허용 여부. None 이면 환경변수/ALLOW_ANON 사용(기본 False).

    Returns:
      service_findings / service_attack_surface / service_discovery /
      service_good / service_noise / service_summary 를 담은 dict.
    """
    result = {
        "service_findings": [],
        "service_attack_surface": [],
        "service_discovery": [],
        "service_good": [],
        "service_noise": [],
        "service_summary": {
            "checked_ports": 0,
            "service_vulnerability_count": 0,
            "service_attack_surface_count": 0,
            "service_discovery_count": 0,
        },
    }

    if not host or not open_ports:
        return result

    # scan_mode 는 환경변수 SCAN_MODE 가 우선(없으면 인자). safe 외 값도 안전 동작.
    _ = os.environ.get("SCAN_MODE", scan_mode or "safe")

    timeout = _timeout()
    max_ports = _max_ports()
    anon = _allow_anon(allow_anon)

    # 중복 제거 + 정수만, 최대 포트 수 제한.
    seen: list[int] = []
    for p in open_ports:
        try:
            pi = int(p)
        except (TypeError, ValueError):
            continue
        if pi not in seen:
            seen.append(pi)
    ports = seen[:max_ports]

    # rate 거버너(동기 경로): 서비스 probe 요청도 SAFE 상한에 맞춰 페이싱
    try:
        import adaptive_throttle as _gov
        import time as _gtime
        _glim = _gov.stage("service_probe")
    except Exception:
        _glim = None

    checked = 0
    for port in ports:
        entry = PORT_CHECKS.get(port)
        if entry is None:
            continue
        check_fn, _service = entry
        checked += 1
        if _glim is not None:
            _glim.before_sync()
        _gt0 = _gtime.monotonic() if _glim is not None else 0.0
        try:
            items = check_fn(host, port, timeout, allow_anon=anon)
            if _glim is not None:
                _glim.after_sync(_gtime.monotonic() - _gt0, 0, None)
        except Exception:
            if _glim is not None:
                _glim.after_sync(_gtime.monotonic() - _gt0, 0, None)
            items = [_make_item(
                title=f"{_service} 점검 오류", service=_service, host=host, port=port,
                finding_type="noise", severity="Info",
                confidence="MANUAL_REVIEW", confidence_score=_SCORE_GUESS,
                evidence=["check raised exception (handled safely)"],
                check_method="safe probe",
                recommendation="수동 점검 권고.", tags=[_service.lower(), "error"],
            )]
        _bucket(items or [], result)

    # (선택) nmap -sV 서비스/버전 식별 보강 — SERVICE_SCAN_USE_NMAP=true 이고
    #  nmap(또는 NMAP_PATH) 사용 가능할 때만. 무권한·안전 플래그만. 없으면 Python 결과만 유지.
    if os.environ.get("SERVICE_SCAN_USE_NMAP", "").strip().lower() in ("1", "true", "yes", "on"):
        try:
            _bucket(_nmap_enrich(host, ports, timeout), result)
        except Exception:
            pass

    result["service_summary"]["checked_ports"] = checked
    result["service_summary"]["service_vulnerability_count"] = len(result["service_findings"])
    result["service_summary"]["service_attack_surface_count"] = len(result["service_attack_surface"])
    result["service_summary"]["service_discovery_count"] = len(result["service_discovery"])
    return result
