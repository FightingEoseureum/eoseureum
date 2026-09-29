import asyncio
import socket
import ssl
import re
import time as _gtime
import uuid
from datetime import datetime

import aiohttp

import adaptive_throttle as _gov   # rate 거버너(미설치/PROOF 시 no-op)


async def _gov_before(stage: str):
    """거버너 통과 대기. 반환 (limiter, t0). 미설치면 (None, t0)."""
    g = _gov.stage(stage)
    if g is not None:
        await g.before()
    return g, _gtime.monotonic()


def _gov_after(gt, status: int = 0):
    g, t0 = gt
    if g is not None:
        g.after(_gtime.monotonic() - t0, status, None)

# 실제 공격에 활용되는 고위험 포트만 선별
HIGH_RISK_PORTS = [
    # 원격 접근 / 관리
    21, 22, 23, 3389, 5900,
    # 웹 서비스
    80, 443, 8080, 8443, 8888, 8000, 8008,
    # 데이터베이스 (무인증 접근 위험)
    3306, 5432, 1433, 1521, 27017, 6379, 11211, 9200,
    # 컨테이너 / 인프라
    2375, 6443, 10250, 2181,
    # 메시지큐 / 모니터링
    15672, 5672, 9090, 9092,
    # 네트워크 서비스
    445, 25, 53,
]

# 심층 스캔 시 추가되는 포트 (웹 서비스 확장)
EXTENDED_PORTS = HIGH_RISK_PORTS + [
    8001, 8002, 8003, 8005, 8009, 8010, 8020, 8081, 8090, 8091,
    8100, 8500, 9000, 9001, 9003, 9080, 9300, 10000, 10443,
    4848, 4369, 28017,
]

# 하위 호환성
COMMON_PORTS = HIGH_RISK_PORTS


def parse_target(raw: str) -> dict:
    """스캔 대상 문자열에서 host/port/scheme 을 분리한다.
    지원: 'host', 'host:port', 'http://host:port/path', 'https://host:port'.
    명시 포트가 있으면 포트스캔을 건너뛰고 그 포트를 직접 점검 대상으로 쓰기 위함."""
    import urllib.parse as _up
    s = (raw or "").strip()
    scheme = None
    if "://" in s:
        u = _up.urlparse(s)
        scheme = (u.scheme or "").lower() or None
        host = u.hostname or ""
        port = u.port
    else:
        # host[:port][/path]
        s = s.split("/", 1)[0]
        host, port = s, None
        if s.count(":") == 1:                       # IPv6 아닌 host:port
            h, _, p = s.partition(":")
            if p.isdigit():
                host, port = h, int(p)
    if scheme is None and port is not None:
        scheme = "https" if port in (443, 8443) else "http"
    return {"host": host, "port": port, "scheme": scheme}

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/admin",
    "/admin/login",
    "/administrator",
    "/api",
    "/api/v1",
    "/api/v2",
    "/config",
    "/config.php",
    "/phpinfo.php",
    "/info.php",
    "/robots.txt",
    "/.htaccess",
    "/wp-admin/",
    "/wp-config.php",
    "/server-status",
    "/server-info",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/beans",
    "/debug",
    "/console",
    "/.well-known/security.txt",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/api-docs",
    "/v1/api-docs",
    "/openapi.json",
    "/graphql",
    "/metrics",
    "/health",
    "/status",
    "/backup",
    "/dump",
    "/test",
]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9200: "Elasticsearch",
    27017: "MongoDB", 11211: "Memcached", 1433: "MSSQL", 1521: "Oracle",
    2375: "Docker", 4848: "GlassFish", 9090: "Prometheus",
    15672: "RabbitMQ-Mgmt", 6443: "Kubernetes", 10250: "Kubelet",
    5672: "AMQP", 9092: "Kafka", 2181: "ZooKeeper",
}


async def discover_subdomains(domain: str) -> list[dict]:
    subdomains = set()
    subdomains.add(domain)
    subdomains.add(f"www.{domain}")

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    for entry in data:
                        names = entry.get("name_value", "")
                        for name in names.split("\n"):
                            name = name.strip().lstrip("*.")
                            if name.endswith(f".{domain}") or name == domain:
                                subdomains.add(name)
    except Exception:
        pass

    results = []
    for sub in list(subdomains)[:30]:
        try:
            ip = socket.gethostbyname(sub)
            results.append({"subdomain": sub, "ip": ip, "resolved": True})
        except Exception:
            results.append({"subdomain": sub, "ip": None, "resolved": False})

    return [r for r in results if r["resolved"]]


async def scan_port(host: str, port: int, timeout: float = 4.0) -> bool:
    # 포트스캔 raw TCP connect 도 rate 거버너에 태운다(SAFE: 31~50 동시 버스트 → 합산 상한 내로 페이싱)
    _gt = await _gov_before("port_scan")
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        _gov_after(_gt, 1)
        return True
    except Exception:
        _gov_after(_gt, 0)
        return False


async def grab_banner(host: str, port: int, timeout: float = 3.0) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        try:
            banner = await asyncio.wait_for(reader.read(512), timeout=timeout)
            writer.close()
            return banner.decode("utf-8", errors="ignore").strip()
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return None


def _parse_cookie_flags(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=")[0].strip() if parts else ""
    flags_lower = {p.lower() for p in parts[1:]}
    samesite = None
    for f in flags_lower:
        if f.startswith("samesite="):
            samesite = f.split("=", 1)[1]
    return {
        "name": name,
        "httponly": any(f == "httponly" for f in flags_lower),
        "secure": any(f == "secure" for f in flags_lower),
        "samesite": samesite,
        "raw": raw[:200],
    }


async def detect_http_service(host: str, port: int, use_ssl: bool) -> dict:
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{host}:{port}"
    info: dict = {
        "url": url, "status": None, "title": None, "server": None, "headers": {},
        "cookies": [], "directory_indexing": False, "redirects_to_https": False,
    }

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_ctx)

    _gt = await _gov_before("service_probe")
    _gt_status = 0
    try:
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=5),
        ) as session:
            async with session.get(url, allow_redirects=True) as resp:
                _gt_status = resp.status
                info["status"] = resp.status
                info["server"] = resp.headers.get("Server", "")
                info["x_powered_by"] = resp.headers.get("X-Powered-By", "")
                info["headers"] = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() in [
                        "server", "x-powered-by", "x-frame-options",
                        "content-security-policy", "strict-transport-security",
                        "x-content-type-options", "x-xss-protection",
                    ]
                }
                info["cookies"] = [_parse_cookie_flags(c) for c in resp.headers.getall("Set-Cookie", [])]
                # Detect redirect to HTTPS (for http_plaintext rule)
                if not use_ssl:
                    info["redirects_to_https"] = str(resp.url).startswith("https://")
                text = await resp.text(errors="ignore")
                match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                if match:
                    info["title"] = match.group(1).strip()[:100]
                if "Index of /" in text or "Directory listing for /" in text:
                    info["directory_indexing"] = True
                # 로그인 폼 존재 여부 (HTTP 평문 전송 취약점의 실질적 위험 판단용)
                info["has_login_form"] = bool(
                    re.search(r'<input[^>]+type=["\']password["\']', text, re.IGNORECASE) or
                    re.search(r'<form[^>]*action=[^>]*(login|signin|auth|logon)', text, re.IGNORECASE)
                )
    except Exception as e:
        info["error"] = str(e)
    finally:
        _gov_after(_gt, _gt_status)

    return info


# DB 엔진별 오류 메시지 시그니처(범용 — DBMS 종류·SQL 구문 오류가 응답에 그대로 노출되면 정보노출).
# 특정 대상(DVWA)에 국한하지 않고 널리 쓰이는 DBMS 오류 문구를 포괄한다.
_DB_ERROR_RE = re.compile(
    r"(You have an error in your SQL syntax|"
    r"(?:MySQL|MariaDB)\s+server\s+version|mysql_fetch|supplied argument is not a valid MySQL|"
    r"Warning:\s*mysqli?_|com\.mysql\.jdbc|"
    r"PostgreSQL.*(?:ERROR|error)|pg_query\(|PG::\w+Error|org\.postgresql\.util\.PSQLException|"
    r"Microsoft SQL Server|ODBC SQL Server Driver|Unclosed quotation mark|"
    r"System\.Data\.SqlClient\.SqlException|"
    r"ORA-[0-9]{4,5}|Oracle error|quoted string not properly terminated|"
    r"SQLite3?::|sqlite_error|SQLITE_ERROR|"
    r"SQLException|SQLSTATE\[|java\.sql\.SQLException|near \"[^\"]*\": syntax error)",
    re.IGNORECASE,
)


def _detect_error_page_leaks(body: str, status: int) -> dict | None:
    leaks = []
    if re.search(r"Traceback \(most recent call last\)|at \w+\.\w+\(.*\.java:\d+\)|NestJS|Exception in thread", body):
        leaks.append("stack_trace")
    if re.search(r"(Apache|nginx|IIS|PHP|Python|Django|Rails|Express|Spring|Tomcat|Node\.js)[/\s]+[\d.]+", body, re.IGNORECASE):
        leaks.append("version_in_body")
    if re.search(r"(/var/www|/usr/local|/home/\w+|C:\\inetpub|C:\\Users)", body, re.IGNORECASE):
        leaks.append("path_disclosure")
    if _DB_ERROR_RE.search(body or ""):
        leaks.append("db_error")   # DB 엔진 오류 메시지 노출 → DBMS 종류·구조 힌트 제공(CWE-209)
    # version_in_body(프레임워크/서버 시그니처)만 노출된 경우는 Server 응답 헤더 노출과 동일 정보라
    # 별도 '에러페이지 정보노출' finding 으로 올리면 중복 노이즈가 된다(사용자 지침: 실증 or 폐기).
    # 실증적 노출(스택트레이스·DB 오류 메시지·내부 경로)이 하나라도 있어야 finding 으로 인정한다.
    _SUBSTANTIVE = {"stack_trace", "db_error", "path_disclosure"}
    if not (set(leaks) & _SUBSTANTIVE):
        return None
    return {"leaks": leaks, "status_code": status}


async def _verify_dangerous_methods(session, scheme, host, port, allowed_methods) -> list:
    """
    Allow 헤더에 나열된 위험 메서드를 실제로 호출해 '진짜로 활성화'된 것만 가려낸다.
    - PUT/DELETE/PATCH: 무해한 임의 경로에 요청 → 2xx(처리됨)만 활성화로 인정.
      403/405/501/401/400/404 등 거부 응답은 비활성으로 간주(오탐 제거).
    - TRACE: 요청이 응답에 그대로 반사(XST)될 때만 활성화로 인정.
    안전 제약: 임의의 존재하지 않는 경로만 대상으로 하며 실제 리소스를 변경/삭제하지 않는다.
    """
    DANGEROUS = {"PUT", "DELETE", "TRACE", "PATCH"}
    advertised = {m.strip().upper() for m in (allowed_methods or [])}
    targets = DANGEROUS & advertised
    if not targets:
        return []

    verified = []
    token = uuid.uuid4().hex[:12]
    probe_path = f"/scanner_method_probe_{token}.txt"

    for method in sorted(targets):
        try:
            if method == "TRACE":
                async with session.request(
                    "TRACE", f"{scheme}://{host}:{port}/", allow_redirects=False
                ) as r:
                    if r.status == 200:
                        body = (await r.text(errors="ignore"))[:500].upper()
                        # TRACE 응답 본문에 요청 라인이 그대로 반사되면 실제 활성화(XST)
                        if "TRACE /" in body or "TRACE HTTP" in body:
                            verified.append("TRACE")
            else:
                kwargs = {"allow_redirects": False}
                if method in ("PUT", "PATCH"):
                    kwargs["data"] = b"scanner-probe"
                async with session.request(
                    method, f"{scheme}://{host}:{port}{probe_path}", **kwargs
                ) as r:
                    if r.status in (200, 201, 204, 207):
                        verified.append(method)
        except Exception:
            pass

    return verified


async def probe_http_extras(host: str, port: int, use_ssl: bool) -> dict:
    """OPTIONS request (allowed methods) + 404 error page leak probe."""
    scheme = "https" if use_ssl else "http"
    result: dict = {"allowed_methods": [], "verified_dangerous_methods": [], "error_page_info": None}

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_ctx)

    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=5)) as session:
        try:
            async with session.options(f"{scheme}://{host}:{port}/", allow_redirects=False) as resp:
                allow = resp.headers.get("Allow", "")
                if allow:
                    result["allowed_methods"] = [m.strip() for m in allow.split(",") if m.strip()]
        except Exception:
            pass

        # Allow 헤더에 광고된 위험 메서드를 실제로 호출해 동작 여부를 검증한다.
        # (OPTIONS의 Allow 목록은 Tomcat 등에서 실제 비활성 메서드까지 나열하므로 오탐의 주원인)
        result["verified_dangerous_methods"] = await _verify_dangerous_methods(
            session, scheme, host, port, result["allowed_methods"]
        )

        try:
            async with session.get(
                f"{scheme}://{host}:{port}/xk9q2m7_scanner_probe_404",
                allow_redirects=False,
            ) as resp:
                if resp.status in (400, 403, 404, 500):
                    body = await resp.text(errors="ignore")
                    ei = _detect_error_page_leaks(body, resp.status)
                    if ei:
                        result["error_page_info"] = ei
        except Exception:
            pass

    return result


def get_ssl_info(host: str, port: int) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        not_after = None
        days_left = None
        if cert and "notAfter" in cert:
            not_after_str = cert["notAfter"]
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.utcnow()).days
            except Exception:
                pass

        subject = {}
        if cert and "subject" in cert:
            for item in cert.get("subject", []):
                subject.update(dict(item))

        return {
            "valid": True,
            "version": version,
            "cipher": cipher[0] if cipher else None,
            "not_after": not_after.isoformat() if not_after else None,
            "days_until_expiry": days_left,
            "subject": subject,
            "expired": days_left < 0 if days_left is not None else None,
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


async def probe_http_paths(host: str, port: int, use_ssl: bool) -> list[dict]:
    scheme = "https" if use_ssl else "http"
    found = []

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_ctx)

    sem = asyncio.Semaphore(10)

    async def check_path(session, path):
        async with sem:
            # 민감경로 probe(웹포트당 10동시)도 rate 거버너에 태운다
            _gt = await _gov_before("path_probe")
            _gt_status = 0
            try:
                url = f"{scheme}://{host}:{port}{path}"
                async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    _gt_status = resp.status
                    if resp.status not in (404, 410):
                        result = {
                            "path": path,
                            "status": resp.status,
                            "content_length": resp.headers.get("Content-Length", ""),
                        }
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            clean = re.sub(r"<[^>]+>", " ", body).strip()
                            clean = re.sub(r"\s+", " ", clean)
                            result["body_preview"] = clean[:400] if clean else body[:400]
                        return result
            except Exception:
                pass
            finally:
                _gov_after(_gt, _gt_status)
            return None

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_path(session, p) for p in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks)

    return [r for r in results if r is not None]


async def probe_port_vuln(host: str, ip: str, port: int, banner: str | None) -> dict | None:
    """
    포트별 취약점 실증 점검.
    실제 서버 응답 데이터(명령 실행 결과, API 응답, 로그인 성공 코드 등)가
    확인된 경우에만 취약점으로 보고합니다. 포트 개방 자체만으로는 보고하지 않습니다.
    """
    b = (banner or "").lower()

    # Telnet (23) - 배너가 실제로 수신된 경우만 보고 (연결 + 데이터 수신 확인)
    if port == 23:
        if not banner:
            return None
        return {
            "vulnerable": True,
            "reason": "Telnet 서비스가 응답합니다. 모든 통신이 평문으로 전송됩니다.",
            "evidence": f"Telnet 연결 성공, 서버 배너 수신:\n{banner[:200]}",
            "recommendation": "Telnet을 비활성화하고 SSH로 대체하세요.",
        }

    # FTP (21) - 익명 로그인 230 성공 응답이 있을 때만 보고
    if port == 21:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 21), timeout=4)
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            resp1 = (await asyncio.wait_for(reader.read(256), timeout=3)).decode("utf-8", errors="ignore")
            writer.write(b"PASS anonymous@\r\n")
            await writer.drain()
            resp2 = (await asyncio.wait_for(reader.read(256), timeout=3)).decode("utf-8", errors="ignore")
            writer.close()
            if "230" in resp2:
                return {
                    "vulnerable": True,
                    "reason": "FTP 익명(Anonymous) 로그인이 허용됩니다.",
                    "evidence": (
                        f"명령: USER anonymous\n응답: {resp1.strip()[:100]}\n"
                        f"명령: PASS anonymous@\n응답: {resp2.strip()[:100]}\n"
                        f"→ 230(로그인 성공) 응답으로 인증 없이 접속 확인됨"
                    ),
                    "recommendation": "FTP 익명 로그인을 비활성화하고, SFTP/FTPS로 전환하세요.",
                }
        except Exception:
            pass
        return None  # 익명 로그인이 실패하면 보고하지 않음

    # Redis (6379) - PING → +PONG 실제 응답 확인
    if port == 6379:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=4)
            writer.write(b"PING\r\n")
            await writer.drain()
            resp = (await asyncio.wait_for(reader.read(128), timeout=3)).decode("utf-8", errors="ignore")
            writer.close()
            if "+PONG" in resp:
                return {
                    "vulnerable": True,
                    "reason": "Redis가 인증 없이 명령 실행이 가능합니다.",
                    "evidence": f"명령: PING\n응답: {resp.strip()[:80]}\n→ 인증 없이 Redis 명령 실행 확인됨",
                    "recommendation": "requirepass 설정으로 Redis 인증을 활성화하고, bind 설정으로 외부 접근을 차단하세요.",
                }
        except Exception:
            pass
        return None

    # Docker API (2375) - /version JSON 데이터 실제 수신 확인
    if port == 2375:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.get(f"http://{ip}:2375/version") as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        ver = data.get("Version", "알 수 없음")
                        os_info = data.get("Os", "")
                        arch = data.get("Arch", "")
                        return {
                            "vulnerable": True,
                            "reason": "Docker 데몬 API가 인증 없이 외부에 노출되어 있습니다.",
                            "evidence": (
                                f"GET http://{host}:2375/version → HTTP 200\n"
                                f"Docker Version: {ver}, OS: {os_info}, Arch: {arch}\n"
                                f"→ 인증 없이 Docker API 접근 및 실제 버전 정보 획득됨"
                            ),
                            "recommendation": "Docker 데몬을 TLS 인증 없이 0.0.0.0에 바인딩하지 마세요. Unix 소켓만 사용하거나 TLS 클라이언트 인증을 적용하세요.",
                        }
        except Exception:
            pass
        return None

    # Elasticsearch (9200) - 클러스터 정보 JSON 실제 수신 확인
    if port == 9200:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.get(f"http://{ip}:9200/") as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        cluster = data.get("cluster_name", "")
                        name = data.get("name", "")
                        version = (data.get("version") or {}).get("number", "")
                        return {
                            "vulnerable": True,
                            "reason": "Elasticsearch가 인증 없이 클러스터 정보를 노출합니다.",
                            "evidence": (
                                f"GET http://{host}:9200/ → HTTP 200\n"
                                f"cluster_name: {cluster}, node: {name}, version: {version}\n"
                                f"→ 인증 없이 Elasticsearch 클러스터 정보 획득됨"
                            ),
                            "recommendation": "Elasticsearch X-Pack 보안 기능을 활성화하거나, 방화벽으로 내부망 접근만 허용하세요.",
                        }
        except Exception:
            pass
        return None

    # MongoDB (27017) - 실제 MongoDB 배너(greeting) 수신된 경우만
    if port == 27017:
        if banner and len(banner) > 5:
            return {
                "vulnerable": True,
                "reason": "MongoDB가 외부에서 접근 가능하며 서버 응답을 반환합니다.",
                "evidence": f"MongoDB 연결 성공, 서버 응답 수신:\n{banner[:200]}",
                "recommendation": "MongoDB 인증(--auth)을 활성화하고 bind_ip를 localhost로 제한하세요.",
            }
        return None

    # Memcached (11211) - stats 명령 STAT 응답 실제 수신 확인
    if port == 11211:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=4)
            writer.write(b"stats\r\n")
            await writer.drain()
            resp = (await asyncio.wait_for(reader.read(512), timeout=3)).decode("utf-8", errors="ignore")
            writer.close()
            if "STAT" in resp:
                return {
                    "vulnerable": True,
                    "reason": "Memcached가 인증 없이 통계 명령에 응답합니다.",
                    "evidence": f"명령: stats\n응답 (일부):\n{resp[:200].strip()}\n→ 인증 없이 Memcached 서버 정보 획득됨",
                    "recommendation": "Memcached를 localhost에만 바인딩하고, 방화벽으로 외부 접근을 차단하세요.",
                }
        except Exception:
            pass
        return None

    # ZooKeeper (2181) - srvr 명령 응답 실제 수신 확인
    if port == 2181:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=4)
            writer.write(b"srvr\r\n")
            await writer.drain()
            resp = (await asyncio.wait_for(reader.read(256), timeout=3)).decode("utf-8", errors="ignore")
            writer.close()
            if "Zookeeper" in resp or "version" in resp.lower():
                return {
                    "vulnerable": True,
                    "reason": "ZooKeeper가 인증 없이 서버 정보를 노출합니다.",
                    "evidence": f"명령: srvr\n응답:\n{resp[:200].strip()}\n→ 인증 없이 ZooKeeper 서버 정보 획득됨",
                    "recommendation": "ZooKeeper에 SASL 인증을 적용하고 방화벽으로 외부 접근을 차단하세요.",
                }
        except Exception:
            pass
        return None

    # MySQL (3306) - 실제 MySQL 핸드셰이크 배너 수신된 경우만
    if port == 3306:
        if banner and ("mysql" in b or "mariadb" in b or len(banner) > 10):
            return {
                "vulnerable": True,
                "reason": "MySQL/MariaDB 데이터베이스가 인터넷에 직접 노출되어 있습니다.",
                "evidence": f"MySQL 연결 성공, 서버 핸드셰이크 수신:\n{banner[:200]}",
                "recommendation": "DB 서버는 bind-address를 제한하고, 방화벽으로 외부 접근을 차단하세요.",
            }
        return None

    # VNC (5900) - RFB 프로토콜 배너가 실제로 수신된 경우만
    if port == 5900:
        if banner and "rfb" in b:
            no_auth = "no authentication" in b or "none" in b
            reason = "VNC 서버가 인증 없이 접근 가능합니다." if no_auth else "VNC 서버가 RFB 프로토콜 배너를 노출합니다."
            return {
                "vulnerable": True,
                "reason": reason,
                "evidence": f"VNC 연결 성공, RFB 배너 수신:\n{banner[:200]}",
                "recommendation": "VNC에 강력한 인증을 설정하고 VPN 뒤에 두세요.",
            }
        return None

    # RDP(3389), SMB(445), PostgreSQL(5432), MSSQL(1433):
    # 포트 개방만으로는 실제 데이터 유출을 증명할 수 없으므로 보고하지 않음
    return None


async def scan_host(host: str, ip: str, deep: bool = False,
                    extra_ports: list | None = None, force_http_ports: list | None = None,
                    force_ssl_ports: list | None = None, only_ports: list | None = None) -> dict:
    open_ports = []
    if only_ports:
        # 스코프 봉쇄: 사용자가 URL 에 포트를 '명시'하면 그 포트만 점검한다.
        # (기본 포트목록을 함께 스캔하면 같은 호스트의 다른 서비스(예: 8080)까지 점검되어 스코프 유출)
        port_list = list(dict.fromkeys(only_ports))
    else:
        port_list = list(EXTENDED_PORTS if deep else HIGH_RISK_PORTS)
        # 명시 포트(예: URL 의 :13006)를 점검 대상에 추가 — 표준 포트가 아니어도 직접 점검
        for _ep in (extra_ports or []):
            if _ep and _ep not in port_list:
                port_list.append(_ep)
    _force_http = set(force_http_ports or [])
    _force_ssl = set(force_ssl_ports or [])

    sem = asyncio.Semaphore(50)

    async def check_port(port):
        async with sem:
            return port, await scan_port(ip, port)

    tasks = [check_port(p) for p in port_list]
    results = await asyncio.gather(*tasks)

    for port, is_open in results:
        if is_open:
            open_ports.append(port)

    # 명시 포트(사용자 지정 URL 의 포트)는 raw TCP 스캔 결과와 무관하게 '열린 것'으로 간주한다.
    # Dreamhack 등 리버스 프록시/포트 라우팅 환경에서는 raw connect 가 거부돼도 HTTP 는 정상
    # 동작하므로, 사용자가 명시한 포트는 HTTP(S) 서비스 탐지를 강제로 수행해야 능동 점검이 돈다.
    for _fp in list(_force_http) + list(_force_ssl):
        if _fp and _fp not in open_ports:
            open_ports.append(_fp)

    service_details = []
    for port in open_ports:
        service_name = SERVICE_NAMES.get(port, "Unknown")
        detail = {
            "port": port,
            "service": service_name,
            "banner": None,
            "http_info": None,
            "ssl_info": None,
            "sensitive_paths": None,
            "allowed_methods": [],
            "verified_dangerous_methods": [],
            "error_page_info": None,
        }

        is_ssl = port in (443, 8443, 993, 995) or port in _force_ssl
        is_http = (port in (80, 8080, 8888, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8020, 8025, 8030, 8040, 8050, 8060, 8070, 8090, 8091, 8100)
                   or port in _force_http)

        if is_ssl or is_http:
            detail["http_info"] = await detect_http_service(host, port, use_ssl=is_ssl)
            detail["sensitive_paths"] = await probe_http_paths(host, port, use_ssl=is_ssl)
            extras = await probe_http_extras(host, port, use_ssl=is_ssl)
            detail["allowed_methods"] = extras["allowed_methods"]
            detail["verified_dangerous_methods"] = extras.get("verified_dangerous_methods", [])
            detail["error_page_info"] = extras["error_page_info"]
        else:
            detail["banner"] = await grab_banner(ip, port)
            detail["port_vuln"] = await probe_port_vuln(host, ip, port, detail["banner"])

        if is_ssl:
            detail["ssl_info"] = get_ssl_info(host, port)

        service_details.append(detail)

    return {
        "host": host,
        "ip": ip,
        "open_ports": open_ports,
        "services": service_details,
        "scan_mode": "deep" if deep else "standard",
    }
