"""
URL Discovery Engine — robots.txt, sitemap, HTML links, JS endpoints, known paths.
Max 200 URLs, depth 2, same-host scope, 0.3s rate limiting.
"""
import asyncio
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, urlunparse
import aiohttp
import xml.etree.ElementTree as ET
import adaptive_throttle as _gov   # safe 모드 전역 rate 거버너(미설치 시 no-op)


def _net_record(ok: bool, raise_on_trip: bool = True):
    """active_probing 의 네트워크 헬스 카운터에 연결 결과를 기록(공유 ContextVar).
    지연/순환 임포트 방지를 위해 호출 시점에 로드하며, 미로드 시 무시(no-op)."""
    try:
        from active_probing import net_record
    except Exception:
        return
    net_record(ok, raise_on_trip=raise_on_trip)


KNOWN_PATHS = [
    # Swagger / OpenAPI
    "/swagger-ui.html", "/swagger-ui/", "/swagger/ui/",
    "/api/swagger-ui.html", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/api/swagger.json", "/api/openapi.json",
    # Spring Actuator
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/actuator/beans", "/actuator/metrics",
    # GraphQL
    "/graphql", "/graphiql", "/playground", "/api/graphql", "/query",
    # Admin pages
    "/admin", "/admin/", "/admin/login", "/admin/dashboard", "/admin/index",
    "/administrator", "/administrator/", "/administrator/index.php",
    "/manage", "/manage/", "/manager", "/manager/",
    "/backend", "/backend/", "/control", "/control/",
    "/cp", "/cp/", "/cms", "/cms/", "/panel", "/panel/",
    "/console", "/console/", "/dashboard", "/dashboard/",
    "/wp-admin", "/wp-login.php", "/phpmyadmin", "/adminer.php",
    "/webadmin", "/sysadmin", "/system", "/superadmin",
    # Admin API endpoints
    "/api/admin", "/api/admin/", "/api/admin/users", "/api/admin/config",
    "/api/users", "/api/user", "/api/accounts",
    "/api/config", "/api/configuration", "/api/settings",
    "/api/system", "/api/system/info", "/api/system/status",
    "/api/debug", "/api/internal", "/api/private",
    "/api/management", "/api/manage",
    # Functional endpoints
    "/api/v1/admin", "/api/v2/admin", "/api/v1/users", "/api/v2/users",
    "/api/v1/config", "/api/v1/settings",
    # Upload / Download
    "/upload", "/uploads/", "/file-upload", "/fileupload",
    "/download", "/downloads/", "/files/",
    # Board / Search
    "/board", "/bbs", "/forum", "/search", "/api/search",
    # Git / backup / 설정·소스 노출 (파일/설정 노출 점검 확대)
    "/.git/config", "/.git/HEAD", "/.svn/entries",
    "/.env", "/.env.local", "/.env.production",
    "/config.php", "/config.js", "/config.json",
    "/.env.dev", "/.env.staging", "/.env.backup",
    "/config.php.bak", "/web.config.bak", "/web.config",
    "/backup", "/backup.sql", "/db.sql", "/dump.sql",
    "/backup.zip", "/backup.tar.gz", "/.DS_Store",
    "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
    "/composer.json", "/package-lock.json", "/yarn.lock", "/phpinfo.php",
    # 프레임워크/관리 콘솔 (확대)
    "/actuator/heapdump", "/actuator/threaddump", "/jolokia",
    "/server-status", "/server-info", "/jenkins", "/kibana", "/grafana",
    "/pma/", "/phpMyAdmin/",
    # Source maps
    "/static/main.js.map", "/assets/index.js.map",
    # Common API
    "/api", "/api/v1", "/api/v2", "/api/v3", "/health", "/status",
    "/healthcheck", "/ping", "/version", "/info",
    "/robots.txt", "/sitemap.xml",
]

# 관리자 관련 경로 패턴 (Finding 생성 판단용)
ADMIN_PATH_PATTERNS = re.compile(
    r'^(/admin|/administrator|/manage|/manager|/backend|/control|/cp|/cms|/panel|/console|/dashboard|/webadmin|/sysadmin|/superadmin)',
    re.IGNORECASE,
)

# 관리자 API 경로 패턴
ADMIN_API_PATTERNS = re.compile(
    r'^(/api/admin|/api/users|/api/user|/api/accounts|/api/config|/api/configuration|'
    r'/api/settings|/api/system|/api/debug|/api/internal|/api/private|/api/management|'
    r'/api/v\d+/admin|/api/v\d+/users|/api/v\d+/config)',
    re.IGNORECASE,
)

JS_ENDPOINT_PATTERNS = [
    re.compile(r'''["'`](/(?:api|v\d+|graphql|admin|actuator|swagger|auth|login|user|account|payment|order|config|settings|system|debug|internal|manage|dashboard)[^\s"'`<>]*?)["'`]'''),
    re.compile(r'''["'`](https?://[^"'`\s<>]+/(?:api|graphql|admin|actuator|config|system|manage)[^"'`\s<>]*)["'`]'''),
    re.compile(r'''fetch\s*\(\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''axios\.\w+\s*\(\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''url\s*[:=]\s*["'`]([/][^"'`\s]+)["'`]'''),
    # React Router / Vue Router / Next.js route patterns
    re.compile(r'''(?:path|to|href|route)\s*[:=]\s*["'`]([/][^"'`\s<>?#]+)["'`]'''),
    re.compile(r'''<Route\s[^>]*path=["']([^"']+)["']'''),
    re.compile(r'''routes?\s*[=:]\s*\[.*?["'`]([/][^"'`\s]+)["'`]'''),
]

# SPA 프레임워크 탐지 패턴
SPA_FRAMEWORK_PATTERNS = [
    (re.compile(r'__NEXT_DATA__', re.IGNORECASE), "Next.js"),
    (re.compile(r'__NUXT__', re.IGNORECASE), "Nuxt.js"),
    (re.compile(r'window\.__REDUX_DEVTOOLS|__redux', re.IGNORECASE), "React/Redux"),
    (re.compile(r'vue\.config|Vue\.prototype|createApp\s*\(', re.IGNORECASE), "Vue.js"),
    (re.compile(r'angular\.module|ng-app|ng-controller', re.IGNORECASE), "Angular"),
    (re.compile(r'window\.__INITIAL_STATE__|__APP_STATE__', re.IGNORECASE), "SPA State"),
    (re.compile(r'sourceMappingURL=([^\s"\']+\.map)', re.IGNORECASE), "Source Map"),
    (re.compile(r'webpack(?:Jsonp|ChunkName|HotUpdate)', re.IGNORECASE), "Webpack"),
]

# API 경로 패턴(probing 대상 기록용) — /api, /v1.., /graphql, /actuator 등
API_PATH_PATTERNS = re.compile(
    r'^/(?:api|v\d+|graphql|actuator|rest|services?|gateway)(?:/|$)',
    re.IGNORECASE,
)

# 검색 입력점 탐지 패턴
SEARCH_INPUT_NAME_RE = re.compile(r'^(q|query|search|keyword|term|s)$', re.IGNORECASE)
SEARCH_PLACEHOLDER_RE = re.compile(r'(검색|search)', re.IGNORECASE)
SEARCH_ACTION_RE = re.compile(r'search', re.IGNORECASE)
SEARCH_PARAM_RE = re.compile(r'^(q|search|query|keyword|term)$', re.IGNORECASE)

# <input ...> 태그 추출 + name/placeholder 추출
_INPUT_TAG_RE = re.compile(r'<input\b[^>]*>', re.IGNORECASE)
_FORM_TAG_RE = re.compile(r'<form\b([^>]*)>', re.IGNORECASE)
_ATTR_NAME_RE = re.compile(r'\bname\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_ATTR_PLACEHOLDER_RE = re.compile(r'\bplaceholder\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_ATTR_ACTION_RE = re.compile(r'\baction\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

# 로그인 필요 추정 힌트(본문에 로그인 유도/세션 만료 등)
_AUTH_REQUIRED_RE = re.compile(
    r'(로그인이?\s*필요|please\s*log\s*in|session\s*expired|세션\s*만료|'
    r'authentication\s*required|access\s*denied|권한이?\s*없)',
    re.IGNORECASE,
)

HTML_LINK_PATTERNS = [
    re.compile(r'''<a\s[^>]*href=["']([^"'#][^"']*)["']''', re.IGNORECASE),
    re.compile(r'''<form\s[^>]*action=["']([^"']*)["']''', re.IGNORECASE),
    re.compile(r'''<script\s[^>]*src=["']([^"']*)["']''', re.IGNORECASE),
    re.compile(r'''<link\s[^>]*href=["']([^"']*)["']''', re.IGNORECASE),
    re.compile(r'''<iframe\s[^>]*src=["']([^"']*)["']''', re.IGNORECASE),
]


@dataclass
class DiscoveredURL:
    url: str
    source: str          # "robots", "sitemap", "html_link", "js_endpoint", "known_path", "crawl", "form_action"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    depth: int = 0
    # 로그인 후에만 접근 가능한 것으로 추정되는 페이지 표시(가능 범위)
    login_required: bool = False
    authenticated: bool = False


@dataclass
class DiscoveryResult:
    base_url: str
    urls: list[DiscoveredURL] = field(default_factory=list)
    robots_disallowed: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)
    known_path_hits: list[str] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Phase 6: 관리자/API/프레임워크 발견 목록
    admin_hits: list[dict] = field(default_factory=list)   # {url, status_code, has_login_form}
    api_hits: list[dict] = field(default_factory=list)     # {url, status_code, is_json}
    framework_hints: list[dict] = field(default_factory=list)  # {framework, evidence}
    # 추가(기존 구조 보존, 신규 필드만 추가)
    form_actions: list[str] = field(default_factory=list)        # crawl 큐에 추가된 form action URL
    api_paths: list[str] = field(default_factory=list)           # probing 대상으로 기록할 API 경로 URL
    search_inputs: list[dict] = field(default_factory=list)      # 검색 입력점 {url, source, name, param}
    auth_required_urls: list[str] = field(default_factory=list)  # 로그인 후 접근 가능 추정 URL

    def unique_url_strings(self) -> list[str]:
        return list({u.url for u in self.urls})


class URLDiscoveryEngine:
    def __init__(
        self,
        max_urls: Optional[int] = None,
        max_depth: Optional[int] = None,
        rate_limit: float = 0.3,
        concurrency: int = 3,
        timeout: int = 8,
        same_origin_only: Optional[bool] = None,
    ):
        # ScanConfig(max_crawl_pages=200, max_crawl_depth=3, same_origin_only=True) 기준.
        # 명시 인자가 주어지면 그 값을 우선(기존 호출부 호환).
        cfg = None
        if max_urls is None or max_depth is None or same_origin_only is None:
            try:
                from probes.config import ScanConfig
                cfg = ScanConfig.from_env()
            except Exception:
                cfg = None
        self.max_urls = max_urls if max_urls is not None else (cfg.max_crawl_pages if cfg else 200)
        self.max_depth = max_depth if max_depth is not None else (cfg.max_crawl_depth if cfg else 3)
        self.same_origin_only = (
            same_origin_only if same_origin_only is not None
            else (cfg.same_origin_only if cfg else True)
        )
        self.rate_limit = rate_limit
        self.concurrency = concurrency
        self.timeout = timeout
        self._visited: set[str] = set()
        self._queued: set[str] = set()
        self._last_request: float = 0.0
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._result: Optional[DiscoveryResult] = None
        self._base_host: str = ""
        # 사용자 스캔 스코프 제외(부분일치 blocklist) — 링크추적/known-path/sitemap 등 모든 크롤에서
        # 해당 URL 을 건드리지 않도록 강제. discover(exclude_patterns=...) 로 주입.
        self._exclude_patterns: list[str] = []
        self._base_url: str = ""
        # soft-404(catch-all) 기준 시그니처 + 관리자 본문 중복 제거용
        self._soft404: Optional[dict] = None
        self._admin_sigs: set = set()

    def _is_excluded(self, url: str) -> bool:
        """URL 이 사용자 제외(blocklist, 부분일치) 범위에 드는가. base_url 자체는 제외 대상 아님."""
        if not url or not self._exclude_patterns:
            return False
        if url == self._base_url:
            return False
        return any(x and x in url for x in self._exclude_patterns)

    def _normalize_url(self, url: str, base: str) -> Optional[str]:
        try:
            url = url.strip()
            if url.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                return None
            joined = urljoin(base, url)
            parsed = urlparse(joined)
            if parsed.scheme not in ("http", "https"):
                return None
            clean = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
            return clean.rstrip("/") or clean
        except Exception:
            return None

    def _in_scope(self, url: str) -> bool:
        try:
            if not getattr(self, "same_origin_only", True):
                return True
            return urlparse(url).netloc == self._base_host
        except Exception:
            return False

    def _record_api_path(self, url: str) -> None:
        """발견한 API 경로를 probing 대상으로 기록(중복 제거)."""
        try:
            path = urlparse(url).path
        except Exception:
            return
        if API_PATH_PATTERNS.match(path) and url not in self._result.api_paths:
            self._result.api_paths.append(url)

    def _mark_login_required(self, url: str) -> None:
        """로그인 후에만 접근 가능한 것으로 추정되는 URL 을 표시/기록한다."""
        for du in self._result.urls:
            if du.url == url:
                du.login_required = True
        if url not in self._result.auth_required_urls:
            self._result.auth_required_urls.append(url)

    def _add_url(self, url: str, source: str, depth: int = 0) -> bool:
        if not url or url in self._queued:
            return False
        if self._is_excluded(url):        # 사용자 제외 범위 → 큐/결과에 넣지 않음(크롤 안 함)
            return False
        if not self._in_scope(url):
            return False
        if len(self._result.urls) >= self.max_urls:
            return False
        self._queued.add(url)
        self._result.urls.append(DiscoveredURL(url=url, source=source, depth=depth))
        return True

    async def _rate_limited_get(self, session: aiohttp.ClientSession, url: str) -> Optional[aiohttp.ClientResponse]:
        # 하드 가드: 제외(blocklist) 범위 URL 은 어떤 경로로든 요청하지 않는다(링크추적/known-path/폼 포함).
        if self._is_excluded(url):
            return None
        self._semaphore = self._semaphore or asyncio.Semaphore(self.concurrency)
        async with self._semaphore:
            elapsed = time.monotonic() - self._last_request
            if elapsed < self.rate_limit:
                await asyncio.sleep(self.rate_limit - elapsed)
            # rate 거버너: 크롤 요청도 통과(Safe: 전역 합산 / PROOF: crawl 단계 상한)
            _g = _gov.stage("crawl")
            if _g is not None:
                await _g.before()
            _gt0 = time.monotonic()
            try:
                # 세션 주입 인증 헤더(대상 호스트로만) — 인증 크롤 지원
                try:
                    import session_inject as _si
                    _inj = _si.headers_for(url)
                except Exception:
                    _inj = {}
                resp = await session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=True,
                    ssl=False,
                    headers=(_inj or None),
                )
                self._last_request = time.monotonic()
                _net_record(True)   # 응답 수신(연결 성공) → 네트워크 헬스 카운터 리셋
                if _g is not None:
                    _g.after(time.monotonic() - _gt0, resp.status,
                             resp.headers.get("Retry-After"))
                return resp
            except Exception as e:
                self._last_request = time.monotonic()
                self._result.errors.append(f"GET {url}: {e}")
                if _g is not None:      # 거버너 슬롯 반납(예외 시에도 반드시)
                    _g.after(time.monotonic() - _gt0, 0, None)
                # 연결 실패 기록(비-raise): 임계 초과 시 tripped 플래그만 세우고 계속 →
                # run_scan 이 url_discovery 스테이지 종료 후 net_tripped() 로 중단 감지
                _net_record(False, raise_on_trip=False)
                return None

    async def _parse_robots(self, session: aiohttp.ClientSession, base_url: str):
        url = urljoin(base_url, "/robots.txt")
        resp = await self._rate_limited_get(session, url)
        if not resp:
            return
        try:
            text = await resp.text(errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line[9:].strip().split()[0] if line[9:].strip() else ""
                    if path and path != "/":
                        self._result.robots_disallowed.append(path)
                        full = urljoin(base_url, path)
                        self._add_url(full, "robots")
                elif line.lower().startswith("sitemap:"):
                    sitemap_url = line[8:].strip()
                    if sitemap_url:
                        await self._parse_sitemap(session, sitemap_url, base_url)
        except Exception as e:
            self._result.errors.append(f"robots.txt parse: {e}")

    async def _parse_sitemap(self, session: aiohttp.ClientSession, sitemap_url: str, base_url: str):
        resp = await self._rate_limited_get(session, sitemap_url)
        if not resp:
            return
        try:
            text = await resp.text(errors="replace")
            root = ET.fromstring(text)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for loc in root.findall(".//sm:loc", ns):
                url = (loc.text or "").strip()
                if url:
                    norm = self._normalize_url(url, base_url)
                    if norm:
                        self._result.sitemap_urls.append(norm)
                        self._add_url(norm, "sitemap")
            # sitemapindex
            for sitemap_el in root.findall(".//sm:sitemap/sm:loc", ns):
                sub_url = (sitemap_el.text or "").strip()
                if sub_url and len(self._result.urls) < self.max_urls:
                    await self._parse_sitemap(session, sub_url, base_url)
        except ET.ParseError:
            # try plain-text sitemap
            for line in text.splitlines():
                url = line.strip()
                if url.startswith("http"):
                    norm = self._normalize_url(url, base_url)
                    if norm:
                        self._result.sitemap_urls.append(norm)
                        self._add_url(norm, "sitemap")
        except Exception as e:
            self._result.errors.append(f"sitemap parse {sitemap_url}: {e}")

    async def _probe_known_paths(self, session: aiohttp.ClientSession, base_url: str,
                                 extra_paths: list[str] | None = None):
        tasks = []
        # 기본 KNOWN_PATHS + 기술 스택 기반 추천 경로(중복 제거, 안전 GET만)
        seen_paths = set()
        for path in list(KNOWN_PATHS) + list(extra_paths or []):
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)
            url = urljoin(base_url, path)
            if url not in self._queued and len(self._result.urls) < self.max_urls:
                tasks.append(self._probe_single_path(session, url, base_url))
        await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    def _soft404_sig(body: str, path: str) -> tuple[int, str]:
        """본문에서 경로/숫자를 제거해 catch-all 비교용 안정 시그니처(길이, 해시)를 만든다."""
        b = body or ""
        if path:
            b = b.replace(path, "")
        b = re.sub(r"\d+", "", b)
        b = re.sub(r"\s+", " ", b).strip()
        return (len(b), hashlib.md5(b.encode("utf-8", errors="ignore")).hexdigest())

    async def _compute_soft404(self, session: aiohttp.ClientSession, base_url: str):
        """존재하지 않는 임의 경로의 응답을 기준선으로 잡는다.
        임의 경로가 404 가 아닌 200 등으로 응답하면 catch-all(soft-404) 사이트로 간주한다.
        """
        self._soft404 = None
        probe_paths = ["/eoseureum-nonexistent-7x9q2k8w", "/zzq-not-here-a1b2c3d4/x"]
        sigs: list[tuple[int, str]] = []
        statuses: set[int] = set()
        for pp in probe_paths:
            resp = await self._rate_limited_get(session, urljoin(base_url, pp))
            if not resp:
                continue
            statuses.add(resp.status)
            if resp.status in (404, 400, 410):
                continue  # 정상적으로 404 를 주는 서버 → catch-all 아님
            try:
                body = await resp.text(errors="replace")
            except Exception:
                body = ""
            sigs.append(self._soft404_sig(body, pp))
        if sigs:
            # 존재하지 않는 경로가 비-404 로 응답 → soft-404 기준선 등록
            self._soft404 = {
                "statuses": statuses,
                "hashes": {h for _, h in sigs},
                "lengths": [ln for ln, _ in sigs],
            }

    def _is_soft404(self, status: int, body: str, path: str) -> bool:
        """응답이 soft-404 기준선과 동일한 catch-all 응답인지 판정."""
        if not self._soft404:
            return False
        if status not in self._soft404["statuses"]:
            return False
        ln, h = self._soft404_sig(body, path)
        if h in self._soft404["hashes"]:
            return True
        for base_len in self._soft404["lengths"]:
            if abs(ln - base_len) <= max(24, int(0.05 * max(base_len, 1))):
                return True
        return False

    async def _probe_single_path(self, session: aiohttp.ClientSession, url: str, base_url: str):
        resp = await self._rate_limited_get(session, url)
        if resp and resp.status not in (404, 400, 410):
            ct = resp.headers.get("Content-Type", "")
            discovered = DiscoveredURL(
                url=url,
                source="known_path",
                status_code=resp.status,
                content_type=ct,
            )
            if url not in self._queued and len(self._result.urls) < self.max_urls:
                self._queued.add(url)
                self._result.urls.append(discovered)
                self._result.known_path_hits.append(url)
            # 발견한 API 경로를 probing 대상으로 기록
            self._record_api_path(url)
            if resp.status in (401, 403):
                self._mark_login_required(url)

            # 관리자 페이지 분류 (403도 노출로 기록 — 존재 자체가 정보)
            parsed_path = urlparse(url).path
            if ADMIN_PATH_PATTERNS.match(parsed_path) and resp.status in (200, 302, 301, 401, 403):
                body = ""
                try:
                    body = await resp.text(errors="replace")
                except Exception:
                    pass
                # 오탐 방지 1) soft-404(catch-all) 응답이면 관리자 페이지로 집계하지 않음
                if resp.status in (200, 301, 302) and self._is_soft404(resp.status, body, parsed_path):
                    pass
                else:
                    # "로그인 폼 있음" 은 실제 password input 또는 <form> 이 확인될 때만(키워드만으론 X)
                    has_password = bool(re.search(r'type\s*=\s*["\']password["\']', body[:6000], re.IGNORECASE))
                    has_form = bool(re.search(r'<form\b', body[:6000], re.IGNORECASE))
                    has_login = has_password or (has_form and bool(re.search(
                        r'(로그인|sign.?in|log.?in)', body[:6000], re.IGNORECASE)))
                    # 오탐 방지 2) 동일 본문이 반복되면(중복 catch-all) 1회만 집계
                    _, sig = self._soft404_sig(body, parsed_path)
                    if sig not in self._admin_sigs:
                        self._admin_sigs.add(sig)
                        self._result.admin_hits.append({
                            "url": url,
                            "status_code": resp.status,
                            "has_login_form": has_login,
                        })

            # 관리자 API 분류 (403은 기록, 200이면 본문 분석)
            elif ADMIN_API_PATTERNS.match(parsed_path) and resp.status in (200, 403):
                is_json = "application/json" in ct
                if resp.status == 200 and not is_json:
                    try:
                        body = await resp.text(errors="replace")
                        is_json = bool(body.strip().startswith("{") or body.strip().startswith("["))
                    except Exception:
                        pass
                self._result.api_hits.append({
                    "url": url,
                    "status_code": resp.status,
                    "is_json": is_json,
                })

    def _extract_html_links(self, html: str, base_url: str, depth: int) -> list[str]:
        found = []
        for pattern in HTML_LINK_PATTERNS:
            for match in pattern.finditer(html):
                url = self._normalize_url(match.group(1), base_url)
                if url and url not in self._queued:
                    found.append((url, depth))
        return found

    def _extract_forms_and_search(self, html: str, page_url: str, depth: int) -> None:
        """폼 action 을 crawl 큐에 추가하고, 검색 입력점을 탐지해 기록한다."""
        # 1) form action → crawl 큐 추가 + 검색 폼 탐지
        for fm in re.finditer(r'<form\b([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL):
            attrs, inner = fm.group(1), fm.group(2)
            am = _ATTR_ACTION_RE.search(attrs)
            action = am.group(1).strip() if am else ""
            action_url = self._normalize_url(action, page_url) if action else None
            if action_url:
                if self._add_url(action_url, "form_action", depth):
                    if action_url not in self._result.form_actions:
                        self._result.form_actions.append(action_url)
                self._record_api_path(action_url)
            form_action_has_search = bool(action and SEARCH_ACTION_RE.search(action))
            # 폼 내부 input 검사
            for itag in _INPUT_TAG_RE.finditer(inner):
                tag = itag.group(0)
                nm = _ATTR_NAME_RE.search(tag)
                ph = _ATTR_PLACEHOLDER_RE.search(tag)
                name = nm.group(1) if nm else ""
                placeholder = ph.group(1) if ph else ""
                is_search = (
                    (name and SEARCH_INPUT_NAME_RE.match(name))
                    or (placeholder and SEARCH_PLACEHOLDER_RE.search(placeholder))
                    or form_action_has_search
                )
                if is_search:
                    self._add_search_input(action_url or page_url, "form", name=name)

        # 2) URL 쿼리 파라미터 기반 검색 입력점
        try:
            qs = urlparse(page_url).query
        except Exception:
            qs = ""
        if qs:
            for pair in qs.split("&"):
                key = pair.split("=", 1)[0]
                if key and SEARCH_PARAM_RE.match(key):
                    self._add_search_input(page_url, "url_param", param=key)

    def _add_search_input(self, url: str, source: str, name: str = "", param: str = "") -> None:
        entry = {"url": url, "source": source, "name": name, "param": param}
        key = (url, source, name, param)
        if not any((e.get("url"), e.get("source"), e.get("name"), e.get("param")) == key
                   for e in self._result.search_inputs):
            self._result.search_inputs.append(entry)

    def _extract_js_endpoints(self, js_text: str, base_url: str, depth: int) -> list[str]:
        found = []
        for pattern in JS_ENDPOINT_PATTERNS:
            for match in pattern.finditer(js_text):
                url = self._normalize_url(match.group(1), base_url)
                if url and url not in self._queued:
                    found.append(url)
        return found

    async def _crawl_url(self, session: aiohttp.ClientSession, url: str, depth: int):
        if url in self._visited or depth > self.max_depth:
            return
        self._visited.add(url)

        resp = await self._rate_limited_get(session, url)
        if not resp:
            return

        ct = resp.headers.get("Content-Type", "")
        status = resp.status

        for discovered in self._result.urls:
            if discovered.url == url:
                discovered.status_code = status
                discovered.content_type = ct
                break

        # 로그인 후 접근 가능 추정: 401/403 또는 본문에 로그인 유도 → login_required 표시
        self._record_api_path(url)
        if status in (401, 403):
            self._mark_login_required(url)

        if "text/html" in ct and depth < self.max_depth:
            try:
                html = await resp.text(errors="replace")
                if _AUTH_REQUIRED_RE.search(html[:5000]):
                    self._mark_login_required(url)
                # 폼 action 을 crawl 큐에 추가 + 검색 입력점 탐지
                self._extract_forms_and_search(html, url, depth + 1)
                links = self._extract_html_links(html, url, depth + 1)
                for link_url, link_depth in links:
                    if self._add_url(link_url, "html_link", link_depth):
                        pass
                # SPA 프레임워크 탐지
                for pattern, framework in SPA_FRAMEWORK_PATTERNS:
                    m = pattern.search(html[:8000])
                    if m:
                        evidence = m.group(0)[:80]
                        if not any(h["framework"] == framework for h in self._result.framework_hints):
                            self._result.framework_hints.append({
                                "framework": framework,
                                "evidence": evidence,
                                "url": url,
                            })
                # Extract inline JS
                js_blocks = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
                for block in js_blocks:
                    endpoints = self._extract_js_endpoints(block, url, depth)
                    for ep in endpoints:
                        if self._add_url(ep, "js_endpoint", depth):
                            self._result.js_endpoints.append(ep)
            except Exception as e:
                self._result.errors.append(f"HTML parse {url}: {e}")

        elif "javascript" in ct or url.endswith(".js"):
            try:
                text = await resp.text(errors="replace")
                endpoints = self._extract_js_endpoints(text, url, depth)
                for ep in endpoints:
                    if self._add_url(ep, "js_endpoint", depth):
                        self._result.js_endpoints.append(ep)
            except Exception as e:
                self._result.errors.append(f"JS parse {url}: {e}")

    async def discover(self, base_url: str, extra_paths: list[str] | None = None,
                       *, seed_urls: list[str] | None = None,
                       exclude_urls: list[str] | None = None,
                       exclude_patterns: list[str] | None = None,
                       skip_passive: bool = False) -> DiscoveryResult:
        """URL 발견을 수행한다.

        재크롤(반복) 지원 인자:
          seed_urls    : base 외에 크롤 시작점으로 추가할 URL(예: 새로 접근 가능해진 페이지).
          exclude_urls : 이미 발견/방문한 것으로 간주해 결과·크롤에서 제외할 URL(차집합용).
          skip_passive : True 면 robots/sitemap/known-path 재탐색을 건너뛰고
                         seed(및 base)에서 링크 크롤만 수행(재크롤 라운드에서 중복 작업 방지).
        """
        parsed = urlparse(base_url)
        if not parsed.scheme:
            base_url = "https://" + base_url
            parsed = urlparse(base_url)

        self._base_host = parsed.netloc
        self._base_url = base_url
        # 사용자 제외(부분일치 blocklist) — 링크추적 포함 모든 크롤 요청에서 이 범위를 건드리지 않는다.
        self._exclude_patterns = [str(p) for p in (exclude_patterns or []) if p]
        self._visited = set()
        self._queued = set()
        self._semaphore = asyncio.Semaphore(self.concurrency)
        self._result = DiscoveryResult(base_url=base_url)

        # 차집합: 이미 본 URL 은 큐/방문셋에 미리 넣어 결과·크롤에서 배제한다.
        for ex in (exclude_urls or []):
            norm = self._normalize_url(ex, base_url)
            if norm:
                self._queued.add(norm)
                self._visited.add(norm)

        headers = {
            "User-Agent": "Eoseureum-Scanner/1.0 (Security Assessment Tool)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        conn = aiohttp.TCPConnector(ssl=False, limit=10)
        async with aiohttp.ClientSession(headers=headers, connector=conn) as session:
            # Seed with base URL (제외 대상이면 _add_url 이 스킵)
            self._add_url(base_url, "crawl", 0)
            # 재크롤 시드: 새로 접근 가능해진 페이지들을 크롤 시작점으로 추가
            for s in (seed_urls or []):
                norm = self._normalize_url(s, base_url)
                if norm:
                    self._add_url(norm, "recrawl_seed", 0)

            if not skip_passive:
                # Phase 1: robots.txt + sitemap (may add /sitemap.xml as well)
                await asyncio.gather(
                    self._parse_robots(session, base_url),
                    self._parse_sitemap(session, urljoin(base_url, "/sitemap.xml"), base_url),
                )

                # Phase 1.5: soft-404(catch-all) 기준선 — 관리자 페이지 오탐 방지
                self._admin_sigs = set()
                await self._compute_soft404(session, base_url)

                # Phase 2: known paths probe (+ 기술 스택 기반 추천 경로)
                await self._probe_known_paths(session, base_url, extra_paths=extra_paths)

            # Phase 3: crawl discovered HTML pages (depth-limited BFS)
            crawl_queue = [u for u in self._result.urls if u.depth <= self.max_depth]
            for discovered in crawl_queue:
                if len(self._visited) >= self.max_urls:
                    break
                if discovered.url not in self._visited:
                    await self._crawl_url(session, discovered.url, discovered.depth)

        return self._result
