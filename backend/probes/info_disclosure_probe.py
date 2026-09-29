"""
probes/info_disclosure_probe.py — 정보 노출(Information Disclosure) probe.

세 가지 점검을 수행한다:
  1) 서버 소프트웨어 버전 노출 (Server 헤더)
  2) 에러 페이지에서 시스템 정보 노출 (scanner.probe_http_extras 의 error_page_info)
  3) 민감 경로 본문 확인 (sensitive path content validation)

원칙:
  - 단순 경로 존재(200)만으로는 finding 이 아니다(discovery). 본문에 민감 마커가 있어야 finding.
  - 네트워크 추가 호출은 ctx.session GET 1회까지만 허용(ctx.throttle 후).
  - 새 탐지 로직(공격성 페이로드 등)을 추가하지 않는다.
"""
from __future__ import annotations

import re
import urllib.parse

from probes.base import BaseProbe, ProbeContext, ProbeResult
import scanner


# 민감 본문 마커 — 응답 본문에 노출되면 정보 노출로 간주한다.
_SENSITIVE_BODY_RE = re.compile(
    r"(BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"
    r"|aws_secret_access_key|aws_access_key_id"
    r"|DB_PASSWORD|DATABASE_URL|SECRET_KEY"
    r"|-----BEGIN CERTIFICATE-----"
    r"|root:.*:0:0:"
    r"|<\?php"
    r"|\[mysqld\])",
    re.IGNORECASE,
)


# ── 내용 기반 승격 대상 민감 경로 ────────────────────────────────────────────────
# 각 항목: (경로, 승격 기준 정규식, severity, 제목, probe_key)
# 본문(또는 401/403/로그인 폼이 아닌 무인증 접근)에 마커가 있을 때만 finding 으로 승격한다.
# 단순 경로 존재/401/403/로그인 폼은 finding 아님(attack_surface 유지).
_SERVER_STATUS_RE = re.compile(r"(Server Status|requests/sec|Total Accesses|workers|client IP|scoreboard|Apache Server Status)", re.IGNORECASE)
_SERVER_INFO_RE = re.compile(r"(Apache Server Information|Server Settings|Module Name|Loaded Modules|Server Built|MPM Information)", re.IGNORECASE)
_ACTUATOR_ENV_RE = re.compile(r"(\"propertySources\"|activeProfiles|systemProperties|spring\.|\"applicationConfig|server\.port)", re.IGNORECASE)
_HEAPDUMP_RE = re.compile(r"(java\.lang|HPROF|\x00\x00\x00|application/octet-stream)", re.IGNORECASE)
_ENV_FILE_RE = re.compile(r"(DB_PASSWORD|DATABASE_URL|SECRET_KEY|API[_-]?KEY|AWS_SECRET|APP_KEY|^\s*[A-Z][A-Z0-9_]+\s*=\s*\S)", re.IGNORECASE | re.MULTILINE)
_GIT_HEAD_RE = re.compile(r"(ref:\s*refs/|^[0-9a-f]{40}\s*$)", re.IGNORECASE | re.MULTILINE)
_PHPINFO_RE = re.compile(r"(phpinfo\(\)|PHP Version|php\.ini|<title>phpinfo\(\))", re.IGNORECASE)
_MANAGER_RE = re.compile(r"(Tomcat Web Application Manager|Manager App|list of applications|/manager/html|HostManager)", re.IGNORECASE)
_GRAPHQL_RE = re.compile(r"(__schema|queryType|GraphiQL|graphql-playground|\"data\"\s*:\s*\{)", re.IGNORECASE)
_SWAGGER_RE = re.compile(r"(swagger-ui|\"swagger\"\s*:|\"openapi\"\s*:|Swagger UI|api-docs)", re.IGNORECASE)

# 401/403 또는 로그인 폼만 노출 → finding 아님(attack_surface). 본문이 보호 페이지인지 판별.
_PROTECTED_BODY_RE = re.compile(r"(type=[\"']password[\"']|로그인|sign\s*in|<form[^>]*login|401 Unauthorized|403 Forbidden|Authentication Required)", re.IGNORECASE)

_SENSITIVE_PATHS = [
    # (path, body_re, severity, title, probe_key)
    ("/server-status", _SERVER_STATUS_RE, "Medium", "Apache server-status 정보 노출", "server_status_exposed"),
    ("/server-info", _SERVER_INFO_RE, "Medium", "Apache server-info 설정 정보 노출", "server_info_exposed"),
    ("/manager", _MANAGER_RE, "High", "관리자 기능 무인증 접근 (Tomcat Manager)", "manager_unauth_access"),
    ("/manager/html", _MANAGER_RE, "High", "관리자 기능 무인증 접근 (Tomcat Manager)", "manager_unauth_access"),
    ("/host-manager/html", _MANAGER_RE, "High", "관리자 기능 무인증 접근 (Tomcat Host Manager)", "manager_unauth_access"),
    ("/actuator", _ACTUATOR_ENV_RE, "Medium", "Spring Actuator 노출", "actuator_exposed"),
    ("/actuator/env", _ACTUATOR_ENV_RE, "High", "Spring Actuator env 무인증 노출", "actuator_env_exposed"),
    ("/actuator/heapdump", _HEAPDUMP_RE, "High", "Spring Actuator heapdump 무인증 노출", "actuator_heapdump_exposed"),
    ("/swagger", _SWAGGER_RE, "Medium", "Swagger UI 노출", "swagger_exposed"),
    ("/swagger-ui", _SWAGGER_RE, "Medium", "Swagger UI 노출", "swagger_exposed"),
    ("/v3/api-docs", _SWAGGER_RE, "Medium", "OpenAPI api-docs 노출", "api_docs_exposed"),
    ("/graphql", _GRAPHQL_RE, "Medium", "GraphQL 엔드포인트 노출", "graphql_exposed"),
    ("/graphiql", _GRAPHQL_RE, "Medium", "GraphiQL 콘솔 노출", "graphiql_exposed"),
    ("/.git/HEAD", _GIT_HEAD_RE, "Medium", ".git/HEAD 접근 가능 (소스 노출 위험)", "git_head_exposed"),
    ("/.env", _ENV_FILE_RE, "High", ".env 파일 내용 노출", "env_file_exposed"),
    ("/phpinfo.php", _PHPINFO_RE, "Medium", "phpinfo() 정보 노출", "phpinfo_exposed"),
]


class InfoDisclosureProbe(BaseProbe):
    name = "info_disclosure"
    category = "info_disclosure"
    enabled_by_default = True

    async def run(self, ctx: ProbeContext) -> list[ProbeResult]:
        await ctx.throttle()
        results: list[ProbeResult] = []

        results.extend(self._check_server_header(ctx))
        results.extend(await self._check_error_page(ctx))
        results.extend(await self._check_sensitive_paths(ctx))
        results.extend(await self._check_known_sensitive_paths(ctx))

        return results

    # ── 1) Server 헤더 노출 ───────────────────────────────────────────────
    def _check_server_header(self, ctx: ProbeContext) -> list[ProbeResult]:
        headers = ctx.headers or {}
        server = ""
        for k, v in headers.items():
            if str(k).lower() == "server":
                server = str(v or "").strip()
                break
        if not server:
            return []
        # 버전 정보가 포함되어야 노출로 본다 (예: nginx/1.18.0, Apache/2.4.41)
        if not re.search(r"[\d.]+", server):
            return []
        return [ProbeResult(
            title="서버 소프트웨어 버전 정보 노출 (Server 헤더)",
            category=self.category,
            finding_type="vulnerability",
            severity="Low",
            confidence="CONFIRMED",
            affected_url=ctx.target_url,
            evidence=[f"Server: {server}"],
            recommendation="Server 응답 헤더에서 소프트웨어/버전 정보를 제거하거나 일반화하라.",
            cwe="CWE-200",
            owasp="A05:2021",
            probe_key="server_header_disclosure",
            raw={"server": server},
        )]

    # ── 2) 에러 페이지 정보 노출 ──────────────────────────────────────────
    async def _check_error_page(self, ctx: ProbeContext) -> list[ProbeResult]:
        use_ssl = (ctx.scheme or "").lower() == "https"
        try:
            extras = await scanner.probe_http_extras(ctx.host, ctx.port, use_ssl)
        except Exception:
            return []
        ei = (extras or {}).get("error_page_info")
        if not ei:
            return []
        leaks = ei.get("leaks") if isinstance(ei, dict) else None
        evidence = []
        if leaks:
            evidence.append("노출 유형: " + ", ".join(str(x) for x in leaks))
        return [ProbeResult(
            title="에러 페이지에서 시스템 정보 노출",
            category=self.category,
            finding_type="vulnerability",
            severity="Medium",
            confidence="CONFIRMED",
            affected_url=ctx.target_url,
            evidence=evidence,
            recommendation="에러 페이지에서 스택 트레이스/버전/경로 정보를 제거하고 일반화된 오류 화면을 제공하라.",
            cwe="CWE-200",
            owasp="A05:2021",
            probe_key="error_page_disclosure",
            raw=ei if isinstance(ei, dict) else {"error_page_info": ei},
        )]

    # ── 3) 민감 경로 본문 확인 ────────────────────────────────────────────
    async def _check_sensitive_paths(self, ctx: ProbeContext) -> list[ProbeResult]:
        """ctx.discovered_urls 중 200 응답 본문에 민감 마커가 있으면 finding.

        - discovered_urls 항목이 dict 면 {"url","status","body"} 를 사용한다.
          이미 본문(body)이 주입되어 있으면 추가 네트워크 호출 없이 검증한다.
        - body 가 없고 session 이 있으면 GET 1회로 본문을 확인한다.
        - 단순 경로 존재(본문에 민감 마커 없음)는 finding 으로 만들지 않는다.
        """
        results: list[ProbeResult] = []
        for item in (ctx.discovered_urls or []):
            url, status, body = self._unpack(item)
            if not url:
                continue
            if status is not None and status != 200:
                continue
            if body is None and ctx.session is not None:
                body = await self._fetch_body(ctx, url)
            if not body:
                continue
            m = _SENSITIVE_BODY_RE.search(body)
            if not m:
                continue
            snippet = body[max(0, m.start() - 40): m.end() + 40].strip()[:200]
            results.append(ProbeResult(
                title="민감 정보가 포함된 응답 본문 노출",
                category=self.category,
                finding_type="vulnerability",
                severity="Medium",
                confidence="CONFIRMED",
                affected_url=url,
                evidence=[f"민감 마커 확인: {snippet}"],
                recommendation="민감 파일/경로에 대한 접근을 차단하고 응답 본문에서 비밀정보 노출을 제거하라.",
                cwe="CWE-200",
                owasp="A05:2021",
                probe_key="sensitive_path_content",
                raw={"url": url, "status": status},
            ))
            # 동일 유형 과다 보고 방지: 첫 발견만 보고
            break
        return results

    # ── 4) 알려진 민감 경로 내용 기반 승격 ──────────────────────────────────
    async def _check_known_sensitive_paths(self, ctx: ProbeContext) -> list[ProbeResult]:
        """지정된 민감 경로의 본문을 확인해 '내용 확인된 노출'만 finding 으로 승격한다.

        - 우선 ctx.discovered_urls(dict {url,status,body}) 에서 본문을 찾는다(네트워크 없음).
        - 본문이 없고 ctx.session 이 있으면 경로당 GET 1회(throttle 준수)로 확인한다.
        - 401/403 또는 로그인 폼만 노출되면 finding 으로 만들지 않는다(attack_surface 유지).
        - 승격 결과에는 tags=['content_confirmed'] 를 부여해 normalizer 가 인식하게 한다.
        """
        results: list[ProbeResult] = []
        # discovered_urls 에서 경로별 본문/상태 인덱싱 (path 끝부분 매칭)
        provided: dict[str, tuple] = {}
        for item in (ctx.discovered_urls or []):
            url, status, body = self._unpack(item)
            if not url:
                continue
            try:
                path = urllib.parse.urlparse(url).path.rstrip("/").lower()
            except Exception:
                path = ""
            provided[path] = (url, status, body)

        seen_keys: set[str] = set()
        base = (ctx.target_url or "").rstrip("/")
        for path, body_re, severity, title, probe_key in _SENSITIVE_PATHS:
            if probe_key in seen_keys:
                continue
            norm_path = path.rstrip("/").lower()
            url, status, body = None, None, None
            if norm_path in provided:
                url, status, body = provided[norm_path]
            else:
                url = base + path if base else path

            # 보호된 응답(401/403)은 승격하지 않음
            if status is not None and status in (401, 403):
                continue
            if status is not None and status != 200:
                continue

            # 본문이 없으면 session 으로 1회 GET
            if body is None and ctx.session is not None:
                body, fetched_status = await self._fetch_body_status(ctx, url)
                if fetched_status is not None and fetched_status in (401, 403):
                    continue
                if fetched_status is not None and fetched_status != 200:
                    continue
            if not body:
                continue

            # 로그인 폼/보호 페이지만 노출된 경우는 승격하지 않음(내용 마커가 따로 있어야 함)
            content_match = body_re.search(body)
            if not content_match:
                continue
            # /server-status 류는 보호 페이지 텍스트만 있는 경우 제외
            if _PROTECTED_BODY_RE.search(body) and not content_match:
                continue

            seen_keys.add(probe_key)
            snippet = body[max(0, content_match.start() - 20): content_match.end() + 60].strip()[:200]
            results.append(ProbeResult(
                title=title,
                category=self.category,
                finding_type="vulnerability",
                severity=severity,
                confidence="CONFIRMED",
                affected_url=url,
                evidence=[f"경로 {path} 본문에서 노출 내용 확인 (content_confirmed): {snippet}"],
                recommendation="해당 민감 경로에 대한 외부 접근을 차단하고 인증/IP 제한을 적용하라.",
                cwe="CWE-200",
                owasp="A05:2021",
                tags=["content_confirmed", probe_key],
                probe_key=probe_key,
                raw={"url": url, "status": status if status is not None else 200,
                     "content_confirmed": True},
            ))
        return results

    async def _fetch_body_status(self, ctx: ProbeContext, url: str):
        """GET 1회로 (body, status) 반환. throttle/rate_limiter 준수. 실패 시 (None, None)."""
        await ctx.throttle()
        try:
            async with ctx.session.get(url, allow_redirects=False) as resp:
                status = resp.status
                if status != 200:
                    return None, status
                return await resp.text(errors="ignore"), status
        except Exception:
            return None, None

    @staticmethod
    def _unpack(item):
        if isinstance(item, dict):
            return item.get("url", ""), item.get("status"), item.get("body")
        return str(item or ""), None, None

    async def _fetch_body(self, ctx: ProbeContext, url: str):
        await ctx.throttle()
        try:
            async with ctx.session.get(url, allow_redirects=False) as resp:
                if resp.status != 200:
                    return None
                return await resp.text(errors="ignore")
        except Exception:
            return None


PROBE = InfoDisclosureProbe()
