"""probes/utils/http_client.py — probe 용 aiohttp 세션 팩토리 (SSL 검증 완화, 타임아웃)."""
from __future__ import annotations

import ssl

import aiohttp

_SCANNER_UA = "Eoseureum-Scanner/1.0 (Security Assessment)"


def make_session(timeout: float = 8.0, cookies: list | None = None) -> aiohttp.ClientSession:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = aiohttp.TCPConnector(ssl=ctx, limit=10)
    # unsafe jar: IP 호스트(127.0.0.1 등) 쿠키도 보존 — 인증 세션·IP 대상 스캔에 필요.
    # (기본 jar 는 IP 호스트 Set-Cookie 를 폐기해 로그인 세션 쿠키가 사라진다)
    cookie_jar = aiohttp.CookieJar(unsafe=True)
    headers = {"User-Agent": _SCANNER_UA}
    return aiohttp.ClientSession(
        connector=conn,
        timeout=aiohttp.ClientTimeout(total=timeout),
        headers=headers,
        cookie_jar=cookie_jar,
    )
