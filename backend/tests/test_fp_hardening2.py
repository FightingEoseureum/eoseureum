"""FP 하드닝 2차 회귀 — csrf / admin_api / js_secrets / sqli_bool.

각 프로브의 약한 확정을 강화: Origin 위조 신호 / 경로·PII 요구 / 엔트로피 게이트 / 안정성·대조군.
"""
import asyncio

import aiohttp
from aiohttp import web

import active_probing as ap


def _run(coro):
    return asyncio.run(coro)


async def _serve(routes):
    app = web.Application()
    for m, p, h in routes:
        app.router.add_route(m, p, h)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"


# ── CSRF: 스푸핑 Origin 이 거부되면(=Origin 검증) 오탐 아님 ──────────────────────
def _form_point(url):
    return [{"url": url, "method": "POST", "source": "form", "params": {"title": "x", "body": "y"},
             "csrf_fields": []}]


def test_csrf_no_fp_when_origin_checked():
    async def t():
        async def submit(request):
            if "evil" in (request.headers.get("Origin", "") + request.headers.get("Referer", "")):
                return web.Response(status=403, text="forbidden")   # Origin 검증 = 보호됨
            return web.Response(text="ok")
        runner, base = await _serve([("POST", "/post", submit)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_csrf(s, base, _form_point(f"{base}/post"))
        finally:
            await runner.cleanup()
    assert _run(t()) is None       # 스푸핑 Origin 거부 → CSRF 오탐 아님


def test_csrf_confirmed_when_origin_ignored():
    async def t():
        async def submit(request):
            return web.Response(text="ok")   # Origin 무시하고 항상 수락 = 취약
        runner, base = await _serve([("POST", "/post", submit)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_csrf(s, base, _form_point(f"{base}/post"))
        finally:
            await runner.cleanup()
    res = _run(t())
    assert res and res["type"] == "no_csrf_token" and res["confirmed"] is True


# ── admin_api: 키 이름만 있으면 오탐 아님, 실제 PII 있어야 확정 ─────────────────
def test_admin_api_no_fp_key_names_only():
    async def t():
        async def api(request):    # 민감 '키'는 있으나 실제 값(PII) 없음
            return web.json_response({"users": [], "config": {"enabled": True}})
        runner, base = await _serve([("GET", "/api/admin", api)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_admin_api(s, base)
        finally:
            await runner.cleanup()
    assert _run(t()) is None


def test_admin_api_confirmed_with_pii():
    async def t():
        async def api(request):
            return web.json_response({"users": [{"email": "admin@corp.com", "role": "admin"}]})
        runner, base = await _serve([("GET", "/api/admin", api)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_admin_api(s, base)
        finally:
            await runner.cleanup()
    res = _run(t())
    assert res and res["confirmed"] is True


def test_admin_api_public_path_not_probed():
    # /api/users 는 경로 목록에서 제거됨 → 공개 목록 API 오탐 방지
    assert "/api/users" not in ap._ADMIN_API_PATHS_P6
    assert "/api/config" not in ap._ADMIN_API_PATHS_P6


# ── js_secrets: 값 게이트 ────────────────────────────────────────────────────
def test_js_secret_value_gate():
    assert ap._looks_like_real_secret("aK9xQ2mLp7Zr4Tn8Wv") is True
    assert ap._looks_like_real_secret("비밀번호를 입력하세요") is False
    assert ap._looks_like_real_secret("please enter your password") is False
    assert ap._looks_like_real_secret("aaaaaaaa") is False


def test_js_secrets_generic_ui_string_not_confirmed():
    async def t():
        async def home(request):
            return web.Response(text='<script src="/app.js"></script>', content_type="text/html")
        async def appjs(request):     # UI 문자열(한글) — 시크릿 아님
            return web.Response(text='var msg = {password: "비밀번호를 입력하세요"};',
                                content_type="application/javascript")
        runner, base = await _serve([("GET", "/", home), ("GET", "/app.js", appjs)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_js_secrets(s, base)
        finally:
            await runner.cleanup()
    res = _run(t())
    # 결과가 있어도 confirmed 는 아니어야(오탐 방지)
    assert res is None or not res.get("confirmed")


def test_js_secrets_vendor_key_confirmed():
    async def t():
        async def home(request):
            return web.Response(text='<script src="/app.js"></script>', content_type="text/html")
        async def appjs(request):
            return web.Response(text='var k = "AKIA1234567890ABCDEF";',  # AWS 구조 키(예시문구 없음)
                                content_type="application/javascript")
        runner, base = await _serve([("GET", "/", home), ("GET", "/app.js", appjs)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_js_secrets(s, base)
        finally:
            await runner.cleanup()
    res = _run(t())
    assert res and res.get("confirmed") is True


# ── sqli_bool: 동적 콘텐츠(불안정)는 오탐 아님 ───────────────────────────────
def _sqli_point(url):
    return [{"url": url, "method": "GET", "params": {"id": "1"}}]


def test_sqli_bool_no_fp_on_dynamic_content():
    import itertools
    ctr = itertools.count()

    async def t():
        async def page(request):    # 매 요청마다 크기가 달라지는 동적 콘텐츠
            n = next(ctr)
            return web.Response(text="X" * (500 + (n * 137) % 900))
        runner, base = await _serve([("GET", "/item", page)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_sqli_bool(s, _sqli_point(f"{base}/item"))
        finally:
            await runner.cleanup()
    assert _run(t()) is None       # 재요청마다 흔들림 → 안정성 실패 → 오탐 아님
