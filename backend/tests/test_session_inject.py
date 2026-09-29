"""세션 주입 인증 — 스코프 안전 헤더 주입 + 요청 관문 배선 + no-op 격리."""
import asyncio

import aiohttp
from aiohttp import web

import session_inject as si
import active_probing as ap


def _run(c):
    return asyncio.run(c)


def test_parse_headers_multiline():
    h = si.parse_headers("Authorization: JWT abc\nX-A: 1")
    assert h == {"Authorization": "JWT abc", "X-A": "1"}


def test_scope_only_target_host():
    si.install(headers="Authorization: JWT tok", host="app.example.com")
    try:
        assert si.headers_for("https://app.example.com/x")["Authorization"] == "JWT tok"
        assert si.headers_for("https://a.app.example.com/y")["Authorization"] == "JWT tok"
        assert si.headers_for("https://evil.com/z") == {}          # 제3자 유출 방지
        assert si.headers_for("https://app.example.com.evil.com/") == {}  # 스코프 우회 방지
    finally:
        si.uninstall()


def test_get_injects_header_to_target(monkeypatch):
    """active_probing._get 이 대상 호스트 요청에 세션 헤더를 실어 보낸다."""
    async def t():
        got = {}

        async def h(req):
            got["auth"] = req.headers.get("Authorization", "")
            return web.Response(text="ok")
        app = web.Application(); app.router.add_get("/{t:.*}", h)
        runner = web.AppRunner(app); await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
        port = site._server.sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/p"
        # 대상 호스트를 127.0.0.1 로 설치(테스트 서버)
        si.install(headers="Authorization: JWT mytoken", host="127.0.0.1")
        try:
            async with aiohttp.ClientSession() as s:
                await ap._get(s, url)
            return got.get("auth")
        finally:
            si.uninstall()
            await runner.cleanup()
    assert _run(t()) == "JWT mytoken"


def test_get_no_inject_offscope(monkeypatch):
    """스코프 밖 호스트에는 세션 헤더를 주입하지 않는다."""
    async def t():
        got = {}

        async def h(req):
            got["auth"] = req.headers.get("Authorization", "")
            return web.Response(text="ok")
        app = web.Application(); app.router.add_get("/{t:.*}", h)
        runner = web.AppRunner(app); await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
        port = site._server.sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/p"
        si.install(headers="Authorization: JWT secret", host="app.example.com")  # 다른 호스트
        try:
            async with aiohttp.ClientSession() as s:
                await ap._get(s, url)
            return got.get("auth")
        finally:
            si.uninstall()
            await runner.cleanup()
    assert _run(t()) == ""   # 127.0.0.1 은 대상(app.example.com) 아님 → 미주입


def test_noop_without_install():
    assert si.active() is False
    assert si.headers_for("https://app.example.com/") == {}


def test_update_headers_swaps_token_in_scope():
    """refresh 갱신 시뮬 — update_headers 로 Authorization 교체 후 대상 요청에 새 값 반영."""
    si.install(headers="Authorization: JWT old", host="app.example.com")
    try:
        assert si.headers_for("https://app.example.com/x")["Authorization"] == "JWT old"
        si.update_headers("Authorization: JWT new")
        assert si.headers_for("https://app.example.com/x")["Authorization"] == "JWT new"
        assert si.headers_for("https://evil.com/x") == {}   # 스코프 유지
    finally:
        si.uninstall()


def test_update_headers_noop_without_install():
    si.uninstall()
    assert si.update_headers("Authorization: JWT x") is None


async def _mutation_visible_in_child():
    """install 이후 생성된 자식 태스크가 in-place 갱신을 보는지(컨텍스트 공유) 확인."""
    si.install(headers="Authorization: JWT old", host="app.example.com")
    seen = {}

    async def child():
        await asyncio.sleep(0.01)
        seen["v"] = si.headers_for("https://app.example.com/")["Authorization"]

    t = asyncio.ensure_future(child())      # install 이후 생성 → 같은 headers dict 공유
    si.update_headers("Authorization: JWT new")   # 제자리 변경
    await t
    si.uninstall()
    return seen["v"]


def test_update_headers_visible_across_tasks():
    assert _run(_mutation_visible_in_child()) == "JWT new"


def test_host_from_target():
    """main.py run_scan 의 세션 설치 host 파생 회귀(과거 bare urllib NameError 버그)."""
    assert si.host_from_target("app.example.com") == "app.example.com"
    assert si.host_from_target("https://app.example.com") == "app.example.com"
    assert si.host_from_target("http://app.example.com/login/main") == "app.example.com"
    assert si.host_from_target("HTTPS://APP.EXAMPLE.com") == "app.example.com"
    assert si.host_from_target("") == ""


def test_session_block_after_send_def_in_run_scan():
    """회귀: run_scan 의 세션 설치 블록은 반드시 `send` 정의 이후에 있어야 한다.
    (앞서면 `await send(...)` 가 UnboundLocalError → 세션 주입이 조용히 '설치 스킵' 됨)"""
    import os
    src = open(os.path.join(os.path.dirname(__file__), "..", "main.py"), encoding="utf-8").read()
    rs = src.index("async def run_scan(")
    body = src[rs:]
    i_send = body.index("async def send(")
    i_sess = body.index('if _scan_auth.get("auth_method") == "session":')
    assert i_send < i_sess, "세션 설치 블록이 send 정의보다 앞서 있음(UnboundLocalError 위험)"


def test_install_with_derived_host_injects():
    """host_from_target 로 파생한 호스트로 install → 대상에만 주입(통합 경로 재현)."""
    host = si.host_from_target("https://app.example.com/login")
    si.install(headers="Authorization: JWT tok", host=host)
    try:
        assert si.headers_for("https://app.example.com/api")["Authorization"] == "JWT tok"
        assert si.headers_for("https://cdn.other.com/x") == {}
    finally:
        si.uninstall()
