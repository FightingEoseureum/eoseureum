"""P1: 자체-세션 aiohttp 경로가 rate 거버너에 배선됐는지 — cleanup_manager 검증."""
import asyncio

import aiohttp
from aiohttp import web

import adaptive_throttle as at
import cleanup_manager as cm


def _run(c):
    return asyncio.run(c)


async def _counting_server():
    counter = {"n": 0}

    async def h(req):
        counter["n"] += 1
        return web.Response(text="clean", status=200)

    async def d(req):
        counter["n"] += 1
        return web.Response(text="", status=204)

    app = web.Application()
    app.router.add_get("/{tail:.*}", h)
    app.router.add_post("/{tail:.*}", h)
    app.router.add_route("DELETE", "/{tail:.*}", d)
    runner = web.AppRunner(app); await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
    return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}", counter


def test_cleanup_delete_paced_by_governor(monkeypatch):
    """cleanup DELETE/GET 이 거버너에 물려 페이싱된다(SAFE 5rps → interval 0.2)."""
    import time

    async def t():
        runner, base, _c = await _counting_server()
        try:
            at.install_profile("SAFE")   # 5rps/단독
            lim = at.stage("cleanup")
            async with aiohttp.ClientSession(connector=cm._ssl_connector()) as s:
                t0 = time.monotonic()
                await cm._delete_resource(s, base + "/a")
                await cm._check_marker_gone(s, base + "/b", "marker")
                await cm._delete_resource(s, base + "/c")
                elapsed = time.monotonic() - t0
            return elapsed, lim.samples
        finally:
            at.uninstall()
            await runner.cleanup()
    elapsed, samples = _run(t())
    assert samples == 3            # 3요청 전부 거버너 통과(after 호출)
    assert elapsed >= 0.35         # 5rps → 3요청 ≈ 0.4s (미배선이면 ~0)


def test_cleanup_noop_without_governor():
    """거버너 미설치(PROOF/off)면 페이싱 없음(빠름)."""
    import time

    async def t():
        runner, base, _c = await _counting_server()
        try:
            at.uninstall()
            assert at.stage("cleanup") is None
            async with aiohttp.ClientSession(connector=cm._ssl_connector()) as s:
                t0 = time.monotonic()
                for _ in range(5):
                    await cm._delete_resource(s, base + "/x")
                return time.monotonic() - t0
        finally:
            await runner.cleanup()
    assert _run(t()) < 0.3


def test_cleanup_slot_released_on_error():
    """예외(연결 실패)에도 거버너 슬롯 반납(누수 없음)."""
    async def t():
        at.install_profile("SAFE")
        lim = at.stage("cleanup")
        try:
            async with aiohttp.ClientSession() as s:
                for _ in range(3):
                    await cm._delete_resource(s, "http://127.0.0.1:1/x")   # 연결 실패
            return lim._sem._value
        finally:
            at.uninstall()
    assert _run(t()) == 1   # SAFE 단독 conc1 → 원복(누수 없음)
