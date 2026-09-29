"""P4: boolean-blind SQLi 통계적 차등 루프 — 일관된 true≠false 는 확증, 간헐 변동은 거부."""
import asyncio

import aiohttp
from aiohttp import web

import active_probing as ap


def _run(c):
    return asyncio.run(c)


async def _serve(handler):
    app = web.Application()
    app.router.add_route("*", "/item", handler)
    runner = web.AppRunner(app); await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
    return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/item"


def test_consistent_true_false_confirmed():
    async def t():
        async def h(req):
            q = req.query.get("id", "")
            if "OR '1'='1" in q or "OR 1=1" in q or "OR 1 in(1)" in q or "'1'='1" in q:
                return web.Response(text="U" * 2000)
            return web.Response(text="S" * 100)
        runner, url = await _serve(h)
        try:
            async with aiohttp.ClientSession() as s:
                return await ap._probe_sqli_bool(s, [{"method": "GET", "url": url, "params": {"id": "1"}}])
        finally:
            await runner.cleanup()
    r = _run(t())
    assert r and r.get("confirmed") is True and r["type"] == "boolean_based"


def test_intermittent_variation_rejected():
    import itertools
    ctr = itertools.count()

    async def t():
        async def h(req):
            n = next(ctr)
            return web.Response(text="X" * (300 + (n * 173) % 1500))
        runner, url = await _serve(h)
        try:
            async with aiohttp.ClientSession() as s:
                return await ap._probe_sqli_bool(s, [{"method": "GET", "url": url, "params": {"id": "1"}}])
        finally:
            await runner.cleanup()
    assert _run(t()) is None
