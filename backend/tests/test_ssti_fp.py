"""SSTI 오탐 수정 회귀 — 마커-차등 확인.

- 서버가 표현식을 실제 '평가'하면(마커 사이 결과) 확정
- 표현식을 그대로 반사만 하거나, 본문 아무 곳에 '49'가 우연히 있어도 오탐 아님
  (ASP.NET/IIS 사이트에 Jinja {{7*7}} 가 Critical 로 오확정되던 버그 방지)
"""
import asyncio
import re

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


def _pt(url):
    return [{"url": url, "method": "GET", "params": {"q": "x"}}]


def test_ssti_confirmed_when_actually_evaluated():
    async def t():
        async def evalpage(request):     # {{7*7}} 를 실제로 49 로 평가(진짜 SSTI)
            q = request.query.get("q", "")
            return web.Response(text="<p>" + q.replace("{{7*7}}", "49") + "</p>")
        runner, base = await _serve([("GET", "/n", evalpage)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_ssti(s, _pt(f"{base}/n"), scan_id="s1")
        finally:
            await runner.cleanup()

    res = _run(t())
    assert res and res["confirmed"] is True and res["expected_result"] == "49"
    assert res["engine"].startswith("Jinja")


def test_ssti_no_fp_on_reflect_and_incidental_49():
    async def t():
        async def reflectpage(request):  # 평가 안 함: 원문 반사 + 페이지 곳곳에 49 존재
            q = request.query.get("q", "")
            return web.Response(text=f"<p>{q}</p><span>조회수 49 · 상품번호 4900</span>")
        runner, base = await _serve([("GET", "/n", reflectpage)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_ssti(s, _pt(f"{base}/n"), scan_id="s2")
        finally:
            await runner.cleanup()

    assert _run(t()) is None       # 반사 + 우연 49 → SSTI 아님(오탐 0)


def test_ssti_no_fp_on_plain_page():
    async def t():
        async def plain(request):
            return web.Response(text="<html><body>뉴스 49건 · 2049년</body></html>")
        runner, base = await _serve([("GET", "/n", plain)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_ssti(s, _pt(f"{base}/n"), scan_id="s3")
        finally:
            await runner.cleanup()

    assert _run(t()) is None
