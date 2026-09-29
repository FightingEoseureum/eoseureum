"""React2Shell(CVE-2025-55182) 상관·탐지 프로브 — 비파괴 회귀 테스트.

- 취약 스택(Next.js/RSC) + Server Actions 파이프라인 응답 → Critical CVE 노출 확정
- Next.js 지문만 있고 Server Actions 없음 → 미보고(오탐 억제)
- 일반(비-React) 사이트 → 미보고
- cve_intel 상관/계약(rule_engine 템플릿·OWASP) 정합
"""
import asyncio

import aiohttp
from aiohttp import web

import active_probing as ap
import cve_intel


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


def test_cve_intel_correlates_react2shell():
    hits = cve_intel.correlate("<script>window.__NEXT_DATA__={...}</script> /_next/static")
    assert any(h["cve"] == "CVE-2025-55182" for h in hits)
    assert not cve_intel.correlate("<html>plain php site</html>")


def test_react2shell_surface_flagged_when_server_actions_active():
    async def t():
        async def home(request):        # Next.js/RSC 지문
            return web.Response(text="<html><script>self.__next_f=[];window.__NEXT_DATA__={}</script>"
                                     "<link href='/_next/static/x.css'></html>")

        async def action(request):      # Next-Action 요청에 RSC(text/x-component)로 응답 = 취약 표면
            if request.headers.get("Next-Action"):
                return web.Response(text='0:I["react-server"]\n', content_type="text/x-component")
            return web.Response(text="<html>page</html>")

        runner, base = await _serve([("GET", "/", home), ("POST", "/", action)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_react2shell(s, base, discovered_urls=[], scan_id="r1")
        finally:
            await runner.cleanup()

    res = _run(t())
    # 파이프라인 활성 = '취약 표면 노출'이지 미패치 증거는 아님 → confirmed=False(확인 필요) + Critical·CVE 유지
    assert res and res["type"] == "react2shell"
    assert res["confirmed"] is False and res["confidence"] == "MANUAL_REVIEW"
    assert "CVE-2025-55182" in res["cve_references"]


def test_react2shell_no_fp_fingerprint_only():
    async def t():
        async def home(request):        # Next.js 지문은 있으나 Server Actions 미활성
            return web.Response(text="<script>window.__NEXT_DATA__={}</script>/_next/static")

        async def nostate(request):     # Next-Action 요청도 평범한 HTML(파이프라인 없음)
            return web.Response(text="<html>ordinary</html>")

        runner, base = await _serve([("GET", "/", home), ("POST", "/", nostate)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_react2shell(s, base, discovered_urls=[], scan_id="r2")
        finally:
            await runner.cleanup()

    assert _run(t()) is None      # 지문만 → 미보고(오탐 억제)


def test_react2shell_no_fp_non_react():
    async def t():
        async def home(request):
            return web.Response(text="<html><body>PHP shop</body></html>")

        runner, base = await _serve([("GET", "/", home), ("POST", "/", home)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_react2shell(s, base, discovered_urls=[], scan_id="r3")
        finally:
            await runner.cleanup()

    assert _run(t()) is None


def test_react2shell_contract_wired():
    import rule_engine as re_
    assert "react2shell" in re_._ACTIVE_PROBE_TEMPLATES
    assert "react2shell" in re_._OWASP_MAPPING
    tpl = re_._ACTIVE_PROBE_TEMPLATES["react2shell"]
    assert tpl["severity"] == "CRITICAL" and "CVE-2025-55182" in tpl["cve_references"]


# ── CVE KB 확대 + 일반 상관 프로브 ───────────────────────────────────────────
def test_cve_intel_has_multiple_entries():
    assert cve_intel.get("CVE-2025-55182") and cve_intel.get("CVE-2025-29927")
    hits = cve_intel.correlate("<script>window.__NEXT_DATA__={}</script>/_next/")
    ids = {h["cve"] for h in hits}
    assert {"CVE-2025-55182", "CVE-2025-29927"} <= ids


def test_cve_correlation_probe_surfaces_nondedicated():
    async def t():
        async def home(request):
            return web.Response(text="<script>window.__NEXT_DATA__={}</script>/_next/static")
        runner, base = await _serve([("GET", "/", home)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_cve_correlation(s, base, scan_id="c1")
        finally:
            await runner.cleanup()

    res = _run(t())
    assert res and res["type"] == "cve_exposure"
    # 전용 프로브(react2shell)는 제외되고, 비전용(CVE-2025-29927)만 승격
    assert "CVE-2025-29927" in res["cve_references"]
    assert "CVE-2025-55182" not in res["cve_references"]


def test_cve_correlation_none_on_non_matching():
    async def t():
        async def home(request):
            return web.Response(text="<html>plain apache php</html>")
        runner, base = await _serve([("GET", "/", home)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_cve_correlation(s, base, scan_id="c2")
        finally:
            await runner.cleanup()

    assert _run(t()) is None


def test_cve_exposure_contract_wired():
    import rule_engine as re_
    assert "cve_exposure" in re_._ACTIVE_PROBE_TEMPLATES
    assert "cve_exposure" in re_._OWASP_MAPPING
