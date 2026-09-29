"""무인증 쓰기 접근통제(BAC) 프로브 — 비파괴 실증 회귀 테스트.

- 취약: 로그인 없이 상태변경 엔드포인트가 핸들러 처리(200) → 확정
- 안전: 401/403 또는 로그인 리다이렉트 → 오탐 0
- 비파괴: 실제 리소스 ID(5)가 아니라 존재하지 않는 ID로 중화되어 요청됨
"""
import asyncio

import aiohttp
from aiohttp import web

import active_probing as ap


def _run(coro):
    return asyncio.run(coro)


async def _serve(routes):
    app = web.Application()
    for method, path, handler in routes:
        app.router.add_route(method, path, handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}"


def test_unauth_write_bac_confirmed_and_nondestructive():
    async def t():
        async def del_vuln(request):     # 세션 없이도 삭제 처리 = 취약
            return web.Response(text="게시글이 삭제되었습니다")

        runner, base = await _serve([("POST", "/board/delete/{id}", del_vuln),
                                     ("DELETE", "/board/delete/{id}", del_vuln)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_unauth_write_bac(
                    s, base, [], discovered_urls=[f"{base}/board/delete/5"], scan_id="t1")
        finally:
            await runner.cleanup()

    res = _run(t())
    assert res and res["type"] == "unauth_write_bac" and res["confirmed"] is True
    # 비파괴: 실제 id(5)가 아니라 존재하지 않는 ID로 중화되어야 함
    assert res["url"].rstrip("/").endswith("999000999")
    assert "게시글 작성" in res["evidence"] or "상태 변경" in res["evidence"]


def test_unauth_write_bac_safe_403_no_fp():
    async def t():
        async def del_protected(request):   # 인증 강제 = 안전
            return web.Response(status=403, text="Forbidden")

        runner, base = await _serve([("POST", "/board/delete/{id}", del_protected),
                                     ("DELETE", "/board/delete/{id}", del_protected)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_unauth_write_bac(
                    s, base, [], discovered_urls=[f"{base}/board/delete/5"], scan_id="t2")
        finally:
            await runner.cleanup()

    assert _run(t()) is None


def test_unauth_write_bac_login_redirect_safe():
    async def t():
        async def upd_redirect(request):    # 로그인으로 리다이렉트 = 안전
            raise web.HTTPFound("/login?next=/notice")

        runner, base = await _serve([("POST", "/notice/update/{id}", upd_redirect)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_unauth_write_bac(
                    s, base, [], discovered_urls=[f"{base}/notice/update/3"], scan_id="t3")
        finally:
            await runner.cleanup()

    assert _run(t()) is None


def test_unauth_write_bac_toggle_off():
    import os
    os.environ["ENABLE_UNAUTH_WRITE_BAC"] = "false"
    try:
        async def t():
            async def del_vuln(request):
                return web.Response(text="삭제되었습니다")
            runner, base = await _serve([("POST", "/board/delete/{id}", del_vuln)])
            try:
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                    return await ap._probe_unauth_write_bac(
                        s, base, [], discovered_urls=[f"{base}/board/delete/5"], scan_id="t4")
            finally:
                await runner.cleanup()
        assert _run(t()) is None      # 토글 OFF → 미수행
    finally:
        os.environ.pop("ENABLE_UNAUTH_WRITE_BAC", None)


def test_unauth_write_bac_contract_wired():
    """gather key ↔ rule_engine 템플릿/OWASP 계약 정합(누락 시 findings 조용히 드롭)."""
    import rule_engine as re_
    assert "unauth_write_bac" in re_._ACTIVE_PROBE_TEMPLATES
    assert "unauth_write_bac" in re_._OWASP_MAPPING
    tpl = re_._ACTIVE_PROBE_TEMPLATES["unauth_write_bac"]
    assert tpl["cwe"] == "CWE-862" and tpl["severity"] == "HIGH"
