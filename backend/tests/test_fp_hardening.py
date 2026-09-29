"""오탐(FP) 하드닝 회귀 — 감사에서 지적된 약한 확정 로직 강화 검증."""
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


# ── A. 미인증 특권 콘텐츠: 표(<table>)만 있는 공개 페이지는 더 이상 오탐 아님 ──
def test_unauth_priv_no_fp_on_plain_table_page():
    async def t():
        async def page(request):    # /member 경로 + 표 있음 + 관리 콘텐츠 아님(로그인도 아님)
            return web.Response(text="<html><h1>회원 후기</h1><table><tr><td>홍길동</td></tr></table></html>")
        runner, base = await _serve([("GET", "/member/reviews", page)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_unauth_privileged_content(
                    s, base, [], discovered_urls=[f"{base}/member/reviews"], scan_id="p1")
        finally:
            await runner.cleanup()
    assert _run(t()) is None       # 표만으로 특권 콘텐츠 오확정 금지


def test_unauth_priv_still_detects_real_admin_content():
    async def t():
        async def admin(request):
            return web.Response(text="<html><h1>회원 목록</h1><div>권한 관리 · 결제 내역</div></html>")
        runner, base = await _serve([("GET", "/admin/members", admin)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_unauth_privileged_content(
                    s, base, [], discovered_urls=[f"{base}/admin/members"], scan_id="p2")
        finally:
            await runner.cleanup()
    res = _run(t())
    assert res and res["type"] == "unauth_privileged_content"   # 실제 관리 콘텐츠는 여전히 탐지


# ── D. 무인증 쓰기 BAC: 처리 근거 없는 단순 200 은 CONFIRMED 아님(POSSIBLE) ──
def test_unauth_write_bac_bare_200_is_possible_not_confirmed():
    async def t():
        async def echo_ok(request):   # 입력 무시하고 항상 짧은 200(성공 문구/마커 없음)
            return web.Response(text="ok")
        runner, base = await _serve([("POST", "/board/write", echo_ok)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_unauth_write_bac(
                    s, base, [], discovered_urls=[f"{base}/board/write"], scan_id="w1")
        finally:
            await runner.cleanup()
    res = _run(t())
    assert res and res["confirmed"] is False and res["confidence"] == "POSSIBLE"


def test_unauth_write_bac_confirmed_when_success_signal():
    async def t():
        async def del_ok(request):    # 성공 문구('삭제되었습니다') = 처리 근거 → CONFIRMED
            return web.Response(text="게시글이 삭제되었습니다")
        runner, base = await _serve([("POST", "/board/delete/{id}", del_ok)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                return await ap._probe_unauth_write_bac(
                    s, base, [], discovered_urls=[f"{base}/board/delete/5"], scan_id="w2")
        finally:
            await runner.cleanup()
    res = _run(t())
    assert res and res["confirmed"] is True


# ── JWT: HS256 단독은 더 이상 취약 이슈로 확정하지 않음 ──
def test_jwt_hs256_alone_not_flagged():
    import base64 as _b64, json as _json, time as _t

    def _b(d):
        return _b64.urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b"=").decode()
    # HS256 + 정상 만료 + 민감필드 없음 → 취약 아님(오탐 금지)
    tok = f"{_b({'alg':'HS256','typ':'JWT'})}.{_b({'sub':'u1','exp':int(_t.time())+3600})}.sig"
    assert ap._probe_jwt_from_cookies([{"raw": f"session={tok}; Path=/"}]) is None
    # alg:none 은 여전히 확정
    bad = f"{_b({'alg':'none','typ':'JWT'})}.{_b({'sub':'u1'})}.AAAA"
    assert ap._probe_jwt_from_cookies([{"raw": f"session={bad}; Path=/"}]) is not None
