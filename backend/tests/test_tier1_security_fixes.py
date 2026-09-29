"""코드검토 티어1 보안 수정 — 스코프우회/auth시크릿/cleanup오보고/OOB오탐 회귀방지."""
import asyncio

import proof_policy as pp
import cleanup_manager as cm
import oob_collaborator as oob


def _run(c):
    return asyncio.run(c)


# ── 1. proof_policy.in_scope 서브스트링 우회 제거 ────────────────────────────
def test_scope_no_substring_bypass():
    scope = ["corp.com"]
    # 정확일치·서브도메인만 허용
    assert pp.in_scope("http://corp.com/", scope) is True
    assert pp.in_scope("http://app.corp.com/", scope) is True
    # 서브스트링 우회는 차단(핵심 수정)
    assert pp.in_scope("http://corp.com.attacker.net/", scope) is False
    assert pp.in_scope("http://notcorp.com/", scope) is False
    assert pp.in_scope("http://evilcorp.com/", scope) is False


def test_scope_internal_still_blocked():
    assert pp.in_scope("http://127.0.0.1/", ["127.0.0.1"]) is False   # 사설/loopback 항상 밖
    assert pp.in_scope("http://169.254.169.254/", None) is False       # 메타데이터


# ── 2. auth 시크릿: 공개 상수 절대 미사용 ────────────────────────────────────
def test_auth_secret_never_public_constant():
    import auth
    assert auth.SECRET_KEY != "security-scanner-secret-change-in-prod"
    assert isinstance(auth.SECRET_KEY, str) and len(auth.SECRET_KEY) >= 32


# ── 3. cleanup: 접근 실패를 성공으로 오보고하지 않음 ──────────────────────────
def test_cleanup_marker_gone_false_on_connection_error():
    async def t():
        async with __import__("aiohttp").ClientSession() as s:
            # 존재하지 않는 포트 → 연결 실패 → '제거 확인 불가' = False (기존엔 True 였음)
            return await cm._check_marker_gone(s, "http://127.0.0.1:1/x", "marker")
    assert _run(t()) is False


def test_cleanup_marker_gone_true_when_actually_absent():
    """마커가 실제로 없으면(정상 응답) True — 정상 경로는 유지."""
    from aiohttp import web

    async def t():
        async def h(req):
            return web.Response(text="clean page, no marker here")
        app = web.Application(); app.router.add_get("/{t:.*}", h)
        runner = web.AppRunner(app); await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
        url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/p"
        try:
            import aiohttp
            async with aiohttp.ClientSession() as s:
                return await cm._check_marker_gone(s, url, "MYMARKER")
        finally:
            await runner.cleanup()
    assert _run(t()) is True


# ── 4. OOB raw-TCP: 데이터 없는 단순 connect 는 히트 아님(오탐 방지) ──────────
def test_oob_raw_bare_connect_not_hit():
    async def t():
        c = oob.OOBCollaborator("127.0.0.1")
        ep = await c.new_raw_endpoint()
        token, hostport = ep
        host, port = hostport.split(":")
        # 바이트 전송 없이 connect 후 즉시 close (포트스캐너/헬스체크 흉내)
        reader, writer = await asyncio.open_connection(host, int(port))
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await asyncio.sleep(0.3)
        bare = c.was_hit(token)
        # 데이터를 보내면 히트
        r2, w2 = await asyncio.open_connection(host, int(port))
        w2.write(b"\x30\x0c\x02\x01\x01")   # LDAP 유사 바이트
        await w2.drain(); w2.close()
        await asyncio.sleep(0.4)
        withdata = c.was_hit(token)
        await c.stop()
        return bare, withdata
    bare, withdata = _run(t())
    assert bare is False      # 단순 connect → 히트 아님(오탐 방지)
    assert withdata is True   # 데이터 전송 → 히트(실 JNDI 확증 유지)
