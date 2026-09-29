"""S5: 발견 엔드포인트 청크 파라미터 마이닝 확장 — 응답캐시(=governed 스캔) 설치 시 수행."""
import asyncio

import aiohttp
from aiohttp import web

import active_probing as ap
import adaptive_throttle as at
import response_cache as rc


def _run(c):
    return asyncio.run(c)


async def _serve():
    async def base(req):
        # 정적(반사 없음, 링크 없음) → base 마이닝은 아무것도 못 찾음
        return web.Response(text="<html><body>home</body></html>", content_type="text/html")

    async def reflect_page(req):
        # 모든 쿼리 값을 본문에 에코 → param_miner 카나리 반사 탐지
        echoed = " ".join(req.query.values())
        return web.Response(text=f"<html>{echoed}</html>", content_type="text/html")

    app = web.Application()
    app.router.add_get("/", base)
    app.router.add_get("/xyzpage", reflect_page)
    runner = web.AppRunner(app); await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
    return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"


def _fast(monkeypatch):
    # 테스트 속도: SAFE rps/conc 상향 + 워드리스트 축소
    monkeypatch.setenv("EOSEUREUM_SAFE_RPS", "100")
    monkeypatch.setenv("EOSEUREUM_SAFE_CONC", "6")
    monkeypatch.setenv("PARAM_MINING_MAX", "24")
    monkeypatch.setenv("SAFE_MINE_MAX_PARAMS", "24")


def test_discovered_endpoint_mined_when_governed(monkeypatch):
    _fast(monkeypatch)

    async def t():
        runner, base = await _serve()
        try:
            at.install_profile("SAFE")
            rc.install()                 # S5 게이트 = 응답캐시 설치
            async with aiohttp.ClientSession() as s:
                pts = await ap._extract_injection_points(
                    s, base + "/", discovered_urls=[base + "/xyzpage"])
            return pts
        finally:
            at.uninstall(); rc.uninstall()
            await runner.cleanup()

    pts = _run(t())
    mined = [p for p in pts if p.get("source") == "param_mining_discovered"]
    assert mined, "발견 엔드포인트 마이닝 결과 없음"
    assert any("/xyzpage" in p["url"] for p in mined)
    assert mined[0].get("params")


def test_no_discovered_mining_without_cache(monkeypatch):
    """캐시 미설치(=비-governed)면 발견 엔드포인트 마이닝을 하지 않음(기존 동작)."""
    monkeypatch.setenv("PARAM_MINING_MAX", "24")

    async def t():
        runner, base = await _serve()
        try:
            at.uninstall(); rc.uninstall()
            async with aiohttp.ClientSession() as s:
                pts = await ap._extract_injection_points(
                    s, base + "/", discovered_urls=[base + "/xyzpage"])
            return pts
        finally:
            await runner.cleanup()

    pts = _run(t())
    assert not [p for p in pts if p.get("source") == "param_mining_discovered"]


def test_out_of_scope_discovered_not_mined(monkeypatch):
    """스코프 밖 발견 URL 은 마이닝하지 않음(제3자 요청 방지)."""
    _fast(monkeypatch)

    async def t():
        runner, base = await _serve()
        try:
            at.install_profile("SAFE")
            rc.install()
            async with aiohttp.ClientSession() as s:
                pts = await ap._extract_injection_points(
                    s, base + "/", discovered_urls=["http://evil.example.com/xyzpage"])
            return pts
        finally:
            at.uninstall(); rc.uninstall()
            await runner.cleanup()

    pts = _run(t())
    assert not any("evil.example.com" in (p.get("url") or "") for p in pts)
