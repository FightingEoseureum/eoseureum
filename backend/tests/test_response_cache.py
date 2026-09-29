"""Safe 모드 응답 재사용 캐시(S4) — 중복 GET 제거 + 변경 후 신선도 보장(정확성 불변식)."""
import asyncio

import aiohttp
from aiohttp import web

import response_cache as rc
import active_probing as ap


def _run(c):
    return asyncio.run(c)


# ── 단위 ──────────────────────────────────────────────────────────────────────
def test_put_get_roundtrip():
    c = rc.ResponseCache()
    assert c.get("http://t/a") is None
    c.put("http://t/a", (200, "body", {"X": "1"}))
    hit = c.get("http://t/a")
    assert hit == (200, "body", {"X": "1"})
    assert c.hits == 1 and c.stores == 1


def test_get_returns_header_copy():
    c = rc.ResponseCache()
    c.put("http://t/a", (200, "b", {"X": "1"}))
    _, _, h = c.get("http://t/a")
    h["X"] = "mutated"
    _, _, h2 = c.get("http://t/a")
    assert h2["X"] == "1"   # 캐시 원본 불변


def test_invalidate_clears():
    c = rc.ResponseCache()
    c.put("http://t/a", (200, "b", {}))
    c.invalidate()
    assert c.get("http://t/a") is None
    assert c.invalidations == 1


def test_cap_evicts_oldest():
    c = rc.ResponseCache(cap=2)
    c.put("u1", (200, "a", {}))
    c.put("u2", (200, "b", {}))
    c.put("u3", (200, "c", {}))   # u1 축출
    assert c.get("u1") is None
    assert c.get("u3") is not None


def test_max_body_not_cached():
    c = rc.ResponseCache(max_body=10)
    c.put("u", (200, "x" * 100, {}))
    assert c.get("u") is None   # 대용량 미저장


# ── 통합(_get/_post) ──────────────────────────────────────────────────────────
async def _counting_server():
    counter = {"n": 0}

    async def h(req):
        counter["n"] += 1
        return web.Response(text=f"hit{counter['n']}")
    app = web.Application()
    app.router.add_get("/", h)
    app.router.add_post("/", h)
    runner = web.AppRunner(app); await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
    url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/"
    return runner, url, counter


def test_duplicate_get_served_from_cache():
    async def t():
        runner, url, counter = await _counting_server()
        try:
            rc.install()
            async with aiohttp.ClientSession() as s:
                a = await ap._get(s, url)
                b = await ap._get(s, url)
                c = await ap._get(s, url)
            return counter["n"], a, b, c
        finally:
            rc.uninstall()
            await runner.cleanup()
    n, a, b, c = _run(t())
    assert n == 1                 # 서버는 1회만 맞음
    assert a == b == c            # 3요청 동일 응답(캐시)


def test_post_invalidates_then_get_is_fresh():
    """저장형 XSS 정확성: 주입(POST) 후 페이지 GET 은 반드시 신선한 응답."""
    async def t():
        runner, url, counter = await _counting_server()
        try:
            rc.install()
            async with aiohttp.ClientSession() as s:
                first = await ap._get(s, url)      # 서버 hit1, 캐시됨
                cached = await ap._get(s, url)     # 캐시(여전히 hit1)
                await ap._post(s, url, data={"x": "1"})  # 상태변경 → 캐시 무효화(서버 hit2)
                after = await ap._get(s, url)      # 신선 재요청(서버 hit3)
            return counter["n"], first, cached, after
        finally:
            rc.uninstall()
            await runner.cleanup()
    n, first, cached, after = _run(t())
    assert first == cached            # 무효화 전엔 캐시 재사용
    assert after != first             # 무효화 후엔 신선(다른 응답)
    assert n == 3                     # GET1 + POST + GET3 (GET2는 캐시)


def test_custom_header_get_bypasses_cache():
    async def t():
        runner, url, counter = await _counting_server()
        try:
            rc.install()
            async with aiohttp.ClientSession() as s:
                await ap._get(s, url, headers={"X-Test": "1"})   # 커스텀 헤더 → 캐시 우회
                await ap._get(s, url, headers={"X-Test": "1"})   # 또 우회
            return counter["n"]
        finally:
            rc.uninstall()
            await runner.cleanup()
    assert _run(t()) == 2   # 캐시 안 됨 → 서버 2회


def test_no_cache_installed_no_dedup():
    async def t():
        runner, url, counter = await _counting_server()
        try:
            rc.uninstall()
            async with aiohttp.ClientSession() as s:
                await ap._get(s, url)
                await ap._get(s, url)
            return counter["n"]
        finally:
            await runner.cleanup()
    assert _run(t()) == 2   # 미설치 → 중복 그대로


def test_cache_hit_skips_throttle(monkeypatch):
    """캐시 히트는 네트워크·스로틀을 소비하지 않음(요청이 실제로 안 나감)."""
    import adaptive_throttle as at

    async def t():
        runner, url, counter = await _counting_server()
        try:
            rc.install()
            at.install("conservative")
            thr = at.stage("active_probing")   # _get 이 쓰는 리미터
            async with aiohttp.ClientSession() as s:
                await ap._get(s, url)     # miss → throttle before/after 1회
                await ap._get(s, url)     # hit → throttle 미소비
                await ap._get(s, url)     # hit → throttle 미소비
            return thr.samples, counter["n"]
        finally:
            rc.uninstall(); at.uninstall()
            await runner.cleanup()
    samples, n = _run(t())
    assert n == 1           # 서버 1회
    assert samples == 1     # 스로틀도 1회만(히트는 미소비)
