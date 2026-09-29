"""Safe 모드 적응형 스로틀(S1/S2) — AIMD 감가속·백오프·동시성·페이싱·no-op 격리."""
import asyncio
import time

import aiohttp
from aiohttp import web

import adaptive_throttle as at
import active_probing as ap


def _run(c):
    return asyncio.run(c)


def test_default_profile_conservative():
    t = at.AdaptiveThrottle("conservative")
    # 안전 최우선 기본 = 증속 끄기 → 시작부터 상한(5rps)에 고정
    assert t.conc == 2 and t.rate == 5.0 and t.rate_max == 5.0
    assert t.slo_factor == 1.2 and t.md_factor == 0.5
    assert t.ramp is False


def test_no_ramp_default_starts_at_ceiling():
    t = at.AdaptiveThrottle("conservative")
    r0 = t.rate
    for _ in range(30):
        t.after(0.001, 200, None)   # 계속 건강해도 증속 안 함(고정)
    assert t.rate == r0 == 5.0
    assert t.increases == 0


def test_ramp_can_be_enabled(monkeypatch):
    monkeypatch.setenv("EOSEUREUM_SAFE_RAMP", "on")
    t = at.AdaptiveThrottle("conservative")
    assert t.rate == 1.0   # 증속 모드에선 낮게 시작
    for _ in range(9):
        t.after(0.01, 200, None)
    assert t.rate > 1.0 and t.increases == 3


def test_safe_mode_hard_cap_5rps():
    """Safe 모드 절대 상한 = 초당 5개(기본). conservative rate_max 도 5."""
    assert at.AdaptiveThrottle("conservative").rate_max == 5.0


def test_hard_cap_clamps_aggressive():
    """공격적 프로파일(rate_max 25)도 safe 절대상한 5 로 클램프."""
    t = at.AdaptiveThrottle("aggressive")
    assert t.rate_max == 5.0
    assert t.rate <= 5.0


def test_env_can_lower_cap(monkeypatch):
    monkeypatch.setenv("EOSEUREUM_SAFE_MAX_RPS", "2")
    t = at.AdaptiveThrottle("conservative")
    assert t.rate_max == 2.0 and t.rate <= 2.0


def test_aimd_never_exceeds_5rps():
    """AIMD 증속도 절대상한 5 를 넘지 못함."""
    t = at.AdaptiveThrottle("conservative")
    for _ in range(300):
        t.after(0.001, 200, None)   # 계속 건강 → 최대치까지 증속
    assert t.rate <= 5.0 + 1e-9


def test_increase_on_healthy(monkeypatch):
    monkeypatch.setenv("EOSEUREUM_SAFE_RAMP", "on")   # 증속 모드에서만 증속 검증
    t = at.AdaptiveThrottle("conservative")
    r0 = t.rate
    # baseline 0.01s, 이후 계속 건강(0.01) → 3회마다 1스텝 증속
    for _ in range(9):
        t.after(0.01, 200, None)
    assert t.rate > r0
    assert t.increases == 3
    assert t.rate <= t.rate_max


def test_decrease_on_high_latency():
    t = at.AdaptiveThrottle("conservative")
    # baseline 확립(빠른 응답 몇 개)
    for _ in range(3):
        t.after(0.01, 200, None)
    r_before = t.rate
    # 지연 급증(> slo×baseline) → 감속
    t.after(0.2, 200, None)
    assert t.rate < r_before
    assert t.decreases >= 1


def test_backoff_on_429_and_retry_after():
    t = at.AdaptiveThrottle("conservative")
    for _ in range(3):
        t.after(0.01, 200, None)
    r_before = t.rate
    t.after(0.01, 429, "2")           # 429 + Retry-After: 2s
    assert t.rate <= r_before * 0.5 + 1e-9   # 강한 감속(×md=0.5)
    assert t._backoff_until > time.monotonic()
    assert t.retry_after_hits == 1


def test_503_triggers_strong_decrease():
    t = at.AdaptiveThrottle("conservative")
    for _ in range(3):
        t.after(0.01, 200, None)
    r = t.rate
    t.after(0.01, 503, None)
    assert t.rate <= r * 0.5 + 1e-9


def test_rate_floor_not_below_min():
    t = at.AdaptiveThrottle("conservative")
    for _ in range(50):
        t.after(0.01, 503, None)      # 계속 감속
    assert t.rate >= t.rate_min


def test_concurrency_semaphore_balanced():
    async def t():
        thr = at.AdaptiveThrottle("conservative")
        for _ in range(5):
            await thr.before()
            thr.after(0.01, 200, None)
        return thr._sem._value
    # 획득/반납 균형 → 세마포어가 원래 값(2)으로 복귀
    assert _run(t()) == 2


def test_before_enforces_min_interval(monkeypatch):
    async def t():
        monkeypatch.setenv("SAFE_THROTTLE_RATE_START", "10")   # interval 0.1s
        monkeypatch.setenv("SAFE_THROTTLE_RATE_MAX", "10")
        thr = at.AdaptiveThrottle("conservative")
        t0 = time.monotonic()
        await thr.before(); thr.after(0.001, 200, None)
        await thr.before(); thr.after(0.001, 200, None)
        await thr.before(); thr.after(0.001, 200, None)
        return time.monotonic() - t0
    # 3요청 → 최소 2 간격(0.1s) ≈ 0.2s 이상
    assert _run(t()) >= 0.18


def test_no_controller_is_noop():
    assert at.current() is None
    at.uninstall()
    assert at.current() is None


def test_install_uninstall_roundtrip():
    async def t():
        assert at.current() is None
        inst = at.install("conservative")
        assert at.current() is inst
        at.uninstall()
        return at.current()
    assert _run(t()) is None


def test_get_paced_when_installed(monkeypatch):
    """_get 이 스로틀 설치 시 페이싱된다(설치 안 하면 즉시)."""
    async def serve():
        async def h(req):
            return web.Response(text="ok")
        app = web.Application(); app.router.add_get("/", h)
        runner = web.AppRunner(app); await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
        return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/"

    async def t():
        monkeypatch.setenv("SAFE_THROTTLE_RATE_START", "5")   # interval 0.2s
        monkeypatch.setenv("SAFE_THROTTLE_RATE_MAX", "5")
        runner, url = await serve()
        try:
            at.install("conservative")
            async with aiohttp.ClientSession() as s:
                t0 = time.monotonic()
                for _ in range(3):
                    await ap._get(s, url)
                elapsed = time.monotonic() - t0
        finally:
            at.uninstall()
            await runner.cleanup()
        return elapsed
    # 3요청 × 0.2s interval → ≥0.35s (설치 안 됐으면 ~0)
    assert _run(t()) >= 0.35


def test_get_not_paced_without_install():
    async def serve():
        async def h(req):
            return web.Response(text="ok")
        app = web.Application(); app.router.add_get("/", h)
        runner = web.AppRunner(app); await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
        return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/"

    async def t():
        at.uninstall()
        runner, url = await serve()
        try:
            async with aiohttp.ClientSession() as s:
                t0 = time.monotonic()
                for _ in range(5):
                    await ap._get(s, url)
                elapsed = time.monotonic() - t0
        finally:
            await runner.cleanup()
        return elapsed
    assert _run(t()) < 0.3   # 페이싱 없음 → 빠름


def test_pts_cap_bounds():
    pts = [{"params": {"a": "1"}} for _ in range(1000)]
    capped = ap._pts_cap(pts)
    assert 1 <= len(capped) <= 1000
    # 기본 injection_points_cap(40×scale) 이하로 제한
    assert len(capped) <= 4000


# ── 일시정지 게이트(요청 단위 즉시 반영) 회귀 ──────────────────────────────────
def test_pause_registry_basic():
    import adaptive_throttle as at
    at.resume("s1")
    assert at.is_paused("s1") is False
    at.pause("s1"); assert at.is_paused("s1") is True
    at.resume("s1"); assert at.is_paused("s1") is False
    assert at.is_paused("") is False


def test_before_blocks_while_paused_and_resumes():
    import asyncio, adaptive_throttle as at
    async def t():
        at.install_profile("SAFE", scan_id="pz")
        lim = at.stage("crawl")
        at.pause("pz")
        done = {"v": False}
        async def call():
            await lim.before(); done["v"] = True
        task = asyncio.ensure_future(call())
        await asyncio.sleep(0.9)
        blocked = (done["v"] is False)   # 일시정지 중 → before() 아직 미완료
        at.resume("pz")
        await asyncio.sleep(0.8)
        await task
        return blocked, done["v"]
    blocked, after = asyncio.run(t())
    at.uninstall()
    assert blocked is True and after is True
