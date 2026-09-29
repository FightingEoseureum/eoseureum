"""토글(PROOF만 유지) + P4(preview 독립 리미터 · probes 프로파일 연동)."""
import asyncio
import time

import aiohttp
from aiohttp import web

import adaptive_throttle as at
import validation_profiles as vp


def _run(c):
    return asyncio.run(c)


# ── 토글: ADVANCED 게이트 제거, PROOF 게이트 유지 ─────────────────────────────
def test_advanced_no_longer_gated(monkeypatch):
    """ADVANCED 는 ALLOW_ADVANCED_VALIDATION 없이도 그대로 유지(강등 안 됨)."""
    monkeypatch.delenv("ALLOW_ADVANCED_VALIDATION", raising=False)
    monkeypatch.delenv("ALLOW_PROOF_MODE", raising=False)
    assert vp.resolve_profile("ADVANCED") == "ADVANCED"
    assert vp.resolve_profile("STANDARD") == "STANDARD"


def test_proof_still_gated(monkeypatch):
    """PROOF 는 여전히 ALLOW_PROOF_MODE=true 일 때만 유지, 아니면 ADVANCED 로 강등."""
    monkeypatch.delenv("ALLOW_PROOF_MODE", raising=False)
    assert vp.resolve_profile("PROOF") == "ADVANCED"      # 미허용 → ADVANCED
    monkeypatch.setenv("ALLOW_PROOF_MODE", "true")
    assert vp.resolve_profile("PROOF") == "PROOF"          # 허용 → PROOF 유지


def test_default_safe():
    assert vp.resolve_profile(None) in ("SAFE", "STANDARD", "ADVANCED", "PROOF")
    assert vp.resolve_profile("BOGUS") == "SAFE"


# ── P4: preview 독립 리미터(AdaptiveThrottle standalone) ─────────────────────
def test_standalone_preview_limiter_paces():
    """preview 가 쓰는 방식(독립 AdaptiveThrottle, contextvar 무관)으로 페이싱된다."""
    async def _serve():
        async def h(req):
            return web.Response(text="ok")
        app = web.Application(); app.router.add_get("/{t:.*}", h)
        runner = web.AppRunner(app); await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
        return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/"

    async def t():
        runner, url = await _serve()
        # preview 와 동일 구성: standalone 5rps/단독
        plim = at.AdaptiveThrottle("conservative", concurrency=1, hard_cap=True, label="preview")
        try:
            async with aiohttp.ClientSession() as s:
                t0 = time.monotonic()
                for _ in range(3):
                    await plim.before()
                    _s = 0
                    try:
                        async with s.get(url) as r:
                            _s = r.status
                    finally:
                        plim.after(0.001, _s, None)
                return time.monotonic() - t0, plim.max_rps
        finally:
            await runner.cleanup()
    elapsed, mrps = _run(t())
    assert mrps == 5.0
    assert elapsed >= 0.35   # 3요청 × 0.2s


def test_preview_limiter_independent_of_contextvar():
    """preview 리미터는 install/uninstall(contextvar)과 무관(누수 없음)."""
    at.uninstall()
    plim = at.AdaptiveThrottle("conservative", concurrency=1, hard_cap=True)
    assert at.current() is None        # 전역 거버너는 여전히 미설치
    assert plim.max_rps == 5.0


# ── P4: probes orchestrator 프로파일 연동 ────────────────────────────────────
def test_orchestrator_clamps_to_profile():
    """거버너(SAFE 5rps) 설치 시 orchestrator RateLimiter 가 5rps 로 클램프된다."""
    from probes.orchestrator import build_context

    async def t():
        at.install_profile("SAFE")   # 5rps
        try:
            ctx = await build_context("t", 80, "http", {"url": "http://t/"},
                                      None, None, scan_id="s")
            # config.global_rps 기본 10 → SAFE 5 로 클램프
            return ctx.rate_limiter.rps
        finally:
            at.uninstall()
    assert _run(t()) == 5.0


def test_orchestrator_unclamped_without_governor():
    """거버너 없음(PROOF) → config.global_rps(기본 10) 그대로."""
    from probes.orchestrator import build_context

    async def t():
        at.uninstall()
        ctx = await build_context("t", 80, "http", {"url": "http://t/"},
                                  None, None, scan_id="s")
        return ctx.rate_limiter.rps
    assert _run(t()) == 10.0
