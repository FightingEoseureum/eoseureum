"""P3: 브라우저(Playwright) 트래픽 rate 거버너 페이싱 — new_context route 핸들러 로직."""
import asyncio
import types

import adaptive_throttle as at
import browser_compat as bc


def _run(c):
    return asyncio.run(c)


class _FakeRoute:
    def __init__(self, rtype):
        self.request = types.SimpleNamespace(resource_type=rtype)
        self.aborted = False
        self.continued = False

    async def abort(self):
        self.aborted = True

    async def continue_(self):
        self.continued = True


class _FakeCtx:
    def __init__(self):
        self.handler = None
        self.pattern = None

    async def route(self, pattern, handler):
        self.pattern = pattern
        self.handler = handler


def test_patch_installed():
    """browser_compat 이 Browser.new_context 를 패치했는지."""
    try:
        from playwright.async_api import Browser
    except Exception:
        import pytest
        pytest.skip("playwright 미설치")
    assert Browser.new_context.__name__ == "_async_new_context"


def test_no_governor_no_route(monkeypatch):
    """거버너 미설치(PROOF)면 route 를 설치하지 않는다(무제한)."""
    async def t():
        at.uninstall()
        ctx = _FakeCtx()
        await bc._attach_async_pacing(ctx)
        return ctx.handler
    assert _run(t()) is None


def test_heavy_resource_aborted(monkeypatch):
    """SAFE 기본: 이미지/폰트/미디어는 abort(요청수↓), 거버너 미소비."""
    monkeypatch.setenv("EOSEUREUM_BROWSER_ABORT_HEAVY", "true")

    async def t():
        at.install_profile("SAFE")
        lim = at.stage("browser")
        try:
            ctx = _FakeCtx()
            await bc._attach_async_pacing(ctx)
            r = _FakeRoute("image")
            await ctx.handler(r)
            return r.aborted, r.continued, lim.samples
        finally:
            at.uninstall()
    aborted, continued, samples = _run(t())
    assert aborted is True and continued is False
    assert samples == 0   # abort 는 거버너 미소비


def test_document_request_paced(monkeypatch):
    """document/xhr 등은 거버너 통과(before/after) 후 continue."""
    monkeypatch.setenv("EOSEUREUM_BROWSER_ABORT_HEAVY", "true")

    async def t():
        at.install_profile("SAFE")
        lim = at.stage("browser")
        try:
            ctx = _FakeCtx()
            await bc._attach_async_pacing(ctx)
            for rt in ("document", "xhr", "script", "fetch"):
                await ctx.handler(_FakeRoute(rt))
            return lim.samples
        finally:
            at.uninstall()
    assert _run(t()) == 4   # 4요청 전부 거버너 통과


def test_browser_shares_global_limiter():
    """SAFE: 'browser' stage 가 다른 stage 와 같은 리미터(전역 합산) 공유."""
    at.install_profile("SAFE")
    try:
        assert at.stage("browser") is at.stage("active_probing")
        assert at.stage("browser").max_rps == 5.0
    finally:
        at.uninstall()


class _SyncRoute:
    def __init__(self, rtype):
        self.request = types.SimpleNamespace(resource_type=rtype)
        self.aborted = False
        self.continued = False

    def abort(self):
        self.aborted = True

    def continue_(self):
        self.continued = True


class _SyncCtx:
    def __init__(self):
        self.handler = None

    def route(self, pattern, handler):
        self.handler = handler


def test_sync_pacing_installs_and_paces(monkeypatch):
    """sync 스크린샷 경로용 _attach_sync_pacing 이 route 설치 + before_sync/after_sync 페이싱."""
    monkeypatch.setenv("EOSEUREUM_BROWSER_ABORT_HEAVY", "true")
    at.install_profile("SAFE")
    lim = at.stage("browser")
    try:
        ctx = _SyncCtx()
        bc._attach_sync_pacing(ctx)
        assert ctx.handler is not None
        ctx.handler(_SyncRoute("image"))      # 무거운 리소스 → abort, 미소비
        ctx.handler(_SyncRoute("document"))   # 페이싱 통과
        ctx.handler(_SyncRoute("script"))     # 페이싱 통과
        assert lim.samples == 2
    finally:
        at.uninstall()


def test_sync_pacing_noop_without_governor():
    at.uninstall()
    ctx = _SyncCtx()
    bc._attach_sync_pacing(ctx)
    assert ctx.handler is None   # 거버너 없음 → route 미설치


def test_to_thread_propagates_governor():
    """asyncio.to_thread 는 거버너 contextvar 를 스레드에 전파(sync 스크린샷이 페이싱되는 근거)."""
    def _in_thread():
        lim = at.stage("browser")
        return None if lim is None else lim.max_rps

    async def t():
        at.install_profile("SAFE")
        try:
            return await asyncio.to_thread(_in_thread)
        finally:
            at.uninstall()
    assert _run(t()) == 5.0


def test_abort_heavy_can_be_disabled(monkeypatch):
    """EOSEUREUM_BROWSER_ABORT_HEAVY=false 면 이미지도 페이싱 후 통과."""
    monkeypatch.setenv("EOSEUREUM_BROWSER_ABORT_HEAVY", "false")

    async def t():
        at.install_profile("SAFE")
        lim = at.stage("browser")
        try:
            ctx = _FakeCtx()
            await bc._attach_async_pacing(ctx)
            r = _FakeRoute("image")
            await ctx.handler(r)
            return r.aborted, r.continued, lim.samples
        finally:
            at.uninstall()
    aborted, continued, samples = _run(t())
    assert aborted is False and continued is True and samples == 1
