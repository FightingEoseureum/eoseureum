"""
Playwright 브라우저 구동 호환 레이어.

번들 chromium이 지원되지 않는 OS(예: Ubuntu 26.04)에서도 스크린샷/브라우저 탐색이
동작하도록 시스템에 설치된 Chrome/Chromium으로 자동 폴백한다.

import 한 번으로 async/sync 양쪽 `chromium.launch()` 에 폴백이 주입된다.
구동 순서: (env override) → 번들 chromium → 시스템 chrome/chromium 채널 →
시스템 Chrome/Chromium 실행 파일 경로(executable_path).
Windows 등 번들이 정상 동작하는 환경에서는 첫 시도(번들)로 끝나므로 영향이 없다.

env override: PLAYWRIGHT_CHROMIUM_CHANNEL, PLAYWRIGHT_CHROMIUM_EXECUTABLE.
"""
import os as _os

_PATCHED = False
# None = 번들 브라우저(기본). 그 다음 시스템 채널 순으로 폴백.
_LAUNCH_CHANNELS = (None, "chrome", "chromium")
_SYSTEM_BINARIES = ("/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
                    "/usr/bin/chromium", "/usr/bin/chromium-browser",
                    "/snap/bin/chromium")


def _fallback_overrides() -> list:
    """launch() 에 순서대로 시도할 override kwargs 목록(env → 번들 → 채널 → executable_path)."""
    overrides = []
    ch = _os.getenv("PLAYWRIGHT_CHROMIUM_CHANNEL")
    ex = _os.getenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
    if ch:
        overrides.append({"channel": ch})
    if ex:
        overrides.append({"executable_path": ex})
    for channel in _LAUNCH_CHANNELS:
        overrides.append({} if channel is None else {"channel": channel})
    for path in _SYSTEM_BINARIES:
        try:
            if _os.path.exists(path):
                overrides.append({"executable_path": path})
        except Exception:
            pass
    seen, uniq = set(), []
    for o in overrides:                       # 중복 제거(순서 보존)
        key = tuple(sorted(o.items()))
        if key not in seen:
            seen.add(key)
            uniq.append(o)
    return uniq


def _patch() -> None:
    global _PATCHED
    if _PATCHED:
        return
    try:
        from playwright.async_api import BrowserType as AsyncBrowserType
        from playwright.sync_api import BrowserType as SyncBrowserType
    except Exception:
        return

    _orig_async_launch = AsyncBrowserType.launch
    _orig_sync_launch = SyncBrowserType.launch

    async def _async_launch(self, **kwargs):
        # 명시적 channel/executable 지정이 있거나 chromium 외 브라우저면 원본 그대로
        if kwargs.get("channel") or kwargs.get("executable_path") \
                or getattr(self, "name", "") != "chromium":
            return await _orig_async_launch(self, **kwargs)
        last_err = None
        for override in _fallback_overrides():
            kw = dict(kwargs); kw.update(override)
            try:
                return await _orig_async_launch(self, **kw)
            except Exception as e:
                last_err = e
        raise last_err

    def _sync_launch(self, **kwargs):
        if kwargs.get("channel") or kwargs.get("executable_path") \
                or getattr(self, "name", "") != "chromium":
            return _orig_sync_launch(self, **kwargs)
        last_err = None
        for override in _fallback_overrides():
            kw = dict(kwargs); kw.update(override)
            try:
                return _orig_sync_launch(self, **kw)
            except Exception as e:
                last_err = e
        raise last_err

    AsyncBrowserType.launch = _async_launch
    SyncBrowserType.launch = _sync_launch

    # ── P3: 브라우저(Playwright) 트래픽을 rate 거버너에 태운다 ──
    # new_context 를 패치해, 생성되는 모든 컨텍스트에 route 핸들러를 설치한다. 핸들러는 각 요청
    # (subresource 포함)을 stage("browser") 로 페이싱한다 → SAFE 에서 브라우저 트래픽도 전역 합산
    # 상한에 포함. 거버너 미설치(PROOF)면 route 미설치(무제한). SAFE 기본 무거운 리소스(이미지/폰트/미디어)
    # 차단으로 요청수↓(EOSEUREUM_BROWSER_ABORT_HEAVY=false 로 해제 가능).
    try:
        from playwright.async_api import Browser as _AsyncBrowser
        from playwright.sync_api import Browser as _SyncBrowser
        _orig_async_nc = _AsyncBrowser.new_context
        _orig_sync_nc = _SyncBrowser.new_context

        async def _async_new_context(self, *a, **kw):
            ctx = await _orig_async_nc(self, *a, **kw)
            try:
                await _attach_async_pacing(ctx)
            except Exception:
                pass
            return ctx

        def _sync_new_context(self, *a, **kw):
            ctx = _orig_sync_nc(self, *a, **kw)
            try:
                _attach_sync_pacing(ctx)
            except Exception:
                pass
            return ctx

        _AsyncBrowser.new_context = _async_new_context
        _SyncBrowser.new_context = _sync_new_context
    except Exception:
        pass

    _PATCHED = True


_BROWSER_HEAVY = {"image", "media", "font"}


def _abort_heavy_enabled() -> bool:
    return _os.getenv("EOSEUREUM_BROWSER_ABORT_HEAVY", "true").strip().lower() in ("1", "true", "yes", "on")


async def _attach_async_pacing(ctx) -> None:
    import adaptive_throttle as _gov
    import time as _time
    try:
        import session_inject as _si
    except Exception:
        _si = None
    lim = _gov.stage("browser")
    inj_active = bool(_si and _si.active())
    if lim is None and not inj_active:   # 페이싱도 세션주입도 없음 → route 불필요
        return
    abort_heavy = _abort_heavy_enabled() if lim is not None else False

    async def _handler(route):
        rt = ""
        try:
            rt = route.request.resource_type
        except Exception:
            pass
        if abort_heavy and rt in _BROWSER_HEAVY:
            try:
                await route.abort()
            except Exception:
                try:
                    await route.continue_()
                except Exception:
                    pass
            return
        _extra = _si.headers_for(route.request.url) if inj_active else {}   # 대상 호스트만 인증헤더 주입
        if lim is not None:
            await lim.before()
        _t0 = _time.monotonic()
        try:
            if _extra:
                await route.continue_(headers={**route.request.headers, **_extra})
            else:
                await route.continue_()
        except Exception:
            pass
        finally:
            if lim is not None:
                lim.after(_time.monotonic() - _t0, 0, None)

    await ctx.route("**/*", _handler)


def _attach_sync_pacing(ctx) -> None:
    import adaptive_throttle as _gov
    import time as _time
    try:
        import session_inject as _si
    except Exception:
        _si = None
    lim = _gov.stage("browser")
    inj_active = bool(_si and _si.active())
    if lim is None and not inj_active:
        return
    abort_heavy = _abort_heavy_enabled() if lim is not None else False

    def _handler(route):
        rt = ""
        try:
            rt = route.request.resource_type
        except Exception:
            pass
        if abort_heavy and rt in _BROWSER_HEAVY:
            try:
                route.abort()
            except Exception:
                try:
                    route.continue_()
                except Exception:
                    pass
            return
        _extra = _si.headers_for(route.request.url) if inj_active else {}
        if lim is not None:
            lim.before_sync()
        _t0 = _time.monotonic()
        try:
            if _extra:
                route.continue_(headers={**route.request.headers, **_extra})
            else:
                route.continue_()
        except Exception:
            pass
        finally:
            if lim is not None:
                lim.after_sync(_time.monotonic() - _t0, 0, None)

    ctx.route("**/*", _handler)


_patch()
