"""로그인 고도화 회귀 테스트 — 통합 엔진(_establish_session)의 HTTP 경로 + 브라우저 graceful.

외부 IO(_http_get/_http_post/_make_session/playwright)는 monkeypatch 로 대체하고
'실제 요청 URL override · JSON 본문 · 추가필드 · 브라우저 폴백' 로직만 검증한다.
"""
import asyncio
import builtins

import authenticated_scan as A


def _run(c):
    return asyncio.run(c)


class Cfg:
    def __init__(self, **kw):
        self.auth_login_url = "http://t/login"
        self.auth_username = "u"
        self.auth_password = "p"
        self.request_timeout = 5.0
        self.auth_success_pattern = "auto"
        self.auth_login_method = "http"   # 기본은 HTTP 경로만(브라우저 배제)
        self.auth_login_action = ""
        self.auth_login_body_mode = "form"
        self.auth_extra_fields = {}
        for k, v in kw.items():
            setattr(self, k, v)


class _Jar:
    def __init__(self):
        self.c = {}

    def update_cookies(self, d, response_url=None):
        self.c.update(d)

    def __iter__(self):
        return iter([])


class _Sess:
    def __init__(self):
        self.cookie_jar = _Jar()
        self.closed = False

    async def close(self):
        self.closed = True


_FORM = ('<form action="/wrong" method="post">'
         '<input name="username"><input type="password" name="password"></form>')


def test_action_override_and_extra_fields(monkeypatch):
    cap = {}
    monkeypatch.setattr(A, "_make_session", lambda timeout=8.0: _Sess())

    async def fget(s, u, timeout=8.0):
        return 200, _FORM, {}

    async def fpost(s, u, data, timeout=8.0):
        cap["url"] = u
        cap["data"] = dict(data)
        return 200, "logout dashboard", {"Set-Cookie": "session=abc"}

    monkeypatch.setattr(A, "_http_get", fget)
    monkeypatch.setattr(A, "_http_post", fpost)
    cfg = Cfg(auth_login_action="http://t/api/auth", auth_extra_fields={"csrf": "X"})
    res = _run(A._establish_session(cfg, "http://t", "http://t/login", "u", "p", 5.0))
    assert res["ok"] is True and res["method"] == "http"
    assert cap["url"] == "http://t/api/auth"          # 폼 action(/wrong) 아닌 override 사용
    assert cap["data"]["username"] == "u" and cap["data"]["password"] == "p"
    assert cap["data"]["csrf"] == "X"                  # 추가필드 병합


def test_json_body_mode(monkeypatch):
    cap = {}
    monkeypatch.setattr(A, "_make_session", lambda timeout=8.0: _Sess())

    async def fget(s, u, timeout=8.0):
        return 200, _FORM, {}

    async def fpj(s, u, payload, timeout=8.0):
        cap["json"] = dict(payload)
        return 200, "logout", {"Set-Cookie": "jwt=x"}

    monkeypatch.setattr(A, "_http_get", fget)
    monkeypatch.setattr(A, "_http_post_json", fpj)
    cfg = Cfg(auth_login_body_mode="json")
    res = _run(A._establish_session(cfg, "http://t", "http://t/login", "u", "p", 5.0))
    assert res["ok"] is True
    assert cap["json"]["username"] == "u" and cap["json"]["password"] == "p"


def test_browser_login_graceful_without_playwright(monkeypatch):
    real = builtins.__import__

    def fi(name, *a, **k):
        if name.startswith("playwright"):
            raise ImportError("no playwright")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fi)
    res = _run(A.browser_login(Cfg(), "http://t/login", "u", "p", 5.0))
    assert res["ok"] is False and "playwright" in res["reason"]


def test_auto_falls_back_to_http_when_browser_unavailable(monkeypatch):
    real = builtins.__import__

    def fi(name, *a, **k):
        if name.startswith("playwright"):
            raise ImportError()
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fi)
    monkeypatch.setattr(A, "_make_session", lambda timeout=8.0: _Sess())

    async def fget(s, u, timeout=8.0):
        return 200, _FORM, {}

    async def fpost(s, u, data, timeout=8.0):
        return 200, "dashboard logout", {"Set-Cookie": "session=1"}

    monkeypatch.setattr(A, "_http_get", fget)
    monkeypatch.setattr(A, "_http_post", fpost)
    cfg = Cfg(auth_login_method="auto")
    res = _run(A._establish_session(cfg, "http://t", "http://t/login", "u", "p", 5.0))
    assert res["ok"] is True and res["method"] == "http"


def test_session_from_browser_cookies(monkeypatch):
    monkeypatch.setattr(A, "_make_session", lambda timeout=8.0: _Sess())
    cookies = [{"name": "session", "value": "abc", "domain": ".t.com", "path": "/", "secure": True}]
    s = A._session_from_browser_cookies(cookies, 5.0)
    assert s is not None and s.cookie_jar.c.get("session") == "abc"
