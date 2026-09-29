"""tests/test_auth_scan.py — 인증 스캔(authenticated_scan) 검증 (네트워크 없음, monkeypatch)."""
import pytest

import authenticated_scan as asc
from probes.config import ScanConfig


class _FakeSession:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _cfg(**kw):
    base = dict(
        enable_auth_scan=True,
        auth_login_url="http://target.example/login",
        auth_username="alice",
        auth_password="s3cret-pw",
        auth_max_pages=10,
        request_timeout=5.0,
        same_origin_only=True,
        global_rps=10.0,
        auth_rps=2.0,
        stop_on_account_lock_hint=True,
    )
    base.update(kw)
    return ScanConfig(**base)


_LOGIN_PAGE = (
    '<html><form action="/login" method="post">'
    '<input name="username" type="text">'
    '<input name="password" type="password">'
    '<input type="submit"></form></html>'
)

_DASHBOARD = (
    '<html><a href="/profile">Profile</a> <a href="/logout">Logout</a>'
    '<form action="/search" method="get"><input name="q"></form>'
    '<a href="/item?id=5">item</a></html>'
)


@pytest.mark.asyncio
async def test_disabled_or_no_credentials_skips():
    # enable_auth_scan=False → 생략
    cfg = _cfg(enable_auth_scan=False)
    res = await asc.perform_login_and_crawl(cfg, "http://target.example")
    assert res["logged_in"] is False
    assert res["session"] is None

    # 계정 미제공 → logged_in=False
    cfg2 = _cfg(auth_username="", auth_password="")
    res2 = await asc.perform_login_and_crawl(cfg2, "http://target.example")
    assert res2["logged_in"] is False
    assert "credential" in res2["reason"].lower()


@pytest.mark.asyncio
async def test_login_success_keeps_session_and_collects_forms(monkeypatch):
    fake = _FakeSession()
    monkeypatch.setattr(asc, "_make_session", lambda timeout=8.0: fake)

    async def fake_get(session, url, timeout=8.0):
        if "login" in url:
            return 200, _LOGIN_PAGE, {}
        return 200, _DASHBOARD, {}

    async def fake_post(session, url, data, timeout=8.0):
        # 로그인 성공: Set-Cookie 세션 발급
        return 302, "", {"Set-Cookie": "sessionid=abc123; Path=/",
                         "Location": "/dashboard"}

    monkeypatch.setattr(asc, "_http_get", fake_get)
    monkeypatch.setattr(asc, "_http_post", fake_post)

    res = await asc.perform_login_and_crawl(_cfg(), "http://target.example")
    assert res["logged_in"] is True
    assert res["session"] is fake          # 세션 유지(닫히지 않음)
    assert fake.closed is False
    assert len(res["urls"]) >= 1
    # 폼/주입 지점 수집(검색 폼 + query parameter)
    assert len(res["forms"]) >= 1
    sources = {f.get("source") for f in res["forms"]}
    assert "form" in sources or "query" in sources


@pytest.mark.asyncio
async def test_account_lock_hint_stops_immediately(monkeypatch):
    fake = _FakeSession()
    monkeypatch.setattr(asc, "_make_session", lambda timeout=8.0: fake)

    async def fake_get(session, url, timeout=8.0):
        return 200, _LOGIN_PAGE, {}

    async def fake_post(session, url, data, timeout=8.0):
        return 200, "<html>Your account has been locked due to too many attempts</html>", {}

    monkeypatch.setattr(asc, "_http_get", fake_get)
    monkeypatch.setattr(asc, "_http_post", fake_post)

    res = await asc.perform_login_and_crawl(_cfg(), "http://target.example")
    assert res["logged_in"] is False
    assert "lock" in res["reason"].lower()


@pytest.mark.asyncio
async def test_password_not_leaked_in_reason(monkeypatch):
    fake = _FakeSession()
    monkeypatch.setattr(asc, "_make_session", lambda timeout=8.0: fake)

    async def fake_get(session, url, timeout=8.0):
        return 200, _LOGIN_PAGE, {}

    async def fake_post(session, url, data, timeout=8.0):
        return 200, "<html>Invalid credentials</html>", {}

    monkeypatch.setattr(asc, "_http_get", fake_get)
    monkeypatch.setattr(asc, "_http_post", fake_post)

    res = await asc.perform_login_and_crawl(_cfg(), "http://target.example")
    assert res["logged_in"] is False
    assert "s3cret-pw" not in res["reason"]
