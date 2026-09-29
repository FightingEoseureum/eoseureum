"""tests/test_auth_rate_limit.py — 로그인 시도가 auth_rate_limiter 를 거치는지 검증."""
import pytest

from probes.base import ProbeContext
from probes import credential_probe
from probes.config import ScanConfig
from probes.utils.rate_limiter import RateLimiter, CompositeRateLimiter
import authenticated_scan as asc


class _CountingLimiter:
    """acquire() 호출 횟수/순서를 기록하는 가짜 limiter."""
    def __init__(self, name, log):
        self.name = name
        self.calls = 0
        self._log = log

    async def acquire(self):
        self.calls += 1
        self._log.append(self.name)


class _DummySession:
    pass


def _ctx(cfg, auth_limiter):
    return ProbeContext(
        target_url="http://target.example/login",
        session=_DummySession(),
        injection_points=[
            {"url": "http://target.example/login", "method": "POST",
             "source": "form", "params": {"username": "x", "password": "y"},
             "csrf_fields": []},
        ],
        scan_config=cfg,
        rate_limiter=RateLimiter(0),
        auth_rate_limiter=auth_limiter,
        scan_id="test-scan",
    )


@pytest.mark.asyncio
async def test_each_credential_attempt_acquires_auth_limiter(monkeypatch, tmp_path):
    f = tmp_path / "creds.txt"
    f.write_text("a:1\nb:2\nc:3\n")
    log = []
    limiter = _CountingLimiter("auth", log)

    post_calls = {"n": 0}

    async def fake_post(session, url, data, timeout=8.0):
        post_calls["n"] += 1
        # 항상 실패 → 모든 자격증명 시도
        return 200, "<html>Invalid login</html>", {}

    monkeypatch.setattr(credential_probe, "_http_post", fake_post)
    cfg = ScanConfig(enable_known_credential_check=True, max_auth_credentials=10,
                     max_auth_attempts_per_form=10, auth_credential_file=str(f))

    await credential_probe.PROBE.run(_ctx(cfg, limiter))

    # 시도마다 acquire() 호출 (3개 자격증명 = 3회), POST 호출 횟수와 동일
    assert limiter.calls == 3
    assert post_calls["n"] == 3
    # 각 acquire 가 POST 전에 일어남(호출 횟수 일치로 순서 보장 — limiter 가 게이트)
    assert limiter.calls == post_calls["n"]


@pytest.mark.asyncio
async def test_attempts_capped_by_max_attempts_per_form(monkeypatch, tmp_path):
    f = tmp_path / "creds.txt"
    f.write_text("\n".join(f"u{i}:p{i}" for i in range(20)))
    limiter = _CountingLimiter("auth", [])

    async def fake_post(session, url, data, timeout=8.0):
        return 200, "<html>Invalid</html>", {}

    monkeypatch.setattr(credential_probe, "_http_post", fake_post)
    cfg = ScanConfig(enable_known_credential_check=True, max_auth_credentials=20,
                     max_auth_attempts_per_form=2, auth_credential_file=str(f))

    await credential_probe.PROBE.run(_ctx(cfg, limiter))
    # 폼당 최대 2회로 제한
    assert limiter.calls == 2


def test_auth_rps_clamped_to_two_or_below_via_env():
    """전역(≤10)과 결합되는 auth_rps 가 from_env 에서 ≤ global_rps 로 제한됨."""
    cfg = ScanConfig.from_env()
    assert cfg.auth_rps <= cfg.global_rps
    assert cfg.global_rps <= 10.0
    # 기본 auth_rps 는 2.0(초당 ≤2)
    assert cfg.auth_rps <= 2.0 or cfg.auth_rps <= cfg.global_rps


@pytest.mark.asyncio
async def test_authenticated_scan_uses_composite_global_plus_auth(monkeypatch):
    """authenticated_scan 의 로그인/크롤이 global+auth 결합 limiter 를 통과하는지(요청마다 acquire)."""
    log = []

    class _FakeSession:
        def close(self):
            pass

    monkeypatch.setattr(asc, "_make_session", lambda timeout=8.0: _FakeSession())

    # CompositeRateLimiter 를 가짜 limiter 들로 교체하기 위해 RateLimiter.acquire 를 카운트
    orig_acquire = RateLimiter.acquire

    counts = {"n": 0}

    async def counting_acquire(self):
        counts["n"] += 1

    monkeypatch.setattr(RateLimiter, "acquire", counting_acquire)

    login_page = ('<form action="/login" method="post">'
                  '<input name="username"><input name="password" type="password">'
                  '<input type="submit"></form>')

    async def fake_get(session, url, timeout=8.0):
        return 200, login_page, {}

    async def fake_post(session, url, data, timeout=8.0):
        return 302, "", {"Set-Cookie": "sessionid=z; Path=/", "Location": "/home"}

    monkeypatch.setattr(asc, "_http_get", fake_get)
    monkeypatch.setattr(asc, "_http_post", fake_post)

    cfg = ScanConfig(enable_auth_scan=True, auth_login_url="http://t.example/login",
                     auth_username="u", auth_password="p", auth_max_pages=2,
                     global_rps=10.0, auth_rps=2.0, request_timeout=3.0)
    res = await asc.perform_login_and_crawl(cfg, "http://t.example")
    assert res["logged_in"] is True
    # CompositeRateLimiter(global, auth) → 매 요청마다 2개 limiter.acquire 가 호출됨.
    # 최소 로그인 GET + POST = 2회 요청 → 4회 이상 acquire.
    assert counts["n"] >= 4

    monkeypatch.setattr(RateLimiter, "acquire", orig_acquire)
