"""tests/test_auth_probe.py — AuthProbe 로그인 폼 탐지/위임 검증 (네트워크 없음)."""
import pytest

import active_probing as ap
from probes.base import ProbeContext, ProbeResult
from probes import auth_probe
from probes.config import ScanConfig
from probes.utils.rate_limiter import RateLimiter


class _DummySession:
    pass


def _ctx(points):
    return ProbeContext(
        target_url="http://target.example/admin",
        session=_DummySession(),
        injection_points=points,
        scan_config=ScanConfig(),
        rate_limiter=RateLimiter(0),
        scan_id="test-scan",
    )


@pytest.mark.asyncio
async def test_run_returns_list_and_detects_login_form(monkeypatch):
    captured = {}

    async def fake_auth_bypass(session, base_url):
        return {"confirmed": True, "url": base_url,
                "evidence": "IP 우회로 접근 제어 우회"}

    async def fake_sqli_auth_bypass(session, points):
        captured["login_points"] = points
        return {"confirmed": True, "url": "http://target.example/login",
                "evidence": "SQL 인증 우회"}

    monkeypatch.setattr(ap, "_probe_auth_bypass", fake_auth_bypass)
    monkeypatch.setattr(ap, "_probe_sqli_auth_bypass", fake_sqli_auth_bypass)

    login_point = {"url": "http://target.example/login", "method": "POST",
                   "source": "form", "params": {"email": "a", "password": "b"}}
    points = [login_point,
              {"url": "http://target.example/p", "method": "GET",
               "source": "url", "params": {"id": "1"}}]
    results = await auth_probe.PROBE.run(_ctx(points))

    assert isinstance(results, list)
    assert all(isinstance(r, ProbeResult) for r in results)
    assert len(results) == 2
    assert all(r.cwe == "CWE-287" for r in results)
    assert all(r.owasp.startswith("A07:2021") for r in results)
    # 로그인 폼 탐지 → sqli_auth_bypass 에 로그인 폼 지점 전달
    assert "login_points" in captured
    assert login_point in captured["login_points"]


@pytest.mark.asyncio
async def test_no_login_form_skips_sqli_auth_bypass(monkeypatch):
    called = {"sqli": False}

    async def fake_auth_bypass(session, base_url):
        return None

    async def fake_sqli_auth_bypass(session, points):
        called["sqli"] = True
        return None

    monkeypatch.setattr(ap, "_probe_auth_bypass", fake_auth_bypass)
    monkeypatch.setattr(ap, "_probe_sqli_auth_bypass", fake_sqli_auth_bypass)

    points = [{"url": "http://target.example/p", "method": "GET",
               "source": "url", "params": {"id": "1"}}]
    results = await auth_probe.PROBE.run(_ctx(points))

    assert isinstance(results, list)
    assert results == []
    assert called["sqli"] is False
