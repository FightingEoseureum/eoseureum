"""tests/test_sqli_probe.py — SqliProbe 위임/로그인 폼 인증 우회 대상 검증 (네트워크 없음)."""
import pytest

import active_probing as ap
from probes.base import ProbeContext, ProbeResult
from probes import sqli_probe
from probes.config import ScanConfig
from probes.utils.rate_limiter import RateLimiter


class _DummySession:
    pass


def _ctx(points):
    return ProbeContext(
        target_url="http://target.example/",
        session=_DummySession(),
        injection_points=points,
        scan_config=ScanConfig(),
        rate_limiter=RateLimiter(0),
        scan_id="test-scan",
    )


def _patch_all(monkeypatch, **overrides):
    async def none_pt(session, points, scan_id=""):
        return None

    monkeypatch.setattr(ap, "_probe_sqli_error", overrides.get("error", none_pt))
    monkeypatch.setattr(ap, "_probe_sqli_union", overrides.get("union", none_pt))

    async def none_bt(session, points):
        return None

    monkeypatch.setattr(ap, "_probe_sqli_bool", overrides.get("bool", none_bt))
    monkeypatch.setattr(ap, "_probe_sqli_time", overrides.get("time", none_bt))
    monkeypatch.setattr(ap, "_probe_sqli_auth_bypass",
                        overrides.get("auth_bypass", none_bt))


@pytest.mark.asyncio
async def test_run_returns_list_of_probe_results(monkeypatch):
    async def fake_error(session, points, scan_id=""):
        return {"confirmed": True, "url": "http://target.example/p?id=1", "evidence": "DB error"}

    _patch_all(monkeypatch, error=fake_error)

    points = [{"url": "http://target.example/p", "method": "GET",
               "source": "url", "params": {"id": "1"}}]
    results = await sqli_probe.PROBE.run(_ctx(points))

    assert isinstance(results, list)
    assert all(isinstance(r, ProbeResult) for r in results)
    assert len(results) == 1
    r = results[0]
    assert r.cwe == "CWE-89"
    assert r.severity == "High"  # error-based
    assert r.probe_key == "sqli_error"


@pytest.mark.asyncio
async def test_login_form_passed_to_auth_bypass(monkeypatch):
    """로그인 폼이 포함된 injection_points → _probe_sqli_auth_bypass 에 로그인 폼 지점 전달."""
    captured = {}

    async def fake_auth_bypass(session, points):
        captured["points"] = points
        return None

    _patch_all(monkeypatch, auth_bypass=fake_auth_bypass)

    login_point = {"url": "http://target.example/login", "method": "POST",
                   "source": "form", "params": {"username": "a", "password": "b"}}
    non_login = {"url": "http://target.example/p", "method": "GET",
                 "source": "url", "params": {"id": "1"}}
    points = [non_login, login_point]
    await sqli_probe.PROBE.run(_ctx(points))

    assert "points" in captured
    assert login_point in captured["points"]
    # 비-로그인 지점은 전달되지 않음(로그인 폼 지점만 우선 전달)
    assert non_login not in captured["points"]
