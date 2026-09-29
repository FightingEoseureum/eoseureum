"""tests/test_xss_probe.py — XssProbe 위임/검색 input 대상 검증 (네트워크 없음)."""
import pytest

import active_probing as ap
from probes.base import ProbeContext, ProbeResult
from probes import xss_probe
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


@pytest.mark.asyncio
async def test_run_returns_list_of_probe_results(monkeypatch):
    async def fake_reflected(session, points, scan_id=""):
        return {"confirmed": True, "url": "http://target.example/?q=x", "evidence": "alert"}

    async def fake_dom(session, base_url, scan_id=""):
        return None

    async def fake_stored(session, base_url, points, scan_id=""):
        return None

    monkeypatch.setattr(ap, "_probe_xss_reflected", fake_reflected)
    monkeypatch.setattr(ap, "_probe_dom_xss", fake_dom)
    monkeypatch.setattr(ap, "_probe_xss_stored", fake_stored)

    points = [{"url": "http://target.example/search", "method": "GET",
               "source": "url", "params": {"q": "test"}}]
    results = await xss_probe.PROBE.run(_ctx(points))

    assert isinstance(results, list)
    assert all(isinstance(r, ProbeResult) for r in results)
    assert len(results) == 1
    r = results[0]
    assert r.cwe == "CWE-79"
    assert r.confidence == "CONFIRMED"
    assert r.probe_key == "xss_reflected"


@pytest.mark.asyncio
async def test_search_input_passed_as_target(monkeypatch):
    """검색 input(params 에 q/search)이 reflected probe 의 points 로 그대로 전달되는지."""
    captured = {}

    async def fake_reflected(session, points, scan_id=""):
        captured["points"] = points
        return None

    async def fake_dom(session, base_url, scan_id=""):
        return None

    async def fake_stored(session, base_url, points, scan_id=""):
        return None

    monkeypatch.setattr(ap, "_probe_xss_reflected", fake_reflected)
    monkeypatch.setattr(ap, "_probe_dom_xss", fake_dom)
    monkeypatch.setattr(ap, "_probe_xss_stored", fake_stored)

    search_point = {"url": "http://target.example/search", "method": "GET",
                    "source": "url", "params": {"q": "kw", "search": "kw"}}
    points = [search_point]
    await xss_probe.PROBE.run(_ctx(points))

    assert "points" in captured
    assert search_point in captured["points"]
    # 검색 input 파라미터(q/search)가 대상에 포함됨
    target_params = set()
    for p in captured["points"]:
        target_params |= set(p.get("params", {}))
    assert {"q", "search"} & target_params
