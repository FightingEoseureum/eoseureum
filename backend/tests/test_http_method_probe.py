"""
test_http_method_probe.py — HttpMethodProbe 검증.

- scanner.probe_http_extras monkeypatch → verified_dangerous_methods=["TRACE"] →
  결과 title 에 "TRACE" 포함 & "PUT"/"DELETE" 미포함.
- verified_dangerous_methods=[] → 결과 [].

실행: venv_linux/bin/python -m pytest tests/test_http_method_probe.py -q
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanner
import probes.http_method_probe as hm_mod
from probes.base import ProbeContext, ProbeResult
from probes.utils.rate_limiter import RateLimiter


def _ctx(**kw):
    base = dict(
        target_url="http://t.example/", host="t.example", port=80, scheme="http",
        session=None, rate_limiter=RateLimiter(0), scan_id="s",
    )
    base.update(kw)
    return ProbeContext(**base)


@pytest.mark.asyncio
async def test_trace_only_in_title(monkeypatch):
    async def fake_extras(host, port, use_ssl):
        return {"allowed_methods": ["GET", "POST", "PUT", "DELETE", "TRACE"],
                "verified_dangerous_methods": ["TRACE"],
                "error_page_info": None}

    monkeypatch.setattr(scanner, "probe_http_extras", fake_extras)
    results = await hm_mod.PROBE.run(_ctx())
    assert len(results) == 1
    r = results[0]
    assert isinstance(r, ProbeResult)
    assert "TRACE" in r.title
    assert "PUT" not in r.title
    assert "DELETE" not in r.title
    assert r.cwe == "CWE-16"
    assert r.owasp == "A05:2021"
    assert r.severity == "Medium"
    assert r.probe_key == "dangerous_methods"
    assert r.evidence == ["검증된 위험 메서드: TRACE"]
    assert "TRACE" in r.recommendation


@pytest.mark.asyncio
async def test_no_verified_returns_empty(monkeypatch):
    async def fake_extras(host, port, use_ssl):
        return {"allowed_methods": ["GET", "POST", "PUT", "DELETE", "TRACE"],
                "verified_dangerous_methods": [],
                "error_page_info": None}

    monkeypatch.setattr(scanner, "probe_http_extras", fake_extras)
    results = await hm_mod.PROBE.run(_ctx())
    assert results == []


@pytest.mark.asyncio
async def test_multiple_verified_in_title(monkeypatch):
    async def fake_extras(host, port, use_ssl):
        return {"allowed_methods": ["GET", "PUT", "TRACE"],
                "verified_dangerous_methods": ["PUT", "TRACE"],
                "error_page_info": None}

    monkeypatch.setattr(scanner, "probe_http_extras", fake_extras)
    results = await hm_mod.PROBE.run(_ctx())
    assert len(results) == 1
    assert "PUT" in results[0].title and "TRACE" in results[0].title
