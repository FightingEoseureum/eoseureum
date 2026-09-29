"""tests/test_cmdi_payload_policy.py — CMDi payload 정책 + 위임 동작 검증.

- safe/balanced 분기.
- payload 에 sleep/ping/benchmark/외부도메인 없음(echo marker 만).
- _probe_cmdi 위임 동작(gather_all_points 로 발굴한 입력점 전달).
"""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import active_probing as ap
from probes import cmdi_probe
from probes.base import ProbeContext
from probes.config import ScanConfig
from probes.utils import payloads
from probes.utils.rate_limiter import RateLimiter


class _DummySession:
    pass


def _ctx(points, config=None):
    return ProbeContext(
        target_url="http://target.example/app",
        session=_DummySession(),
        injection_points=points,
        scan_config=config or ScanConfig(),
        rate_limiter=RateLimiter(0),
        scan_id="test-scan",
    )


def test_payload_levels():
    safe = payloads.get_cmdi_payloads(ScanConfig(payload_level="safe"))
    balanced = payloads.get_cmdi_payloads(ScanConfig(payload_level="balanced"))
    assert len(safe) >= 1
    assert len(balanced) > len(safe)


def test_payloads_echo_marker_only_no_destructive():
    forbidden = re.compile(r"sleep|ping|benchmark|curl|wget|nslookup|http://|https://|\.com|\bnc\b",
                           re.IGNORECASE)
    for level in ("safe", "balanced", "aggressive"):
        for p in payloads.get_cmdi_payloads(ScanConfig(payload_level=level)):
            assert "echo" in p.lower(), f"echo marker 기반이 아님: {p}"
            assert not forbidden.search(p), f"금지 payload 검출: {p}"


@pytest.mark.asyncio
async def test_probe_cmdi_delegation(monkeypatch):
    captured = {}

    async def fake_probe_cmdi(session, points, scan_id=""):
        captured["points"] = points
        return {"confirmed": True, "url": "http://target.example/app",
                "evidence": "에코 토큰 확인됨"}

    monkeypatch.setattr(ap, "_probe_cmdi", fake_probe_cmdi)
    point = {"url": "http://target.example/app", "method": "GET",
             "source": "generic", "params": {"cmd": "ls"}}
    results = await cmdi_probe.PROBE.run(_ctx([point]))

    assert "points" in captured
    assert any(p.get("params", {}).get("cmd") == "ls" for p in captured["points"])
    assert len(results) == 1
    assert results[0].cwe == "CWE-78"
    assert results[0].confidence == "CONFIRMED"


@pytest.mark.asyncio
async def test_probe_cmdi_skipped_when_no_points(monkeypatch):
    called = {"v": False}

    async def fake_probe_cmdi(session, points, scan_id=""):
        called["v"] = True
        return {"confirmed": True}

    monkeypatch.setattr(ap, "_probe_cmdi", fake_probe_cmdi)
    results = await cmdi_probe.PROBE.run(_ctx([]))
    assert results == []
    assert called["v"] is False
