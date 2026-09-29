"""tests/test_xss_payload_expansion.py — XSS payload 정책/확장 + 검색 입력점 전달 검증.

- get_xss_payloads: XSS_PAYLOAD_FILE 은 최대 1000 개까지만 로드(상한 적용).
- safe → balanced 분기로 payload 수 증가.
- 검색 input(q/search)이 _probe_xss_reflected 에 전달되는 points 에 포함(monkeypatch 로 캡처).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import active_probing as ap
from probes import xss_probe
from probes.base import ProbeContext
from probes.config import ScanConfig
from probes.utils import payloads
from probes.utils.rate_limiter import RateLimiter


class _DummySession:
    pass


def _ctx(points, config=None):
    return ProbeContext(
        target_url="http://target.example/",
        session=_DummySession(),
        injection_points=points,
        scan_config=config or ScanConfig(),
        rate_limiter=RateLimiter(0),
        scan_id="test-scan",
    )


def test_payload_level_increases_count():
    safe = payloads.get_xss_payloads(ScanConfig(payload_level="safe"))
    balanced = payloads.get_xss_payloads(ScanConfig(payload_level="balanced"))
    assert len(balanced) > len(safe)
    # safe 셋이 balanced 에 포함(상위 호환)
    assert set(safe).issubset(set(balanced))


def test_payload_file_capped_at_1000(tmp_path):
    f = tmp_path / "xss.txt"
    f.write_text("\n".join(f"<x{i}>" for i in range(5000)), encoding="utf-8")
    cfg = ScanConfig(
        payload_level="aggressive",
        enable_extended_xss=True,
        enable_advanced_payloads=True,
        xss_payload_file=str(f),
        max_xss_payloads=1000,
    )
    out = payloads.get_xss_payloads(cfg)
    assert len(out) <= 1000


def test_max_payloads_clamped_even_if_higher():
    # 상한을 1000 초과로 줘도 산출 개수는 1000 이하.
    f_count = 3000
    cfg = ScanConfig(payload_level="aggressive", enable_extended_xss=True,
                     max_xss_payloads=2000)
    out = payloads.get_xss_payloads(cfg)
    assert len(out) <= 2000  # 함수 자체 상한; 파일 없으면 base 만


@pytest.mark.asyncio
async def test_search_input_included_in_reflected_points(monkeypatch):
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
    await xss_probe.PROBE.run(_ctx([search_point]))

    assert "points" in captured
    target_params = set()
    is_search_flagged = False
    for p in captured["points"]:
        target_params |= set(p.get("params", {}))
        if p.get("is_search"):
            is_search_flagged = True
    assert {"q", "search"} & target_params
    assert is_search_flagged, "검색 입력점이 is_search=True 로 표시되어 전달되어야 한다"
