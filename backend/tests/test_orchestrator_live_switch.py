"""
test_orchestrator_live_switch.py — USE_PROBE_ORCHESTRATOR 라이브 전환 + graceful fallback 검증.

검증 항목 (네트워크 없음, monkeypatch 로 호출 캡처):
  - USE_PROBE_ORCHESTRATOR=false(기본) → 기존 경로(probe_http_vulnerabilities) 사용.
  - =true → orchestrator 경로(probe_http_vulnerabilities_via_orchestrator) 사용.
  - orchestrator 경로가 예외를 던지면 기존 경로로 graceful fallback.
  - 반환 구조(service["active_probes"]) 불변.

실행: venv_linux/bin/python -m pytest tests/test_orchestrator_live_switch.py -q
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import active_probing as ap


def _host_results():
    return [{
        "host": "t.example",
        "services": [
            {"port": 80, "http_info": {"url": "http://t.example/"}, "discovered_urls": []},
        ],
    }]


def _patch_calls(monkeypatch):
    calls = {"legacy": 0, "orchestrator": 0}

    async def fake_legacy(host, port, use_ssl, http_info, cookies=None, scan_id="",
                          discovered_urls=None, login_candidates=None, technologies=None,
                          log_cb=None):
        calls["legacy"] += 1
        return {"_via": "legacy"}

    async def fake_orchestrator(host, port, is_ssl, http_info, cookies, scan_id="", discovered_urls=None):
        calls["orchestrator"] += 1
        return [{"_via": "orchestrator"}]

    monkeypatch.setattr(ap, "probe_http_vulnerabilities", fake_legacy)
    monkeypatch.setattr(ap, "probe_http_vulnerabilities_via_orchestrator", fake_orchestrator)
    return calls


@pytest.mark.asyncio
async def test_default_uses_legacy_path(monkeypatch):
    monkeypatch.setenv("USE_PROBE_ORCHESTRATOR", "false")
    calls = _patch_calls(monkeypatch)

    hr = _host_results()
    out = await ap.probe_active_for_all_hosts(hr)

    assert calls["legacy"] == 1
    assert calls["orchestrator"] == 0
    svc = out[0]["services"][0]
    assert "active_probes" in svc
    assert svc["active_probes"] == {"_via": "legacy"}


@pytest.mark.asyncio
async def test_true_uses_orchestrator_path(monkeypatch):
    monkeypatch.setenv("USE_PROBE_ORCHESTRATOR", "true")
    calls = _patch_calls(monkeypatch)

    hr = _host_results()
    out = await ap.probe_active_for_all_hosts(hr)

    assert calls["orchestrator"] == 1
    assert calls["legacy"] == 0
    svc = out[0]["services"][0]
    assert "active_probes" in svc
    assert svc["active_probes"] == [{"_via": "orchestrator"}]


@pytest.mark.asyncio
async def test_orchestrator_error_falls_back_to_legacy(monkeypatch):
    monkeypatch.setenv("USE_PROBE_ORCHESTRATOR", "true")
    calls = {"legacy": 0, "orchestrator": 0}

    async def fake_legacy(host, port, use_ssl, http_info, cookies=None, scan_id="", discovered_urls=None,
                          technologies=None, log_cb=None):
        calls["legacy"] += 1
        return {"_via": "legacy_fallback"}

    async def boom_orchestrator(host, port, is_ssl, http_info, cookies, scan_id="", discovered_urls=None):
        calls["orchestrator"] += 1
        raise RuntimeError("orchestrator boom")

    monkeypatch.setattr(ap, "probe_http_vulnerabilities", fake_legacy)
    monkeypatch.setattr(ap, "probe_http_vulnerabilities_via_orchestrator", boom_orchestrator)

    hr = _host_results()
    out = await ap.probe_active_for_all_hosts(hr)

    # orchestrator 가 호출되고 예외 → 기존 경로로 fallback
    assert calls["orchestrator"] == 1
    assert calls["legacy"] == 1
    svc = out[0]["services"][0]
    assert svc["active_probes"] == {"_via": "legacy_fallback"}


@pytest.mark.asyncio
async def test_return_structure_preserved(monkeypatch):
    """반환은 host_results 리스트 그대로, service 에 active_probes 키만 추가됨."""
    monkeypatch.setenv("USE_PROBE_ORCHESTRATOR", "false")
    _patch_calls(monkeypatch)

    hr = _host_results()
    out = await ap.probe_active_for_all_hosts(hr)

    assert out is hr  # 동일 리스트 객체 반환(구조 불변)
    assert isinstance(out, list)
    assert "active_probes" in out[0]["services"][0]
