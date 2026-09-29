"""
test_sensitive_path_escalation.py — 민감 경로 내용 기반 승격 검증.

검증 항목 (네트워크 없음, discovered_urls 에 body 주입 / scanner.probe_http_extras monkeypatch):
  - /server-status 200 + 민감 본문(scoreboard 등) → info_disclosure_probe finding(Medium)
    & finding_normalizer.classify == "vulnerability".
  - /.env 내용(DB_PASSWORD=...) → finding High & classify == "vulnerability".
  - 401/로그인 폼만 → finding 아님(attack_surface), classify != "vulnerability".

실행: venv_linux/bin/python -m pytest tests/test_sensitive_path_escalation.py -q
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanner
import finding_normalizer as fn
import probes.info_disclosure_probe as info_mod
from probes.base import ProbeContext, ProbeResult
from probes.adapter import convert_probe_result_to_legacy_finding
from probes.utils.rate_limiter import RateLimiter


def _no_error_page(monkeypatch):
    async def fake_extras(host, port, use_ssl):
        return {"allowed_methods": [], "verified_dangerous_methods": [], "error_page_info": None}
    monkeypatch.setattr(scanner, "probe_http_extras", fake_extras)


def _ctx(**kw):
    base = dict(
        target_url="http://t.example", host="t.example", port=80, scheme="http",
        session=None, rate_limiter=RateLimiter(0), scan_id="s",
        headers={}, discovered_urls=[],
    )
    base.update(kw)
    return ProbeContext(**base)


@pytest.mark.asyncio
async def test_server_status_content_escalates(monkeypatch):
    _no_error_page(monkeypatch)
    discovered = [{
        "url": "http://t.example/server-status", "status": 200,
        "body": "<h1>Apache Server Status</h1>\nTotal accesses\nScoreboard: __W_K\nworkers",
    }]
    results = await info_mod.PROBE.run(_ctx(discovered_urls=discovered))
    matches = [r for r in results if r.probe_key == "server_status_exposed"]
    assert len(matches) == 1
    r = matches[0]
    assert isinstance(r, ProbeResult)
    assert r.severity == "Medium"
    assert r.finding_type == "vulnerability"
    assert "content_confirmed" in r.tags

    # normalizer 가 vulnerability 로 승격
    legacy = convert_probe_result_to_legacy_finding(r, "t.example", 80)
    assert fn.classify(legacy) == "vulnerability"


@pytest.mark.asyncio
async def test_env_file_content_escalates_high(monkeypatch):
    _no_error_page(monkeypatch)
    discovered = [{
        "url": "http://t.example/.env", "status": 200,
        "body": "APP_ENV=production\nDB_PASSWORD=s3cr3t\nSECRET_KEY=abcd",
    }]
    results = await info_mod.PROBE.run(_ctx(discovered_urls=discovered))
    matches = [r for r in results if r.probe_key == "env_file_exposed"]
    assert len(matches) == 1
    r = matches[0]
    assert r.severity == "High"
    assert r.finding_type == "vulnerability"

    legacy = convert_probe_result_to_legacy_finding(r, "t.example", 80)
    assert fn.classify(legacy) == "vulnerability"


@pytest.mark.asyncio
async def test_actuator_env_escalates_high(monkeypatch):
    _no_error_page(monkeypatch)
    discovered = [{
        "url": "http://t.example/actuator/env", "status": 200,
        "body": '{"activeProfiles":["prod"],"propertySources":[{"name":"systemProperties"}]}',
    }]
    results = await info_mod.PROBE.run(_ctx(discovered_urls=discovered))
    matches = [r for r in results if r.probe_key == "actuator_env_exposed"]
    assert len(matches) == 1
    assert matches[0].severity == "High"


@pytest.mark.asyncio
async def test_401_protected_not_finding(monkeypatch):
    _no_error_page(monkeypatch)
    discovered = [{
        "url": "http://t.example/manager/html", "status": 401,
        "body": "401 Unauthorized",
    }]
    results = await info_mod.PROBE.run(_ctx(discovered_urls=discovered))
    assert not any(r.probe_key == "manager_unauth_access" for r in results)

    # 401 보호된 관리 경로는 normalizer 에서 attack_surface (취약점 아님)
    f = {
        "title": "숨겨진 경로 발견: /manager/html (HTTP 401)",
        "severity": "MEDIUM", "tool_source": "ffuf",
        "evidence_url": "http://t.example/manager/html",
        "judgment": "취약", "evidence_detail": "",
    }
    assert fn.classify(f) == "attack_surface"


@pytest.mark.asyncio
async def test_login_form_only_not_finding(monkeypatch):
    """관리자 경로 200 + 로그인 폼만 → manager 승격 마커가 없으므로 finding 아님."""
    _no_error_page(monkeypatch)
    discovered = [{
        "url": "http://t.example/manager/html", "status": 200,
        "body": "<form action='/login'><input type='password' name='pw'>로그인</form>",
    }]
    results = await info_mod.PROBE.run(_ctx(discovered_urls=discovered))
    assert not any(r.probe_key == "manager_unauth_access" for r in results)


@pytest.mark.asyncio
async def test_path_existence_only_not_finding(monkeypatch):
    """민감 마커 없는 단순 200 경로는 승격하지 않는다."""
    _no_error_page(monkeypatch)
    discovered = [{
        "url": "http://t.example/server-status", "status": 200,
        "body": "<html><body>Nothing sensitive here</body></html>",
    }]
    results = await info_mod.PROBE.run(_ctx(discovered_urls=discovered))
    assert not any(r.probe_key == "server_status_exposed" for r in results)
