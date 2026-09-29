"""
test_info_disclosure_probe.py — InfoDisclosureProbe 검증.

세 경로 각각이 finding ProbeResult 를 생성하는지 확인한다(네트워크 없음):
  1) Server 헤더 노출
  2) 에러 페이지 정보 노출 (scanner.probe_http_extras monkeypatch)
  3) 민감 경로 본문 확인 (discovered_urls 에 body 주입)
그리고 단순 경로 존재(민감 마커 없음)는 finding 이 아님을 확인한다.

실행: venv_linux/bin/python -m pytest tests/test_info_disclosure_probe.py -q
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanner
import probes.info_disclosure_probe as info_mod
from probes.base import ProbeContext, ProbeResult
from probes.utils.rate_limiter import RateLimiter


def _ctx(**kw):
    base = dict(
        target_url="http://t.example/", host="t.example", port=80, scheme="http",
        session=None, rate_limiter=RateLimiter(0), scan_id="s",
        headers={}, discovered_urls=[],
    )
    base.update(kw)
    return ProbeContext(**base)


def _no_error_page(monkeypatch):
    async def fake_extras(host, port, use_ssl):
        return {"allowed_methods": [], "verified_dangerous_methods": [], "error_page_info": None}
    monkeypatch.setattr(scanner, "probe_http_extras", fake_extras)


@pytest.mark.asyncio
async def test_server_header_finding(monkeypatch):
    _no_error_page(monkeypatch)
    results = await info_mod.PROBE.run(_ctx(headers={"Server": "nginx/1.18.0"}))
    matches = [r for r in results if r.probe_key == "server_header_disclosure"]
    assert len(matches) == 1
    r = matches[0]
    assert isinstance(r, ProbeResult)
    assert r.title == "서버 소프트웨어 버전 정보 노출 (Server 헤더)"
    assert r.severity == "Low"
    assert r.cwe == "CWE-200"
    assert r.owasp == "A05:2021"
    assert r.finding_type == "vulnerability"


@pytest.mark.asyncio
async def test_server_header_without_version_no_finding(monkeypatch):
    _no_error_page(monkeypatch)
    results = await info_mod.PROBE.run(_ctx(headers={"Server": "nginx"}))
    assert not any(r.probe_key == "server_header_disclosure" for r in results)


@pytest.mark.asyncio
async def test_error_page_finding(monkeypatch):
    async def fake_extras(host, port, use_ssl):
        return {"allowed_methods": [], "verified_dangerous_methods": [],
                "error_page_info": {"leaks": ["stack_trace", "path_disclosure"], "status_code": 500}}
    monkeypatch.setattr(scanner, "probe_http_extras", fake_extras)

    results = await info_mod.PROBE.run(_ctx())
    matches = [r for r in results if r.probe_key == "error_page_disclosure"]
    assert len(matches) == 1
    r = matches[0]
    assert r.title == "에러 페이지에서 시스템 정보 노출"
    assert r.severity == "Medium"
    assert r.cwe == "CWE-200"


@pytest.mark.asyncio
async def test_sensitive_path_content_finding(monkeypatch):
    _no_error_page(monkeypatch)
    discovered = [{
        "url": "http://t.example/.env", "status": 200,
        "body": "DEBUG=false\nSECRET_KEY=abcd1234\nDATABASE_URL=postgres://u:p@db/x",
    }]
    results = await info_mod.PROBE.run(_ctx(discovered_urls=discovered))
    matches = [r for r in results if r.probe_key == "sensitive_path_content"]
    assert len(matches) == 1
    r = matches[0]
    assert r.affected_url == "http://t.example/.env"
    assert r.finding_type == "vulnerability"
    assert r.severity == "Medium"
    assert r.cwe == "CWE-200"


@pytest.mark.asyncio
async def test_path_existence_only_no_finding(monkeypatch):
    """본문에 민감 마커가 없는 단순 200 경로는 finding 이 아니다(discovery)."""
    _no_error_page(monkeypatch)
    discovered = [{"url": "http://t.example/about", "status": 200,
                   "body": "<html><body>About us</body></html>"}]
    results = await info_mod.PROBE.run(_ctx(discovered_urls=discovered))
    assert not any(r.probe_key == "sensitive_path_content" for r in results)


@pytest.mark.asyncio
async def test_no_findings_when_clean(monkeypatch):
    _no_error_page(monkeypatch)
    results = await info_mod.PROBE.run(_ctx())
    assert results == []
