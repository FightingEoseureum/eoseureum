"""httpx 핑거프린팅 + wpscan 연동 회귀 테스트.

외부 바이너리는 _run/_which 를 monkeypatch 하여 파싱·연동 로직만 검증한다.
"""
import asyncio

import external_tools as et


def _run(coro):
    return asyncio.run(coro)


# ── available_tools: 내부화로 ffuf/httpx/katana 제외, wpscan 유지 ─────────────
def test_available_tools_excludes_internalized_and_has_wpscan():
    keys = et.available_tools().keys()
    assert "wpscan" in keys
    assert "httpx" not in keys and "ffuf" not in keys and "katana" not in keys


# ── wpscan: JSON → findings ──────────────────────────────────────────────────
def test_wpscan_findings_core_plugin_and_exposure():
    data = {
        "version": {"number": "5.8",
                    "vulnerabilities": [{"title": "Core RCE", "references": {"cve": ["2021-1234"]}}]},
        "plugins": {"contact-form": {"vulnerabilities": [
            {"title": "Stored XSS", "references": {"cve": ["2022-5678"]}}]}},
        "interesting_findings": [
            {"type": "xmlrpc", "to_s": "http://t/xmlrpc.php"},
            {"type": "headers", "to_s": "noise"},   # 잡음 — 제외돼야 함
        ],
    }
    fs = et._wpscan_findings_from_json(data, "t", 80)
    titles = " ".join(f["title"] for f in fs)
    assert len(fs) == 3
    assert "코어 취약점" in titles and "플러그인" in titles and "XML-RPC" in titles
    # CVE 정규화(CVE- 접두 부여)
    cves = [c for f in fs for c in (f.get("cve_references") or [])]
    assert "CVE-2021-1234" in cves and "CVE-2022-5678" in cves


def test_wpscan_findings_empty_when_clean():
    assert et._wpscan_findings_from_json({}, "t", 80) == []


def test_run_wpscan_absent_returns_empty(monkeypatch):
    monkeypatch.setattr(et, "_which", lambda n: None)
    assert _run(et.run_wpscan("http://t", "t", 80)) == []
