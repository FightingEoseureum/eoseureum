"""
test_nmap_service_enrich.py — service_scan 의 nmap -sV 보강(선택) 검증.

검증 항목:
  - SERVICE_SCAN_USE_NMAP=true 일 때 _nmap_version_scan 결과가 합류.
    제품/버전이 식별된 항목은 공격표면 정보노출(service_attack_surface, Info) — 취약점 아님.
    미식별(name 만)은 Info discovery.
  - 플래그 미설정 시 nmap 호출/항목 없음(Python 점검만 — 폴백).
  - _nmap_binary: NMAP_PATH 우선 / 없으면 None.
  - 실제 네트워크/subprocess 는 _nmap_version_scan 을 monkeypatch 하여 차단.

실행: cd backend && venv_linux/bin/python -m pytest tests/test_nmap_service_enrich.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import service_scan as ss


HOST = "10.0.0.9"

# nmap 이 호출되더라도 실제 실행되지 않도록 PORT_CHECKS 가 없는 포트만 사용해도 되고,
# 여기서는 _nmap_version_scan 을 항상 monkeypatch 한다.
_FAKE_NMAP = {
    80: {"name": "http", "product": "nginx", "version": "1.18.0", "extrainfo": "Ubuntu"},
    22: {"name": "ssh", "product": "OpenSSH", "version": "8.9p1", "extrainfo": ""},
}


def _version_titles(result):
    # 제품 식별 항목은 공격표면(service_attack_surface, Info), 미식별은 service_discovery(Info)
    return [it.get("title", "") for it in
            (result["service_attack_surface"] + result["service_discovery"])]


def test_nmap_enrich_added_when_enabled(monkeypatch):
    monkeypatch.setenv("SERVICE_SCAN_USE_NMAP", "true")
    monkeypatch.setattr(ss, "_nmap_version_scan", lambda h, p, t: _FAKE_NMAP)
    # PORT_CHECKS 동작은 무관하게, 네트워크는 타지 않도록 배너류도 비활성 응답으로
    monkeypatch.setattr(ss, "_recv_banner", lambda h, p, t, send=None: "")
    monkeypatch.setattr(ss, "_tcp_connect_ok", lambda h, p, t: False)

    result = ss.scan_services(HOST, [80, 22])
    titles = " | ".join(_version_titles(result))
    assert "nginx 1.18.0" in titles
    assert "OpenSSH 8.9p1" in titles
    # 제품/버전이 식별된 서비스/버전 항목은 '취약점'이 아니라 공격표면(정보노출)으로 분류
    vdet = [it for it in (result["service_attack_surface"] + result["service_discovery"])
            if "version-detection" in it.get("tags", [])]
    assert vdet, "버전 식별 항목이 있어야 함"
    for it in vdet:
        # _FAKE_NMAP 은 두 항목 모두 product 를 가짐 → 전부 attack_surface(Info), 취약 아님
        assert it["finding_type"] == "attack_surface"
        assert it["severity"] == "Info"
        assert it.get("judgment") != "취약"      # 취약 판정 아님(카운트/위험도 제외)
        assert it["cwe"] == "CWE-200"
        assert it["safe_check"] is True
    # 취약 findings 로는 라우팅되지 않음(공격표면 버킷으로만)
    assert all("version-detection" not in it.get("tags", [])
               for it in result["service_findings"])


def test_nmap_enrich_bare_service_stays_info(monkeypatch):
    """제품/버전 미식별(name 만)인 경우 LOW 승격하지 않고 Info discovery 유지(오탐 방지)."""
    monkeypatch.setenv("SERVICE_SCAN_USE_NMAP", "true")
    monkeypatch.setattr(ss, "_nmap_version_scan", lambda h, p, t:
                        {8081: {"name": "http-proxy", "product": "", "version": "", "extrainfo": ""}})
    monkeypatch.setattr(ss, "_recv_banner", lambda h, p, t, send=None: "")
    monkeypatch.setattr(ss, "_tcp_connect_ok", lambda h, p, t: False)

    result = ss.scan_services(HOST, [8081])
    vdet = [it for it in (result["service_findings"] + result["service_discovery"])
            if "version-detection" in it.get("tags", [])]
    assert len(vdet) == 1
    assert vdet[0]["finding_type"] == "discovery"
    assert vdet[0]["severity"] == "Info"


def test_nmap_not_called_when_disabled(monkeypatch):
    monkeypatch.delenv("SERVICE_SCAN_USE_NMAP", raising=False)
    called = {"n": 0}

    def _spy(h, p, t):
        called["n"] += 1
        return _FAKE_NMAP

    monkeypatch.setattr(ss, "_nmap_version_scan", _spy)
    monkeypatch.setattr(ss, "_recv_banner", lambda h, p, t, send=None: "")
    monkeypatch.setattr(ss, "_tcp_connect_ok", lambda h, p, t: False)

    result = ss.scan_services(HOST, [80, 22])
    assert called["n"] == 0
    assert not any("version-detection" in it.get("tags", []) for it in result["service_discovery"])


def test_nmap_binary_resolution(monkeypatch, tmp_path):
    # NMAP_PATH 가 실행가능 파일이면 그 경로 반환
    fake = tmp_path / "nmap"
    fake.write_text("#!/bin/sh\n")
    os.chmod(fake, 0o755)
    monkeypatch.setenv("NMAP_PATH", str(fake))
    assert ss._nmap_binary() == str(fake)

    # NMAP_PATH 가 존재하지 않으면 None
    monkeypatch.setenv("NMAP_PATH", str(tmp_path / "missing"))
    assert ss._nmap_binary() is None


def test_nmap_version_scan_returns_empty_without_binary(monkeypatch):
    # 바이너리 미해결 시 {} (폴백) — 실제 subprocess 실행 없음
    monkeypatch.setattr(ss, "_nmap_binary", lambda: None)
    assert ss._nmap_version_scan(HOST, [80], 5.0) == {}
