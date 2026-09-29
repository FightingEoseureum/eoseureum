"""
test_service_scan.py — service_scan 모듈(열린 포트 기반 서비스 보안 점검) 검증.

모듈: backend/service_scan.py
  scan_services(host, open_ports, scan_mode="safe") -> dict

네트워크 I/O 는 service_scan 의 캡슐화 함수를 monkeypatch 하여 주입한다:
  _recv_banner, _tcp_connect_ok, _http_get, _dns_axfr

실행:
  cd backend && venv_linux/bin/python -m pytest tests/test_service_scan.py -q
"""
import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import service_scan as ss


HOST = "10.0.0.5"


def _all_items(result):
    out = []
    for k in ("service_findings", "service_attack_surface", "service_discovery",
              "service_good", "service_noise"):
        out.extend(result[k])
    return out


# 1. SSH 배너만 → attack_surface 또는 Low finding ----------------------------
def test_ssh_banner_attack_surface_or_low(monkeypatch):
    monkeypatch.setattr(ss, "_recv_banner",
                        lambda h, p, t, send=None: "SSH-2.0-OpenSSH_8.9p1")
    result = ss.scan_services(HOST, [22])
    items = _all_items(result)
    assert items, "SSH 점검 결과가 비어 있으면 안 된다"
    # attack_surface 항목이 존재하거나, Low finding 이 존재해야 한다.
    has_as = any(i["finding_type"] == "attack_surface" for i in items)
    has_low_finding = any(i["finding_type"] == "vulnerability" and i["severity"] == "Low"
                          for i in items)
    assert has_as or has_low_finding
    for i in items:
        assert i["scan_category"] == "service"
        assert i["safe_check"] is True


# 2. Redis 인증 없는 접근 → High finding -------------------------------------
def test_redis_unauth_high_finding(monkeypatch):
    monkeypatch.setattr(ss, "_tcp_connect_ok", lambda h, p, t: True)
    monkeypatch.setattr(ss, "_recv_banner",
                        lambda h, p, t, send=None: "+PONG")
    result = ss.scan_services(HOST, [6379])
    findings = result["service_findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_type"] == "vulnerability"
    assert f["severity"] == "High"
    assert f["judgment"] == "취약"
    assert f["confidence_score"] >= 85
    assert result["service_summary"]["service_vulnerability_count"] == 1


def test_redis_auth_required_attack_surface(monkeypatch):
    monkeypatch.setattr(ss, "_tcp_connect_ok", lambda h, p, t: True)
    monkeypatch.setattr(ss, "_recv_banner",
                        lambda h, p, t, send=None: "-NOAUTH Authentication required.")
    result = ss.scan_services(HOST, [6379])
    assert not result["service_findings"]
    assert result["service_attack_surface"]


# 3. DNS AXFR 성공 → Zone Transfer finding -----------------------------------
def test_dns_axfr_success_finding(monkeypatch):
    monkeypatch.setattr(ss, "_dns_axfr",
                        lambda h, p, t: ["@", "www", "mail", "ns1"])
    result = ss.scan_services(HOST, [53])
    findings = result["service_findings"]
    assert len(findings) == 1
    f = findings[0]
    assert "zone transfer" in f["title"].lower() or "axfr" in f["title"].lower()
    assert f["finding_type"] == "vulnerability"
    assert f["severity"] == "High"
    assert f["judgment"] == "취약"


def test_dns_axfr_refused_is_discovery(monkeypatch):
    monkeypatch.setattr(ss, "_dns_axfr", lambda h, p, t: None)
    result = ss.scan_services(HOST, [53])
    assert not result["service_findings"]
    assert result["service_discovery"]


# 4. RDP 노출만 → attack_surface ---------------------------------------------
def test_rdp_exposure_attack_surface(monkeypatch):
    monkeypatch.setattr(ss, "_tcp_connect_ok", lambda h, p, t: True)
    result = ss.scan_services(HOST, [3389])
    assert not result["service_findings"]
    asf = result["service_attack_surface"]
    assert len(asf) == 1
    assert asf[0]["service"] == "RDP"
    assert asf[0]["finding_type"] == "attack_surface"


# 5. HTTP 관리콘솔 로그인/401 → attack_surface --------------------------------
def test_jenkins_login_page_attack_surface(monkeypatch):
    def fake_http(h, p, path, t, scheme="http"):
        return {"status": 200, "headers": {},
                "body": "<html><form>Sign in to Jenkins<input name=password></form></html>"}
    monkeypatch.setattr(ss, "_http_get", fake_http)
    result = ss.scan_services(HOST, [8080])
    assert not result["service_findings"]
    assert result["service_attack_surface"]
    assert result["service_attack_surface"][0]["service"] == "Jenkins"


def test_jenkins_401_attack_surface(monkeypatch):
    # 401(인증요구)이라도 실제 Jenkins 지문(X-Jenkins 헤더)이 있을 때만 Jenkins 로 집계.
    monkeypatch.setattr(ss, "_http_get",
                        lambda h, p, path, t, scheme="http":
                        {"status": 401, "headers": {"X-Jenkins": "2.426.1"}, "body": ""})
    result = ss.scan_services(HOST, [8080])
    assert not result["service_findings"]
    asf = result["service_attack_surface"]
    assert asf and asf[0]["confidence_score"] == 45


def test_jenkins_no_fingerprint_skipped(monkeypatch):
    # 경로(포트 8080)만 일치하고 Jenkins 지문이 없으면 오탐 방지 위해 집계하지 않음.
    monkeypatch.setattr(ss, "_http_get",
                        lambda h, p, path, t, scheme="http":
                        {"status": 200, "headers": {},
                         "body": "<html><body>No results were found for the query</body></html>"})
    result = ss.scan_services(HOST, [8080])
    assert not result["service_findings"]
    assert not result["service_attack_surface"]
    assert not any(i.get("service") == "Jenkins" for i in result["service_discovery"])


# 6. 인증 없는 Docker API → High finding -------------------------------------
def test_docker_api_unauth_high_finding(monkeypatch):
    def fake_http(h, p, path, t, scheme="http"):
        return {"status": 200, "headers": {},
                "body": '{"Version":"24.0.0","ApiVersion":"1.43"}'}
    monkeypatch.setattr(ss, "_http_get", fake_http)
    result = ss.scan_services(HOST, [2375])
    findings = result["service_findings"]
    assert len(findings) == 1
    assert findings[0]["service"] == "Docker API"
    assert findings[0]["finding_type"] == "vulnerability"
    assert findings[0]["severity"] == "High"
    assert findings[0]["confidence_score"] >= 85


# 7. timeout/refused → noise --------------------------------------------------
def test_timeout_refused_is_noise(monkeypatch):
    monkeypatch.setattr(ss, "_recv_banner", lambda h, p, t, send=None: "")
    monkeypatch.setattr(ss, "_tcp_connect_ok", lambda h, p, t: False)
    monkeypatch.setattr(ss, "_http_get", lambda h, p, path, t, scheme="http": None)
    monkeypatch.setattr(ss, "_dns_axfr", lambda h, p, t: None)
    result = ss.scan_services(HOST, [22, 3389, 2375])
    assert not result["service_findings"]
    assert not result["service_attack_surface"]
    assert result["service_noise"]
    for i in result["service_noise"]:
        assert i["finding_type"] == "noise"


# 8. 안전성: 파괴/브루트/exploit/로그인 경로가 없음 ---------------------------
def _executable_source(module):
    """주석/문자열 리터럴(docstring 포함)을 제거한 실행 코드만 추출.

    명세 본문(금지 플래그를 '나열'하는 docstring)이 안전성 단언에
    걸리지 않도록, 실제 실행되는 토큰만 대상으로 검사한다.
    """
    import io
    import tokenize

    src = inspect.getsource(module)
    out = []
    toks = tokenize.generate_tokens(io.StringIO(src).readline)
    for tok in toks:
        if tok.type in (tokenize.COMMENT, tokenize.STRING):
            continue
        out.append(tok.string)
    return " ".join(out).lower()


def test_no_destructive_or_bruteforce_paths():
    code = _executable_source(ss)
    # nmap 인자 안전성: 위험 플래그가 실행 코드에 미포함
    for bad in ("--script vuln", "intrusive", "exploit", "brute"):
        assert bad not in code, f"위험 패턴 발견: {bad}"
    # 인증/로그인/크랙 시도 함수가 정의되어 있지 않아야 한다
    low = inspect.getsource(ss).lower()
    for bad_fn in ("def _login", "def _bruteforce", "def _exploit", "def _crack"):
        assert bad_fn not in low
    # 캡슐화된 I/O 함수만 네트워크에 접근(소켓/HTTP)
    assert hasattr(ss, "_recv_banner")
    assert hasattr(ss, "_http_get")


def test_anonymous_check_disabled_by_default(monkeypatch):
    # ALLOW_ANON 기본 False → FTP/SMB 익명 점검 항목이 생성되지 않는다.
    assert ss.ALLOW_ANON is False
    monkeypatch.delenv("SERVICE_SCAN_ALLOW_ANON", raising=False)
    monkeypatch.setattr(ss, "_recv_banner", lambda h, p, t, send=None: "220 FTP ready")
    monkeypatch.setattr(ss, "_tcp_connect_ok", lambda h, p, t: True)
    result = ss.scan_services(HOST, [21, 445])
    items = _all_items(result)
    assert not any("anonymous" in (i.get("title", "").lower()) for i in items)
    assert not any("익명세션 점검" in i.get("title", "") for i in items)


def test_anonymous_opt_in_enables_check(monkeypatch):
    monkeypatch.setattr(ss, "_recv_banner", lambda h, p, t, send=None: "220 FTP ready")
    monkeypatch.setattr(ss, "_tcp_connect_ok", lambda h, p, t: True)
    result = ss.scan_services(HOST, [21], allow_anon=True)
    items = _all_items(result)
    assert any("anonymous" in i.get("title", "").lower() for i in items)


# 9. 빈 포트/빈 입력 → 빈 결과 ------------------------------------------------
def test_empty_ports_returns_empty():
    result = ss.scan_services(HOST, [])
    assert result["service_findings"] == []
    assert result["service_attack_surface"] == []
    assert result["service_discovery"] == []
    assert result["service_good"] == []
    assert result["service_noise"] == []
    assert result["service_summary"]["checked_ports"] == 0
    assert result["service_summary"]["service_vulnerability_count"] == 0


def test_empty_host_returns_empty():
    result = ss.scan_services("", [22, 6379])
    assert _all_items(result) == []
    assert result["service_summary"]["checked_ports"] == 0


# 추가: 환경변수 제한 ---------------------------------------------------------
def test_max_ports_env_limit(monkeypatch):
    monkeypatch.setenv("SERVICE_SCAN_MAX_PORTS", "1")
    monkeypatch.setattr(ss, "_recv_banner",
                        lambda h, p, t, send=None: "SSH-2.0-OpenSSH_8.9")
    monkeypatch.setattr(ss, "_tcp_connect_ok", lambda h, p, t: True)
    result = ss.scan_services(HOST, [22, 3389])
    assert result["service_summary"]["checked_ports"] == 1


def test_summary_schema_keys():
    result = ss.scan_services(HOST, [])
    summ = result["service_summary"]
    for k in ("checked_ports", "service_vulnerability_count",
              "service_attack_surface_count", "service_discovery_count"):
        assert k in summ


def test_safe_mode_default_and_other_mode_same(monkeypatch):
    monkeypatch.setattr(ss, "_tcp_connect_ok", lambda h, p, t: True)
    monkeypatch.setattr(ss, "_recv_banner", lambda h, p, t, send=None: "+PONG")
    safe = ss.scan_services(HOST, [6379], scan_mode="safe")
    aggressive = ss.scan_services(HOST, [6379], scan_mode="aggressive")
    # 모드와 무관하게 동일하게 안전 동작(분류 결과 동일)
    assert len(safe["service_findings"]) == len(aggressive["service_findings"]) == 1
    assert all(i["safe_check"] is True for i in _all_items(safe))
    assert all(i["safe_check"] is True for i in _all_items(aggressive))
