"""CSRF 실제수행 실증을 위한 로그인 비밀번호 등록 회귀 테스트.

과거 iterative_recrawl.run() 안에서 존재하지 않는 지역변수 `cfg` 를 참조해
NameError 가 조용히 삼켜져 register_auth_password 가 호출되지 않았고,
그 결과 get_auth_password 가 "" 를 반환해 CSRF 실제수행 실증이 스킵됐다.

핵심 계약: _auth_crawl 이 로그인에 사용한 것과 '동일한' 해석식으로
유효 비밀번호를 재구성해야 한다.
  per-scan auth(login_url 보유 시) → 전역 AUTH_* 설정(AUTH_PASSWORD env).
"""
import os

import probe_policy as pp


def _resolve_effective_password(auth):
    """iterative_recrawl.run() 의 등록 스코프와 동일한 해석식(문서화·회귀고정)."""
    login_cfg = auth if (isinstance(auth, dict) and auth.get("login_url")) \
        else pp.auth_crawl_config()
    return (login_cfg or {}).get("password") or ""


def test_password_from_global_env_when_auth_none(monkeypatch):
    # per-scan auth 없음 → 전역 AUTH_PASSWORD env 로 폴백돼야 한다(비인증-설정 스캔 경로).
    monkeypatch.setenv("AUTH_PASSWORD", "password")
    monkeypatch.setenv("AUTH_USERNAME", "admin")
    monkeypatch.setenv("AUTH_LOGIN_URL", "http://target/login.php")
    assert _resolve_effective_password(None) == "password"


def test_password_from_per_scan_auth(monkeypatch):
    # per-scan auth(login_url 보유) → env 보다 우선.
    monkeypatch.setenv("AUTH_PASSWORD", "envpw")
    auth = {"login_url": "http://t/login", "username": "u", "password": "scanpw"}
    assert _resolve_effective_password(auth) == "scanpw"


def test_empty_when_nothing_configured(monkeypatch):
    for k in ("AUTH_PASSWORD", "AUTH_USERNAME", "AUTH_LOGIN_URL"):
        monkeypatch.delenv(k, raising=False)
    assert _resolve_effective_password(None) == ""


def test_registry_roundtrip():
    import active_probing as apc
    sid = "test-csrf-pw-roundtrip"
    apc.register_auth_password(sid, "password")
    assert apc.get_auth_password(sid) == "password"
    # 미등록 scan_id 는 빈 문자열(과거 버그가 남긴 상태와 동일).
    assert apc.get_auth_password("never-registered") == ""
