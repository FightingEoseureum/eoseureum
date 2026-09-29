"""test_auth_crawl.py — 인증 후 크롤 설정/판정/coverage(순수 헬퍼; 네트워크 없음)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import probe_policy as pp
import input_points as ip
import authenticated_scan as auth

def test_auth_crawl_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ENABLE_AUTH_CRAWL", raising=False)
    assert pp.auth_crawl_enabled() is False
    cfg = pp.auth_crawl_config()
    assert pp.auth_crawl_skip_reason(cfg) == "ENABLE_AUTH_CRAWL=false"

def test_auth_crawl_skip_reason_missing_creds(monkeypatch):
    monkeypatch.setenv("ENABLE_AUTH_CRAWL", "true")
    monkeypatch.setenv("AUTH_LOGIN_URL", "http://t/login")
    monkeypatch.delenv("AUTH_USERNAME", raising=False)
    cfg = pp.auth_crawl_config()
    assert "USERNAME" in pp.auth_crawl_skip_reason(cfg)

def test_login_form_detection():
    html = '<form action="/login"><input name="uid"><input type="password" name="pw"></form>'
    pts = ip.parse_forms(html, "http://t/login")
    assert ip.is_login_form_points(pts) is True
    assert len(ip.login_form_points(pts)) >= 1

def test_login_success_judgment():
    # 성공 패턴/로그아웃 등장 → 성공
    assert auth._judge_login_success("login form", 200,
        "<a href=/logout>Logout</a> dashboard", {}, "http://t/login", "auto") is True
    # 실패(로그인 폼 잔존) → 실패
    assert auth._judge_login_success("login", 200,
        "Invalid username or password. <form><input type=password></form>",
        {}, "http://t/login", "auto") is False

def test_build_auth_coverage():
    cov = pp.build_auth_coverage(enabled=True, login_success=True, login_forms=1,
                                 authenticated_pages=12, reason="")
    assert cov["auth_crawl_enabled"] is True
    assert cov["auth_login_success"] is True
    assert cov["authenticated_pages"] == 12
    assert cov["login_forms"] == 1
