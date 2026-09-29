"""세션 인지 능동 점검(고도화 #2) 회귀 테스트 — 인증 쿠키 레지스트리."""
import active_probing as ap


def test_auth_cookie_registry_roundtrip():
    ap.clear_auth_cookies("s1")
    ap.register_auth_cookies("s1", [{"name": "SESSION", "value": "abc"},
                                    {"name": "csrftoken", "value": "xyz"}])
    got = ap.get_auth_cookies("s1")
    assert {c["name"] for c in got} == {"SESSION", "csrftoken"}
    ap.clear_auth_cookies("s1")
    assert ap.get_auth_cookies("s1") == []


def test_register_ignores_nameless_and_empty():
    ap.clear_auth_cookies("s2")
    ap.register_auth_cookies("s2", [{"value": "novalue"}, {"name": "", "value": "x"}])
    assert ap.get_auth_cookies("s2") == []
    ap.register_auth_cookies("s2", [])
    assert ap.get_auth_cookies("s2") == []


def test_auth_probe_enabled_gate(monkeypatch):
    monkeypatch.delenv("ENABLE_AUTH_PROBE", raising=False)
    assert ap.auth_probe_enabled() is False
    monkeypatch.setenv("ENABLE_AUTH_PROBE", "true")
    assert ap.auth_probe_enabled() is True
