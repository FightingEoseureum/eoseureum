"""csp_analyzer 단위 테스트 — CSP 우회 클래스 탐지 검증."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import csp_analyzer as c

# Dreamhack DOM-XSS 챌린지 실제 CSP
CHALLENGE_CSP = (
    "default-src 'self'; img-src https://dreamhack.io; style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'nonce-abc123' 'strict-dynamic'"
)


def _ids(csp, **kw):
    return {f["id"] for f in c.analyze_csp(csp, **kw)}


def test_parse_basic():
    d = c.parse_csp("default-src 'self'; script-src 'self' 'nonce-x'")
    assert d["default-src"] == ["'self'"]
    assert d["script-src"] == ["'self'", "'nonce-x'"]


def test_parse_empty():
    assert c.parse_csp("") == {}
    assert c.analyze_csp("") == []


def test_challenge_base_uri_hijack_detected():
    ids = _ids(CHALLENGE_CSP, has_injection_point=True)
    assert "base_uri_script_hijack" in ids
    assert c.base_uri_hijackable(CHALLENGE_CSP) is True
    assert c.is_xss_bypassable(CHALLENGE_CSP, has_injection_point=True) is True


def test_challenge_severity_escalates_with_injection():
    # 주입점 있으면 critical, 없으면 high
    with_inj = [f for f in c.analyze_csp(CHALLENGE_CSP, has_injection_point=True)
                if f["id"] == "base_uri_script_hijack"][0]
    no_inj = [f for f in c.analyze_csp(CHALLENGE_CSP, has_injection_point=False)
              if f["id"] == "base_uri_script_hijack"][0]
    assert with_inj["severity"] == "critical"
    assert with_inj["enables_xss"] is True
    assert no_inj["severity"] == "high"
    assert no_inj["enables_xss"] is False


def test_base_uri_none_is_safe():
    safe = ("default-src 'self'; script-src 'self' 'nonce-x' 'strict-dynamic'; "
            "base-uri 'none'; object-src 'none'")
    assert c.base_uri_hijackable(safe) is False
    assert _ids(safe, has_injection_point=True) == set()


def test_base_uri_self_is_safe():
    safe = "script-src 'self' 'nonce-x' 'strict-dynamic'; base-uri 'self'; object-src 'none'"
    assert "base_uri_script_hijack" not in _ids(safe)


def test_base_uri_wildcard_still_hijackable():
    bad = "script-src 'nonce-x' 'strict-dynamic'; base-uri *; object-src 'none'"
    assert "base_uri_script_hijack" in _ids(bad)


def test_no_nonce_no_base_uri_hijack():
    # nonce/strict-dynamic 의존이 없으면 base-uri 하이재킹 대상 아님
    plain = "script-src 'self'; base-uri" # base-uri 없음이지만 nonce 미의존
    assert "base_uri_script_hijack" not in _ids("script-src 'self'")


def test_unsafe_inline_without_nonce_flagged():
    assert "script_unsafe_inline" in _ids("script-src 'self' 'unsafe-inline'")


def test_unsafe_inline_with_nonce_nullified():
    # nonce 존재 시 브라우저가 unsafe-inline 무시 → 약점 아님
    csp = "script-src 'self' 'unsafe-inline' 'nonce-x'; base-uri 'none'; object-src 'none'"
    assert "script_unsafe_inline" not in _ids(csp)


def test_no_script_restriction():
    ids = _ids("img-src 'self'")  # script-src/default-src 모두 없음
    assert "no_script_restriction" in ids


def test_wildcard_script_src():
    assert "script_scheme_wildcard" in _ids("script-src *")
    assert "script_scheme_wildcard" in _ids("script-src https:")


def test_unsafe_eval():
    assert "unsafe_eval" in _ids("script-src 'self' 'unsafe-eval'; base-uri 'none'; object-src 'none'")


def test_default_src_fallback():
    # script-src 없고 default-src 로 폴백
    csp = "default-src 'self' 'unsafe-inline'"
    assert "script_unsafe_inline" in _ids(csp)


def test_object_src_open():
    assert "object_src_open" in _ids("script-src 'self'")
    # default-src 'none' 이면 object 도 막힘
    assert "object_src_open" not in _ids("default-src 'none'; script-src 'self'")


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call(["python", "-m", "pytest", __file__, "-v"]))
