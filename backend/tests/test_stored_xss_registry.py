# -*- coding: utf-8 -*-
"""저장형 XSS 주입 레지스트리/마커 헬퍼 단위테스트(네트워크 없음)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import active_probing as ap


def test_stored_marker_in_body():
    assert ap.stored_marker_in_body("<div>EOSEUREUM_XSS_PROBE_STORED_abc</div>", "EOSEUREUM_XSS_PROBE_STORED_abc")
    assert not ap.stored_marker_in_body("<div>clean</div>", "EOSEUREUM_XSS_PROBE_STORED_abc")
    assert not ap.stored_marker_in_body("", "m")
    assert not ap.stored_marker_in_body("body", "")


def test_registry_register_get_clear():
    sid = "test-scan-xyz"
    ap.clear_stored_xss_injections(sid)
    assert ap.get_stored_xss_injections(sid) == []
    ap.register_stored_xss_injection(sid, "MARK1", "http://x/comment", "content", "http://x")
    ap.register_stored_xss_injection(sid, "MARK1", "http://x/comment", "content", "http://x")  # 중복
    ap.register_stored_xss_injection(sid, "MARK2", "http://x/post", "body", "http://x")
    got = ap.get_stored_xss_injections(sid)
    assert len(got) == 2  # 중복 제거
    markers = {g["marker"] for g in got}
    assert markers == {"MARK1", "MARK2"}
    assert got[0]["submit_url"] == "http://x/comment" and got[0]["param"] == "content"
    ap.clear_stored_xss_injections(sid)
    assert ap.get_stored_xss_injections(sid) == []


def test_registry_isolated_by_scan():
    ap.clear_stored_xss_injections("s1")
    ap.clear_stored_xss_injections("s2")
    ap.register_stored_xss_injection("s1", "M", "u", "p")
    assert len(ap.get_stored_xss_injections("s1")) == 1
    assert ap.get_stored_xss_injections("s2") == []
    ap.clear_stored_xss_injections("s1")


def test_register_ignores_empty_marker():
    ap.clear_stored_xss_injections("s3")
    ap.register_stored_xss_injection("s3", "", "u", "p")
    assert ap.get_stored_xss_injections("s3") == []


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
