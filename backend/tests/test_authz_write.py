# -*- coding: utf-8 -*-
"""authz_write 순수 로직 단위테스트(네트워크 없음)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import authz_write as aw


def test_is_state_changing():
    assert aw.is_state_changing("POST", "/save")
    assert aw.is_state_changing("PUT", "/x")
    assert aw.is_state_changing("DELETE", "/x")
    assert not aw.is_state_changing("GET", "/list")
    assert aw.is_state_changing("GET", "/post/delete")  # 쓰기 action 은 GET이라도 탐지


def test_is_destructive():
    assert aw.is_destructive("DELETE", "/x")
    assert aw.is_destructive("POST", "/post/delete")
    assert not aw.is_destructive("POST", "/post/edit")


def test_pick_mutable_field_skips_sensitive():
    params = {"id": "1", "csrf_token": "abc", "password": "x", "email": "a@b", "title": "hi"}
    assert aw.pick_mutable_field(params) == "title"   # 민감/식별/CSRF 제외 후 title
    assert aw.pick_mutable_field({"id": "1", "password": "x"}) is None
    assert aw.pick_mutable_field({}) is None


def test_gather_write_candidates():
    forms = [
        {"method": "POST", "url": "http://x/post/edit", "params": {"id": "1", "content": "hi"},
         "csrf_fields": [], "view_url": "http://x/post/1"},
        {"method": "GET", "url": "http://x/list", "params": {"q": "a"}},          # 읽기 → 제외
        {"method": "DELETE", "url": "http://x/post/1", "params": {"body": "z"}},   # 삭제 → 기본 제외
        {"method": "POST", "url": "http://x/pw", "params": {"password": "p"}},     # 수정필드 없음 → 제외
    ]
    cands = aw.gather_write_candidates([], forms)
    assert len(cands) == 1
    assert cands[0]["url"] == "http://x/post/edit"
    assert cands[0]["mutable_field"] == "content"
    # 삭제 허용 시 delete 후보 포함(수정 필드 body 존재)
    cands2 = aw.gather_write_candidates([], forms, allow_destructive=True)
    assert any(c["method"] == "DELETE" for c in cands2)


def test_judge_write_authz():
    # B 수정 수락(2xx) + 재조회 마커 확인 → 실증
    assert aw.judge_write_authz(200, True, True) == "CONFIRMED_WRITE"
    # 2xx 인데 반영 미확정 → 가능성
    assert aw.judge_write_authz(200, False, True) == "POSSIBLE"
    assert aw.judge_write_authz(200, None, True) == "POSSIBLE"
    # 차단 → 취약 아님
    assert aw.judge_write_authz(403, True, True) is None
    assert aw.judge_write_authz(401, None, True) is None
    # A 소유 미확인 → None
    assert aw.judge_write_authz(200, True, False) is None
    # 리다이렉트 + 마커 확인 → 실증, 마커 없으면 None
    assert aw.judge_write_authz(302, True, True) == "CONFIRMED_WRITE"
    assert aw.judge_write_authz(302, False, True) is None


def test_analyze_csrf():
    forms = [
        {"method": "POST", "url": "http://x/save", "params": {"title": "a"}},          # 토큰 없음 → 보고
        {"method": "POST", "url": "http://x/ok", "params": {"csrf_token": "t", "title": "a"}},  # 토큰 → 제외
        {"method": "GET", "url": "http://x/list", "params": {"q": "a"}},               # 읽기 → 제외
    ]
    f = aw.analyze_csrf(forms, cookies=[])
    assert len(f) == 1
    assert f[0]["cwe"] == "CWE-352"
    assert f[0]["severity"] == "MEDIUM"
    # SameSite 미설정 쿠키가 있으면 HIGH 로 가중
    f2 = aw.analyze_csrf(forms, cookies=[{"raw": "sid=abc; Path=/"}])
    assert f2[0]["severity"] == "HIGH"


def test_extract_field_value():
    html = '<input name="title" value="Hello World"> <textarea name="body">line1\nline2</textarea>'
    assert aw.extract_field_value(html, "title") == "Hello World"
    assert aw.extract_field_value(html, "body") == "line1\nline2"
    assert aw.extract_field_value(html, "missing") is None
    # value 가 name 앞
    assert aw.extract_field_value('<input value="V" name="f">', "f") == "V"


def test_safety_guard():
    ok, _ = aw.safety_guard({"method": "POST", "url": "http://x/edit",
                             "mutable_field": "title", "view_url": "http://x/1"})
    assert ok
    # 삭제 계열 기본 차단
    ok, _ = aw.safety_guard({"method": "DELETE", "url": "http://x/1",
                             "mutable_field": "body", "view_url": "http://x/1"})
    assert not ok
    # view_url 없음 → 차단
    ok, _ = aw.safety_guard({"method": "POST", "url": "http://x/e",
                             "mutable_field": "title", "view_url": ""})
    assert not ok
    # 민감 필드 → 차단
    ok, _ = aw.safety_guard({"method": "POST", "url": "http://x/e",
                             "mutable_field": "password", "view_url": "http://x/1"})
    assert not ok


def test_write_marker_stable():
    assert aw.write_marker("a") == aw.write_marker("a")
    assert aw.write_marker("a") != aw.write_marker("b")
    assert aw.write_marker("a").startswith(aw.WRITE_MARKER_PREFIX)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
