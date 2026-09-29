# -*- coding: utf-8 -*-
"""authz_matrix(BFLA) 순수 로직 단위테스트(네트워크 없음)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import authz_matrix as am


def test_is_privileged():
    assert am.is_privileged("http://x/admin")
    assert am.is_privileged("http://x/admin/users")
    assert am.is_privileged("http://x/api/admin/config")
    assert am.is_privileged("http://x/api/users")
    assert am.is_privileged("http://x/api/v1/config")
    assert not am.is_privileged("http://x/about")
    assert not am.is_privileged("http://x/blog/1")
    assert not am.is_privileged("http://x/search?q=1")


def test_gather_privileged_endpoints():
    hr = [{"host": "x", "services": [{
        "discovery_result": {
            "admin_hits": [{"url": "http://x/admin"}],
            "api_hits": [{"url": "http://x/api/admin/users"}],
        },
        "discovered_urls": ["http://x/about", "http://x/manage/settings", "http://x/blog"],
    }]}]
    eps = am.gather_privileged_endpoints(hr)
    urls = {e["url"] for e in eps}
    assert "http://x/admin" in urls
    assert "http://x/api/admin/users" in urls
    assert "http://x/manage/settings" in urls   # discovered_urls 중 특권 경로
    assert "http://x/about" not in urls          # 비특권 제외
    assert "http://x/blog" not in urls
    kinds = {e["url"]: e["kind"] for e in eps}
    assert kinds["http://x/admin"] == "admin_page"
    assert kinds["http://x/api/admin/users"] == "admin_api"


def test_classify_access():
    assert am.classify_access(200, "<h1>Admin Dashboard</h1>") == am.ALLOWED
    assert am.classify_access(200, "<form><input type='password'></form>") == am.DENIED  # 로그인 페이지
    assert am.classify_access(403, "") == am.DENIED
    assert am.classify_access(401, "") == am.DENIED
    assert am.classify_access(302, "") == am.DENIED  # 리다이렉트=통제
    assert am.classify_access(404, "") == am.NOTFOUND
    assert am.classify_access(500, "") == am.ERROR
    assert am.classify_access(0, "") == am.ERROR
    assert am.classify_access(None, None) == am.ERROR


def test_role_rank():
    assert am.role_rank("admin") == 3
    assert am.role_rank("관리자") == 3
    assert am.role_rank("user") == 1
    assert am.role_rank("일반회원") == 1
    assert am.role_rank("") == 0
    assert am.role_rank("editor") == 2  # 알려졌으나 애매


def test_judge_bfla_missing_auth():
    g, cat, _ = am.judge_bfla(am.ALLOWED, am.DENIED, am.ALLOWED)
    assert g == "CONFIRMED" and cat == "missing_auth"


def test_judge_bfla_roles_known():
    # B(user) < A(admin) 이고 B 접근 허용 → 확정
    g, cat, _ = am.judge_bfla(am.DENIED, am.ALLOWED, am.ALLOWED, role_a="admin", role_b="user")
    assert g == "CONFIRMED" and cat == "bfla"
    # B 가 동급/상위 → 정상
    g, _, _ = am.judge_bfla(am.DENIED, am.ALLOWED, am.ALLOWED, role_a="user", role_b="admin")
    assert g is None


def test_judge_bfla_roles_unknown():
    g, cat, _ = am.judge_bfla(am.DENIED, am.ALLOWED, am.ALLOWED)
    assert g == "POSSIBLE" and cat == "bfla"


def test_judge_bfla_b_denied_ok():
    g, _, _ = am.judge_bfla(am.DENIED, am.DENIED, am.ALLOWED, role_a="admin", role_b="user")
    assert g is None


def test_build_matrix_and_summary():
    results = [
        {"endpoint": {"url": "http://x/admin", "kind": "admin_page"},
         "anon": am.ALLOWED, "b": am.ALLOWED, "a": am.ALLOWED, "grade": "CONFIRMED", "category": "missing_auth"},
        {"endpoint": {"url": "http://x/api/users", "kind": "admin_api"},
         "anon": am.DENIED, "b": am.ALLOWED, "a": am.ALLOWED, "grade": "POSSIBLE", "category": "bfla"},
        {"endpoint": {"url": "http://x/manage", "kind": "function"},
         "anon": am.DENIED, "b": am.DENIED, "a": am.ALLOWED, "grade": None, "category": ""},
    ]
    m = am.build_matrix(results)
    assert m["columns"] == ["anon", "B", "A"]
    assert len(m["rows"]) == 3
    s = am.summarize(results)
    assert s == {"tested": 3, "confirmed": 1, "possible": 1}


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
