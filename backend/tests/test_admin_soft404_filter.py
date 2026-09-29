"""test_admin_soft404_filter.py — Admin/민감 경로 soft-404 오탐 필터 검증."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import external_tools as et


def test_admin_length0_excluded():
    # HTTP 200 + 빈 본문(length 0) → 등록 자격 없음
    assert et.admin_surface_eligible(200, "") is False
    assert et.admin_surface_eligible(200, "   ") is False


def test_random_equal_is_soft404():
    cand = {"status": 200, "length": 120, "body": "<html>Welcome page</html>", "title": ""}
    rnd  = {"status": 200, "length": 120, "body": "<html>Welcome page</html>", "title": ""}
    assert et.is_soft404(cand, [rnd]) is True


def test_distinct_admin_not_soft404():
    cand = {"status": 200, "length": 900, "body": "<html>" + "A" * 880 + "admin login form</html>", "title": "admin"}
    rnd  = {"status": 200, "length": 25, "body": "<html>not found</html>", "title": "404"}
    assert et.is_soft404(cand, [rnd]) is False


def test_password_form_eligible():
    body = '<html><form><input type="password" name="pw"></form></html>'
    assert et.admin_surface_eligible(200, body) is True


def test_admin_keyword_eligible():
    assert et.admin_surface_eligible(200, "<html>Administrator Dashboard</html>") is True


def test_401_protected_eligible():
    assert et.admin_surface_eligible(401, "") is True
    assert et.admin_surface_eligible(403, "") is True


def test_no_keyword_no_form_excluded():
    assert et.admin_surface_eligible(200, "<html><body>hello world</body></html>") is False
