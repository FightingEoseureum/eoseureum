"""test_input_discovery.py — 입력점 발굴/표준화 + 컨텍스트 분류."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import input_points as ip

PAGE = "http://t/page"

def test_get_query_params_collected():
    pts = ip.query_input_points("http://t/s?q=1&page=2")
    params = {p["param"] for p in pts}
    assert params == {"q", "page"}
    assert all(p["method"] == "GET" and p["source"] == "query" for p in pts)

def test_post_form_inputs_collected():
    html = '<form method="post" action="/login"><input name="user"><input type="password" name="pw"><input type="submit"></form>'
    pts = ip.parse_forms(html, PAGE)
    names = {p["param"]: p for p in pts}
    assert "user" in names and "pw" in names
    assert names["user"]["method"] == "POST"
    assert names["user"]["source"] == "form"
    # submit 은 입력점 아님
    assert all(p["input_type"] != "submit" for p in pts)

def test_hidden_input_marked():
    html = '<form><input type="hidden" name="csrf" value="x"><input name="a"></form>'
    pts = ip.parse_forms(html, PAGE)
    csrf = next(p for p in pts if p["param"] == "csrf")
    assert csrf["source"] == "hidden" and csrf["input_type"] == "hidden"

def test_textarea_select_collected():
    html = '<form><textarea name="comment"></textarea><select name="cat"></select></form>'
    pts = ip.parse_forms(html, PAGE)
    srcs = {p["param"]: p["source"] for p in pts}
    assert srcs.get("comment") == "textarea" and srcs.get("cat") == "select"

def test_search_input_context():
    html = '<form action="/search"><input name="q" placeholder="검색"></form>'
    pts = ip.parse_forms(html, PAGE)
    assert any(p["context"] == "search" for p in pts)
    assert ip.classify_context(name="keyword") == "search"

def test_password_input_context_login():
    html = '<form><input name="username"><input type="password" name="password"></form>'
    pts = ip.parse_forms(html, PAGE)
    # password 가 있는 폼의 입력점은 login 컨텍스트
    assert all(p["context"] == "login" for p in pts)
    assert ip.is_login_form_points(pts) is True

def test_authenticated_flag_propagates():
    html = '<form><input name="a"></form>'
    pts = ip.parse_forms(html, PAGE, authenticated=True)
    assert all(p["authenticated"] is True for p in pts)

def test_api_context():
    assert ip.classify_context(name="x", url="http://t/api/users?x=1") == "api"
