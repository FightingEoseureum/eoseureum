"""test_login_sqli_safe.py — 로그인 폼 SQLi 안전 점검(비브루트포스, 상태값, 필드식별)."""
import os, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import login_sqli as L

LOGIN_HTML = ('<form action="/doLogin.jsp" method="post">'
              '<input name="uid" type="text"><input name="passw" type="password">'
              '<input type="submit"></form>')

def test_find_login_form_by_password_type():
    forms = L.find_login_forms(LOGIN_HTML, "http://t/login.jsp")
    assert len(forms) == 1
    assert forms[0]["password_field"] == "passw"     # 이름 아닌 type=password 로 식별
    assert forms[0]["username_field"] == "uid"
    assert forms[0]["action"].endswith("/doLogin.jsp")

def test_default_body_includes_submit_and_hidden():
    """sqlmap 완전 body 재현: submit 버튼·hidden 기본값까지 default_body 에 포함."""
    html = ('<form action="/doLogin" method="post">'
            '<input name="uid" type="text"><input name="passw" type="password">'
            '<input type="hidden" name="csrf" value="abc">'
            '<input type="submit" name="btnSubmit" value="Login"></form>')
    forms = L.find_login_forms(html, "http://t/login.jsp")
    db = forms[0]["default_body"]
    assert db.get("btnSubmit") == "Login"     # submit 버튼 포함
    assert db.get("csrf") == "abc"            # hidden 기본값 포함
    assert "uid" in db and "passw" in db

def test_identify_fields_standard_names():
    assert L.identify_login_fields(["email", "password"]) == ("email", "password")
    assert L.identify_login_fields(["q", "submit"]) == (None, None)

def test_no_login_form_when_no_password():
    forms = L.find_login_forms('<form action="/s"><input name="q"></form>', "http://t/s")
    assert forms == []

@pytest.mark.asyncio
async def test_safe_check_max_3_attempts_no_bruteforce():
    forms = L.find_login_forms(LOGIN_HTML, "http://t/login.jsp")
    calls = []
    async def post_fn(url, data):
        calls.append(data)
        return {"status": 200, "body": "Invalid username or password", "final_url": url}
    r = await L.safe_login_sqli_check(forms[0], post_fn)
    assert r["status"] == L.TESTED_SAFE_NO_SIGNAL
    # baseline 1 + payload ≤3 → 최대 4회 (브루트포스 아님)
    assert len(calls) <= 4
    assert r["attempts"] <= 3

@pytest.mark.asyncio
async def test_safe_check_sql_error_is_possible():
    forms = L.find_login_forms(LOGIN_HTML, "http://t/login.jsp")
    async def post_fn(url, data):
        if data.get("passw") == "eoseureum_probe_pw":
            return {"status": 200, "body": "login form", "final_url": url}
        return {"status": 500, "body": "You have an error in your SQL syntax", "final_url": url}
    r = await L.safe_login_sqli_check(forms[0], post_fn)
    assert r["status"] == L.TESTED_SAFE_POSSIBLE

@pytest.mark.asyncio
async def test_safe_check_success_signal_is_manual_review():
    forms = L.find_login_forms(LOGIN_HTML, "http://t/login.jsp")
    async def post_fn(url, data):
        if data.get("passw") == "eoseureum_probe_pw":
            return {"status": 200, "body": "Invalid password", "final_url": url}
        return {"status": 302, "body": "", "final_url": "/dashboard"}   # 우회 성공 신호
    r = await L.safe_login_sqli_check(forms[0], post_fn)
    assert r["status"] == L.MANUAL_REVIEW_REQUIRED  # 안전점검은 단독 CONFIRMED 금지 → 수동검토

@pytest.mark.asyncio
async def test_negative_control_confirms_bypass():
    """우회 성공 + 음성 대조 실패 + baseline 실패 → CONFIRMED_AUTH_BYPASS 로 승격."""
    forms = L.find_login_forms(LOGIN_HTML, "http://t/login.jsp")
    async def post_fn(url, data):
        v = " ".join(str(x) for x in data.values())
        if "eoseureum_probe" in v:                       # baseline → 실패
            return {"status": 200, "body": "Invalid username or password", "final_url": url}
        if "AND '1'='2'" in v or 'AND "1"="2"' in v:  # 음성 대조(거짓) → 실패
            return {"status": 200, "body": "Invalid username or password", "final_url": url}
        return {"status": 302, "body": "", "final_url": "/dashboard"}   # 우회(참) → 성공
    r = await L.safe_login_sqli_check(forms[0], post_fn)
    assert r["status"] == L.CONFIRMED_AUTH_BYPASS
    assert r.get("control_payload")

@pytest.mark.asyncio
async def test_confirms_via_redirect_target_testfire_style():
    """성공/실패가 둘 다 302 이고 Location 목적지로만 갈리는 경우(testfire) 확정.
    실패→login.jsp, OR-참 우회→/bank/main.jsp, 음성대조(AND 거짓)→login.jsp → CONFIRMED."""
    forms = L.find_login_forms(LOGIN_HTML, "http://t/login.jsp")
    async def post_fn(url, data):
        v = " ".join(str(x) for x in data.values())
        # OR-참 계열만 /bank/main.jsp 로(성공), 그 외(baseline·AND거짓)는 login.jsp 로(실패)
        if ("OR '1'='1" in v or 'OR "1"="1' in v or "OR 1=1" in v) and "1'='2" not in v and '1"="2' not in v:
            return {"status": 302, "body": "", "final_url": "/bank/main.jsp"}
        return {"status": 302, "body": "", "final_url": "login.jsp"}
    r = await L.safe_login_sqli_check(forms[0], post_fn)
    assert r["status"] == L.CONFIRMED_AUTH_BYPASS
    assert r["signals"].get("success_redirect") is True


@pytest.mark.asyncio
async def test_generalizes_body_based_no_redirect():
    """리다이렉트 없는 사이트(200 + 본문 내용으로 성공/실패 구분)도 확정 — testfire 특화 아님."""
    forms = L.find_login_forms(LOGIN_HTML, "http://t/login.jsp")
    async def post_fn(url, data):
        v = " ".join(str(x) for x in data.values())
        if ("OR '1'='1" in v or 'OR "1"="1' in v) and "1'='2" not in v and '1"="2' not in v:
            return {"status": 200, "body": "<h1>Welcome back</h1> Sign Out | My Account", "final_url": url}
        return {"status": 200, "body": "Invalid username or password", "final_url": url}
    r = await L.safe_login_sqli_check(forms[0], post_fn)
    assert r["status"] == L.CONFIRMED_AUTH_BYPASS


@pytest.mark.asyncio
async def test_generalizes_arbitrary_redirect_targets():
    """임의의 성공/실패 목적지(URL 하드코딩 아님): 실패→/account/login?e=1, 성공→/portal/home."""
    forms = L.find_login_forms(LOGIN_HTML, "http://t/login.jsp")
    async def post_fn(url, data):
        v = " ".join(str(x) for x in data.values())
        if ("OR '1'='1" in v or 'OR "1"="1' in v) and "1'='2" not in v and '1"="2' not in v:
            return {"status": 302, "body": "", "final_url": "/portal/home"}      # 성공(로그인 아님)
        return {"status": 302, "body": "", "final_url": "/account/login?e=1"}     # 실패(로그인 페이지)
    r = await L.safe_login_sqli_check(forms[0], post_fn)
    assert r["status"] == L.CONFIRMED_AUTH_BYPASS


@pytest.mark.asyncio
async def test_generalizes_no_token_login_page():
    """로그인 페이지 URL에 토큰이 없어도(예: '/') 차등으로 구분: 실패→'/', 성공→'/dashboard'."""
    forms = L.find_login_forms(LOGIN_HTML, "http://t/login.jsp")
    async def post_fn(url, data):
        v = " ".join(str(x) for x in data.values())
        if ("OR '1'='1" in v or 'OR "1"="1' in v) and "1'='2" not in v and '1"="2' not in v:
            return {"status": 302, "body": "", "final_url": "/dashboard"}
        return {"status": 302, "body": "", "final_url": "/"}
    r = await L.safe_login_sqli_check(forms[0], post_fn)
    assert r["status"] == L.CONFIRMED_AUTH_BYPASS


@pytest.mark.asyncio
async def test_no_promote_when_control_also_succeeds():
    """우회·대조가 둘 다 성공(앱이 아무 POST 나 성공) → 승격 안 함(참고 유지)."""
    forms = L.find_login_forms(LOGIN_HTML, "http://t/login.jsp")
    async def post_fn(url, data):
        if data.get("passw") == "eoseureum_probe_pw":
            return {"status": 200, "body": "Invalid password", "final_url": url}
        return {"status": 302, "body": "", "final_url": "/dashboard"}   # 무엇이든 성공
    r = await L.safe_login_sqli_check(forms[0], post_fn)
    assert r["status"] == L.MANUAL_REVIEW_REQUIRED

@pytest.mark.asyncio
async def test_skipped_no_form_action():
    r = await L.safe_login_sqli_check({"action": None, "password_field": "pw"}, None)
    assert r["status"] == L.SKIPPED_NO_FORM_ACTION
