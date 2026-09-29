"""test_auth_bypass_nonstandard_fields.py — 로그인 SQLi 인증 우회 확정 경로가
비표준 필드명(uid/passw, 예: demo.testfire.net) 폼도 인식하고, username 필드 주입뿐 아니라
password 필드 주입('알려진 계정 admin + 패스워드 SQLi') 시나리오도 확정하는지 검증한다."""
import os, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import active_probing as ap


def _testfire_form():
    # demo.testfire.net 스타일: uid/passw (표준 username/password 이름 아님)
    return [{"url": "http://demo.testfire.net/doLogin", "method": "POST",
             "source": "form", "params": {"uid": "", "passw": ""}}]


def test_field_recognition_covers_uid_passw():
    assert ap._auth_is_user_field("uid") is True
    assert ap._auth_is_pw_field("passw") is True


@pytest.mark.asyncio
async def test_bypass_confirmed_on_username_injection(monkeypatch):
    """uid 필드에 OR-참 주입 → 비로그인 페이지로 302 → 확정."""
    async def fake_post(session, url, data=None, **kw):
        val = " ".join(str(v) for v in (data or {}).values())
        if "OR '1'='1" in val or "admin'" in val:
            return (302, "", {"Location": "/bank/main.jsp"})   # 로그인/에러 아님 = 성공
        return (200, "<form>login</form>", {})
    monkeypatch.setattr(ap, "_post", fake_post)

    res = await ap._probe_sqli_auth_bypass(None, _testfire_form())
    assert res is not None, "uid/passw 폼이 인식되어 확정되어야 함(기존엔 SKIP)"
    assert res["type"] == "sql_auth_bypass" and res["confirmed"] is True


@pytest.mark.asyncio
async def test_bypass_confirmed_on_password_injection(monkeypatch):
    """username=admin(고정) + passw 에 OR-참 주입 → 성공 키워드 응답 → 확정.
    사용자가 수동으로 찾은 시나리오(admin / 1' or '1'='1'-- -)."""
    async def fake_post(session, url, data=None, **kw):
        d = data or {}
        pw = str(d.get("passw", ""))
        # 오직 passw 에 OR-참이 들어간 경우만 성공(username 주입은 여기선 실패로 둔다)
        if d.get("uid") == "admin" and ("OR '1'='1" in pw or "OR 1=1" in pw):
            return (200, "Welcome admin — Sign Off / My Account " + "x" * 300, {})
        return (200, "<form>login</form> Invalid", {})
    monkeypatch.setattr(ap, "_post", fake_post)

    res = await ap._probe_sqli_auth_bypass(None, _testfire_form())
    assert res is not None, "password 필드 주입(알려진 계정+SQLi) 시나리오가 확정되어야 함"
    assert res["confirmed"] is True
    assert res["param"] == "passw"


@pytest.mark.asyncio
async def test_no_false_positive_when_all_fail(monkeypatch):
    """모든 시도가 로그인 실패면 확정하지 않는다(오탐 방지)."""
    async def fake_post(session, url, data=None, **kw):
        return (200, "<form>login</form> Invalid username or password", {})
    monkeypatch.setattr(ap, "_post", fake_post)

    res = await ap._probe_sqli_auth_bypass(None, _testfire_form())
    assert res is None
