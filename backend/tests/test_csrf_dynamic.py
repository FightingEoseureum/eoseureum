"""test_csrf_dynamic.py — 동적 CSRF 검증(교차출처+토큰제거 수락 판정, 영향 기반 심각도, 비파괴 제외)."""
import os, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import csrf_dynamic as cd


def test_group_post_forms():
    pts = [{"url": "http://t/sendFeedback", "method": "POST", "param": "comments"},
           {"url": "http://t/sendFeedback", "method": "POST", "param": "name"},
           {"url": "http://t/search", "method": "GET", "param": "q"}]
    forms = cd.group_post_forms(pts)
    assert len(forms) == 1                       # POST 폼만
    assert forms[0]["action"] == "http://t/sendFeedback"
    assert set(forms[0]["fields"]) == {"comments", "name"}


def test_destructive_excluded():
    assert cd.is_destructive({"action": "http://t/deleteAccount", "fields": []}) is True
    assert cd.is_destructive({"action": "http://t/transfer", "fields": ["amount"]}) is True
    assert cd.is_destructive({"action": "http://t/sendFeedback", "fields": ["msg"]}) is False


def test_impact_severity_model():
    # 공유상태(게시판) + 세션 → HIGH
    assert cd.impact_severity({"action": "http://t/board/post", "fields": []}, has_session=True) == "HIGH"
    # 공유상태 or 세션 → MEDIUM (익명이라도 도배/가용성 영향)
    assert cd.impact_severity({"action": "http://t/sendFeedback", "fields": []}, has_session=False) == "MEDIUM"
    # 로그인 CSRF 는 클래스 약함 → LOW
    assert cd.impact_severity({"action": "http://t/doLogin", "fields": []}, has_session=True) == "LOW"
    # 완전 익명·무영향 → LOW
    assert cd.impact_severity({"action": "http://t/setTheme", "fields": ["c"]}, has_session=False) == "LOW"


@pytest.mark.asyncio
async def test_enforcement_missing_when_accepted():
    """토큰 제거 + 교차출처인데 서버가 수락 → CSRF 방어 부재."""
    form = {"action": "http://t/sendFeedback", "method": "POST",
            "fields": ["name", "comments", "csrf_token"]}
    captured = {}
    async def post_fn(url, data, headers):
        captured["data"], captured["headers"] = data, headers
        return {"status": 200, "body": "감사합니다. 피드백이 등록되었습니다.", "final_url": url}
    r = await cd.verify_csrf(form, post_fn, has_session=False)
    assert r["status"] == cd.CSRF_ENFORCEMENT_MISSING
    assert r["severity"] == "MEDIUM"                     # 익명이지만 공유상태(feedback)
    assert "csrf_token" not in captured["data"]          # 토큰 필드 제거됨
    assert captured["headers"]["Origin"] == cd.FORGED_ORIGIN
    # 텍스트 PoC 증거 — 요청 원문 + 재현 curl 포함
    assert r.get("curl", "").startswith("curl -i -X POST")
    assert "sendFeedback" in r["curl"]
    assert r["request"]["method"] == "POST"
    assert "재현:" in r["evidence"] and "판정 근거:" in r["evidence"]


@pytest.mark.asyncio
async def test_enforced_when_rejected():
    form = {"action": "http://t/sendFeedback", "method": "POST", "fields": ["comments"]}
    async def post_fn(url, data, headers):
        return {"status": 403, "body": "Invalid CSRF token", "final_url": url}
    r = await cd.verify_csrf(form, post_fn, has_session=False)
    assert r["status"] == cd.CSRF_ENFORCED


@pytest.mark.asyncio
async def test_destructive_skipped():
    form = {"action": "http://t/deleteAccount", "method": "POST", "fields": ["id"]}
    async def post_fn(url, data, headers):
        raise AssertionError("파괴적 폼엔 요청을 보내면 안 됨")
    r = await cd.verify_csrf(form, post_fn)
    assert r["status"] == cd.SKIPPED_DESTRUCTIVE
