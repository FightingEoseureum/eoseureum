"""test_candidate_verification.py — 후보 검증/위험도 평가 로직 검증(오탐 방지 핵심)."""
import os, sys, asyncio
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import candidate_verification as cv


# ── IDOR 교차 계정 비교 ──────────────────────────────────────────────────────
def test_idor_confirmed_when_b_sees_a_data():
    owner = {"status": 200, "body": "주문번호 1001 고객 alice@a.com 주소 서울", "headers": {}}
    cross = {"status": 200, "body": "주문번호 1001 고객 alice@a.com 주소 서울", "headers": {}}
    r = cv.compare_idor(owner, cross, owner_identity=["alice@a.com"], cross_identity=["bob@b.com"])
    assert r["grade"] == "CONFIRMED_RESPONSE"


def test_idor_manual_review_when_b_blocked():
    owner = {"status": 200, "body": "alice data", "headers": {}}
    cross = {"status": 403, "body": "forbidden", "headers": {}}
    r = cv.compare_idor(owner, cross, owner_identity=["alice@a.com"])
    assert r["grade"] == "MANUAL_REVIEW"
    assert r["signals"]["cross_blocked"] is True


def test_idor_manual_review_on_login_redirect():
    owner = {"status": 200, "body": "alice data", "headers": {}}
    cross = {"status": 302, "body": "", "headers": {"Location": "/login?next=/x"}}
    r = cv.compare_idor(owner, cross, owner_identity=["alice@a.com"])
    assert r["grade"] == "MANUAL_REVIEW"


def test_idor_manual_review_when_b_sees_own_data():
    owner = {"status": 200, "body": "고객 alice@a.com 주문 1001 항목 ......", "headers": {}}
    cross = {"status": 200, "body": "고객 bob@b.com 주문 2002 전혀 다른 내용 길이도 차이남" * 3, "headers": {}}
    r = cv.compare_idor(owner, cross, owner_identity=["alice@a.com"], cross_identity=["bob@b.com"])
    assert r["grade"] == "MANUAL_REVIEW"


def test_idor_possible_when_similar_no_identity():
    body = "공통 페이지 내용 " * 50
    owner = {"status": 200, "body": body, "headers": {}}
    cross = {"status": 200, "body": body, "headers": {}}
    r = cv.compare_idor(owner, cross, owner_identity=["zzz_not_present"], cross_identity=[])
    assert r["grade"] == "POSSIBLE"


def test_verify_idor_skips_non_get_and_dedups():
    async def run():
        cands = [
            {"url": "http://t/o?id=1", "method": "GET"},
            {"url": "http://t/o?id=1", "method": "GET"},   # dup
            {"url": "http://t/del?id=1", "method": "POST"},  # state-change → skip
        ]
        async def get_a(u): return {"status": 200, "body": "alice@a.com obj", "headers": {}}
        async def get_b(u): return {"status": 200, "body": "alice@a.com obj", "headers": {}}
        return await cv.verify_idor_candidates(cands, get_a, get_b,
                                               owner_identity=["alice@a.com"])
    res = asyncio.run(run())
    assert len(res) == 1                          # dedup + POST 제외
    assert res[0]["grade"] == "CONFIRMED_RESPONSE"


# ── CSRF 위험도 ──────────────────────────────────────────────────────────────
def test_csrf_high_for_sensitive_tokenless():
    r = cv.score_csrf_risk({"url": "https://t/account/change-password", "method": "POST",
                            "params": ["new_password"], "token_present": False,
                            "samesite": None, "authenticated": True})
    assert r["risk"] == "HIGH"
    assert r["sensitive"] is True


def test_csrf_medium_for_tokenless_nonsensitive():
    r = cv.score_csrf_risk({"url": "https://t/comment/add", "method": "POST",
                            "params": ["text"], "token_present": False, "samesite": "Lax"})
    assert r["risk"] == "MEDIUM"


def test_csrf_low_when_token_and_samesite():
    r = cv.score_csrf_risk({"url": "https://t/account/delete", "method": "POST",
                            "params": [], "token_present": True, "samesite": "Strict"})
    assert r["risk"] == "LOW"


# ── Stored XSS 판정 ──────────────────────────────────────────────────────────
def test_stored_xss_grades():
    assert cv.judge_stored_xss(marker_reflected=True, alert_fired=True) == "CONFIRMED_BROWSER"
    assert cv.judge_stored_xss(marker_reflected=True, alert_fired=False) == "MANUAL_REVIEW"
    assert cv.judge_stored_xss(marker_reflected=False, alert_fired=False) is None


# ── 파일 업로드 분석 ─────────────────────────────────────────────────────────
def test_file_upload_analysis_no_actual_upload():
    forms = [
        {"url": "http://t/upload", "enctype": "multipart/form-data", "method": "POST",
         "file_inputs": [{"name": "file", "accept": "image/*"}]},
        {"url": "http://t/text", "enctype": "application/x-www-form-urlencoded",
         "file_inputs": []},
    ]
    out = cv.analyze_file_upload_forms(forms)
    assert len(out) == 1
    assert out[0]["multipart"] is True
    assert out[0]["extension_restriction"] == "client-accept"
    assert "image/*" in out[0]["accept_attr"]


# ── 비즈니스 로직 후보 ───────────────────────────────────────────────────────
def test_business_logic_candidates():
    points = [
        {"method": "POST", "url": "http://t/buy", "params": {"price": "100", "qty": "1"}},
        {"method": "GET", "url": "http://t/u", "params": {"role": "user"}},
        {"method": "GET", "url": "http://t/s", "params": {"q": "x"}},
    ]
    out = cv.classify_business_logic_params(points)
    names = {c["param"] for c in out}
    assert {"price", "qty", "role"} <= names
    assert "q" not in names


# ── 검증 요약 ────────────────────────────────────────────────────────────────
def test_summarize_verification():
    s = cv.summarize_verification(23, 7,
        ["CONFIRMED_RESPONSE"] + ["MANUAL_REVIEW"] * 6)
    assert s == {"candidates": 23, "verified": 7, "promoted": 1, "manual_review": 6}
