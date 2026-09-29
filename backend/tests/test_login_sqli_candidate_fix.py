"""test_login_sqli_candidate_fix.py — 관리자/로그인 페이지가 Login SQLi 후보로 연결되고,
발견 수 > 0인데 '미발견' 사유가 나오지 않으며, 시도 수가 실제 수행과 일치하는지 검증."""
import os, sys, asyncio
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import active_probing as ap
import login_sqli as lsq


# ── 미수행 사유 일관성(순수 헬퍼) ─────────────────────────────────────────────
def test_reason_not_notfound_when_discovered():
    # 발견 3, 파싱 0 → '미발견' 아님, '구조 분석 실패'
    r = lsq.login_coverage_reason(discovered=3, parsed=0, performed=0)
    assert "미발견" not in r
    assert "구조 분석 실패" in r


def test_reason_notfound_only_when_zero():
    assert lsq.login_coverage_reason(0, 0, 0) == "로그인 폼 미발견"


def test_reason_condition_unmet_when_parsed_but_not_performed():
    r = lsq.login_coverage_reason(discovered=2, parsed=2, performed=0)
    assert "미발견" not in r and "조건 불충족" in r


def test_reason_empty_when_performed():
    assert lsq.login_coverage_reason(2, 2, 2) == ""


def test_reason_uses_probe_reason():
    r = lsq.login_coverage_reason(2, 2, 0, probe_reason="점검 조건 불충족(필드/폼 action 부족)")
    assert r == "점검 조건 불충족(필드/폼 action 부족)"


# ── 관리자 발견 → 로그인 후보 수집 ────────────────────────────────────────────
def test_collect_login_candidates_from_admin_hits():
    service = {"discovery_result": {"admin_hits": [
        {"url": "http://t/admin/login", "has_login_form": True},
        {"url": "http://t/manage", "has_login_form": True},
        {"url": "http://t/info", "has_login_form": False},   # 로그인 폼 없음 → 제외
    ]}}
    cands = ap._collect_login_candidates(service, ["http://t/x", "http://t/user/signin"])
    assert "http://t/admin/login" in cands
    assert "http://t/manage" in cands
    assert "http://t/info" not in cands
    assert "http://t/user/signin" in cands     # 로그인 힌트 URL 도 후보


# ── _probe_login_sqli: 관리자 로그인 페이지 점검 + 카운트 일치 ────────────────
_ADMIN_LOGIN_HTML = """
<html><body><form action="/admin/login" method="POST">
<input type="text" name="username"><input type="password" name="password">
<input type="submit"></form></body></html>
"""


def test_probe_login_sqli_uses_admin_candidates(monkeypatch):
    async def fake_get(session, url):
        if "admin" in url:
            return 200, _ADMIN_LOGIN_HTML, {}
        return 200, "<html><body>no form here</body></html>", {}

    async def fake_post(session, url, data=None):
        # baseline/페이로드 응답 동일 → 신호 없음(안전)
        return 200, "<html>login page</html>", {}

    monkeypatch.setattr(ap, "_get", fake_get)
    monkeypatch.setattr(ap, "_post", fake_post)
    ap.reset_coverage("t1")

    r = asyncio.run(ap._probe_login_sqli(
        None, "http://t/", scan_id="t1",
        login_candidates=["http://t/admin/login"]))
    assert r is not None
    assert r["login_forms_found"] >= 1               # 관리자 로그인 폼 발견
    assert r["login_forms_tested"] >= 1
    assert r["attempts"] >= 1                          # 실제 수행됨
    # coverage 의 시도 수와 실제 수행 일치
    cov = ap.get_coverage("t1")
    assert cov.get("login_sqli_attempts", 0) == r["attempts"]


def test_probe_login_sqli_structure_failure(monkeypatch):
    # 로그인 페이지로 보이지만 폼이 JS 렌더 등으로 파싱 불가 → structure_failed
    async def fake_get(session, url):
        return 200, "<html><body>관리자 로그인 화면 (login)</body></html>", {}

    async def fake_post(session, url, data=None):
        return 200, "x", {}

    monkeypatch.setattr(ap, "_get", fake_get)
    monkeypatch.setattr(ap, "_post", fake_post)
    ap.reset_coverage("t2")
    r = asyncio.run(ap._probe_login_sqli(
        None, "http://t/admin/login", scan_id="t2"))
    assert r is not None
    assert r["login_forms_found"] == 0
    assert r["structure_failed"] >= 1
    assert "구조 분석 실패" in r["skip_reason"]
    assert r["attempts"] == 0
    # 발견은 됐으나(페이지) 미발견 사유가 아니어야 함
    reason = lsq.login_coverage_reason(
        discovered=max(0, r["login_pages_seen"]), parsed=r["login_forms_found"],
        performed=r["attempts"], probe_reason=r["skip_reason"])
    assert "미발견" not in reason


def test_account_lockout_policy_capped(monkeypatch):
    # 폼당 시도 수가 LOGIN_SQLI_MAX_ATTEMPTS(기본 3) 이내로 제한되는지(계정 잠금 방지)
    monkeypatch.delenv("LOGIN_SQLI_MAX_ATTEMPTS", raising=False)

    async def fake_get(session, url):
        return 200, _ADMIN_LOGIN_HTML, {}

    async def fake_post(session, url, data=None):
        return 200, "<html>ok</html>", {}

    monkeypatch.setattr(ap, "_get", fake_get)
    monkeypatch.setattr(ap, "_post", fake_post)
    ap.reset_coverage("t3")
    r = asyncio.run(ap._probe_login_sqli(None, "http://t/admin/login", scan_id="t3"))
    # 단일 폼 기준 시도 수는 3 이하(브루트포스/잠금 방지)
    assert r["attempts"] <= 3
