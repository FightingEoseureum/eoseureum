"""test_idor_dual_account.py — IDOR 교차계정 검증 오케스트레이션 + 후보 finding 빌드."""
import os, sys, asyncio, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import authenticated_scan as ascan
import rule_engine as re_eng


def _cfg(**kw):
    base = dict(auth_login_url="http://t/login", auth_username="alice",
               auth_password="pw1", auth_username_b="bob", auth_password_b="pw2",
               request_timeout=5.0, stop_on_account_lock_hint=True,
               global_rps=10.0, auth_rps=2.0, idor_verify_max=20,
               auth_username_field="auto", auth_password_field="auto",
               auth_success_pattern="auto")
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_dual_account_confirmed(monkeypatch):
    async def fake_login(config, login_url, username, password, timeout, limiter, lock):
        return types.SimpleNamespace(name=username, _who=username), True, "ok"

    async def fake_get(session, url, timeout=8.0):
        # 두 계정 모두 alice 의 데이터를 본다 → IDOR 실증
        return 200, "주문 1001 고객 alice 주소 서울", {}

    monkeypatch.setattr(ascan, "_login_only", fake_login)
    monkeypatch.setattr(ascan, "_http_get", fake_get)

    cands = [{"url": "http://t/order?id=1001", "method": "GET", "param": "id"}]
    out = asyncio.run(ascan.verify_idor_dual_account(_cfg(), "http://t", cands))
    assert out["performed"] is True
    assert out["summary"]["verified"] == 1
    assert out["results"][0]["grade"] == "CONFIRMED_RESPONSE"
    assert out["summary"]["promoted"] == 1


def test_dual_account_skipped_without_b():
    out = asyncio.run(ascan.verify_idor_dual_account(
        _cfg(auth_username_b="", auth_password_b=""), "http://t",
        [{"url": "http://t/o?id=1", "method": "GET"}]))
    assert out["performed"] is False
    assert "B" in out["reason"] or "계정" in out["reason"]


def test_dual_account_blocked_stays_manual(monkeypatch):
    async def fake_login(config, login_url, username, password, timeout, limiter, lock):
        return types.SimpleNamespace(_who=username), True, "ok"

    async def fake_get(session, url, timeout=8.0):
        # 계정 B(2번째 호출)는 403 차단 → 우회 증거 없음
        who = getattr(session, "_who", "")
        if who == "bob":
            return 403, "forbidden", {}
        return 200, "alice data 1001", {}

    monkeypatch.setattr(ascan, "_login_only", fake_login)
    monkeypatch.setattr(ascan, "_http_get", fake_get)
    cands = [{"url": "http://t/order?id=1001", "method": "GET"}]
    out = asyncio.run(ascan.verify_idor_dual_account(_cfg(), "http://t", cands))
    assert out["results"][0]["grade"] == "MANUAL_REVIEW"
    assert out["summary"]["promoted"] == 0


# ── 후보 finding 빌드(비즈니스로직/파일업로드/CSRF 위험도) ──────────────────────
def test_business_and_fileupload_candidates_build_as_reference():
    ap = {
        "business_logic_candidate": {
            "type": "business_logic_candidate", "confirmed": False, "count": 1,
            "candidates": [{"url": "http://t/buy", "method": "POST", "param": "price",
                            "sample_value": "100"}],
            "evidence": "비즈니스 로직 파라미터 1건",
        },
        "file_upload_candidate": {
            "type": "file_upload_candidate", "confirmed": False, "count": 1,
            "candidates": [{"url": "http://t/upload", "method": "POST", "multipart": True,
                            "accept_attr": ["image/*"], "extension_restriction": "client-accept"}],
            "evidence": "파일 업로드 폼 1건",
        },
    }
    findings = re_eng._build_active_probe_findings("t", 80, "http", ap, set())
    assert len(findings) == 2
    for f in findings:
        assert f["judgment"] == "참고"
        assert f["confidence"] == "MANUAL_REVIEW"
        assert f["force_finding_type"] == "discovery"


def test_csrf_candidate_gets_risk_severity():
    ap = {
        "csrf_candidate": {
            "type": "csrf_candidate", "confirmed": False, "count": 1,
            "candidates": [{"url": "http://t/account/change-password", "method": "POST",
                            "params": ["new_password"]}],
            "weak_samesite_cookies": [{"name": "SID", "samesite": "미설정"}],
            "evidence": "CSRF 후보 1건",
        }
    }
    findings = re_eng._build_active_probe_findings("t", 80, "http", ap, set())
    assert len(findings) == 1
    f = findings[0]
    # 민감 기능 + 토큰 부재 + SameSite 미흡 → HIGH 추천 위험도
    assert f["severity"] == "HIGH"
    assert "위험도 HIGH" in f["title"]
    assert f["judgment"] == "참고"  # 자동 확정 금지
