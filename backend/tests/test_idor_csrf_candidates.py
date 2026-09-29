"""test_idor_csrf_candidates.py — IDOR/CSRF 후보(수동검토) 탐지 및 분류 검증.

원칙: 자동 공격/상태변경 미수행, 취약 확정 아님(참고/MANUAL_REVIEW), 참고(discovery) 버킷.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import active_probing as ap
import rule_engine as re_eng
import finding_normalizer as fn


# ── IDOR 후보 ────────────────────────────────────────────────────────────────
def test_idor_candidate_detects_object_ref_params():
    points = [
        {"method": "GET", "url": "http://t/view?id=1001", "params": {"id": "1001"}, "source": "link"},
        {"method": "GET", "url": "http://t/order?orderId=55", "params": {"orderId": "55"}, "source": "link"},
        {"method": "GET", "url": "http://t/search?q=abc", "params": {"q": "abc"}, "source": "link"},
    ]
    r = ap._probe_idor_candidates(points)
    assert r is not None
    assert r["type"] == "idor_candidate"
    assert r["confirmed"] is False           # 자동 공격 미수행
    params = {c["param"] for c in r["candidates"]}
    assert "id" in params and "orderId" in params
    assert "q" not in params                 # 일반 검색 파라미터는 후보 아님


def test_idor_candidate_none_when_no_object_refs():
    points = [{"method": "GET", "url": "http://t/?q=x", "params": {"q": "x"}, "source": "link"}]
    assert ap._probe_idor_candidates(points) is None


# ── CSRF 후보 ────────────────────────────────────────────────────────────────
def test_csrf_candidate_flags_tokenless_state_change():
    points = [
        {"method": "POST", "url": "http://t/transfer", "params": {"amount": "100"},
         "source": "form", "csrf_fields": []},
        {"method": "POST", "url": "http://t/safe", "params": {"x": "1"},
         "source": "form", "csrf_fields": ["csrf_token"]},   # 토큰 존재 → 후보 아님
    ]
    cookies = [{"name": "SESSIONID", "samesite": None}]
    r = ap._probe_csrf_candidates(points, cookies)
    assert r is not None
    assert r["type"] == "csrf_candidate"
    assert r["confirmed"] is False
    urls = {c["url"] for c in r["candidates"]}
    assert "http://t/transfer" in urls
    assert "http://t/safe" not in urls
    assert any(w["name"] == "SESSIONID" for w in r["weak_samesite_cookies"])


def test_csrf_candidate_none_when_protected():
    points = [{"method": "POST", "url": "http://t/x", "params": {"a": "1"},
               "source": "form", "csrf_fields": ["_token"]}]
    cookies = [{"name": "SID", "samesite": "Strict"}]
    assert ap._probe_csrf_candidates(points, cookies) is None


# ── 후보 finding 분류: 참고/MANUAL_REVIEW, discovery 버킷 ─────────────────────
def test_candidate_findings_are_reference_not_vulnerability():
    active_probes = {
        "idor_candidate": {
            "type": "idor_candidate", "confirmed": False, "count": 1,
            "candidates": [{"url": "http://t/v?id=1", "method": "GET", "param": "id",
                            "sample_value": "1", "numeric": True}],
            "evidence": "객체 참조 추정 파라미터 1건",
        },
        "csrf_candidate": {
            "type": "csrf_candidate", "confirmed": False, "count": 1,
            "candidates": [{"url": "http://t/p", "method": "POST", "params": ["a"],
                            "reason": "토큰 없음"}],
            "weak_samesite_cookies": [],
            "evidence": "CSRF 토큰 없는 상태변경 요청 1건",
        },
    }
    findings = re_eng._build_active_probe_findings("t", 80, "http", active_probes, set())
    assert len(findings) == 2
    for f in findings:
        assert f["judgment"] == "참고"
        assert f["confidence"] == "MANUAL_REVIEW"
        assert f["force_finding_type"] == "discovery"
        assert f.get("is_candidate") is True
        # 분류기가 강제 버킷을 존중 → 취약점으로 집계되지 않음
        assert fn.classify(f) == "discovery"


def test_normalize_keeps_candidates_out_of_vuln_count():
    f_idor = {"title": "[참고] IDOR 가능성", "judgment": "참고",
              "confidence": "MANUAL_REVIEW", "force_finding_type": "discovery",
              "host": "t", "port": 80}
    out = fn.normalize([f_idor])
    assert out["summary"]["vulnerability_count"] == 0
    assert out["summary"]["discovery_count"] == 1
