"""test_detection_intelligence.py — Data Integrity Fix + Detection Intelligence v1.

판정(Rule Engine/Severity/Confidence/SAFE) 불변. 수치 무결성 + 탐지 전략 계층 검증.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import report
import proof_evidence as pe
import detection_intelligence as di
import detection_coverage as dc
import report_qa as rqa
import report_html_renderer as hr


def _analysis(coverage=None):
    a = {"findings": [
        {"title": "SSTI", "family": "ssti", "severity": "HIGH", "confidence": "CONFIRMED_RESPONSE",
         "host": "t", "url": "https://t/search?q=1", "parameter": "q", "payload": "{{7*7}}",
         "evidence_detail": "Jinja2 49", "judgment": "취약", "finding_uid": "F1"},
        {"title": "Clickjacking", "family": "clickjacking", "severity": "MEDIUM",
         "confidence": "MANUAL_REVIEW", "host": "t", "url": "https://t/",
         "evidence_detail": "iframe loaded X-Frame 미설정", "judgment": "취약", "finding_uid": "F2"},
        {"title": "IDOR 후보", "family": "idor", "severity": "MEDIUM", "confidence": "MANUAL_REVIEW",
         "host": "t", "url": "https://t/api/o?userId=1", "parameter": "userId",
         "evidence_detail": "단일 계정", "judgment": "취약", "finding_uid": "F3"}],
        "coverage": coverage or {"sqli_tested": 12, "xss_tested": 8, "ssti_tested": 3}}
    a.update(pe.build_all(a))
    a.update(dc.build_coverage(a))
    a.update(di.build_strategies(a))
    a["report_qa"] = rqa.check(a)
    return a


# ── 1① Security Score ─────────────────────────────────────────────────────────
def test_security_score_not_100_when_high_exists():
    # evidence_levels/business_impact 가 비어 있어도 High 존재 시 100 불가
    a = {"findings": [{"title": "X", "family": "ssti", "severity": "HIGH",
                       "confidence": "CONFIRMED_RESPONSE", "judgment": "취약"}]}
    assert report._v3_security_score(a) < 100
    # Critical 존재 시 위험 구간
    a2 = {"findings": [{"title": "Y", "family": "sqli", "severity": "CRITICAL",
                        "confidence": "CONFIRMED_RESPONSE", "judgment": "취약"}]}
    assert report._v3_security_score(a2) <= 69
    # 취약점 없으면 100 가능
    assert report._v3_security_score({"findings": []}) == 100


# ── 1② Validation Distribution ────────────────────────────────────────────────
def test_validation_distribution_matches_findings():
    a = {"findings": [
        {"title": "A", "confidence": "CONFIRMED_RESPONSE", "severity": "HIGH", "judgment": "취약"},
        {"title": "B", "confidence": "MANUAL_REVIEW", "severity": "LOW", "judgment": "취약"}]}
    ev = report._eff_levels(a)   # evidence_levels 없어도 findings 에서 재집계
    assert ev["level3_proven"] == 1 and ev["level1_observed"] == 1


# ── 1③ Business Function fallback ─────────────────────────────────────────────
def test_business_function_fallback_mapping():
    assert pe.business_function({"family": "clickjacking", "title": "Clickjacking"})["function"] == "User Interaction / Web UI"
    assert pe.business_function({"family": "http_method", "title": "TRACE"})["function"] == "Web Server / HTTP Interface"
    assert pe.business_function({"family": "server", "title": "Server Header"})["function"] == "Infrastructure Exposure"
    # 키워드 매칭이 fallback 보다 우선
    assert pe.business_function({"family": "ssti", "title": "검색", "url": "/search"})["function"] == "Search"


# ── 4 Attack Pack ─────────────────────────────────────────────────────────────
def test_attack_pack_by_business_function():
    assert "ssti" in di.attack_pack("Search")["techniques"]
    assert "session_fixation" in di.attack_pack("Authentication")["techniques"]
    assert "bola" in di.attack_pack("API Gateway")["techniques"]
    # family fallback
    assert di.attack_pack("", "clickjacking")["pack"] == "Web UI"


# ── 5 Adaptive Payload (SAFE) ─────────────────────────────────────────────────
def test_adaptive_payload_selection_safe():
    ssti = di.adaptive_payloads("ssti", fingerprint="Jinja2")
    assert "{{7*7}}" in ssti["payloads"] and "os command" in " ".join(ssti["forbidden"])
    sqli = di.adaptive_payloads("sqli", fingerprint="MySQL")
    assert "boolean" in sqli["injection_types"] and "time_based(limited)" not in sqli["injection_types"]
    assert "time_based(limited)" in di.adaptive_payloads("sqli", time_based_allowed=True)["injection_types"]
    xss = di.adaptive_payloads("xss", context="attribute")
    assert xss["context"] == "attribute" and "session theft" in " ".join(xss["forbidden"])


def test_ssti_evidence_goal_and_card_observed_49():
    assert "observed_actual_value" in di.evidence_goal("ssti")
    a = _analysis()
    c = {x["finding_uid"]: x for x in a["proof_evidence_cards"]}["F1"]
    assert c["observed_result"] == "49" and c["expected_result"] == "49"


def test_xss_evidence_goal_browser():
    assert "screenshot" in di.evidence_goal("xss") and "alert_text" in di.evidence_goal("xss")
    assert "Playwright" in di.adaptive_payloads("xss")["evidence"]


def test_idor_one_account_manual_review():
    a = _analysis()
    m = {r["technique"]: r for r in a["detection_coverage"]["matrix"]}
    assert m["IDOR/AuthZ"]["manual_review"] >= 1
    assert "second account" in m["IDOR/AuthZ"]["reason"]
    # 전략상 IDOR 단일계정은 Manual Review
    assert di.adaptive_payloads("idor")["single_account"] == "Manual Review"


# ── 7 Detection Coverage matrix ───────────────────────────────────────────────
def test_detection_coverage_matrix():
    a = _analysis()
    m = {r["technique"]: r for r in a["detection_coverage"]["matrix"]}
    assert m["SQL Injection"]["tested"] == 12 and m["SQL Injection"]["confirmed"] == 0
    # 정직성 v2: 검사했으나 미발견 → tested_clean(검사함·안전)
    assert m["SQL Injection"]["status"] == "tested_clean"
    assert m["SQL Injection"]["reason"] == "검사 수행 · 취약점 미발견"
    assert m["SSTI"]["confirmed"] == 1 and m["SSTI"]["status"] == "confirmed"


# ── HTML parity: Detection Coverage + Developer Appendix ─────────────────────
def test_html_includes_detection_coverage_and_appendix():
    a = _analysis()
    html = hr.generate_html({"domain": "t", "analysis": a, "created_at": "2026-07-02"})
    assert "Detection Coverage" in html and "SQL Injection" in html
    assert "Developer Appendix" in html and "Report QA" in html
    assert "검사 수행" in html          # 정직성 v2: 검사함·안전 사유


# ── Report QA flags score/distribution mismatch ──────────────────────────────
def test_report_qa_flags_score_mismatch():
    # 강제로 잘못된 evidence_levels(모두 0) + High finding → QA 가 잡아야
    a = {"findings": [{"title": "X", "family": "ssti", "severity": "HIGH",
                       "confidence": "CONFIRMED_RESPONSE", "judgment": "취약", "finding_uid": "F1"}],
         "evidence_levels": {"level3_proven": 0, "level2_evidence": 0, "level1_observed": 0,
                             "level0_info": 0}}
    a.update(pe.build_all(a))
    issues = rqa._check_score_distribution(a, a["findings"])
    assert any("Validation Distribution 불일치" in i for i in issues)
