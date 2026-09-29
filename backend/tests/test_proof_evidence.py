"""test_proof_evidence.py — Proof Evidence Detail v1 + DOM Snapshot 3.5 + Report QA/Renderer.

판정(Rule Engine/Severity/Confidence/Validation/Evidence/Risk)은 변경하지 않고 표현·설명·
점수만 산출함을 검증. SAFE(위험 검증 미수행) 표기 확인.
"""
import os, sys, io
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import proof_evidence as pe
import report_qa as rqa
import report_renderer as rr
import evidence_levels as evl
from discovery_worker import discovery3 as d3


# ── Fingerprint Framework ─────────────────────────────────────────────────────
def test_fingerprint_ssti_safe_only():
    f = {"title": "SSTI 후보", "family": "ssti", "evidence_detail": "Jinja2 template 7*7=49 반사"}
    fp = pe.fingerprint(f)
    assert fp["fingerprint_name"] == "Jinja2"
    assert fp["rce_validation_status"] == "SKIPPED_SAFE"       # RCE 미수행
    assert "산술" in fp["supported_feature"] or "Arithmetic" in fp["supported_feature"]


def test_fingerprint_sqli_dbms_injection():
    f = {"title": "SQL Injection", "family": "sqli",
         "evidence_detail": "MySQL error boolean-based 응답 차이"}
    fp = pe.fingerprint(f)
    assert fp["fingerprint_name"] == "MySQL" and "Boolean" in fp["injection_type"]


def test_fingerprint_tls_and_generic():
    assert pe.fingerprint({"family": "tls", "tls_version": "TLS 1.2"})["fingerprint_name"] == "TLS 1.2"
    assert pe.fingerprint({"family": "generic", "evidence_detail": "Server: nginx php"})["framework"] == "nginx"


# ── Proof Card + SAFE limitations ─────────────────────────────────────────────
def test_proof_card_fields_and_safe():
    f = {"title": "관리자 IDOR 실증 — 객체 참조", "family": "idor", "confidence": "CONFIRMED_RESPONSE",
         "severity": "HIGH", "url": "https://t/api/users/1", "evidence_url": "https://t/api/users/1",
         "parameter": "id", "evidence_detail": "타 계정 노출", "judgment": "취약", "_idx": 1}
    card = pe.build_proof_card(f, {})
    for k in ("finding_id", "vulnerability_type", "affected_endpoint", "method", "payload",
              "expected_result", "observed_result", "response_evidence_snippet",
              "validation_level", "proof_profile", "reproduction_steps", "limitations",
              "fingerprint", "business_function", "proof_quality"):
        assert k in card
    assert "SAFE" in card["limitations"] and "덤프" in card["limitations"]
    # validation_level 은 Rule Engine(evidence_levels) 그대로
    assert card["validation_level"] == evl.level_of(f)
    # response 전체가 아닌 snippet(<=310자)
    assert len(card["response_evidence_snippet"]) <= 310


def test_proof_quality_score_range():
    f = {"title": "XSS", "family": "xss", "confidence": "CONFIRMED_BROWSER", "severity": "MEDIUM",
         "url": "https://t/s?q=1", "parameter": "q", "payload": "<script>alert(1)</script>",
         "evidence_detail": "alert 실행", "judgment": "취약", "_idx": 1,
         "evidence_screenshot": "shot.png"}
    card = pe.build_proof_card(f, {})
    pq = card["proof_quality"]
    assert 0 <= pq["score"] <= 100 and pq["grade"] in ("높음", "보통", "낮음")
    assert any("Payload" in x for x in pq["factors"])


def test_business_function_mapping():
    assert pe.business_function({"title": "로그인 폼 취약", "url": "/login"})["function"] == "Authentication"
    assert pe.business_function({"title": "결제 API", "url": "/api/payment"})["function"] == "Payment"
    assert pe.business_function({"title": "무관", "url": "/x"})["function"] == "미상"


def test_build_all_summary():
    a = {"findings": [
        {"title": "SQLi", "family": "sqli", "confidence": "CONFIRMED_RESPONSE", "severity": "HIGH",
         "url": "https://t/api/x?id=1", "parameter": "id", "evidence_detail": "MySQL error",
         "judgment": "취약", "_idx": 1},
        {"title": "정보", "family": "generic", "confidence": "MANUAL_REVIEW", "severity": "LOW",
         "judgment": "취약", "_idx": 2}]}
    out = pe.build_all(a)
    assert out["proof_quality_summary"]["proof_cards"] == 2
    assert "business_process_map" in out and isinstance(out["fingerprints"], list)


# ── DOM Snapshot 3.5 ──────────────────────────────────────────────────────────
def test_dom_snapshot_structured_no_html():
    raw = {"url": "https://t/pay", "title": "결제", "h1": ["결제하기"], "h2": [],
           "forms": [{"action": "/api/pay", "method": "POST", "section": "form",
                      "fields": [{"name": "card", "type": "text", "placeholder": "카드번호",
                                  "label": "카드", "role": "", "selector": "#card"}]}],
           "buttons": [{"text": "결제", "section": "form", "selector": "#pay", "bbox": {}}]}
    snap = d3.normalize_dom_snapshot(raw)
    assert "text" not in snap and "innerHTML" not in snap        # 전체 HTML 미저장
    assert snap["business_function"] == "Payment"
    ctx = snap["forms"][0]["fields"][0]["context"]
    assert ctx["sensitive_candidate"] is True                    # 카드 → 민감
    assert snap["buttons"][0]["context"]["state_change_candidate"] is True   # 결제 → 상태변경


def test_element_context_hints():
    c = d3.element_context({"text": "삭제", "name": "delete_btn", "section": "form"})
    assert c["state_change_candidate"] is True
    c2 = d3.element_context({"name": "password", "type": "password"})
    assert c2["sensitive_candidate"] is True


def test_request_dom_correlation():
    dom = [d3.normalize_dom_snapshot({"url": "https://t/pay", "title": "결제",
            "forms": [{"action": "/api/pay", "method": "POST", "section": "form",
                       "fields": [{"name": "card", "type": "text"}]}], "buttons": []})]
    reqs = [{"url": "https://t/api/pay", "method": "POST"}]
    links = d3.correlate_requests_dom(reqs, dom)
    assert links and links[0]["source_form"] == "/api/pay"
    assert "card" in links[0]["related_inputs"]


# ── Report QA Checker ─────────────────────────────────────────────────────────
def test_report_qa_detects_and_fixes():
    a = {"findings": [
        {"title": "A", "url": "https://t/fontawesome-webfont.woff2",
         "affected_endpoints": ["https://t/api/real?id=1"], "recommendation": "고치세요. 고치세요.",
         "judgment": "취약"},
        {"title": "B", "recommendation": "", "url": "https://t/x", "judgment": "취약"}]}
    rep = rqa.check(a)
    # 리소스 URL → 실제 취약 URL 로 자동 교체
    assert a["findings"][0]["evidence_url"] == "https://t/api/real?id=1"
    # 중복 문장 정리
    assert a["findings"][0]["recommendation"].count("고치세요") == 1
    # 권고 누락 이슈 검출
    assert any("권장 조치 누락" in i for i in rep["issues"])
    assert rep["auto_fixed"] >= 2 and "checks" in rep


def test_report_qa_resource_url_helper():
    assert rqa.is_resource_url("https://x/a.woff2") is True
    assert rqa.is_resource_url("https://x/api/users?id=1") is False


# ── Report Renderer Interface ─────────────────────────────────────────────────
def test_report_renderer_registry():
    assert rr.get_renderer("docx").name == "docx"
    # HTML v1 구현됨 → html 렌더러 반환
    assert rr.get_renderer("html").name == "html"
    assert "docx" in rr.available_formats() and "html" in rr.available_formats()


def test_docx_renderer_generates():
    from tests.test_report_v4_ux import _rich
    buf = rr.get_renderer("docx").render({"domain": "t.example.com", "analysis": _rich(),
                                          "created_at": "2026-07-02", "results": []})
    assert isinstance(buf, io.BytesIO) and len(buf.getvalue()) > 0


# ── 회귀: Browser Discovery OFF 시 proof/qa 정상(빈 데이터에도 안전) ───────────
def test_offsafe_empty_analysis():
    out = pe.build_all({})
    assert out["proof_quality_summary"]["proof_cards"] == 0
    assert rqa.check({})["passed"] is True
