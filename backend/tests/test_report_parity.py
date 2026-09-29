"""test_report_parity.py — HTML/PDF Content Parity + Finding별 Evidence 매핑 버그 수정 검증.

핵심: 각 Finding 카드는 자기 자신의 evidence/proof/fingerprint 만 사용해야 한다
(SSTI에 Server Header 증거가 들어가면 실패). 판정 로직은 불변.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import proof_evidence as pe
import security_knowledge_graph as kg
import report_qa as rqa
import report_html_renderer as hr


def _multi_finding_analysis():
    a = {"findings": [
        {"title": "서버사이드 템플릿 인젝션(SSTI)", "family": "ssti", "severity": "HIGH",
         "confidence": "CONFIRMED_RESPONSE", "host": "t.com", "url": "https://t.com/search?q=1",
         "parameter": "q", "payload": "{{7*7}}", "evidence_detail": "응답에 49 출력, Jinja2",
         "judgment": "취약", "finding_uid": "F1"},
        {"title": "Clickjacking 가능", "family": "clickjacking", "severity": "MEDIUM",
         "confidence": "MANUAL_REVIEW", "host": "t.com", "url": "https://t.com/",
         "evidence_detail": "X-Frame-Options 미설정, iframe loaded", "judgment": "취약", "finding_uid": "F2"},
        {"title": "위험한 HTTP Method(TRACE)", "family": "http_method", "severity": "LOW",
         "confidence": "MANUAL_REVIEW", "host": "t.com", "allow_header": "GET, POST, TRACE",
         "evidence_detail": "TRACE echo 확인", "judgment": "취약", "finding_uid": "F3"},
        {"title": "Server Header 노출", "family": "server", "severity": "LOW",
         "confidence": "MANUAL_REVIEW", "host": "t.com",
         "evidence_detail": "Server: Apache-Coyote/1.1", "judgment": "취약", "finding_uid": "F4"}]}
    a.update(pe.build_all(a))
    a.update(kg.build_all(a))
    a["report_qa"] = rqa.check(a)
    return a


# ── 2. Finding별 매핑 버그 수정 ──────────────────────────────────────────────
def test_finding_ids_stable_not_none():
    a = _multi_finding_analysis()
    ids = [c["finding_id"] for c in a["proof_evidence_cards"]]
    assert ids == ["F1", "F2", "F3", "F4"]          # None 이 아니어야(예전 버그)
    assert len(set(ids)) == 4


def test_cards_not_cross_contaminated():
    a = _multi_finding_analysis()
    cards = {c["finding_uid"]: c for c in a["proof_evidence_cards"]}
    # 서로 다른 Finding 의 Observed 가 동일하면 실패
    obs = [c["observed_result"] for c in a["proof_evidence_cards"]]
    assert len(set(obs)) == len(obs), "카드 Observed 교차 오염"
    # SSTI 카드에 Server Header 증거가 들어가면 안 됨
    assert "Apache" not in cards["F1"]["observed_result"]
    assert "Server:" not in cards["F1"]["response_evidence_snippet"]


def test_ssti_card_has_arithmetic_proof():
    c = {x["finding_uid"]: x for x in _multi_finding_analysis()["proof_evidence_cards"]}["F1"]
    assert c["payload"] == "{{7*7}}" and c["expected_result"] == "49" and c["observed_result"] == "49"
    assert c["template_engine_guess"] == "Jinja2"
    assert c["validation_method"] == "ssti_arithmetic_probe"
    assert "SAFE" in c["skip_reason"]


def test_clickjacking_card_has_xfo_iframe():
    c = {x["finding_uid"]: x for x in _multi_finding_analysis()["proof_evidence_cards"]}["F2"]
    blob = (c["observed_result"] + c["response_evidence_snippet"] + c["technical_basis"]).lower()
    assert "iframe" in blob or "x-frame" in blob or "frame-ancestors" in blob


def test_trace_card_has_allow_trace():
    c = {x["finding_uid"]: x for x in _multi_finding_analysis()["proof_evidence_cards"]}["F3"]
    blob = (c["observed_result"] + c["response_evidence_snippet"]).lower()
    assert "trace" in blob or "allow" in blob


def test_server_card_has_server_header_only():
    c = {x["finding_uid"]: x for x in _multi_finding_analysis()["proof_evidence_cards"]}["F4"]
    assert "Server:" in c["observed_result"] and "Apache" in c["observed_result"]
    assert "49" not in c["observed_result"]        # SSTI 증거가 섞이면 안 됨


# ── 4. 비전문가용 3단 설명 ───────────────────────────────────────────────────
def test_three_tier_explanation():
    c = {x["finding_uid"]: x for x in _multi_finding_analysis()["proof_evidence_cards"]}["F1"]
    assert c["one_liner"] and c["why_risky"] and c["technical_basis"]
    assert "49" in c["technical_basis"]


# ── 1. HTML Content Parity ───────────────────────────────────────────────────
def test_html_content_parity_sections():
    import proof_validation as pv
    a = _multi_finding_analysis()
    a.update(pv.run_proof_validation(a))            # Proof Validation Summary 데이터
    a["report_qa"] = rqa.check(a)
    html = hr.generate_html({"domain": "t.com", "analysis": a, "created_at": "2026-07-02",
                             "results": [{"host": "t.com", "ip": "1.2.3.4", "open_ports": [80, 443]}]})
    for sec in ("Executive Summary", "Findings Overview", "Findings Detail",
                "Detection Coverage", "Findings", "Recommendations",
                "Developer Appendix", "Report QA"):
        assert sec in html, f"HTML 섹션 누락: {sec}"
    # 3단 설명·SSTI 실제값
    assert "한 줄 요약" in html and "왜 위험한가" in html and "기술 근거" in html
    assert "49" in html and "{{7*7}}" in html
    # 각 Finding 제목이 모두 포함(Detailed Findings 전체)
    for t in ("SSTI", "Clickjacking", "TRACE", "Server Header"):
        assert t in html


def test_html_pdf_qa_detects_cross_contamination():
    # 의도적 오염: 두 유형이 같은 Observed
    a = {"findings": [
        {"title": "SSTI", "family": "ssti", "severity": "HIGH", "confidence": "CONFIRMED_RESPONSE",
         "evidence_detail": "동일값", "judgment": "취약", "finding_uid": "F1"},
        {"title": "XSS", "family": "xss", "severity": "MEDIUM", "confidence": "CONFIRMED_BROWSER",
         "evidence_detail": "동일값", "judgment": "취약", "finding_uid": "F2"}]}
    a.update(pe.build_all(a))
    # 강제로 동일 observed 로 오염시켜 검출되는지
    for c in a["proof_evidence_cards"]:
        c["observed_result"] = "IDENTICAL_OBSERVED"
    issues = rqa.check_html_pdf(a)
    assert any("교차 오염" in i for i in issues)
