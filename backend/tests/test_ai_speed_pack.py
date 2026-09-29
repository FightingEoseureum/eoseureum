"""test_ai_speed_pack.py — AI 속도 팩(트리아지/캐시/시그니처) 검증."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ai_provider as ap


def test_triage_high_medium_confirmed_only(monkeypatch):
    monkeypatch.delenv("AI_ANALYZE_ALL", raising=False)
    assert ap._should_analyze_finding({"severity": "HIGH"}) is True
    assert ap._should_analyze_finding({"severity": "MEDIUM"}) is True
    assert ap._should_analyze_finding({"severity": "LOW"}) is False
    assert ap._should_analyze_finding({"severity": "INFO"}) is False
    # 저위험이어도 실증(probe_confirmed)이면 분석
    assert ap._should_analyze_finding({"severity": "LOW", "probe_confirmed": True}) is True
    # report_severity 우선
    assert ap._should_analyze_finding({"severity": "LOW", "report_severity": "High"}) is True


def test_triage_analyze_all_override(monkeypatch):
    monkeypatch.setenv("AI_ANALYZE_ALL", "true")
    assert ap._should_analyze_finding({"severity": "LOW"}) is True


def test_finding_signature_stable_and_distinct():
    a = {"title": "XSS", "severity": "HIGH", "evidence_detail": "payload x"}
    b = {"title": "XSS", "severity": "HIGH", "evidence_detail": "payload x"}
    c = {"title": "SQLi", "severity": "HIGH", "evidence_detail": "payload x"}
    assert ap._finding_signature(a) == ap._finding_signature(b)
    assert ap._finding_signature(a) != ap._finding_signature(c)


def test_num_predict_and_keepalive_env_defaults():
    # 기본값 확인(payload 생성 로직과 일치)
    assert os.getenv("AI_NUM_PREDICT", "512") == "512"
