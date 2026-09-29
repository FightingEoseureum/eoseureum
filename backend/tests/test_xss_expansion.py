"""test_xss_expansion.py — XSS 확장(검색창/DOM/Stored) 정책·게이트."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import probe_policy as pp

def test_reflected_xss_confirmed_only_on_alert():
    assert pp.judge_reflected_xss(alert_fired=True) == "CONFIRMED"
    assert pp.judge_reflected_xss(alert_fired=False, reflected=True) == "POSSIBLE"
    assert pp.judge_reflected_xss(alert_fired=False, reflected=False) is None

def test_dom_xss_no_alert_not_confirmed():
    assert pp.judge_dom_xss(alert_fired=True) == "CONFIRMED"
    # alert 없으면 절대 CONFIRMED 아님
    assert pp.judge_dom_xss(alert_fired=False, sink_found=True) == "POSSIBLE"
    assert pp.judge_dom_xss(alert_fired=False, sink_found=False) is None

def test_dom_xss_enabled_default(monkeypatch):
    monkeypatch.delenv("ENABLE_DOM_XSS", raising=False)
    assert pp.dom_xss_enabled() is True

def test_stored_xss_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ENABLE_STORED_XSS", raising=False)
    assert pp.stored_xss_enabled() is False

def test_stored_xss_marker_uses_scan_id(monkeypatch):
    monkeypatch.delenv("STORED_XSS_MARKER_PREFIX", raising=False)
    m = pp.stored_xss_marker("abcd-1234-ef")
    assert m.startswith("EOSEUREUM_STORED_XSS_PROBE_")
    assert "abcd1234ef" in m
