"""test_sqlmap_failure_analysis.py — SQLMap 실패 메시지 파싱."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import external_tools as et

CRIT = ("[CRITICAL] all tested parameters do not appear to be injectable. "
        "Try to increase values for '--level'/'--risk' options if you wish to perform more tests. "
        "Rerun without providing the option '--technique'. "
        "If you suspect that there is some kind of protection mechanism involved maybe try "
        "'--tamper=space2comment' and/or '--random-agent'")

def test_parse_no_injectable():
    fr = et.parse_sqlmap_failure_reason(CRIT, "")
    assert fr["no_injectable_parameter"] is True

def test_parse_increase_level_risk():
    fr = et.parse_sqlmap_failure_reason(CRIT, "")
    assert fr["suggest_increase_level_risk"] is True

def test_parse_without_technique():
    fr = et.parse_sqlmap_failure_reason(CRIT, "")
    assert fr["suggest_remove_technique"] is True

def test_parse_tamper_and_random_agent():
    fr = et.parse_sqlmap_failure_reason(CRIT, "")
    assert fr["suggest_tamper"] is True
    assert fr["suggest_random_agent"] is True

def test_recommended_next_steps_present():
    fr = et.parse_sqlmap_failure_reason(CRIT, "")
    assert isinstance(fr["recommended_next_steps"], list) and fr["recommended_next_steps"]
    joined = " ".join(fr["recommended_next_steps"])
    assert "level" in joined.lower() or "technique" in joined.lower()

def test_clean_output_no_false_flags():
    fr = et.parse_sqlmap_failure_reason("sqlmap identified injection", "")
    assert fr["no_injectable_parameter"] is False
    assert fr["suggest_remove_technique"] is False
