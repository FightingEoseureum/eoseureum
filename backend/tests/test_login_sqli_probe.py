"""test_login_sqli_probe.py — 로그인 폼 SQLi/인증 우회 정책(제한 시도, time-based 금지)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import probe_policy as pp

def test_payloads_no_time_based_and_bounded():
    for lvl in ("safe", "balanced"):
        pl = pp.login_sqli_payloads(lvl)
        assert 1 <= len(pl) <= 8   # 브루트포스 아님(소수)
        joined = " ".join(pl).lower()
        for forbidden in ("sleep", "benchmark", "waitfor", "pg_sleep"):
            assert forbidden not in joined
    assert "' OR '1'='1" in pp.login_sqli_payloads("safe")

def test_safe_subset_of_balanced():
    assert set(pp.login_sqli_payloads("safe")).issubset(set(pp.login_sqli_payloads("balanced")))

def test_judge_login_sqli_levels():
    assert pp.judge_login_sqli(logout_seen=True) == "CONFIRMED"
    assert pp.judge_login_sqli(dashboard_seen=True) == "CONFIRMED"
    assert pp.judge_login_sqli(url_changed=True, failure_absent=True) == "LIKELY"
    assert pp.judge_login_sqli(db_error=True) == "POSSIBLE"
    assert pp.judge_login_sqli(response_diff=True) == "MANUAL_REVIEW"
    assert pp.judge_login_sqli() is None
