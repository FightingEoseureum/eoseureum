"""test_platform_upgrade.py — 5대 업그레이드 검증.
① 벤치마크 ② Detection Intelligence 결선 ③ 오탐 억제 ④ 리포트 모델 파사드 ⑤ 하드닝.
판정(Rule Engine/Severity/Confidence) 불변, SAFE 유지.
"""
import os, sys, io, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark import golden as bg, evaluate as be
import attack_surface_planner as asp
import detection_intelligence as di
import false_positive_filter as fpf
import report_model as rm
import secrets_store as ss
import audit_log as al


# ── ① 벤치마크 ────────────────────────────────────────────────────────────────
def test_benchmark_recall_and_missing():
    gd = bg.resolve_golden("demo.testfire.net")
    assert gd and any(e["family"] == "sqli" for e in gd["expected"])
    analysis = {"findings": [
        {"title": "SQLi", "family": "sqli", "confidence": "CONFIRMED_RESPONSE", "judgment": "취약"},
        {"title": "XSS", "family": "xss", "confidence": "MANUAL_REVIEW", "judgment": "취약"}]}
    r = be.evaluate(analysis, gd)
    assert r["true_positive"] == 2 and r["false_negative"] == 1   # server 누락
    assert 0 <= r["recall"] <= 1 and r["detail"]
    assert any(d["status"].startswith("TP") for d in r["detail"])


def test_benchmark_resolve_by_name_and_custom():
    assert bg.resolve_golden("dvwa")["expected"]
    custom = {"label": "X", "expected": [{"family": "xss"}], "exhaustive": True}
    r = be.evaluate({"findings": [{"title": "A", "family": "sqli", "judgment": "취약"}]},
                    bg.resolve_golden("x", custom))
    # 기대(xss) 누락 + 기대외(sqli) → exhaustive 라 FP 계산
    assert r["false_negative"] == 1 and r["false_positive"] == 1


# ── ② Detection Intelligence 결선 ────────────────────────────────────────────
def test_di_point_signal_and_planner_boost():
    sig = di.point_signal({"param": "userId", "url": "https://t/api/x"})
    assert "idor" in sig["techniques"] and sig["boost"] > 0
    idor = asp.analyze_input_point({"param": "userId", "url": "https://t/api/account", "method": "GET"})
    gen = asp.analyze_input_point({"param": "color", "url": "https://t/pref", "method": "GET"})
    assert idor["priority_score"] > gen["priority_score"]          # 실제 우선순위 상승
    assert "idor" in idor["recommended_techniques"]
    # active_probing 예산 정렬에 쓰이는 raw_point_score 에도 반영
    assert asp.raw_point_score({"url": "https://t/api/x", "method": "GET",
                                "params": {"userId": "1"}}) > 0


def test_di_adaptive_payloads_safe():
    assert "{{7*7}}" in di.adaptive_payloads("ssti", fingerprint="Jinja2")["payloads"]
    assert "dump" in " ".join(di.adaptive_payloads("sqli")["forbidden"])


# ── ③ 오탐 억제 ──────────────────────────────────────────────────────────────
def test_fp_soft404_and_waf_high():
    assert fpf.assess({"family": "sqli", "confidence": "MANUAL_REVIEW",
                       "evidence_detail": "404 Not Found page"})["fp_risk"] == "high"
    assert fpf.assess({"family": "xss", "confidence": "POSSIBLE",
                       "evidence_detail": "Request blocked by WAF"})["fp_risk"] == "high"


def test_fp_confirmed_low_but_inconsistent_flag():
    # 실증인데 soft-404 신호 → 불일치 경고
    a = fpf.assess({"family": "sqli", "confidence": "CONFIRMED_RESPONSE",
                    "evidence_detail": "soft-404 문서 반사"})
    assert a["inconsistent_confirmed"] is True
    # 정상 실증 → 낮음
    assert fpf.assess({"family": "sqli", "confidence": "CONFIRMED_RESPONSE",
                       "evidence_detail": "boolean 응답 차이"})["fp_risk"] == "low"


def test_fp_annotate_does_not_change_verdict():
    a = {"findings": [{"title": "X", "family": "xss", "confidence": "POSSIBLE",
                       "severity": "MEDIUM", "evidence_detail": "반사만", "judgment": "취약"}]}
    before = dict(a["findings"][0])
    out = fpf.annotate(a)
    assert "_fp_risk" in a["findings"][0]
    assert a["findings"][0]["confidence"] == before["confidence"]   # 판정 불변
    assert a["findings"][0]["severity"] == before["severity"]
    assert "fp_risk_summary" in {"fp_risk_summary": out["fp_risk_summary"]}


# ── ③-A 정적 에셋 인젝션 오탐 억제 ───────────────────────────────────────────
def test_fp_family_from_title_and_evidence_url():
    # 실제 스캔 형태: family/vuln_type 없음, URL 은 evidence_url 에만 → title 로 family 유도 + 억제
    a = {"findings": [{"title": "서버사이드 템플릿 인젝션 (SSTI) 실증 확인",
                       "family": None, "vuln_type": None, "url": None,
                       "evidence_url": "http://t/resources/font/x.woff",
                       "confidence": "CONFIRMED", "judgment": "취약", "finding_uid": "F1"}],
         "proof_validation": [{"finding_title": "서버사이드 템플릿 인젝션 (SSTI) 실증 확인",
                               "finding_uid": "F1", "performed_techniques": ["banner_observe"]}]}
    fpf.annotate(a)
    assert a["findings"][0]["_fp_suppressed"] is True     # family=None 이어도 title→ssti 유도 후 억제


def test_fp_static_asset_injection_suppressed():
    # 정적 폰트(.woff)에 SSTI '실증' → 물리적 불가 → 억제
    a = fpf.assess({"family": "ssti", "confidence": "CONFIRMED_RESPONSE",
                    "url": "http://t/resources/font/fontawesome-webfont.woff",
                    "evidence_detail": "{{7*7}} → 49"})
    assert a["suppress"] is True and a["fp_risk"] == "high"
    # 동적 경로의 SSTI 는 억제하지 않음(정상 정탐 보호)
    b = fpf.assess({"family": "ssti", "confidence": "CONFIRMED_RESPONSE",
                    "url": "http://t/search?q=1", "evidence_detail": "{{7*7}} → 49"})
    assert b["suppress"] is False


# ── ③-B family↔검증방법 불일치 억제 ─────────────────────────────────────────
def test_fp_method_mismatch_suppressed():
    analysis = {"findings": [{"title": "SSTI", "family": "ssti", "severity": "HIGH",
                              "confidence": "CONFIRMED_RESPONSE", "judgment": "취약",
                              "url": "http://t/search", "finding_uid": "F1"}],
                "proof_validation": [{"finding_title": "SSTI", "finding_uid": "F1",
                                      "performed_techniques": ["banner_observe"]}]}
    out = fpf.annotate(analysis)
    assert analysis["findings"][0]["_fp_suppressed"] is True
    assert out["fp_risk_summary"]["suppressed_count"] == 1
    # 올바른 능동 실증(arithmetic) 이면 억제 안 함
    analysis["proof_validation"][0]["performed_techniques"] = ["ssti_arithmetic_probe"]
    fpf.annotate(analysis)
    assert analysis["findings"][0]["_fp_suppressed"] is False


# ── ③-D 억제 항목은 점수·심각도 분포에서 제외 ───────────────────────────────
def test_suppressed_excluded_from_score_and_severity():
    import report
    base = {"findings": [
        {"title": "SSTI", "family": "ssti", "severity": "HIGH", "confidence": "CONFIRMED_RESPONSE",
         "judgment": "취약", "url": "http://t/x.woff", "finding_uid": "F1"},
        {"title": "Server", "family": "server", "severity": "LOW", "confidence": "MANUAL_REVIEW",
         "judgment": "취약", "url": "http://t", "finding_uid": "F2"}]}
    fpf.annotate(base)
    assert base["findings"][0]["_fp_suppressed"] is True      # SSTI on .woff 억제
    sev = report._eff_severity_counts(base)
    assert sev["High"] == 0                                   # 억제로 High 0
    score = report._v3_security_score(base)
    # High 가 억제되면 84 상한 해제 → 점수 상승 여지
    assert score > 50


# ── ④ 리포트 모델 파사드 ─────────────────────────────────────────────────────
def test_report_model_normalized_findings():
    import proof_evidence as pe, security_knowledge_graph as kg
    a = {"findings": [
        {"title": "SSTI", "family": "ssti", "severity": "HIGH", "confidence": "CONFIRMED_RESPONSE",
         "evidence_detail": "Jinja2 49", "payload": "{{7*7}}", "judgment": "취약", "finding_uid": "F1"},
        {"title": "Server", "family": "server", "severity": "LOW", "confidence": "MANUAL_REVIEW",
         "evidence_detail": "Server: nginx", "judgment": "취약", "finding_uid": "F2"}]}
    a.update(pe.build_all(a)); a.update(kg.build_all(a)); fpf.annotate(a)
    model = rm.build_report_model({"domain": "t", "analysis": a, "created_at": "x"})
    nfs = model["findings"]
    assert len(nfs) == 2
    byuid = {n["uid"]: n for n in nfs}
    # 각 finding 이 자기 카드만(교차 오염 없음)
    assert byuid["F1"]["card"]["observed_result"] == "49"
    assert "nginx" in byuid["F2"]["card"]["observed_result"]
    assert byuid["F1"]["card"]["observed_result"] != byuid["F2"]["card"]["observed_result"]
    assert "security_score" in model["summary"] and "findings" in model["summary"]


# ── ⑤ 플랫폼 하드닝 ──────────────────────────────────────────────────────────
def test_secrets_encrypt_decrypt_roundtrip():
    if not ss.available():
        return
    tok = ss.encrypt("s3cr3t!")
    assert tok and tok != "s3cr3t!" and ss.decrypt(tok) == "s3cr3t!"
    assert ss.mask("p@ssw0rd").startswith("***")


def test_audit_log_scrubs_secrets():
    with tempfile.TemporaryDirectory() as td:
        import importlib
        al._LOG = __import__("pathlib").Path(td) / "audit.jsonl"
        al.log("test_action", user="admin", role="admin", target="t.com",
               password="SHOULD_NOT_APPEAR", detail_field="ok")
        entries = al.recent(10)
        assert entries and entries[0]["action"] == "test_action"
        blob = str(entries[0])
        assert "SHOULD_NOT_APPEAR" not in blob and "***" in blob    # 민감값 마스킹


def test_audit_recent_order():
    with tempfile.TemporaryDirectory() as td:
        al._LOG = __import__("pathlib").Path(td) / "a.jsonl"
        al.log("a1", user="u"); al.log("a2", user="u")
        r = al.recent(5)
        assert r[0]["action"] == "a2"     # 최근 순
