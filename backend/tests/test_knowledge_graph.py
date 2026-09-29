"""test_knowledge_graph.py — Security Knowledge Graph v1 + HTML Renderer + Theme + Workers.

판정(Rule Engine/Severity/Confidence/Validation/Risk) 불변, 표현·관계·설명만 검증.
"""
import os, sys, io
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import proof_evidence as pe
import security_knowledge_graph as kg
import report_qa as rqa
import report_theme as th
import report_renderer as rr
import report_html_renderer as hr
import workers as wk


def _rich_graph_analysis():
    a = {"findings": [
        {"title": "SSTI", "family": "ssti", "confidence": "CONFIRMED_RESPONSE", "severity": "HIGH",
         "host": "t.com", "port": 80, "url": "https://t.com/search?q=1", "parameter": "q",
         "evidence_detail": "Jinja2 7*7=49", "judgment": "취약", "_idx": 1},
        {"title": "결제 IDOR", "family": "idor", "confidence": "CONFIRMED_RESPONSE", "severity": "HIGH",
         "host": "t.com", "port": 80, "url": "https://t.com/api/payment?id=1", "parameter": "id",
         "evidence_detail": "타 계정", "judgment": "취약", "_idx": 2}],
        "remediation_items": [{"finding_title": "SSTI", "remediation_title": "템플릿 샌드박스"}],
        "summary": {"by_severity": {"Critical": 0, "High": 2, "Medium": 0, "Low": 0}}}
    a.update(pe.build_all(a))
    a.update(kg.build_all(a))
    return a


# ── Security Knowledge Graph ─────────────────────────────────────────────────
def test_kg_nodes_and_edges():
    a = _rich_graph_analysis()
    g = a["security_knowledge_graph"]
    assert g["summary"]["node_count"] > 10 and g["summary"]["edge_count"] > 8
    types = g["summary"]["nodes_by_type"]
    for t in ("Internet", "Host", "Endpoint", "Parameter", "Finding", "Evidence", "Proof"):
        assert t in types
    etypes = g["summary"]["edges_by_type"]
    assert "HAS_HOST" in etypes and "HAS_FINDING" in etypes and "HAS_EVIDENCE" in etypes
    # Node/Edge 공통 필드
    n = g["nodes"][0]
    assert {"id", "type", "label", "risk", "severity", "confidence", "source", "metadata"} <= set(n)
    e = g["edges"][0]
    assert {"source", "target", "type", "confidence", "reason", "metadata"} <= set(e)


def test_kg_attack_path_flow():
    a = _rich_graph_analysis()
    ap = a["attack_path_graph"]
    assert ap["summary"]["attack_paths"] == 2 and ap["top_path"]
    nodes = [s["node"] for s in ap["top_path"]["steps"]]
    assert any("Internet" in n for n in nodes) and any("Host" in n for n in nodes)
    assert any("조치" in n or "Impact" in n for n in nodes)


def test_kg_risk_context_why_prioritized():
    a = _rich_graph_analysis()
    ctx = a["graph_risk_context"]["by_finding"][2]   # 결제 IDOR
    assert ctx["graph_priority"] > 0
    joined = " ".join(ctx["reasons"])
    assert "Host" in joined or "비즈니스" in joined or "실증" in joined


def test_kg_no_external_deps_json_serializable():
    import json
    a = _rich_graph_analysis()
    json.dumps(a["security_knowledge_graph"])   # 직렬화 가능해야 함
    json.dumps(a["attack_path_graph"])


# ── Business Process Engine 2.0 ──────────────────────────────────────────────
def test_business_2_0_expanded_and_reason():
    assert pe.business_function({"title": "알림", "url": "/notifications/list"})["function"] == "Notification"
    assert pe.business_function({"title": "문의하기", "url": "/support"})["function"] == "Customer Service"
    assert pe.business_function({"title": "API", "url": "/api/v2/x"})["function"] == "API Gateway"
    unk = pe.business_function({"title": "무관", "url": "/zzz"})
    assert unk["function"] == "미상" and unk["reason"]        # Unknown 도 reason 보유


# ── Fingerprint Engine 2.0 ───────────────────────────────────────────────────
def test_fingerprint_2_0_clickjacking_and_method():
    cj = pe.fingerprint({"family": "clickjacking", "title": "Clickjacking",
                         "evidence_detail": "iframe loaded, x-frame 미설정"})
    assert cj["fingerprint_name"] == "Clickjacking" and "x_frame_options" in cj
    hm = pe.fingerprint({"family": "http_method", "title": "TRACE Method",
                         "allow_header": "GET, POST, TRACE", "evidence_detail": "trace echo"})
    assert hm["fingerprint_name"] == "HTTP Method" and hm["allow_header"] == "GET, POST, TRACE"


# ── Theme System ─────────────────────────────────────────────────────────────
def test_theme_yaml_loading():
    names = th.available_themes()
    assert "corporate_blue" in names and "dark_security" in names
    t = th.get_theme("dark_security")
    assert t["name"] == "dark_security" and t["primary_color"] and "severity_colors" in t
    # 미상 테마 → 기본
    assert th.get_theme("no_such")["name"] in names


def test_theme_env_override(monkeypatch):
    monkeypatch.setenv("REPORT_THEME", "executive_black")
    assert th.active_theme_name() == "executive_black"


# ── HTML Renderer v1 ─────────────────────────────────────────────────────────
def test_html_renderer_smoke():
    a = _rich_graph_analysis()
    a["report_qa"] = rqa.check(a)
    html = hr.generate_html({"domain": "t.com", "analysis": a, "created_at": "2026-07-02"})
    assert html.startswith("<!doctype html>") and "</html>" in html
    for token in ("Eoseureum", "Security Assessment Report", "Executive Summary",
                  "Findings Overview", "Detection Coverage", "Findings",
                  "CONFIDENTIAL", "SSTI"):
        assert token in html, f"HTML 누락: {token}"
    # 렌더러 레지스트리에서 html 사용 가능(구현됨)
    assert rr.get_renderer("html").name == "html"
    buf = rr.get_renderer("html").render({"domain": "t.com", "analysis": a, "created_at": "x"})
    assert isinstance(buf, io.BytesIO) and len(buf.getvalue()) > 500


def test_html_escapes_and_safe():
    a = {"findings": [{"title": "<script>x</script>", "family": "xss", "severity": "LOW",
                       "confidence": "MANUAL_REVIEW", "judgment": "취약", "_idx": 1}]}
    a.update(pe.build_all(a)); a.update(kg.build_all(a))
    html = hr.generate_html({"domain": "t", "analysis": a})
    assert "<script>x</script>" not in html and "&lt;script&gt;" in html


# ── Report QA 2.0 ────────────────────────────────────────────────────────────
def test_report_qa_2_0_extended_checks():
    a = _rich_graph_analysis()
    rep = rqa.check(a)
    assert "checks" in rep and any("Knowledge Graph" in c for c in rep["checks"])
    # 빈 그래프면 이슈로 기록
    empty = {"findings": [{"title": "X", "judgment": "취약", "recommendation": "x"}],
             "security_knowledge_graph": {"summary": {"node_count": 0}},
             "attack_path_graph": {"paths": []}}
    r2 = rqa.check(empty)
    assert any("Knowledge Graph" in i or "Attack Story" in i for i in r2["issues"])


# ── Worker-ready Architecture ────────────────────────────────────────────────
def test_worker_job_model_and_local_workers():
    j = wk.WorkerJob(job_id="j1", scan_id="s1", kind="graph", input={"analysis": _rich_graph_analysis()})
    assert wk.WorkerJob.from_dict(j.to_dict()).kind == "graph"
    regs = wk.local_workers()
    assert "graph" in regs and "proof" in regs and "qa" in regs
    out = regs["graph"].run(j)
    assert out.status == wk.WorkerStatus.DONE and "security_knowledge_graph" in out.output
    assert set(["discovery", "validation", "proof", "graph", "report", "renderer", "qa"]) == set(wk.WORKER_KINDS)


# ── OFF-safe: 빈 analysis ─────────────────────────────────────────────────────
def test_offsafe_empty():
    g = kg.build_all({})
    assert g["security_knowledge_graph"]["summary"]["node_count"] >= 1   # internet 루트
    assert g["attack_path_graph"]["summary"]["attack_paths"] == 0
    assert hr.generate_html({"domain": "x", "analysis": {}}).startswith("<!doctype html>")
