"""test_multi_agent_evidence_graph.py — Multi-Agent Solver + Evidence Graph Engine."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attack_graph as ag
import attack_path_prioritizer as app
import solver_orchestrator as so
import evidence_correlation as ec
import evidence_graph as eg
from agents import agent_registry as areg
from agents import agent_orchestrator as ao
from agents import base_agent as bagent


def _full_analysis():
    a = {
        "domain": "t.example.com",
        "coverage": {"login_forms_found": 1, "auth_login_success": True},
        "findings": [
            {"title": "관리자 IDOR 실증 — 객체 참조", "confidence": "CONFIRMED_RESPONSE",
             "severity": "HIGH", "evidence_detail": "타 계정 노출", "is_verified_idor": True,
             "evidence_url": "http://t/admin/account?accountId=2"},
            {"title": "반사형 XSS", "confidence": "CONFIRMED_BROWSER",
             "evidence_detail": "alert 발생", "evidence_url": "http://t/s?q=1"},
        ],
        "discovery_items": [{"title": "[참고] 파일 업로드 후보", "confidence": "MANUAL_REVIEW",
                             "evidence_url": "http://t/upload"}],
        "candidate_verification": {"idor": {"promoted": 1}},
    }
    g = ag.build_attack_graph(a)
    a["attack_graph"] = g["attack_graph"]
    a["attack_paths"] = g["attack_paths"]
    a["attack_path_summary"] = g["attack_path_summary"]
    prio = app.prioritize(a["attack_paths"], a["attack_graph"]["nodes"], max_paths=5)
    a["prioritized_paths"] = prio["selected"]
    solv = so.run_solvers(prio, a, max_solvers=5)
    a["solver_results"] = solv["results"]
    a["evidence_chains"] = ec.correlate(a)["chains"]
    return a, prio, solv


# ── Agent Registry ───────────────────────────────────────────────────────────
def test_registry_groups_and_select():
    assert "object_reference_agent" in areg.list_agents()
    idor_agents = areg.select_agents("idor")
    assert {a.name for a in idor_agents} == {
        "object_reference_agent", "access_control_agent", "auth_context_agent"}
    # solver name / semantic role 로도 선택
    assert areg.select_agents("xss_solver")
    assert areg.select_agents("search_function")


def test_registry_extensible_new_agent():
    class JwtClaimAgent(bagent.BaseAgent):
        name = "jwt_claim_agent"; role = "JWT 클레임 분석"; family = "jwt"
    areg.register_agent(JwtClaimAgent)
    assert "jwt_claim_agent" in areg.list_agents()
    assert areg.select_agents("jwt")[0].name == "jwt_claim_agent"


# ── Agent Orchestrator + Agent Groups ────────────────────────────────────────
def test_orchestrator_runs_agent_groups():
    a, prio, solv = _full_analysis()
    out = ao.run_agents(prio, solv, a, max_paths=5)
    assert out["summary"]["agent_runs"] >= 3
    fams = {r["family"] for r in out["results"]}
    assert "idor" in fams or "xss" in fams
    # IDOR Agent Group 동작: 3개 agent observation
    idor_res = next((r for r in out["results"] if r["family"] == "idor"), None)
    if idor_res:
        assert len(idor_res["agents"]) == 3
        names = {a["agent_name"] for a in idor_res["agents"]}
        assert "access_control_agent" in names


def test_xss_and_upload_agent_groups():
    a, prio, solv = _full_analysis()
    out = ao.run_agents(prio, solv, a, max_paths=10)
    fams = {r["family"] for r in out["results"]}
    assert "xss" in fams
    xss_res = next(r for r in out["results"] if r["family"] == "xss")
    assert {a["agent_name"] for a in xss_res["agents"]} == {
        "reflection_agent", "context_agent", "browser_evidence_agent"}


# ── Agent 안전 불변식 ─────────────────────────────────────────────────────────
def test_agent_no_discovery_no_level_change():
    a, prio, solv = _full_analysis()
    out = ao.run_agents(prio, solv, a, max_paths=10)
    assert out["summary"]["level_changes"] == 0
    assert out["summary"]["discovery_runs"] == 0
    for r in out["results"]:
        for ag_out in r["agents"]:
            assert ag_out["did_discovery"] is False
            assert ag_out["level_changed"] is False


def test_agent_cannot_confirm_or_change_level():
    # evil agent 가 판정/level 키를 넣어도 base 가 제거
    class EvilAgent(bagent.BaseAgent):
        name = "evil_agent"; family = "idor"
        def _observe(self, ctx):
            return {"observation": "x", "verdict": "CONFIRMED", "is_vulnerable": True,
                    "evidence_level": 3, "level_changed": True, "did_discovery": True}
    out = EvilAgent().analyze({"finding": {}, "attack_path": {}})
    assert "verdict" not in out and "is_vulnerable" not in out and "evidence_level" not in out
    assert out["level_changed"] is False and out["did_discovery"] is False


# ── Evidence Graph ────────────────────────────────────────────────────────────
def test_evidence_graph_nodes_and_edges():
    a, prio, solv = _full_analysis()
    agents_out = ao.run_agents(prio, solv, a, max_paths=10)
    graph = eg.build_evidence_graph(a, agent_out=agents_out, prioritized=prio)
    types = {n["node_type"] for n in graph["evidence_graph_nodes"]}
    assert eg.N_ENTRY in types and eg.N_FINDING in types and eg.N_EVIDENCE in types
    assert eg.N_AGENT in types          # agent observation 노드 연결됨
    rels = {e["relation"] for e in graph["evidence_graph_edges"]}
    assert eg.E_BELONGS in rels and eg.E_BY_AGENT in rels and eg.E_SUPPORTS in rels


def test_agent_observation_linked_in_graph():
    a, prio, solv = _full_analysis()
    agents_out = ao.run_agents(prio, solv, a, max_paths=10)
    graph = eg.build_evidence_graph(a, agent_out=agents_out, prioritized=prio)
    agent_nodes = [n for n in graph["evidence_graph_nodes"] if n["node_type"] == eg.N_AGENT]
    assert agent_nodes
    # agent 노드는 analyzed_by_agent 엣지로 finding 과 연결
    agent_ids = {n["node_id"] for n in agent_nodes}
    by_agent = [e for e in graph["evidence_graph_edges"] if e["relation"] == eg.E_BY_AGENT]
    assert any(e["to_node"] in agent_ids for e in by_agent)


def test_evidence_graph_summary():
    a, prio, solv = _full_analysis()
    agents_out = ao.run_agents(prio, solv, a, max_paths=10)
    s = eg.build_evidence_graph(a, agent_out=agents_out, prioritized=prio)["evidence_graph_summary"]
    assert s["total_nodes"] > 0 and s["total_edges"] > 0
    assert s["agent_observations"] >= 1
    assert s["confirmed_paths"] >= 1            # CONFIRMED_RESPONSE/BROWSER 경로 존재
    assert isinstance(s["top_recommendations"], list)


# ── AI Failure Fallback ──────────────────────────────────────────────────────
def test_ai_failure_fallback():
    def broken(prompt):
        raise RuntimeError("ollama down")
    a, prio, solv = _full_analysis()
    out = ao.run_agents(prio, solv, a, max_paths=5, ai_fn=broken)
    # AI 실패해도 결정적 관찰로 정상 동작
    assert out["summary"]["agent_runs"] >= 1
    for r in out["results"]:
        for ag_out in r["agents"]:
            assert ag_out["observation"]
