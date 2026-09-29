"""test_solver_framework.py — Attack Path Prioritizer + Solver Framework + Evidence Correlation."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attack_graph as ag
import attack_path_prioritizer as app
import solver_orchestrator as so
import solver_registry as registry
import evidence_correlation as ec
import solvers.base as sbase


def _analysis_with_paths():
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
        "discovery_items": [
            {"title": "[참고] CSRF 가능성", "confidence": "MANUAL_REVIEW",
             "evidence_url": "http://t/p"},
        ],
        "candidate_verification": {"idor": {"promoted": 1, "verified": 1}},
    }
    g = ag.build_attack_graph(a)
    a["attack_graph"] = g["attack_graph"]
    a["attack_paths"] = g["attack_paths"]
    a["attack_path_summary"] = g["attack_path_summary"]
    return a


# ── Path Scoring / Prioritization ────────────────────────────────────────────
def test_path_scoring_weights():
    a = _analysis_with_paths()
    nodes = a["attack_graph"]["nodes"]
    idx = app._nodes_index(nodes)
    # 관리자+객체참조+Level3 경로가 높은 점수
    idor_path = next(p for p in a["attack_paths"] if "IDOR" in p["title"] or "객체" in p["title"])
    sc = app.score_path(idor_path, idx)
    assert sc["score"] >= app._W_LEVEL3      # Level3 포함
    assert sc["priority"] in ("Critical", "High")


def test_prioritization_sorted_and_budget():
    a = _analysis_with_paths()
    prio = app.prioritize(a["attack_paths"], a["attack_graph"]["nodes"], max_paths=2)
    assert prio["summary"]["total_paths"] == len(a["attack_paths"])
    assert prio["summary"]["prioritized_paths"] == 2
    # 점수 내림차순
    scores = [p["score"] for p in prio["prioritized"]]
    assert scores == sorted(scores, reverse=True)
    # 추천 solver 가 배정됨
    assert any(p["recommended_solver"] for p in prio["selected"])


# ── Solver Selection / Orchestration ─────────────────────────────────────────
def test_solver_selection_by_role():
    assert registry.select_solver("object_reference").name == "idor_solver"
    assert registry.select_solver("search_function").name == "xss_solver"
    assert registry.select_solver("file_handling").name == "upload_solver"
    assert registry.select_solver("business_logic").name == "logic_solver"


def test_orchestration_runs_solvers_on_selected_only():
    a = _analysis_with_paths()
    prio = app.prioritize(a["attack_paths"], a["attack_graph"]["nodes"], max_paths=5)
    res = so.run_solvers(prio, a, max_solvers=5)
    assert res["summary"]["solver_runs"] >= 1
    assert res["summary"]["solver_runs"] <= len(prio["selected"])
    # 결과에 solver/evidence/execution_summary 구조
    for r in res["results"]:
        assert "solver_result" in r and "execution_summary" in r


# ── Solver 안전 불변식: Level 변경/Discovery 금지 ─────────────────────────────
def test_solver_cannot_change_level_or_discover():
    a = _analysis_with_paths()
    prio = app.prioritize(a["attack_paths"], a["attack_graph"]["nodes"], max_paths=5)
    res = so.run_solvers(prio, a, max_solvers=5)
    assert res["summary"]["level_changes"] == 0
    assert res["summary"]["discovery_runs"] == 0
    for r in res["results"]:
        assert r["level_changed"] is False
        assert r["did_discovery"] is False


def test_solver_evil_subclass_still_blocked():
    # Solver 가 Level 변경/Discovery 를 시도해도 base.solve() 가 강제 차단
    class EvilSolver(sbase.BaseSolver):
        name = "evil_solver"
        def _assess(self, ctx):
            return {"solver_result": "EVIDENCE_CORRELATED", "level_changed": True,
                    "did_discovery": True, "evidence": ["x"]}
    out = EvilSolver().solve({"evidence": {"level": 3}})
    assert out["level_changed"] is False
    assert out["did_discovery"] is False


# ── Solver Registry 확장성 ───────────────────────────────────────────────────
def test_registry_extensible_new_solver():
    class GraphqlSolver(sbase.BaseSolver):
        name = "graphql_solver"
        technique = "graphql"
        handles = ("graphql", "api_object")
    registry.register_solver(GraphqlSolver)
    assert "graphql_solver" in registry.all_solvers()
    assert registry.select_solver("graphql").name == "graphql_solver"


# ── Budget Reduction (31 입력점 → 소수 경로 → 소수 Solver) ────────────────────
def test_budget_reduction_effect():
    a = _analysis_with_paths()
    total_paths = len(a["attack_paths"])
    prio = app.prioritize(a["attack_paths"], a["attack_graph"]["nodes"], max_paths=1)
    res = so.run_solvers(prio, a, max_solvers=1)
    assert prio["summary"]["prioritized_paths"] == 1
    assert res["summary"]["solver_runs"] <= 1
    assert prio["summary"]["prioritized_paths"] <= total_paths


# ── AI Failure Fallback ──────────────────────────────────────────────────────
def test_ai_failure_fallback():
    def broken_ai(prompt):
        raise RuntimeError("ollama down")
    a = _analysis_with_paths()
    prio = app.prioritize(a["attack_paths"], a["attack_graph"]["nodes"],
                          max_paths=3, ai_fn=broken_ai)
    # AI 실패해도 결정적 reasoning 으로 정상 동작
    assert prio["summary"]["total_paths"] >= 1
    assert all(p.get("reasoning") for p in prio["prioritized"])


# ── Evidence Correlation ─────────────────────────────────────────────────────
def test_evidence_correlation_chains():
    a = _analysis_with_paths()
    corr = ec.correlate(a)
    fams = {c["family"] for c in corr["chains"]}
    assert "idor" in fams
    idor_chain = next(c for c in corr["chains"] if c["family"] == "idor")
    assert idor_chain["max_level"] == 3            # CONFIRMED_RESPONSE + 교차검증 승격
    assert idor_chain["supporting_findings"]
    assert "IDOR Evidence Chain" in idor_chain["evidence_chain"]
    assert corr["summary"]["confirmed_chains"] >= 1


def test_correlation_confidence_change_strengthens():
    a = {
        "discovery_items": [{"title": "[참고] IDOR 가능성", "confidence": "MANUAL_REVIEW",
                             "evidence_url": "http://t/x?id=1"}],
        "candidate_verification": {"idor": {"promoted": 1}},
        "findings": [], "attack_paths": [],
    }
    corr = ec.correlate(a)
    idor = next(c for c in corr["chains"] if c["family"] == "idor")
    # Level1 후보 → Level3 검증으로 강화 표기
    assert "강화" in idor["confidence_change"]
