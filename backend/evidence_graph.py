"""
evidence_graph.py — Evidence Graph Engine.

기존 선형 Evidence Chain(Finding→Evidence→Impact)을 그래프로 확장한다.
Entry Point / Attack Surface / Attack Path / Prioritized Path / Solver Result /
Agent Observation / Finding / Evidence / Limitation / Impact / Recommendation /
Blocked Action / Manual Review 노드를 관계 엣지로 연결한다.

신규 판정/Level 생성 없음 — 기존 analysis(Rule Engine 결과 + Solver/Agent 산출)만 연결.
"""
from __future__ import annotations

import evidence_levels as evl

# Node 타입
N_ENTRY = "Entry Point"
N_SURFACE = "Attack Surface"
N_PATH = "Attack Path"
N_PRIO = "Prioritized Path"
N_SOLVER = "Solver Result"
N_AGENT = "Agent Observation"
N_FINDING = "Finding"
N_EVIDENCE = "Evidence"
N_LIMIT = "Limitation"
N_IMPACT = "Impact"
N_RECO = "Recommendation"
N_BLOCK = "Blocked Action"
N_MANUAL = "Manual Review"

# Edge 관계
E_SUPPORTS = "supports"
E_EXPLAINS = "explains"
E_DERIVED = "derived_from"
E_CORRELATES = "correlates_with"
E_LIMITED = "limited_by"
E_RECOMMENDS = "recommends"
E_BLOCKS = "blocks"
E_MANUAL = "requires_manual_review"
E_BELONGS = "belongs_to_path"
E_BY_SOLVER = "produced_by_solver"
E_BY_AGENT = "analyzed_by_agent"

_CONFIRMED = "Confirmed Path"
_EVIDENCE = "Evidence Path"
_OBSERVED = "Observed Path"


class _G:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self._ek: set = set()
        self._n = 0

    def node(self, nid, ntype, label, **m):
        if nid not in self.nodes:
            self.nodes[nid] = {
                "node_id": nid, "node_type": ntype, "label": str(label)[:160],
                "source": m.get("source", ""), "evidence_level": m.get("evidence_level", 0),
                "confidence": m.get("confidence", ""), "summary": m.get("summary", "")[:200],
                "refs": list(m.get("refs", []) or [])[:5],
            }
        return nid

    def edge(self, frm, to, rel, *, confidence="", reason=""):
        if not frm or not to or frm == to:
            return
        key = (frm, to, rel)
        if key in self._ek:
            return
        self._ek.add(key)
        self._n += 1
        self.edges.append({"edge_id": f"EG{self._n:04d}", "from_node": frm,
                           "to_node": to, "relation": rel,
                           "confidence": confidence, "reason": reason})


def build_evidence_graph(analysis: dict, *, agent_out: dict | None = None,
                         prioritized: dict | None = None) -> dict:
    """analysis + agent 결과로 Evidence Graph 를 구성한다."""
    analysis = analysis or {}
    agent_out = agent_out or {}
    g = _G()
    entry = g.node("eg_entry", N_ENTRY, f"진입점({analysis.get('domain','target')})",
                   source="recon")

    # 공격 표면 요약
    asp = (analysis.get("attack_surface_plan") or {}).get("summary") or {}
    if asp:
        sid = g.node("eg_surface", N_SURFACE,
                     f"공격 표면 {asp.get('total_surfaces',0)}개", source="attack_surface_plan",
                     summary=f"인증 후 {asp.get('auth_after_surfaces',0)}개")
        g.edge(entry, sid, E_DERIVED, reason="공격 표면 분석")

    # 우선순위 경로 인덱스
    prio_sel = (prioritized or {}).get("selected") or analysis.get("prioritized_paths") or []
    prio_ids = {p.get("path_id") for p in prio_sel}

    # 경로/솔버/에이전트/증거 연결
    agent_by_path = {r.get("path_id"): r for r in (agent_out.get("results") or [])}
    solver_by_path = {r.get("path_id"): r for r in (analysis.get("solver_results") or [])}

    for p in (analysis.get("attack_paths") or []):
        pid = p.get("path_id")
        level = int(p.get("evidence_level", 0) or 0)
        pconf = p.get("path_confidence", "")
        ntype = N_PRIO if pid in prio_ids else N_PATH
        pnode = g.node(f"eg_path_{pid}", ntype, p.get("title", "경로"),
                       source="attack_graph", evidence_level=level, confidence=pconf,
                       summary=p.get("path_summary", ""), refs=p.get("evidence_refs"))
        g.edge(entry, pnode, E_BELONGS, confidence=pconf, reason="경로 소속")

        # Finding + Evidence
        fnode = g.node(f"eg_find_{pid}", N_FINDING, p.get("title", ""), source="rule_engine",
                       evidence_level=level)
        g.edge(pnode, fnode, E_DERIVED, reason="경로의 발견")
        if level >= 1:
            enode = g.node(f"eg_ev_{pid}", N_EVIDENCE, evl.label_of(level),
                           source="rule_engine", evidence_level=level,
                           summary=p.get("possible_impact", ""))
            g.edge(fnode, enode, E_SUPPORTS, confidence=evl.label_of(level),
                   reason="증거가 발견을 뒷받침")
            if level >= 2:
                g.edge(enode, fnode, E_CORRELATES, reason="상관 증거")
        else:
            mnode = g.node(f"eg_manual_{pid}", N_MANUAL, "수동 검토 필요",
                           source="rule_engine")
            g.edge(fnode, mnode, E_MANUAL, reason="증거 부족 — 수동 검토")

        # Solver Result
        sr = solver_by_path.get(pid)
        if sr:
            snode = g.node(f"eg_solver_{pid}", N_SOLVER, sr.get("solver", "solver"),
                           source="solver", summary=sr.get("execution_summary", ""))
            g.edge(fnode, snode, E_BY_SOLVER, reason="Solver 증거 강화")

        # Agent Observations (협력 계층)
        ar = agent_by_path.get(pid)
        if ar:
            for a in ar.get("agents", []):
                anode = g.node(f"eg_agent_{pid}_{a.get('agent_name')}", N_AGENT,
                               f"{a.get('agent_role')}: {a.get('observation','')}",
                               source=a.get("agent_name"),
                               summary=a.get("observation", ""))
                g.edge(fnode, anode, E_BY_AGENT, reason="Agent 분석")
                g.edge(anode, pnode, E_EXPLAINS, reason="경로 설명 보강")
                if a.get("limitation"):
                    lnode = g.node(f"eg_lim_{pid}_{a.get('agent_name')}", N_LIMIT,
                                   a.get("limitation"), source=a.get("agent_name"))
                    g.edge(anode, lnode, E_LIMITED, reason="제한사항")
                if a.get("recommended_next_step"):
                    rid = "eg_reco_" + _slug(a.get("recommended_next_step"))
                    rnode = g.node(rid, N_RECO, a.get("recommended_next_step"),
                                   source=a.get("agent_name"))
                    g.edge(anode, rnode, E_RECOMMENDS, reason="권고")

        # Impact + Blocked Action
        if p.get("possible_impact"):
            iid = g.node(f"eg_impact_{pid}", N_IMPACT, p.get("possible_impact"),
                         source="analysis", evidence_level=level)
            g.edge(fnode, iid, E_EXPLAINS, reason="가능한 영향")
        if p.get("blocked_actions"):
            bid = g.node("eg_blocked", N_BLOCK, p.get("blocked_actions"), source="policy")
            g.edge(pnode, bid, E_BLOCKS, reason="정책상 차단된 위험 행위")

    summary = _summarize(g, analysis)
    return {
        "evidence_graph": {"nodes": list(g.nodes.values()), "edges": g.edges},
        "evidence_graph_nodes": list(g.nodes.values()),
        "evidence_graph_edges": g.edges,
        "evidence_graph_summary": summary,
        "ai_cannot_confirm": True,
    }


def _summarize(g: _G, analysis: dict) -> dict:
    nodes = list(g.nodes.values())
    def cnt(t):
        return sum(1 for n in nodes if n["node_type"] == t)
    paths = analysis.get("attack_paths") or []
    def pconf(v):
        return sum(1 for p in paths if p.get("path_confidence") == v)
    # 상위 지지 발견(증거 수준 높은 순)
    finding_nodes = [n for n in nodes if n["node_type"] == N_FINDING]
    finding_nodes.sort(key=lambda n: n.get("evidence_level", 0), reverse=True)
    top_findings = [n["label"] for n in finding_nodes[:5] if n["label"]]
    reco_nodes = [n["label"] for n in nodes if n["node_type"] == N_RECO]
    return {
        "total_nodes": len(nodes),
        "total_edges": len(g.edges),
        "evidence_nodes": cnt(N_EVIDENCE),
        "agent_observations": cnt(N_AGENT),
        "confirmed_paths": pconf(_CONFIRMED),
        "evidence_paths": pconf(_EVIDENCE),
        "observed_paths": pconf(_OBSERVED),
        "manual_review_nodes": cnt(N_MANUAL),
        "blocked_actions": cnt(N_BLOCK),
        "top_supported_findings": top_findings,
        "top_recommendations": reco_nodes[:5],
    }


def _slug(s: str) -> str:
    return "".join(ch for ch in (s or "")[:24] if ch.isalnum())
