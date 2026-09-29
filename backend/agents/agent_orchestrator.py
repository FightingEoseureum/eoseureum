"""
agents/agent_orchestrator.py — Solver 결과를 받아 경로별로 여러 Agent 를 배정·실행한다.

Attack Path → Solver Result → Agent Selection → Agent Analysis → (Evidence Graph 입력).
Agent 는 기존 증거만 해석·보강하며 Discovery/Level 변경/판정을 하지 않는다(base 가 강제).
"""
from __future__ import annotations

from . import agent_registry as registry


def run_agents(prioritized: dict, solver_out: dict, analysis: dict, *,
               max_paths: int = 0, ai_fn=None) -> dict:
    """선별 경로 + Solver 결과에 Agent Group 을 배정·실행한다.

    반환: {results[], summary{}}.
      results: [{path_id, family, solver, agents:[agent_result...]}]
    """
    selected = (prioritized or {}).get("selected") or []
    if max_paths and max_paths > 0:
        selected = selected[:max_paths]
    paths_by_id = {p.get("path_id"): p for p in (analysis.get("attack_paths") or [])}
    solver_by_path = {r.get("path_id"): r for r in (solver_out or {}).get("results", [])}
    findings_by_title = {f.get("title"): f for f in (analysis.get("findings") or [])}
    chains_by_family = {c.get("family"): c for c in (analysis.get("evidence_chains") or [])}

    results: list[dict] = []
    by_group: dict[str, int] = {}
    agent_runs = 0

    for sp in selected:
        pid = sp.get("path_id")
        path = paths_by_id.get(pid, {})
        solver = solver_by_path.get(pid, {})
        family = _family_of(sp, solver)
        agents = registry.select_agents(family, sp.get("recommended_solver"),
                                        (path.get("title") or ""))
        if not agents:
            continue
        chain = chains_by_family.get(family) or {}
        finding = findings_by_title.get(path.get("title")) or _match_finding(
            analysis.get("findings"), path.get("title"))
        ctx = {
            "attack_path": path,
            "solver_result": solver,
            "evidence_chain": chain,
            "attack_surface": {"title": sp.get("title"), "priority": sp.get("priority")},
            "finding": finding or {},
            "evidence": {"level": path.get("evidence_level", sp.get("evidence_level", 0))},
            "context": {"ai_fn": ai_fn},
        }
        agent_outs = []
        for ag in agents:
            out = ag.analyze(ctx)
            # 안전 불변식 재확인
            out["level_changed"] = False
            out["did_discovery"] = False
            if ai_fn:
                out["observation"] = _ai_enrich(ai_fn, out["observation"]) or out["observation"]
            agent_outs.append(out)
            agent_runs += 1
        by_group[family] = by_group.get(family, 0) + 1
        results.append({"path_id": pid, "family": family,
                        "solver": sp.get("recommended_solver"), "agents": agent_outs})

    summary = {
        "agent_runs": agent_runs,
        "paths_analyzed": len(results),
        "by_group": by_group,
        "level_changes": 0,        # Agent 는 Level 변경 불가(항상 0)
        "discovery_runs": 0,       # Agent 는 Discovery 미수행(항상 0)
    }
    return {"results": results, "summary": summary, "ai_cannot_confirm": True}


def _family_of(sp: dict, solver: dict) -> str:
    rs = (sp.get("recommended_solver") or "")
    if rs.endswith("_solver"):
        return rs[:-7]
    tech = (solver.get("solver") or "").replace("_solver", "")
    return tech or "generic"


def _match_finding(findings, title):
    if not findings or not title:
        return None
    for f in findings:
        if f.get("title") == title:
            return f
    # 부분 매칭(제목 키워드)
    for f in findings:
        ft = f.get("title", "")
        if ft and (ft in title or title in ft):
            return f
    return None


def _ai_enrich(ai_fn, observation: str) -> str | None:
    """AI 는 관찰 문장만 보강. 판정/Level/Confidence 변경 불가(텍스트만)."""
    try:
        text = ai_fn("Improve only this security observation sentence. Do NOT decide "
                     f"vulnerability, level, or confidence. Text: {observation}")
        return str(text).strip() if text else None
    except Exception:
        return None
