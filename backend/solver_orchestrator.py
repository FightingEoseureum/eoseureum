"""
solver_orchestrator.py — Attack Path Prioritizer 결과를 받아 우선순위 경로에 Solver 배정.

원칙:
  - Prioritizer 를 통과한 '선별 경로'에만 Solver 를 배정한다(신규 입력점/Discovery 금지).
  - Solver 는 기존 증거 검토·상관·재검증·보강만 수행하며 Level 을 변경하지 못한다.
  - 실행 예산(execution_budget)과 상한(max_solvers)으로 Solver 실행 수를 제한한다.
"""
from __future__ import annotations

import solver_registry as registry


def run_solvers(prioritized: dict, analysis: dict, *, max_solvers: int = 0) -> dict:
    """선별 경로에 Solver 배정·실행(증거 강화). 반환: {results[], summary{}}.

    prioritized: attack_path_prioritizer.prioritize() 결과(selected 사용).
    analysis    : 기존 결과(증거 컨텍스트 제공용).
    max_solvers : 0=무제한(예산 기준), >0 이면 실행 Solver 수 상한.
    """
    selected = (prioritized or {}).get("selected") or []
    paths_by_id = {p.get("path_id"): p for p in (analysis.get("attack_paths") or [])}
    ctx_common = {
        "candidate_verification": analysis.get("candidate_verification") or {},
        "evidence_levels": analysis.get("evidence_levels") or {},
    }

    results: list[dict] = []
    by_type: dict[str, int] = {}
    executed = 0
    for sp in selected:
        if sp.get("execution_budget", 0) <= 0:
            continue                       # 예산 없는(낮은 우선순위) 경로는 Solver 미배정
        if max_solvers and executed >= max_solvers:
            break
        solver_name = sp.get("recommended_solver")
        solver = registry.get_solver(solver_name) if solver_name else None
        if solver is None:
            continue
        path = paths_by_id.get(sp.get("path_id"), {})
        ctx = {
            "attack_path": path,
            "attack_surface": {"title": sp.get("title"),
                               "priority": sp.get("priority")},
            "technique": getattr(solver, "technique", ""),
            "evidence": {
                "level": path.get("evidence_level", sp.get("evidence_level", 0)),
                "detail": (path.get("possible_impact") or path.get("path_summary") or ""),
                "refs": path.get("evidence_refs") or [],
            },
            "context": ctx_common,
        }
        out = solver.solve(ctx)
        # 안전 불변식 재확인(Solver 가 우회해도 강제)
        out["level_changed"] = False
        out["did_discovery"] = False
        out["path_id"] = sp.get("path_id")
        out["priority"] = sp.get("priority")
        out["path_confidence"] = sp.get("confidence")   # Rule Engine 기반
        results.append(out)
        by_type[solver.name] = by_type.get(solver.name, 0) + 1
        executed += 1

    summary = {
        "solver_runs": executed,
        "by_solver": by_type,
        "level_changes": 0,                # Solver 는 Level 변경 불가(항상 0)
        "discovery_runs": 0,               # Solver 는 Discovery 미수행(항상 0)
    }
    return {"results": results, "summary": summary}
