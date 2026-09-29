"""
service_pipeline.py — Service Security Framework v2: 서비스 영역 전체 파이프라인 통합.

서비스 표면/경로(v1)를 받아 웹 영역과 동일하게
  Prioritizer → Solver Orchestrator → Multi-Agent → Evidence Graph → Validation Readiness
흐름에 편입한다. 기존 Solver/Agent Orchestrator 를 재사용한다.

원칙: 새 능동 탐색/브루트포스/exploit 없음. 기존 수집 증거만 해석. Level/Confidence 변경 불가.
"""
from __future__ import annotations

import solver_orchestrator as _so
from agents import agent_orchestrator as _ao
import service_surface_planner as ssp

_TYPE_WEIGHT = {
    ssp.S_CONTAINER: 9, ssp.S_DB: 8, ssp.S_DATA: 8, ssp.S_AUTH: 7,
    ssp.S_FILE: 6, ssp.S_MESSAGING: 4, ssp.S_OTHER: 2,
}
_BUDGET = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}


# ── 1. Service Attack Path Prioritization ─────────────────────────────────────
def _score_surface_path(surface: dict) -> dict:
    st = surface["attack_surface_type"]
    ev = surface.get("evidence") or {}
    lvl = surface.get("evidence_level", 1)
    score = _TYPE_WEIGHT.get(st, 2)
    factors = [f"표면 유형({st})={_TYPE_WEIGHT.get(st, 2)}"]
    # 외부 노출(외부 스캔에서 식별됨)
    score += 3; factors.append("외부 노출(+3)")
    # 인증 미요구/무인증 증거
    if ev.get("auth_required") == "no" or ev.get("protected_mode") == "off" \
            or ev.get("guest") == "allowed":
        score += 4; factors.append("무인증/익명 접근 증거(+4)")
    # 데이터 접근/민감 표면
    if st in (ssp.S_DB, ssp.S_DATA, ssp.S_CONTAINER):
        score += 3; factors.append("민감/데이터 접근(+3)")
    # 관리자/원격 접속 성격
    if st == ssp.S_AUTH:
        score += 2; factors.append("관리자/원격 접속(+2)")
    if st == ssp.S_FILE:
        score += 1; factors.append("파일 공유(+1)")
    # Evidence Level
    score += {3: 6, 2: 4, 1: 1}.get(lvl, 0)
    factors.append(f"Evidence Level {lvl}(+{{3:6,2:4,1:1}}.get)")
    if score >= 18:
        priority = "Critical"
    elif score >= 13:
        priority = "High"
    elif score >= 8:
        priority = "Medium"
    else:
        priority = "Low"
    strength = {3: "strong", 2: "moderate", 1: "weak"}.get(lvl, "informational")
    return {"score": score, "priority": priority, "evidence_strength": strength,
            "factors": factors}


def prioritize_service_paths(surfaces: list[dict], paths: list[dict]) -> dict:
    """서비스 경로 우선순위화 → {selected[], summary{}} (Solver/Agent 입력 형식)."""
    path_by_key = {}
    for p in (paths or []):
        refs = p.get("evidence_refs") or []
        key = refs[0] if refs else (p.get("service_family"), )
        path_by_key[key] = p

    selected: list[dict] = []
    for s in (surfaces or []):
        sc = _score_surface_path(s)
        key = f"{s.get('host','')}:{s.get('port','')}"
        p = path_by_key.get(key) or next(
            (x for x in paths if x.get("service_family") == s["family"]), {})
        selected.append({
            "path_id": p.get("path_id", f"SVC-{s.get('port')}"),
            "title": p.get("title", s.get("attack_surface_type")),
            "score": sc["score"], "priority": sc["priority"],
            "confidence": p.get("path_confidence", s.get("evidence_level") and "Observed Path"),
            "evidence_strength": sc["evidence_strength"],
            "evidence_level": s.get("evidence_level", 1),
            "recommended_solver": s.get("recommended_solver"),
            "execution_budget": _BUDGET.get(sc["priority"], 0),
            "family": s["family"],
            "reasoning": f"{s.get('reasoning','')} 우선순위 {sc['priority']}({sc['score']}). "
                         f"근거: {', '.join(sc['factors'][:4])}",
        })
    selected.sort(key=lambda x: x["score"], reverse=True)
    summary = {
        "total_service_paths": len(selected),
        "critical": sum(1 for x in selected if x["priority"] == "Critical"),
        "high": sum(1 for x in selected if x["priority"] == "High"),
        "medium": sum(1 for x in selected if x["priority"] == "Medium"),
        "low": sum(1 for x in selected if x["priority"] == "Low"),
        "high_priority": sum(1 for x in selected if x["priority"] in ("Critical", "High")),
    }
    return {"prioritized": selected, "selected": selected, "summary": summary}


# ── 5. Service Evidence Graph (전용 노드/엣지 타입) ────────────────────────────
N_SURFACE = "Service Surface"
N_PORT = "Open Port"
N_BANNER = "Banner Evidence"
N_VERSION = "Version Evidence"
N_AUTH = "Auth Requirement Evidence"
N_TLS = "TLS Evidence"
N_SOLVER = "Service Solver Result"
N_AGENT = "Service Agent Observation"
N_IMPACT = "Service Business Impact"
N_REMED = "Service Remediation"

E_EXPOSED = "exposed_as"
E_IDENT = "identifies_service"
E_SUPPORT = "supports_service_risk"
E_BY_SOLVER = "analyzed_by_service_solver"
E_BY_AGENT = "analyzed_by_service_agent"
E_TO_IMPACT = "maps_to_business_impact"
E_TO_REMED = "maps_to_remediation"


def build_service_evidence_graph(surfaces, solver_out, agent_out, impacts, remediations):
    nodes: dict = {}
    edges: list = []
    eid = [0]

    def node(nid, ntype, label, **m):
        nodes.setdefault(nid, {"node_id": nid, "node_type": ntype, "label": str(label)[:120],
                               "evidence_level": m.get("evidence_level", 0),
                               "summary": m.get("summary", "")[:160]})
        return nid

    def edge(a, b, rel):
        if a and b and a != b:
            eid[0] += 1
            edges.append({"edge_id": f"SEG{eid[0]:04d}", "from_node": a,
                          "to_node": b, "relation": rel})

    solver_by_fam = {}
    for r in (solver_out or {}).get("results", []):
        solver_by_fam.setdefault(r.get("path_id"), r)
    agent_by_path = {r.get("path_id"): r for r in (agent_out or {}).get("results", [])}
    impact_by_fam = {}
    for it in (impacts or []):
        impact_by_fam.setdefault(it.get("family"), it)
    remed_by_fam = {}
    for it in (remediations or []):
        remed_by_fam.setdefault(it.get("family"), it)

    for s in (surfaces or []):
        port = s.get("port"); fam = s.get("family")
        pn = node(f"sport_{port}", N_PORT, f"{port}/tcp", summary=s.get("service", ""))
        sn = node(f"ssurf_{fam}_{port}", N_SURFACE, s.get("attack_surface_type"),
                  evidence_level=s.get("evidence_level", 1), summary=s.get("reasoning", ""))
        edge(pn, sn, E_EXPOSED)
        ev = s.get("evidence") or {}
        if ev.get("version"):
            edge(node(f"sver_{fam}_{port}", N_VERSION, ev["version"]), sn, E_IDENT)
        if s.get("service"):
            edge(node(f"sban_{fam}_{port}", N_BANNER, s.get("service")), sn, E_IDENT)
        if "auth_required" in ev or "guest" in ev or "protected_mode" in ev:
            edge(node(f"sauth_{fam}_{port}", N_AUTH,
                      f"auth={ev.get('auth_required','?')}/guest={ev.get('guest','?')}"), sn, E_SUPPORT)
        if ev.get("tls"):
            edge(node(f"stls_{fam}_{port}", N_TLS, ev["tls"]), sn, E_SUPPORT)
        # solver/agent/impact/remediation 연결 (solver 이름 접두 == family 로 매칭)
        for r in (solver_out or {}).get("results", []):
            if r.get("solver", "").startswith(fam):
                edge(node(f"ssol_{fam}", N_SOLVER, r.get("solver"),
                          summary=r.get("execution_summary", "")), sn, E_BY_SOLVER)
                break
        ar = next((a for a in (agent_out or {}).get("results", []) if a.get("family") == fam), None)
        if ar:
            for a in ar.get("agents", [])[:3]:
                edge(node(f"sagt_{fam}_{a.get('agent_name')}", N_AGENT,
                          a.get("observation", ""), summary=a.get("observation", "")), sn, E_BY_AGENT)
        if fam in impact_by_fam:
            edge(sn, node(f"simp_{fam}", N_IMPACT, impact_by_fam[fam].get("business_risk", "")),
                 E_TO_IMPACT)
        if fam in remed_by_fam:
            edge(sn, node(f"srem_{fam}", N_REMED, remed_by_fam[fam].get("remediation_title", "")),
                 E_TO_REMED)

    summary = {
        "total_nodes": len(nodes), "total_edges": len(edges),
        "service_surfaces": sum(1 for n in nodes.values() if n["node_type"] == N_SURFACE),
        "agent_observations": sum(1 for n in nodes.values() if n["node_type"] == N_AGENT),
    }
    return {"nodes": list(nodes.values()), "edges": edges, "summary": summary}


# ── 6. Service Validation Readiness ───────────────────────────────────────────
_SVC_VALIDATION = {
    "ssh": ("약한 인증 정책 검토(비밀번호 로그인 허용 여부)", "비밀번호 로그인 정책/인증 방식 확인"),
    "ftp": ("Anonymous Read 검증", "익명 접속 허용 여부 확인"),
    "smb": ("Guest 접근 검증", "Guest/익명 공유 접근 허용 여부 확인"),
    "mysql": ("외부 노출/인증 필요 여부 확인", "외부 접근 시 인증 요구 여부 확인"),
    "redis": ("인증 필요 여부 확인", "noauth/Protected Mode 여부 확인"),
    "elasticsearch": ("인증/접근제어 확인", "인증 활성 여부 확인"),
    "docker": ("API 인증/노출 확인", "Docker API 인증 요구 여부 확인"),
    "k8s": ("API 익명 접근 확인", "API Server/kubelet 익명 접근 여부 확인"),
    "smtp": ("오픈 릴레이 검증", "릴레이 허용 여부 확인"),
}
_SVC_PRIO = {"redis": "High", "mysql": "High", "docker": "High", "k8s": "High",
             "ssh": "Medium", "smb": "Medium", "ftp": "Medium", "smtp": "Low"}


def service_validation_candidates(surfaces: list[dict]) -> dict:
    """서비스 후보를 Validation Readiness 형식으로 생성(실제 검증 미수행 — 후보/우선순위만)."""
    cands: list[dict] = []
    for s in (surfaces or []):
        fam = s["family"]
        base = _SVC_VALIDATION.get(fam)
        if not base:
            # 패밀리 별칭 폴백
            for k in _SVC_VALIDATION:
                if fam.startswith(k):
                    base = _SVC_VALIDATION[k]; fam = k; break
        if not base:
            continue
        cur = s.get("evidence_level", 1)
        if cur >= 2:
            # 이미 증거 수준 — 추가 검증 여지 낮음(수동 확인)
            target = 2
        else:
            target = 2   # 서비스는 자동 exploit 없이 증거(L2)까지만 승격 대상
        if cur >= target:
            continue
        rec, req = base
        cands.append({
            "family": fam,
            "validation_candidate": f"[서비스] {s.get('attack_surface_type')} {s.get('port')}/tcp {s.get('service')}",
            "current_level": cur, "target_level": target,
            "validation_priority": _SVC_PRIO.get(fam, "Medium"),
            "validation_reason": f"현재 관찰(L1) → 증거(L2) 승격 가능. 부족 증거: {req}.",
            "recommended_validation": rec, "required_evidence": req,
            "promotable_to_level3": False, "scan_category": "service",
        })
    rank = {"High": 3, "Medium": 2, "Low": 1}
    cands.sort(key=lambda c: rank.get(c["validation_priority"], 0), reverse=True)
    summary = {
        "service_validation_candidates": len(cands),
        "by_family": _count(cands, "family"),
        "high_priority": sum(1 for c in cands if c["validation_priority"] == "High"),
    }
    return {"candidates": cands, "summary": summary}


def _count(items, key):
    out = {}
    for it in items:
        out[it.get(key)] = out.get(it.get(key), 0) + 1
    return out


# ── 전체 서비스 파이프라인 실행 ───────────────────────────────────────────────
def run_service_pipeline(analysis: dict, host_results: list[dict]) -> dict:
    """서비스 표면/경로 → Prioritizer → Solver → Agent → Evidence Graph → Validation →
    Business Impact → Remediation 를 실행하고 analysis 에 service_* 키로 저장한다."""
    import remediation_planner as _rp

    plan = ssp.plan_service_surfaces(host_results)
    surfaces = plan.get("service_surfaces") or []
    paths = plan.get("service_attack_paths") or []
    if not surfaces:
        return {"ran": False}

    # 1) 우선순위화
    prio = prioritize_service_paths(surfaces, paths)
    # svc-scoped analysis (Orchestrator 입력)
    svc_an = {
        "attack_paths": paths,
        "candidate_verification": analysis.get("candidate_verification") or {},
        "evidence_levels": analysis.get("evidence_levels") or {},
        "findings": [], "domain": analysis.get("domain", ""),
    }
    # 2) Solver Orchestration(서비스 Solver)
    solver_out = _so.run_solvers(prio, svc_an, max_solvers=20)
    # 3) Multi-Agent Orchestration(서비스 Agent Group)
    agent_out = _ao.run_agents(prio, solver_out, svc_an, max_paths=20)
    # 7) Business Impact + Remediation
    impacts = ssp.service_business_impact(surfaces)
    remed = _rp.plan_remediation({"items": impacts})
    # 5) Service Evidence Graph
    seg = build_service_evidence_graph(surfaces, solver_out, agent_out, impacts,
                                       remed.get("items"))
    # 6) Validation Readiness
    vr = service_validation_candidates(surfaces)
    # 9) Controls
    controls = ssp.service_controls(surfaces)

    summary = {
        "total_service_surfaces": plan["service_surface_summary"]["total_service_surfaces"],
        "service_high_priority_paths": prio["summary"]["high_priority"],
        "service_solver_runs": solver_out["summary"].get("solver_runs", 0),
        "service_agent_runs": agent_out["summary"].get("agent_runs", 0),
        "service_evidence_graph_nodes": seg["summary"]["total_nodes"],
        "service_evidence_graph_edges": seg["summary"]["total_edges"],
        "service_validation_candidates": vr["summary"]["service_validation_candidates"],
        "service_business_impacts": len(impacts),
        "service_remediations": len(remed.get("items", [])),
        "surface_summary": plan["service_surface_summary"],
        "path_summary": prio["summary"],
    }
    return {
        "ran": True,
        "service_surfaces": surfaces,
        "service_attack_paths": paths,
        "service_prioritized_paths": prio["selected"],
        "service_solver_results": solver_out["results"],
        "service_agent_results": agent_out["results"],
        "service_evidence_graph": seg,
        "service_validation_candidates": vr["candidates"],
        "service_validation_summary": vr["summary"],
        "service_business_impact": impacts,
        "service_remediation_plan": remed.get("priority_action_plan"),
        "service_remediation_items": remed.get("items"),
        "service_security_controls": controls,
        "service_summary": summary,
    }
