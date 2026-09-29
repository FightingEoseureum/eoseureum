"""
asset_graph.py — IP 대역 결과를 그래프로 구성(Network Discovery Framework v1).

Network Range → Host → Port → Service → Web Endpoint → Service Surface →
Attack Path → Business Impact → Remediation 를 노드/엣지로 연결한다.
기존 결과만 사용(새 탐색 없음).
"""
from __future__ import annotations

N_RANGE = "Network Range"
N_HOST = "Host"
N_PORT = "Port"
N_SERVICE = "Service"
N_WEB = "Web Endpoint"
N_SURFACE = "Service Surface"
N_PATH = "Attack Path"
N_IMPACT = "Business Impact"
N_REMED = "Remediation"

E_CONTAINS = "contains_host"
E_EXPOSES = "exposes_port"
E_RUNS = "runs_service"
E_HOSTS_WEB = "hosts_web"
E_TO_SURFACE = "maps_to_service_surface"
E_TO_PATH = "maps_to_attack_path"
E_TO_IMPACT = "maps_to_business_impact"
E_TO_REMED = "maps_to_remediation"


def build_asset_graph(assets: list[dict], normalized_targets: list[dict],
                      analysis: dict | None = None) -> dict:
    analysis = analysis or {}
    nodes: dict = {}
    edges: list = []
    _e = [0]

    def node(nid, ntype, label, **m):
        nodes.setdefault(nid, {"node_id": nid, "node_type": ntype, "label": str(label)[:120],
                               "summary": m.get("summary", "")[:140],
                               "priority": m.get("priority", ""),
                               "risk_tags": m.get("risk_tags", [])})
        return nid

    def edge(a, b, rel):
        if a and b and a != b:
            _e[0] += 1
            edges.append({"edge_id": f"AG{_e[0]:04d}", "from_node": a, "to_node": b, "relation": rel})

    # Network Range 노드(CIDR 입력)
    range_nodes = []
    for t in (normalized_targets or []):
        if t.get("type") == "cidr":
            rn = node(f"range_{t['value']}", N_RANGE, t["value"],
                      summary=f"호스트 {t.get('host_count','?')}개")
            range_nodes.append(rn)

    # 서비스 표면/경로/영향/조치 인덱스(가족 기준)
    surf_by_fam = {s.get("family"): s for s in (analysis.get("service_surfaces") or [])}
    path_by_fam = {p.get("service_family"): p for p in (analysis.get("attack_paths") or [])
                   if p.get("scan_category") == "service"}
    imp_by_fam = {i.get("family"): i for i in (analysis.get("service_business_impact") or [])}
    rem_by_fam = {r.get("family"): r for r in (analysis.get("service_remediation_items") or [])}

    for a in (assets or []):
        ip = a.get("ip", "")
        hn = node(f"host_{ip}", N_HOST, ip, summary=a.get("asset_type", ""),
                  priority=a.get("priority", ""), risk_tags=a.get("risk_tags", []))
        for rn in range_nodes:
            edge(rn, hn, E_CONTAINS)
        for p in (a.get("open_ports") or []):
            pn = node(f"port_{ip}_{p}", N_PORT, f"{p}/tcp")
            edge(hn, pn, E_EXPOSES)
        for s in (a.get("detected_services") or []):
            fam = s.get("family")
            sn = node(f"svc_{ip}_{s.get('port')}", N_SERVICE,
                      f"{s.get('port')}/tcp {s.get('service')}", summary=fam)
            edge(node(f"port_{ip}_{s.get('port')}", N_PORT, f"{s.get('port')}/tcp"), sn, E_RUNS)
            # 서비스 표면/경로/영향/조치 연결
            if fam in surf_by_fam:
                surf = surf_by_fam[fam]
                su = node(f"surf_{fam}", N_SURFACE, surf.get("attack_surface_type", ""),
                          priority=surf.get("priority", ""))
                edge(sn, su, E_TO_SURFACE)
                if fam in path_by_fam:
                    edge(su, node(f"spath_{fam}", N_PATH, path_by_fam[fam].get("title", "")), E_TO_PATH)
                if fam in imp_by_fam:
                    edge(su, node(f"simp_{fam}", N_IMPACT, imp_by_fam[fam].get("business_risk", "")), E_TO_IMPACT)
                if fam in rem_by_fam:
                    edge(su, node(f"srem_{fam}", N_REMED, rem_by_fam[fam].get("remediation_title", "")), E_TO_REMED)
        for w in (a.get("web_endpoints") or []):
            wn = node(f"web_{w}", N_WEB, w)
            edge(hn, wn, E_HOSTS_WEB)

    summary = {
        "total_nodes": len(nodes), "total_edges": len(edges),
        "hosts": sum(1 for n in nodes.values() if n["node_type"] == N_HOST),
        "ports": sum(1 for n in nodes.values() if n["node_type"] == N_PORT),
        "services": sum(1 for n in nodes.values() if n["node_type"] == N_SERVICE),
        "web_endpoints": sum(1 for n in nodes.values() if n["node_type"] == N_WEB),
        "ranges": sum(1 for n in nodes.values() if n["node_type"] == N_RANGE),
    }
    return {"asset_graph": {"nodes": list(nodes.values()), "edges": edges},
            "asset_nodes": list(nodes.values()), "asset_edges": edges,
            "asset_summary": summary}
