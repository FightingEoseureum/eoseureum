"""
security_knowledge_graph.py — Security Knowledge Graph v1.

Finding 을 목록이 아니라 관계 그래프로 연결한다:
  Asset → Host → Service/Port → URL/Endpoint → Parameter/Form → Finding → Evidence →
  Proof → Fingerprint → BusinessFunction → AttackPath → Remediation.

원칙: 신규 탐지/판정 없음. 이미 산출된 analysis 데이터(findings/proof_evidence_cards/
business_process_map/remediation)로 그래프를 '구성'만 한다. 외부 그래프 DB(Neo4j 등) 금지 —
JSON 직렬화 가능한 내부 dict/list 로만 구현. Severity/Risk 는 인용만(변경 없음).
"""
from __future__ import annotations

from urllib.parse import urlparse

import evidence_levels as evl

# 노드/엣지 타입 상수
N_INTERNET = "Internet"
NODE_TYPES = ["Asset", "Host", "Service", "Port", "URL", "Endpoint", "API", "Parameter",
              "Form", "DOMElement", "BusinessFunction", "Finding", "Evidence", "Proof",
              "Fingerprint", "AttackPath", "Remediation", "ReportSection"]
EDGE_TYPES = ["HAS_HOST", "EXPOSES_SERVICE", "HAS_ENDPOINT", "HAS_PARAMETER", "HAS_FORM",
              "HAS_DOM_ELEMENT", "TRIGGERS_REQUEST", "HAS_FINDING", "HAS_EVIDENCE",
              "HAS_PROOF", "HAS_FINGERPRINT", "AFFECTS_BUSINESS_FUNCTION",
              "PART_OF_ATTACK_PATH", "MITIGATED_BY", "REPORTED_IN"]

_HIGH_RISK_BIZ = {"Payment", "Transfer", "Administration", "Authentication", "Approval"}


class _Graph:
    def __init__(self):
        self._n: dict = {}
        self._e: list = []
        self._eseen: set = set()

    def node(self, nid, ntype, label, **meta):
        if nid not in self._n:
            self._n[nid] = {"id": nid, "type": ntype, "label": str(label)[:120],
                            "risk": meta.pop("risk", ""), "severity": meta.pop("severity", ""),
                            "confidence": meta.pop("confidence", ""),
                            "source": meta.pop("source", ""), "metadata": meta}
        return nid

    def edge(self, src, tgt, etype, confidence="", reason="", **meta):
        if not src or not tgt:
            return
        k = (src, tgt, etype)
        if k in self._eseen:
            return
        self._eseen.add(k)
        self._e.append({"source": src, "target": tgt, "type": etype,
                        "confidence": confidence, "reason": reason, "metadata": meta})

    def out(self):
        by_type = {}
        for n in self._n.values():
            by_type[n["type"]] = by_type.get(n["type"], 0) + 1
        e_by_type = {}
        for e in self._e:
            e_by_type[e["type"]] = e_by_type.get(e["type"], 0) + 1
        return {"nodes": list(self._n.values()), "edges": self._e,
                "summary": {"node_count": len(self._n), "edge_count": len(self._e),
                            "nodes_by_type": by_type, "edges_by_type": e_by_type}}


def _host_of(url):
    try:
        return urlparse(url if "://" in url else "//" + url).hostname or ""
    except Exception:
        return ""


def _fuid(f):
    return f.get("finding_uid") or f.get("_idx") or ("T:" + (f.get("title") or ""))


def _proof_for(f, analysis):
    uid = _fuid(f)
    for c in (analysis.get("proof_evidence_cards") or []):
        if c.get("finding_id") == uid or c.get("finding_uid") == uid:
            return c
    return None


def build_graph(analysis: dict) -> dict:
    """analysis → Security Knowledge Graph(nodes/edges/summary). 판정 변경 없음."""
    g = _Graph()
    internet = g.node("internet", N_INTERNET, "Internet", source="root")
    findings = [f for f in (analysis.get("findings") or []) if f.get("judgment") != "양호"]

    for f in findings:
        idx = _fuid(f)
        host = f.get("host") or _host_of(f.get("url") or f.get("evidence_url") or "") or "unknown"
        port = str(f.get("port") or "")
        url = f.get("evidence_url") or f.get("url") or ""
        param = f.get("parameter") or f.get("param") or ""
        sev = f.get("severity", "")
        conf = f.get("confidence", "")
        pc = _proof_for(f, analysis)

        host_id = g.node(f"host:{host}", "Host", host, source="scan")
        g.edge(internet, host_id, "HAS_HOST", reason="인터넷 노출 자산")
        anchor = host_id
        if port:
            port_id = g.node(f"port:{host}:{port}", "Port", f"{host}:{port}", source="scan")
            g.edge(host_id, port_id, "EXPOSES_SERVICE",
                   reason=f"{f.get('service') or 'service'} on {port}")
            anchor = port_id
        if url:
            ep_id = g.node(f"endpoint:{url}", "Endpoint", url, source="discovery",
                           metadata={"is_api": "/api/" in url.lower()})
            g.edge(anchor, ep_id, "HAS_ENDPOINT", reason="점검 대상 엔드포인트")
            anchor = ep_id
        if param:
            p_id = g.node(f"param:{url}#{param}", "Parameter", param, source="discovery")
            g.edge(anchor, p_id, "HAS_PARAMETER", reason="입력점")
            anchor = p_id

        fnode = g.node(f"finding:{idx}", "Finding", f.get("title", ""),
                       severity=sev, confidence=conf, risk=sev, source="rule_engine",
                       family=f.get("family", ""), idx=idx)
        g.edge(anchor, fnode, "HAS_FINDING", confidence=conf, reason="발견 취약점")

        level = evl.level_of(f)
        ev_id = g.node(f"evidence:{idx}", "Evidence", evl.label_of(level),
                       source="rule_engine", level=level)
        g.edge(fnode, ev_id, "HAS_EVIDENCE", reason="검증 수준(Rule Engine)")
        if pc:
            pr_id = g.node(f"proof:{idx}", "Proof",
                           f"Proof {pc.get('proof_quality',{}).get('score',0)}%", source="proof",
                           quality=pc.get("proof_quality", {}).get("score", 0))
            g.edge(ev_id, pr_id, "HAS_PROOF", reason="증거 기반 재현/설명")
            fp = pc.get("fingerprint") or {}
            if fp.get("fingerprint_name", "미상") != "미상":
                fp_id = g.node(f"fp:{idx}", "Fingerprint", fp["fingerprint_name"], source="proof",
                               confidence=fp.get("fingerprint_confidence", ""))
                g.edge(pr_id, fp_id, "HAS_FINGERPRINT", reason=fp.get("fingerprint_reason", ""))
            biz = pc.get("business_function", "미상")
            if biz and biz != "미상":
                b_id = g.node(f"biz:{biz}", "BusinessFunction", biz, source="business",
                              risk=("high" if biz in _HIGH_RISK_BIZ else "normal"))
                g.edge(fnode, b_id, "AFFECTS_BUSINESS_FUNCTION",
                       reason=("고위험 비즈니스 기능" if biz in _HIGH_RISK_BIZ else "비즈니스 기능"))
        # Remediation
        rem = _match_remediation(f, analysis)
        if rem:
            r_id = g.node(f"rem:{idx}", "Remediation",
                          rem.get("remediation_title") or "조치", source="remediation")
            g.edge(fnode, r_id, "MITIGATED_BY", reason="권고 조치")
    return g.out()


def _match_remediation(f, analysis):
    title = f.get("title")
    for it in (analysis.get("remediation_items") or []):
        if it.get("finding_title") == title:
            return it
    return None


# ── 6. Attack Path Graph (KG 기반 최중요 경로) ────────────────────────────────
def build_attack_paths(analysis: dict, graph: dict | None = None) -> dict:
    """Finding 별로 Internet→Host→Port→Endpoint→Param→Finding→Proof→Business→Impact→
    Remediation 흐름을 구성. Severity·Proof Quality 로 정렬(판정 아님, 표현 순서)."""
    graph = graph or build_graph(analysis)
    findings = [f for f in (analysis.get("findings") or []) if f.get("judgment") != "양호"]
    rank = {"Critical": 4, "긴급": 4, "High": 3, "높음": 3, "Medium": 2, "중간": 2,
            "Low": 1, "낮음": 1}
    paths = []
    for f in findings:
        pc = _proof_for(f, analysis) or {}
        host = f.get("host") or _host_of(f.get("url") or "") or "unknown"
        steps = [{"node": "Internet", "icon": "🌐"},
                 {"node": f"Host {host}", "icon": "🖥"}]
        if f.get("port"):
            steps.append({"node": f"Port {f.get('port')}", "icon": "🔌"})
        if f.get("evidence_url") or f.get("url"):
            steps.append({"node": (f.get("evidence_url") or f.get("url"))[:50], "icon": "🔗"})
        if f.get("parameter") or f.get("param"):
            steps.append({"node": f"param {f.get('parameter') or f.get('param')}", "icon": "⌨"})
        steps.append({"node": f.get("title", ""), "icon": "⚠",
                      "severity": f.get("severity", ""), "level": evl.level_of(f)})
        if pc:
            steps.append({"node": f"Proof {pc.get('proof_quality',{}).get('score',0)}%",
                          "icon": "◎"})
            steps.append({"node": f"Business: {pc.get('business_function','미상')}", "icon": "🏢"})
        steps.append({"node": "Impact: " + (pc.get("expected_result") or "영향 분석")[:40],
                      "icon": "💥"})
        rem = _match_remediation(f, analysis)
        steps.append({"node": "조치: " + ((rem or {}).get("remediation_title")
                      or (f.get("recommendation") or "권고")[:40]), "icon": "🛠"})
        score = rank.get(f.get("severity", ""), 1) * 100 + pc.get("proof_quality", {}).get("score", 0)
        paths.append({"finding_id": _fuid(f), "title": f.get("title", ""),
                      "severity": f.get("severity", ""), "score": score, "steps": steps})
    paths.sort(key=lambda p: p["score"], reverse=True)
    return {"paths": paths, "top_path": paths[0] if paths else None,
            "summary": {"attack_paths": len(paths)}}


# ── 7. Graph Risk Context (왜 우선 조치인가 — Severity 변경 없음) ─────────────
def graph_risk_context(analysis: dict, graph: dict | None = None) -> dict:
    """그래프 맥락으로 '왜 이 항목이 우선인지' 설명 근거를 생성(정렬/설명용, 판정 불변)."""
    findings = [f for f in (analysis.get("findings") or []) if f.get("judgment") != "양호"]
    host_counts: dict = {}
    for f in findings:
        h = f.get("host") or _host_of(f.get("url") or "") or "unknown"
        host_counts[h] = host_counts.get(h, 0) + 1
    ctx = {}
    for f in findings:
        idx = _fuid(f)
        pc = _proof_for(f, analysis) or {}
        h = f.get("host") or _host_of(f.get("url") or "") or "unknown"
        reasons, score = [], 0
        if host_counts.get(h, 0) >= 2:
            reasons.append(f"동일 Host에 취약점 {host_counts[h]}건 집중"); score += 15
        if (f.get("confidence") or "").upper().startswith("CONFIRMED"):
            reasons.append("실증(브라우저/응답)으로 확인됨"); score += 25
        q = pc.get("proof_quality", {}).get("score", 0)
        if q >= 75:
            reasons.append(f"높은 Proof Quality({q}%)"); score += 15
        biz = pc.get("business_function", "미상")
        if biz in _HIGH_RISK_BIZ:
            reasons.append(f"고위험 비즈니스 기능({biz})"); score += 25
        if not (f.get("authenticated")):
            reasons.append("인증 전 접근 가능 표면"); score += 10
        if "/api/" in (f.get("url") or f.get("evidence_url") or "").lower():
            reasons.append("인터넷 노출 API 연결"); score += 10
        ctx[idx] = {"reasons": reasons or ["단독 항목 — 표준 우선순위 적용"],
                    "graph_priority": min(100, score)}
    return {"by_finding": ctx,
            "summary": {"contextualized": len(ctx),
                        "multi_finding_hosts": sum(1 for c in host_counts.values() if c >= 2)}}


def build_all(analysis: dict) -> dict:
    graph = build_graph(analysis)
    ap = build_attack_paths(analysis, graph)
    rc = graph_risk_context(analysis, graph)
    graph["summary"]["attack_paths"] = ap["summary"]["attack_paths"]
    return {"security_knowledge_graph": graph, "attack_path_graph": ap,
            "graph_risk_context": rc}
