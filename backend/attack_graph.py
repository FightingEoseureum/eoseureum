"""
attack_graph.py — Attack Graph Engine.

개별 Finding/후보/검증 결과를 모의해킹 관점의 '공격 경로(Attack Path)'로 연결한다.

원칙(코드로 강제):
  - 새로운 공격 실행 없음 — 기존 analysis(Evidence/Rule Engine 결과)만 사용.
  - destructive/shell/webshell 자동화 없음(이 모듈은 네트워크 I/O 자체가 없음).
  - 경로의 '존재/확신'은 증거 수준(evidence_levels)으로만 결정. AI 는 설명만 보강하며
    Confirmed Path 를 임의 생성할 수 없다(confidence 는 Level 기반 계산값).
  - 불확실한 연결은 'may_lead_to' 엣지 + 'Observed/Informational' 경로로만 표시.
"""
from __future__ import annotations

import evidence_levels as evl

# ── Node / Edge 타입 ─────────────────────────────────────────────────────────
N_ENTRY = "Entry Point"
N_LOGIN = "Login Page"
N_AUTH = "Authenticated Area"
N_ADMIN = "Admin Surface"
N_API = "API Endpoint"
N_FORM = "Form"
N_PARAM = "Parameter"
N_OBJREF = "Object Reference"
N_FILE = "File Handling"
N_STATE = "State Changing Action"
N_FINDING = "Finding"
N_EVIDENCE = "Evidence"
N_SENSITIVE = "Sensitive Function"
N_BIZ = "Business Logic"
N_FETCH = "External Fetch"
N_IMPACT = "Report Impact"

# Edge relations
E_DISCOVERED = "discovered_from"
E_REQUIRES_AUTH = "requires_auth"
E_SUBMITS = "submits_to"
E_CONTAINS = "contains_parameter"
E_TECHNIQUE = "maps_to_technique"
E_PRODUCED = "produced_evidence"
E_ESCALATES = "escalates_to"
E_RELATED = "related_to"
E_MAY_LEAD = "may_lead_to"
E_CONFIRMED_BY = "confirmed_by"
E_BLOCKED = "blocked_by_policy"

# 경로 신뢰도(증거 수준 기반 — AI 변경 불가)
CONFIRMED_PATH = "Confirmed Path"
EVIDENCE_PATH = "Evidence Path"
OBSERVED_PATH = "Observed Path"
INFO_PATH = "Informational Path"

# 경로 등급
P_CRITICAL = "Critical Path"
P_HIGH = "High Path"
P_MEDIUM = "Medium Path"
P_LOW = "Low Path"
P_OBSERVED = "Observed Path"


class _Graph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self._edge_keys: set = set()
        self._eid = 0

    def node(self, node_id, node_type, label, **meta):
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "node_id": node_id, "node_type": node_type, "label": label,
                "url": meta.get("url", ""), "method": meta.get("method", ""),
                "auth_state": meta.get("auth_state", ""),
                "semantic_role": meta.get("semantic_role", ""),
                "risk_level": meta.get("risk_level", ""),
                "evidence_level": meta.get("evidence_level", 0),
                "source": meta.get("source", ""), "summary": meta.get("summary", ""),
            }
        return node_id

    def edge(self, frm, to, relation, *, confidence="", evidence="", reason=""):
        key = (frm, to, relation)
        if key in self._edge_keys or frm == to:
            return
        self._edge_keys.add(key)
        self._eid += 1
        self.edges.append({
            "edge_id": f"E{self._eid:04d}", "from_node": frm, "to_node": to,
            "relation": relation, "confidence": confidence,
            "evidence": evidence, "reason": reason,
        })


# ── 의미역할/노드타입 추론 ────────────────────────────────────────────────────
def _infer_role(text: str) -> tuple[str, str]:
    """finding/후보 텍스트로 (node_type, semantic_role) 추론."""
    t = (text or "").lower()
    if "idor" in t or "object" in t or "객체 참조" in t:
        return N_OBJREF, "object_reference"
    if "xss" in t or "스크립트" in t:
        return N_PARAM, "search_function"
    if ("sql" in t or "인젝션" in t) and "명령" not in t:
        return N_PARAM, "search_function"
    if "csrf" in t:
        return N_STATE, "state_change"
    if "업로드" in t or "upload" in t or "파일" in t:
        return N_FILE, "file_handling"
    if "비즈니스" in t or "business" in t or "가격" in t or "권한" in t:
        return N_BIZ, "business_logic"
    if "ssrf" in t or "fetch" in t or "webhook" in t:
        return N_FETCH, "url_fetch"
    if "리다이렉트" in t or "redirect" in t:
        return N_STATE, "redirect"
    if "관리자" in t or "admin" in t:
        return N_ADMIN, "admin"
    if "로그인" in t or "login" in t or "인증" in t:
        return N_LOGIN, "authentication"
    return N_FINDING, "generic"


_SENSITIVE_HINT = ("비밀번호", "password", "계정", "account", "권한", "role",
                   "결제", "payment", "관리자", "admin", "삭제", "delete")


def _has_sensitive(text: str) -> bool:
    t = (text or "").lower()
    return any(h in t for h in _SENSITIVE_HINT)


# ── 메인 빌더 ────────────────────────────────────────────────────────────────
def build_attack_graph(analysis: dict, *, ai_fn=None) -> dict:
    """analysis(기존 결과)로 attack graph + paths 를 생성한다(실행/판정 없음)."""
    g = _Graph()
    analysis = analysis or {}
    domain = (analysis.get("target") or analysis.get("domain") or "target")

    # 1) Entry Point
    entry = g.node("entry", N_ENTRY, f"진입점({domain})", source="recon",
                   summary="외부 노출 진입점")

    # 2) 로그인/인증/관리자 표면(coverage·attack_surface_plan 기반)
    cov = analysis.get("coverage") or {}
    login_found = _to_int(cov.get("login_forms_found", cov.get("login_forms")))
    auth_ok = bool(cov.get("auth_login_success"))
    login_node = auth_node = admin_node = None
    if login_found:
        login_node = g.node("login", N_LOGIN, "로그인 페이지", source="coverage",
                            summary=f"로그인 폼 {login_found}건 발견")
        g.edge(entry, login_node, E_DISCOVERED, reason="로그인 페이지 발견")
    if auth_ok:
        auth_node = g.node("authed", N_AUTH, "인증 후 영역", auth_state="authenticated",
                           source="auth_crawl", summary="테스트 계정 로그인 성공 후 영역")
        g.edge(login_node or entry, auth_node, E_REQUIRES_AUTH, reason="로그인 성공 후 접근")

    asp = (analysis.get("attack_surface_plan") or {}).get("summary") or {}
    if asp.get("by_type", {}).get("Authentication") or login_found:
        pass
    # 관리자 표면: attack_surface_items/discovery 에 admin 힌트
    if _any_admin(analysis):
        admin_node = g.node("admin", N_ADMIN, "관리자 인터페이스", source="discovery",
                            summary="관리자/로그인 인터페이스 발견")
        g.edge(entry, admin_node, E_DISCOVERED, reason="관리자 표면 발견")

    # 3) anchor 수집: 취약점 + 후보(참고) + IDOR 검증결과
    anchors = _collect_anchors(analysis)

    paths: list[dict] = []
    for i, a in enumerate(anchors):
        path = _build_path(g, a, i, entry=entry, login=login_node,
                           auth=auth_node, admin=admin_node, ai_fn=ai_fn)
        if path:
            paths.append(path)

    paths.sort(key=lambda p: p["risk_score"], reverse=True)
    summary = _summarize_paths(paths)
    return {
        "attack_graph": {"nodes": list(g.nodes.values()), "edges": g.edges},
        "attack_nodes": list(g.nodes.values()),
        "attack_edges": g.edges,
        "attack_paths": paths,
        "attack_path_summary": summary,
        "ai_cannot_confirm": True,
    }


def _collect_anchors(analysis: dict) -> list[dict]:
    """경로의 종착 앵커(증거가 있는 finding/후보/검증결과) 수집."""
    out: list[dict] = []
    for f in (analysis.get("findings") or []):
        out.append({"kind": "finding", "title": f.get("title", ""), "f": f,
                    "level": evl.level_of(f, finding_type="vulnerability"),
                    "authed": _authed_finding(f)})
    for f in (analysis.get("attack_surface_items") or []):
        out.append({"kind": "surface", "title": f.get("title", ""), "f": f,
                    "level": evl.level_of(f, finding_type="attack_surface"),
                    "authed": _authed_finding(f)})
    for f in (analysis.get("discovery_items") or []):
        # 후보(참고) 중 접근제어/로직류만 경로화(정보성 노이즈 제외)
        title = (f.get("title") or "")
        if any(k in title for k in ("IDOR", "CSRF", "비즈니스", "업로드", "참고")):
            out.append({"kind": "candidate", "title": title, "f": f,
                        "level": evl.level_of(f, finding_type="discovery"),
                        "authed": _authed_finding(f)})
    return out


def _build_path(g, anchor, idx, *, entry, login, auth, admin, ai_fn=None) -> dict | None:
    f = anchor["f"]
    title = anchor["title"] or "발견 항목"
    level = anchor["level"]
    authed = anchor["authed"]
    node_type, role = _infer_role(title)

    seq = [entry]
    # 인증/관리자 선행 단계
    if admin and ("admin" in role or "관리자" in title.lower()):
        seq.append(admin)
    if authed:
        if login:
            seq.append(login)
        if auth:
            seq.append(auth)

    # 의미 노드(파라미터/객체참조/폼/파일 등)
    surf_id = f"surf{idx}"
    g.node(surf_id, node_type, _role_label(node_type), url=f.get("evidence_url", ""),
           method=f.get("method", ""), semantic_role=role,
           auth_state="authenticated" if authed else "", source=anchor["kind"],
           summary=title[:120])
    g.edge(seq[-1], surf_id, E_CONTAINS if node_type in (N_PARAM, N_OBJREF) else E_DISCOVERED,
           reason="공격 표면 식별")
    seq.append(surf_id)

    # Finding 노드
    fid = f"find{idx}"
    g.node(fid, N_FINDING, title[:80], url=f.get("evidence_url", ""),
           risk_level=f.get("severity", ""), evidence_level=level,
           source=anchor["kind"], summary=title[:160])
    g.edge(surf_id, fid, E_TECHNIQUE, reason="기법 적용 대상")
    seq.append(fid)

    # Evidence 노드(Level ≥1)
    if level >= 1:
        eid = f"ev{idx}"
        g.node(eid, N_EVIDENCE, evl.label_of(level), evidence_level=level,
               source="rule_engine",
               summary=(f.get("evidence_detail") or "")[:160])
        g.edge(fid, eid, E_PRODUCED, confidence=evl.label_of(level),
               evidence=(f.get("evidence_detail") or "")[:120], reason="증거 수집")
        if level >= 2:
            g.edge(fid, eid, E_CONFIRMED_BY, confidence=evl.label_of(level),
                   reason="Rule Engine 증거 기반")
        seq.append(eid)

    # 민감 기능/영향 노드
    if _has_sensitive(title) or node_type in (N_OBJREF, N_BIZ, N_FILE, N_ADMIN):
        sid = f"sens{idx}"
        g.node(sid, N_SENSITIVE, "민감 기능/데이터", source="analysis",
               summary="민감 기능·데이터 접근 가능성")
        g.edge(seq[-1], sid, E_MAY_LEAD if level < 2 else E_ESCALATES,
               reason="민감 자산으로 연결 가능")
        seq.append(sid)

    # Report Impact 종착
    impact = _impact_text(node_type, level)
    iid = f"impact{idx}"
    g.node(iid, N_IMPACT, impact, evidence_level=level, source="analysis", summary=impact)
    g.edge(seq[-1], iid, E_MAY_LEAD if level < 3 else E_ESCALATES, reason="영향 도달")
    seq.append(iid)

    score, grade = _score_path(seq, g, level, authed, node_type, title)
    confidence = _path_confidence(seq, g)
    desc = _describe(title, node_type, level, authed)
    enrich = _ai_enrich(ai_fn, desc, impact) if ai_fn else {}

    return {
        "path_id": f"AP-{idx+1:03d}",
        "title": _path_title(node_type, authed),
        "steps": [_step_text(g.nodes[n]) for n in seq],
        "node_ids": seq,
        "risk_score": score,
        "risk_grade": grade,
        "path_confidence": confidence,
        "evidence_level": level,
        "path_summary": enrich.get("summary") or desc,
        "possible_impact": enrich.get("impact") or impact,
        "recommendation": enrich.get("recommendation") or _recommend(node_type),
        "required_conditions": _required_conditions(node_type, level, authed),
        "blocked_actions": "쉘 획득·리버스셸·웹쉘·파괴적 행위는 정책상 자동 수행하지 않음",
        "evidence_refs": [f.get("evidence_url", "")] if f.get("evidence_url") else [],
        "ai_cannot_confirm": True,
    }


# ── 점수/신뢰도 ───────────────────────────────────────────────────────────────
def _score_path(seq, g, level, authed, node_type, title) -> tuple[int, str]:
    score = 0
    nodes = [g.nodes[n] for n in seq]
    if level >= 3:
        score += 5
    elif level == 2:
        score += 3
    elif level == 1:
        score += 1
    if authed:
        score += 2
    if any(n["node_type"] == N_ADMIN for n in nodes):
        score += 3
    if any(n["node_type"] == N_OBJREF for n in nodes):
        score += 2
    if any(n["node_type"] == N_SENSITIVE for n in nodes):
        score += 2
    if any(n["node_type"] == N_FILE for n in nodes):
        score += 2
    if any(n["node_type"] == N_STATE for n in nodes):
        score += 1
    if any(n["node_type"] == N_BIZ for n in nodes):
        score += 2
    # 여러 finding 연결(체인 길이)
    if len(seq) >= 6:
        score += 1

    if score >= 11:
        grade = P_CRITICAL
    elif score >= 8:
        grade = P_HIGH
    elif score >= 5:
        grade = P_MEDIUM
    elif score >= 2:
        grade = P_LOW
    else:
        grade = P_OBSERVED
    return score, grade


def _path_confidence(seq, g) -> str:
    """증거 수준 기반 — AI 변경 불가. Level 3→Confirmed, 2→Evidence, 1→Observed, 0→Info."""
    maxlvl = max((g.nodes[n].get("evidence_level", 0) for n in seq), default=0)
    if maxlvl >= 3:
        return CONFIRMED_PATH
    if maxlvl == 2:
        return EVIDENCE_PATH
    if maxlvl == 1:
        return OBSERVED_PATH
    return INFO_PATH


def _summarize_paths(paths: list[dict]) -> dict:
    def cnt(key, val):
        return sum(1 for p in paths if p.get(key) == val)
    auth_paths = sum(1 for p in paths if "인증 후" in (p.get("title") or ""))
    sens_paths = sum(1 for p in paths if "민감" in (p.get("possible_impact") or "")
                     or "관리자" in (p.get("title") or ""))
    return {
        "total_paths": len(paths),
        "critical_paths": cnt("risk_grade", P_CRITICAL),
        "high_paths": cnt("risk_grade", P_HIGH),
        "medium_paths": cnt("risk_grade", P_MEDIUM),
        "low_paths": cnt("risk_grade", P_LOW),
        "observed_paths": cnt("risk_grade", P_OBSERVED),
        "confirmed_paths": cnt("path_confidence", CONFIRMED_PATH),
        "evidence_paths": cnt("path_confidence", EVIDENCE_PATH),
        "observed_conf_paths": cnt("path_confidence", OBSERVED_PATH),
        "informational_paths": cnt("path_confidence", INFO_PATH),
        "auth_based_paths": auth_paths,
        "sensitive_admin_paths": sens_paths,
        "priority_action_paths": cnt("path_confidence", CONFIRMED_PATH)
                                  + cnt("path_confidence", EVIDENCE_PATH),
    }


# ── AI 설명 보강(증거/신뢰도 변경 금지) ────────────────────────────────────────
def _ai_enrich(ai_fn, desc: str, impact: str) -> dict:
    """AI 는 설명/영향/권고 텍스트만 보강. confidence/evidence_level 은 반환해도 무시."""
    try:
        import json, re
        text = ai_fn(
            "Explain this attack path for a security report. Only enrich the narrative, "
            "impact, and recommendation. You MUST NOT decide confidence or whether it is "
            f"confirmed. Path: {desc}. Return JSON "
            '{"summary":"","impact":"","recommendation":""}')
        if not text:
            return {}
        m = re.search(r"\{.*\}", text, re.DOTALL)
        raw = json.loads(m.group(0)) if m else {}
        # 신뢰/증거 류 키는 폐기(AI 가 경로 확정 불가)
        return {k: str(raw[k]) for k in ("summary", "impact", "recommendation")
                if k in raw and isinstance(raw[k], (str, int, float))}
    except Exception:
        return {}


# ── 텍스트 헬퍼 ───────────────────────────────────────────────────────────────
def _role_label(node_type):
    return {N_OBJREF: "객체 참조 파라미터", N_PARAM: "입력 파라미터", N_FILE: "파일 처리 폼",
            N_STATE: "상태 변경 요청", N_BIZ: "비즈니스 로직 파라미터",
            N_FETCH: "서버측 URL 페치", N_ADMIN: "관리자 인터페이스",
            N_LOGIN: "로그인 폼"}.get(node_type, "공격 표면")


def _step_text(node):
    lbl = node["label"]
    url = node.get("url")
    return f"{node['node_type']}: {lbl}" + (f" ({url})" if url else "")


def _path_title(node_type, authed):
    base = {N_OBJREF: "객체 접근(IDOR) 경로", N_PARAM: "인젝션/스크립트 경로",
            N_FILE: "파일 처리 경로", N_STATE: "상태 변경(CSRF/리다이렉트) 경로",
            N_BIZ: "비즈니스 로직 경로", N_FETCH: "서버측 요청(SSRF) 경로",
            N_ADMIN: "관리자 표면 경로", N_LOGIN: "인증 우회 점검 경로"}.get(node_type, "공격 경로")
    return ("인증 후 " if authed else "") + base


def _impact_text(node_type, level):
    base = {N_OBJREF: "객체 단위 접근제어 미흡 시 타 사용자 정보 노출 가능",
            N_PARAM: "클라이언트/서버 측 스크립트·쿼리 실행 위험",
            N_FILE: "서버측 검증 미흡 시 악성 파일 처리 위험(자동 업로드 미수행)",
            N_STATE: "교차 출처 상태 변경/리다이렉트 악용 가능",
            N_BIZ: "가격/권한 등 로직 변조 시 금전·권한 피해 가능",
            N_FETCH: "서버측 내부망 요청(SSRF) 가능성",
            N_ADMIN: "관리 인터페이스 노출로 공격 표면 증가"}.get(node_type, "보안 영향 가능")
    if level < 2:
        return base + " (관찰 수준 — 수동 검증 필요)"
    return base


def _recommend(node_type):
    return {N_OBJREF: "객체 조회 시 로그인 사용자와 객체 소유자 매핑 검증",
            N_PARAM: "입력 검증/출력 인코딩 및 파라미터화 쿼리 적용",
            N_FILE: "서버측 확장자/콘텐츠 검증 + 실행 불가 경로 저장",
            N_STATE: "CSRF 토큰·SameSite·Origin 검증 적용",
            N_BIZ: "민감 값 서버측 재검증(권한/소유/범위)",
            N_FETCH: "아웃바운드 목적지 화이트리스트 + 내부망 차단",
            N_ADMIN: "관리 인터페이스 내부망/IP 제한 + MFA"}.get(node_type, "서버측 검증 강화")


def _required_conditions(node_type, level, authed):
    conds = []
    if authed:
        conds.append("유효 인증 세션 필요")
    if node_type == N_OBJREF:
        conds.append("타 사용자 객체 식별자 추정 가능")
    if level < 2:
        conds.append("증거 부족 — 수동 검증으로 확인 필요(가능 경로)")
    if node_type == N_FILE:
        conds.append("업로드 가능 여부는 별도 승인 시에만 확인")
    return conds or ["추가 조건 없음(증거 기반 경로)"]


def _describe(title, node_type, level, authed):
    pre = "인증 후 " if authed else ""
    return (f"{pre}{_role_label(node_type)} 을(를) 통해 '{title}' 에 도달하는 경로. "
            f"검증 수준 {evl.label_of(level)}.")


# ── 내부 유틸 ────────────────────────────────────────────────────────────────
def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _authed_finding(f) -> bool:
    if f.get("authenticated") or f.get("is_verified_idor"):
        return True
    pd = f.get("probe_detail") or {}
    if pd.get("authenticated"):
        return True
    txt = (f.get("title", "") + " " + (f.get("evidence_detail") or "")).lower()
    return "인증 후" in txt or "authenticated" in txt


def _any_admin(analysis) -> bool:
    for bucket in ("findings", "attack_surface_items", "discovery_items"):
        for f in (analysis.get(bucket) or []):
            t = (f.get("title") or "").lower()
            if "admin" in t or "관리자" in t:
                return True
    return False
