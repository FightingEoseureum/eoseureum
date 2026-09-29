"""
discovery3.py — Browser Discovery 3.0: 런타임 후킹·숨은 API·스토리지·이벤트·관계 그래프.

목표: "더 많은 공격 표면을 정확하게 발견". 판정(Rule Engine/Validation/Evidence)은 절대
변경하지 않는다. 모든 항목에 source/confidence/reason 을 부여해 Planner 가 우선순위를
정할 수 있게 한다. 브라우저 의존 로직(JS 후킹)은 주입 스크립트 상수로 두고, 수집된 raw
데이터의 정규화/그래프/후보 생성은 순수 함수로 분리해 결정적으로 테스트한다.

안전: 값은 항상 마스킹(키/존재 여부만). Replay 는 '후보'만 생성하고 수행하지 않는다.
"""
from __future__ import annotations

import re as _re
from urllib.parse import urlparse, urljoin

from .request_recorder import MASK, _JWT_RX

# ── 1-1 JS Runtime Hook: 페이지 로드 전에 주입할 후킹 스크립트 ──────────────────
# fetch / XHR / pushState / replaceState / WebSocket / sendBeacon 호출 시 생성되는
# Endpoint 를 window.__eoseureum 에 누적한다(네트워크 요청은 발생시키지 않고 인자만 기록).
INIT_HOOK_SCRIPT = r"""
(() => {
  if (window.__eoseureum) return;
  window.__eoseureum = { endpoints: [], forms: [], events: [] };
  const rec = (u, source, method) => {
    try { if (u && typeof u === 'string') window.__eoseureum.endpoints.push(
      { url: u, source: source, method: method || 'GET' }); } catch (e) {}
  };
  try { const _f = window.fetch; window.fetch = function (i, init) {
    rec(typeof i === 'string' ? i : (i && i.url), 'runtime_fetch', init && init.method);
    return _f.apply(this, arguments); }; } catch (e) {}
  try { const _o = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (m, u) { rec(u, 'runtime_xhr', m);
      return _o.apply(this, arguments); }; } catch (e) {}
  try { const _p = history.pushState; history.pushState = function (s, t, u) {
    rec(u, 'runtime_pushState', 'GET'); return _p.apply(this, arguments); }; } catch (e) {}
  try { const _r = history.replaceState; history.replaceState = function (s, t, u) {
    rec(u, 'runtime_replaceState', 'GET'); return _r.apply(this, arguments); }; } catch (e) {}
  try { const _W = window.WebSocket; if (_W) window.WebSocket = function (u, p) {
    rec(u, 'runtime_ws', 'WS'); return new _W(u, p); }; } catch (e) {}
  try { if (navigator.sendBeacon) { const _b = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (u, d) { rec(u, 'runtime_beacon', 'POST'); return _b(u, d); }; } } catch (e) {}
  // 1-5 Runtime Form Discovery: 동적 추가 form/input 관찰(값 미수집)
  try {
    const scan = () => { document.querySelectorAll('form').forEach(f => {
      const fields = []; f.querySelectorAll('input,textarea,select').forEach(el => {
        const t = (el.getAttribute('type') || el.tagName).toLowerCase();
        if (['submit','button','image','reset'].indexOf(t) < 0 && el.name)
          fields.push({ name: el.name, type: t }); });
      if (fields.length) window.__eoseureum.forms.push(
        { action: f.getAttribute('action') || '', method: (f.getAttribute('method')||'GET').toUpperCase(),
          fields: fields }); }); };
    const mo = new MutationObserver(() => { try { scan(); } catch (e) {} });
    mo.observe(document.documentElement, { childList: true, subtree: true });
    scan();
  } catch (e) {}
})();
"""

# 수집 스냅샷: 스토리지 '키'와 JWT 존재 여부만(값 미수집). 이벤트 핸들러 요소 메타.
COLLECT_SNAPSHOT_JS = r"""
() => {
  const out = { localStorage: [], sessionStorage: [], cookies: [], hasJWT: false,
                runtime: (window.__eoseureum || {}) };
  try { out.localStorage = Object.keys(localStorage || {}); } catch (e) {}
  try { out.sessionStorage = Object.keys(sessionStorage || {}); } catch (e) {}
  try { out.cookies = (document.cookie || '').split(';').map(c => c.split('=')[0].trim()).filter(Boolean); } catch (e) {}
  try {
    // JWT 형식 토큰만 수집(임의 값 저장 안 함) — 오프라인 취약점 분석용
    const jwt = /^eyJ[\w-]+\.[\w-]+\.[\w-]*$/;
    out.jwtTokens = [];
    const push = v => { v = (v || '').trim();
      if (jwt.test(v) && out.jwtTokens.indexOf(v) < 0 && out.jwtTokens.length < 10) out.jwtTokens.push(v); };
    try { for (let i = 0; i < localStorage.length; i++) push(localStorage.getItem(localStorage.key(i))); } catch (e) {}
    try { for (let i = 0; i < sessionStorage.length; i++) push(sessionStorage.getItem(sessionStorage.key(i))); } catch (e) {}
    try { (document.cookie || '').split(';').forEach(c => push(c.split('=').slice(1).join('='))); } catch (e) {}
    out.hasJWT = out.jwtTokens.length > 0;
  } catch (e) {}
  try {
    const evs = []; document.querySelectorAll('[onclick],[onsubmit],[onchange]').forEach(el => {
      evs.push({ tag: el.tagName.toLowerCase(), text: (el.innerText||'').trim().slice(0,40),
                 handlers: ['onclick','onsubmit','onchange'].filter(a => el.getAttribute(a)) }); });
    out.runtime.events = (out.runtime.events || []).concat(evs);
  } catch (e) {}
  return out;
}
"""

_CONF = {"runtime_fetch": 0.9, "runtime_xhr": 0.9, "runtime_pushState": 0.75,
         "runtime_replaceState": 0.75, "runtime_ws": 0.85, "runtime_beacon": 0.8,
         "openapi": 0.95, "swagger": 0.95, "graphql": 0.85, "sitemap": 0.7,
         "robots": 0.55, "manifest": 0.6, "well_known": 0.7, "js_concat": 0.6,
         "storage": 0.5, "static_js": 0.6}


def confidence_for(source: str) -> float:
    return _CONF.get(source, 0.5)


def _abs(u: str, base: str) -> str:
    try:
        if u.startswith(("http://", "https://", "ws://", "wss://")):
            return u
        return urljoin(base or "", u)
    except Exception:
        return u


# ── 1-1 런타임 Endpoint 정규화 ──────────────────────────────────────────────
def normalize_runtime_endpoints(raw: list, base_url: str = "") -> list[dict]:
    """window.__eoseureum.endpoints raw → source/confidence/reason 부여한 endpoint 후보."""
    out, seen = [], set()
    for e in raw or []:
        u = (e.get("url") or "").strip()
        if not u or u.startswith(("data:", "blob:", "javascript:", "#")):
            continue
        src = e.get("source", "runtime")
        full = _abs(u, base_url)
        key = (full, e.get("method", "GET"), src)
        if key in seen:
            continue
        seen.add(key)
        out.append({"endpoint": full, "method_hint": (e.get("method") or "GET").upper(),
                    "source": src, "confidence": confidence_for(src),
                    "reason": "브라우저 런타임 후킹으로 실행 중 생성된 요청",
                    "is_api_candidate": ("/api/" in full.lower() or "graphql" in full.lower()
                                         or full.lower().startswith(("ws://", "wss://"))),
                    "is_websocket": full.lower().startswith(("ws://", "wss://")),
                    "is_graphql": "graphql" in full.lower(), "runtime": True})
    return out


# ── 1-2 JS 변수조합 Endpoint(경량 data-flow 휴리스틱) ───────────────────────
_CONST_RX = _re.compile(r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*['"`]([^'"`]+)['"`]""")
_CALL_RX = _re.compile(r"""(?:fetch|axios|\.open|\.get|\.post)\s*\(\s*([A-Za-z_$][\w$]*)\s*\+\s*['"`]([^'"`]+)['"`]""")


def resolve_js_concat_endpoints(js_text: str, source_file: str = "") -> list[dict]:
    """`const api="/api"; fetch(api+"/user/"+id)` 형태의 변수 조합 endpoint 추적(휴리스틱)."""
    text = js_text or ""
    consts = {m.group(1): m.group(2) for m in _CONST_RX.finditer(text)}
    out, seen = [], set()
    for m in _CALL_RX.finditer(text):
        var, tail = m.group(1), m.group(2)
        if var not in consts:
            continue
        ep = (consts[var].rstrip("/") + "/" + tail.lstrip("/"))
        if ep in seen:
            continue
        seen.add(ep)
        out.append({"endpoint": ep, "method_hint": "GET", "source": "js_concat",
                    "confidence": confidence_for("js_concat"),
                    "reason": f"변수 조합({var}+…) 기반 endpoint 추적", "source_file": source_file,
                    "is_api_candidate": "/api/" in ep.lower(), "is_websocket": False,
                    "is_graphql": "graphql" in ep.lower(), "runtime": False})
    return out


# ── 1-3 Hidden API Discovery (robots/sitemap/manifest/.well-known/openapi/graphql) ──
_PATH_RX = _re.compile(r"""["'(]\s*(/[A-Za-z0-9_\-./{}]+)""")
_URLLOC_RX = _re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", _re.I)


def discover_hidden_apis(assets: dict, base_url: str = "") -> list[dict]:
    """정적 자산 텍스트(dict: name->text)에서 API/endpoint 후보 추출.

    assets 키 예: 'robots','sitemap','manifest','openapi','graphql','well_known'.
    """
    out, seen = [], set()

    def add(ep, source, reason, method="GET"):
        full = _abs(ep, base_url)
        k = (full, method, source)
        if not ep or k in seen:
            return
        seen.add(k)
        out.append({"endpoint": full, "method_hint": method, "source": source,
                    "confidence": confidence_for(source), "reason": reason,
                    "is_api_candidate": ("/api/" in full.lower() or "graphql" in full.lower()),
                    "is_websocket": False, "is_graphql": "graphql" in full.lower(),
                    "runtime": False})

    for name, text in (assets or {}).items():
        if not text:
            continue
        low = name.lower()
        if "sitemap" in low:
            for m in _URLLOC_RX.finditer(text):
                add(m.group(1), "sitemap", "sitemap.xml 등록 URL")
        elif "robots" in low:
            for line in text.splitlines():
                if ":" in line and ("allow" in line.lower() or "sitemap" in line.lower()):
                    val = line.split(":", 1)[1].strip()
                    if val.startswith("/") or val.startswith("http"):
                        add(val, "robots", "robots.txt 경로")
        elif "openapi" in low or "swagger" in low:
            for m in _re.finditer(r'"(/[^"]+)"\s*:\s*\{', text):   # paths 객체 키
                add(m.group(1), "openapi", "OpenAPI/Swagger paths 정의")
        elif "graphql" in low:
            add("/graphql", "graphql", "GraphQL endpoint 후보", "POST")
        else:  # manifest / well-known / 기타 JSON
            src = "manifest" if "manifest" in low else ("well_known" if "well" in low else "manifest")
            for m in _PATH_RX.finditer(text):
                add(m.group(1), src, f"{name} 내 경로 후보")
    return out


# ── 1-4 Browser Storage Discovery (값 미수집, 키/존재만) ─────────────────────
def normalize_storage(raw: dict) -> dict:
    """localStorage/sessionStorage/cookie 키 + JWT 존재 여부. 값은 절대 저장하지 않음."""
    r = raw or {}
    return {
        "local_storage_keys": list(r.get("localStorage") or [])[:50],
        "session_storage_keys": list(r.get("sessionStorage") or [])[:50],
        "cookie_names": list(r.get("cookies") or [])[:50],
        "has_jwt": bool(r.get("hasJWT")),
        "note": "값은 수집하지 않으며 키/존재 여부만 기록(민감정보 보호).",
    }


def storage_input_points(storage: dict, base_url: str = "") -> list[dict]:
    """스토리지 키를 Planner 참고용 입력 표면(값 마스킹)으로. 능동 점검 주입 대상 아님."""
    pts = []
    for loc, keys in (("localStorage", storage.get("local_storage_keys")),
                      ("sessionStorage", storage.get("session_storage_keys")),
                      ("cookie", storage.get("cookie_names"))):
        for k in keys or []:
            pts.append({"parameter_name": k, "parameter_location": loc, "sample_value": MASK,
                        "source": "storage", "discovered_by": "browser_storage",
                        "confidence": confidence_for("storage")})
    return pts


# ── 1-6 Event Discovery → Interaction Points (자동 클릭 안 함) ───────────────
def extract_interaction_points(events: list) -> list[dict]:
    """수집된 이벤트 핸들러 요소 → Interaction Point 후보(Planner 전달용)."""
    out = []
    for e in events or []:
        out.append({"element": (e.get("text") or e.get("tag") or "").strip()[:40],
                    "tag": e.get("tag", ""), "handlers": e.get("handlers") or [],
                    "interaction_type": ",".join(e.get("handlers") or []) or "event",
                    "source": "event_handler", "confidence": 0.5,
                    "note": "상호작용 후보(자동 클릭·제출하지 않음)"})
    return out


# ── 1-5 Runtime Form → 입력점 ────────────────────────────────────────────────
def normalize_runtime_forms(forms: list, base_url: str = "") -> list[dict]:
    """동적 생성 form 필드를 입력점으로(값 미수집)."""
    out, seen = [], set()
    for f in forms or []:
        action = _abs(f.get("action") or base_url, base_url)
        method = (f.get("method") or "GET").upper()
        for fld in f.get("fields") or []:
            name = fld.get("name")
            if not name:
                continue
            key = (action, method, name)
            if key in seen:
                continue
            seen.add(key)
            out.append({"parameter_name": name, "param": name,
                        "parameter_location": "form" if method != "GET" else "query",
                        "endpoint": action, "url": action, "method": method,
                        "sample_value": "test", "source": "runtime_form",
                        "discovered_by": "runtime_form", "runtime": True,
                        "confidence": 0.7, "authenticated": False})
    return out


# ── 1-7 API Relationship Graph ───────────────────────────────────────────────
_ID_SEG = _re.compile(r"^(\d+|[0-9a-f]{8,}|[0-9a-f-]{16,})$", _re.I)


def _templatize(path: str) -> str:
    parts = []
    for seg in (path or "/").split("/"):
        parts.append("{id}" if seg and _ID_SEG.match(seg) else seg)
    return "/".join(parts) or "/"


def _ancestors(tmpl: str) -> list[str]:
    """'/api/users/{id}/orders' → ['/api','/api/users','/api/users/{id}','/api/users/{id}/orders']."""
    segs = [s for s in tmpl.split("/") if s]
    out, cur = [], ""
    for s in segs:
        cur = cur + "/" + s
        out.append(cur)
    return out or ["/"]


def build_api_relationship_graph(endpoints: list) -> dict:
    """endpoint 목록에서 경로 계층 관계(부모→자식) 그래프 생성. 중간 경로는 synthetic 노드로
    보강해 트리를 연결한다. Attack Graph 에서 활용 가능."""
    real: dict[str, dict] = {}
    for e in endpoints or []:
        ep = e.get("endpoint") or e.get("url") or ""
        try:
            path = urlparse(ep).path or "/"
        except Exception:
            continue
        if path.lower().startswith(("ws:", "wss:")):
            continue
        tmpl = _templatize(path)
        real.setdefault(tmpl, {"template": tmpl, "method": e.get("method_hint", "GET"),
                               "source": e.get("source", ""), "synthetic": False})
    # 중간 경로(synthetic) 노드 보강
    nodes: dict[str, dict] = {}
    for tmpl in real:
        for anc in _ancestors(tmpl):
            if anc in real:
                nodes[anc] = real[anc]
            else:
                nodes.setdefault(anc, {"template": anc, "method": "-", "source": "derived",
                                       "synthetic": True})
    for n in nodes.values():
        n["depth"] = n["template"].count("/")
    # 부모→자식 edge
    edges, seen = [], set()
    for child in nodes:
        parent = child.rsplit("/", 1)[0] or "/"
        if parent != child and parent in nodes:
            k = (parent, child)
            if k not in seen:
                seen.add(k)
                last = child.rsplit("/", 1)[-1]
                edges.append({"from": parent, "to": child,
                              "relation": "by_id" if last == "{id}" else "contains"})
    node_list = sorted(nodes.values(), key=lambda n: (n["depth"], n["template"]))
    return {"nodes": node_list, "edges": edges,
            "summary": {"api_nodes": len(node_list), "api_edges": len(edges),
                        "real_endpoints": sum(1 for n in node_list if not n["synthetic"])}}


# ══ Browser DOM Snapshot 3.5 (구조화 정보만, 전체 HTML 미저장) ══════════════════
# 페이지 구조를 구조화 정보로만 수집(전체 innerHTML 미저장). 값 미수집.
DOM_SNAPSHOT_JS = r"""
() => {
  const txt = (e) => (e && (e.innerText || e.value || e.getAttribute('aria-label') || '')).trim().slice(0, 60);
  const sel = (e) => { try { if (e.id) return '#' + e.id;
    let s = e.tagName.toLowerCase(); if (e.name) s += '[name="' + e.name + '"]'; return s; } catch (x) { return ''; } };
  const section = (e) => { let n = e; while (n) { const t = n.tagName ? n.tagName.toLowerCase() : '';
    if (['header','footer','nav','aside','main','dialog','form'].indexOf(t) >= 0) return t;
    if (n.getAttribute && (n.getAttribute('role') === 'dialog')) return 'modal'; n = n.parentElement; } return 'body'; };
  const bb = (e) => { try { const r = e.getBoundingClientRect(); return { x: Math.round(r.x), y: Math.round(r.y),
    w: Math.round(r.width), h: Math.round(r.height) }; } catch (x) { return {}; } };
  const forms = [];
  document.querySelectorAll('form').forEach(f => {
    const fields = []; f.querySelectorAll('input,textarea,select').forEach(el => {
      const t = (el.getAttribute('type') || el.tagName).toLowerCase();
      fields.push({ name: el.name || '', type: t, placeholder: el.getAttribute('placeholder') || '',
        label: txt(el.labels && el.labels[0]) || '', role: el.getAttribute('role') || '',
        selector: sel(el) }); });
    forms.push({ action: f.getAttribute('action') || '', method: (f.getAttribute('method')||'GET').toUpperCase(),
      section: section(f), fields: fields }); });
  const buttons = [];
  document.querySelectorAll('button,[role=button],input[type=submit]').forEach(b => {
    buttons.push({ text: txt(b), section: section(b), selector: sel(b), bbox: bb(b) }); });
  return { url: location.href, title: (document.title||'').slice(0,120),
    h1: [...document.querySelectorAll('h1')].slice(0,5).map(txt),
    h2: [...document.querySelectorAll('h2')].slice(0,8).map(txt),
    forms: forms, buttons: buttons };
}
"""

_SENSITIVE_HINT = _re.compile(r"(password|passwd|card|cvv|ssn|account|token|secret|otp|pin|"
                              r"비밀번호|카드|계좌|주민)", _re.I)
_STATE_HINT = _re.compile(r"(delete|remove|save|update|submit|pay|transfer|approve|create|"
                          r"삭제|저장|수정|결제|송금|승인|등록)", _re.I)
_BIZ_HINT = [(("login", "signin", "로그인"), "Login"), (("search", "검색"), "Search"),
             (("pay", "checkout", "결제"), "Payment"), (("transfer", "송금"), "Transfer"),
             (("upload", "업로드"), "File Upload"), (("admin", "관리"), "Administration"),
             (("order", "cart", "주문"), "Order")]


def element_context(el: dict) -> dict:
    """DOM 요소 → 비즈니스/보안 힌트 컨텍스트(표시·우선순위용, 판정 아님)."""
    blob = " ".join(str(el.get(k, "")) for k in
                    ("text", "label", "placeholder", "name", "role", "selector", "section")).lower()
    biz = next((n for kws, n in _BIZ_HINT if any(k in blob for k in kws)), "")
    sensitive = bool(_SENSITIVE_HINT.search(blob))
    state = bool(_STATE_HINT.search(blob))
    itype = el.get("type") or ("button" if el.get("text") else "field")
    return {"business_hint": biz, "security_hint": ("sensitive" if sensitive else "-"),
            "interaction_type": itype, "state_change_candidate": state,
            "sensitive_candidate": sensitive, "confidence": 0.5,
            "reason": f"섹션 {el.get('section','body')} · 힌트 {biz or '-'}"}


def normalize_dom_snapshot(raw: dict) -> dict:
    """DOM raw 스냅샷 → 구조화 정보(전체 HTML 미저장). 요소마다 element_context 부여."""
    r = raw or {}
    forms = []
    for f in r.get("forms") or []:
        fields = []
        for fld in f.get("fields") or []:
            fields.append({**{k: fld.get(k, "") for k in
                              ("name", "type", "placeholder", "label", "role", "selector")},
                           "context": element_context({**fld, "section": f.get("section", "")})})
        forms.append({"action": f.get("action", ""), "method": f.get("method", "GET"),
                      "section": f.get("section", "body"), "fields": fields})
    buttons = [{"text": b.get("text", ""), "section": b.get("section", "body"),
                "selector": b.get("selector", ""), "bbox": b.get("bbox", {}),
                "context": element_context(b)} for b in (r.get("buttons") or [])]
    return {"url": r.get("url", ""), "title": r.get("title", ""),
            "headings": {"h1": r.get("h1", []), "h2": r.get("h2", [])},
            "forms": forms, "buttons": buttons,
            "business_function": _dom_business_function(r)}


def _dom_business_function(raw: dict) -> str:
    hay = " ".join([str(raw.get("title", ""))] + list(raw.get("h1", []))
                   + list(raw.get("h2", []))).lower()
    return next((n for kws, n in _BIZ_HINT if any(k in hay for k in kws)), "미상")


# ══ Request ↔ DOM Correlation ════════════════════════════════════════════════
def correlate_requests_dom(requests: list, dom_snapshots: list) -> list[dict]:
    """요청 URL 을 DOM(page/form) 과 연결(same path·action 매칭)."""
    from urllib.parse import urlparse
    links = []
    forms_idx = []
    for snap in dom_snapshots or []:
        for f in snap.get("forms") or []:
            forms_idx.append((snap.get("url", ""), f))
    for r in requests or []:
        url = r.get("url", "")
        try:
            rpath = urlparse(url).path
        except Exception:
            rpath = ""
        src_page = src_form = ""
        related = []
        conf = 0.0
        for page_url, f in forms_idx:
            action = f.get("action", "")
            if action and (action in url or (rpath and action.endswith(rpath))):
                src_page, src_form = page_url, action
                related = [fl.get("name") for fl in f.get("fields", []) if fl.get("name")]
                conf = 0.7
                break
        if not src_page and dom_snapshots:
            # 같은 path 페이지에서 유발된 요청으로 추정
            for snap in dom_snapshots:
                try:
                    if urlparse(snap.get("url", "")).path == rpath:
                        src_page = snap.get("url", ""); conf = 0.4; break
                except Exception:
                    continue
        if src_page or src_form:
            links.append({"request": url, "source_page": src_page, "source_form": src_form,
                          "related_inputs": related[:10], "correlation_confidence": conf})
    return links


# ── 1-9 Replay Candidate (수행 안 함, 후보만) ───────────────────────────────
def mark_replay_candidates(requests: list) -> list[dict]:
    """안전하게 재현 가능한(조회성) 요청을 Replay 후보로 표시. Validation 이 필요 시 재사용."""
    out = []
    for r in requests or []:
        method = (r.get("method") or "GET").upper()
        replayable = method in ("GET", "HEAD") and not r.get("post_data")
        if replayable:
            out.append({"url": r.get("url"), "method": method,
                        "content_type": r.get("content_type", ""),
                        "is_api": r.get("is_api", False),
                        "note": "조회성 요청 — Validation 재사용 후보(자동 실행 안 함)"})
    return out
