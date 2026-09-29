"""
js_endpoint_extractor.py — HTML/JS 정적 텍스트에서 Endpoint / SPA Route 후보를 추출한다.

브라우저 실행 없이 결정적으로 동작(정규식 기반). 추출된 후보는 오케스트레이터가
입력점 정규화 → Attack Surface Planner 로 전달한다. 실행/검증은 하지 않는다.
"""
from __future__ import annotations

import re as _re

# ── Endpoint 후보 패턴 ────────────────────────────────────────────────────────
_PATTERNS = [
    # (regex, method_hint, reason, confidence)
    (_re.compile(r"""fetch\(\s*['"`]([^'"`]+)['"`]""", _re.I), "GET", "fetch()", 0.8),
    (_re.compile(r"""axios\.(get|post|put|delete|patch)\(\s*['"`]([^'"`]+)['"`]""", _re.I),
     None, "axios.method()", 0.85),
    (_re.compile(r"""axios\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]""", _re.I), "GET",
     "axios({url})", 0.8),
    (_re.compile(r"""\.open\(\s*['"`](GET|POST|PUT|DELETE|PATCH)['"`]\s*,\s*['"`]([^'"`]+)['"`]""",
                 _re.I), None, "XMLHttpRequest.open()", 0.85),
    (_re.compile(r"""\$\.(get|post|ajax)\(\s*['"`]([^'"`]+)['"`]""", _re.I), None,
     "jQuery ajax", 0.8),
    (_re.compile(r"""\$\.ajax\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]""", _re.I), "GET",
     "jQuery $.ajax({url})", 0.8),
    (_re.compile(r"""new\s+WebSocket\(\s*['"`]([^'"`]+)['"`]""", _re.I), "WS",
     "WebSocket()", 0.9),
    (_re.compile(r"""action\s*=\s*['"`]([^'"`]+)['"`]""", _re.I), "POST", "form action", 0.6),
    # REST/API 문자열 리터럴 경로
    (_re.compile(r"""['"`](/(?:api|v\d+|rest|graphql)/[A-Za-z0-9_\-./{}:]*)['"`]""", _re.I),
     "GET", "API path literal", 0.65),
]
_GRAPHQL_RX = _re.compile(r"""['"`](/(?:api/)?graphql)['"`]""", _re.I)


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _is_api(ep: str) -> bool:
    e = ep.lower()
    return any(s in e for s in ("/api/", "/v1/", "/v2/", "/rest/", "graphql",
                                ".json")) or e.startswith(("ws://", "wss://"))


def extract_endpoints(text: str, source_file: str = "") -> list[dict]:
    """텍스트에서 endpoint 후보 목록을 추출(중복 제거)."""
    out: dict[tuple, dict] = {}
    text = text or ""
    for rx, mhint, reason, conf in _PATTERNS:
        for m in rx.finditer(text):
            groups = [g for g in m.groups() if g]
            if not groups:
                continue
            if len(groups) == 2 and groups[0].upper() in (
                    "GET", "POST", "PUT", "DELETE", "PATCH"):
                method, ep = groups[0].upper(), groups[1]
            else:
                method, ep = (mhint or "GET"), groups[-1]
            ep = ep.strip()
            if not ep or ep.startswith(("data:", "javascript:", "mailto:", "#")):
                continue
            if len(ep) > 300:
                continue
            key = (method, ep)
            if key in out:
                continue
            out[key] = {
                "endpoint": ep,
                "method_hint": method,
                "source_file": source_file,
                "source_line": _line_of(text, m.start()),
                "confidence": conf,
                "reason": reason,
                "is_api_candidate": _is_api(ep),
                "is_websocket": ep.lower().startswith(("ws://", "wss://")) or method == "WS",
                "is_graphql": "graphql" in ep.lower(),
            }
    return list(out.values())


# ── SPA Route 패턴 ────────────────────────────────────────────────────────────
_ROUTE_PATTERNS = [
    (_re.compile(r"""<Route[^>]*\bpath\s*=\s*['"`]([^'"`]+)['"`]""", _re.I), "react-router"),
    (_re.compile(r"""\bpath\s*:\s*['"`](/[^'"`]*)['"`]""", _re.I), "route config"),
    (_re.compile(r"""\{\s*path\s*:\s*['"`]([^'"`]+)['"`]""", _re.I), "angular/vue route"),
    (_re.compile(r"""href\s*=\s*['"`](#/[^'"`]+)['"`]""", _re.I), "hash route href"),
    (_re.compile(r"""(?:pushState|replaceState)\([^,]*,[^,]*,\s*['"`]([^'"`]+)['"`]""", _re.I),
     "history API"),
]


def extract_spa_routes(text: str, source_file: str = "") -> list[dict]:
    """React/Vue/Angular 클라이언트 라우트 후보 추출."""
    out: dict[str, dict] = {}
    text = text or ""
    for rx, source in _ROUTE_PATTERNS:
        for m in rx.finditer(text):
            route = (m.group(1) or "").strip()
            if not route or route in ("/", "#") or len(route) > 200:
                continue
            if route.startswith(("http://", "https://", "mailto:", "data:")):
                continue
            if route in out:
                continue
            authed = any(k in route.lower() for k in
                         ("admin", "account", "mypage", "dashboard", "settings", "profile"))
            out[route] = {
                "route": route,
                "source": source,
                "discovered_by": "js_static",
                "source_file": source_file,
                "auth_required_guess": authed,
                "confidence": 0.6,
            }
    return list(out.values())
