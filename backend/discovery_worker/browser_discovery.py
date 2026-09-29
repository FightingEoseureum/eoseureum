"""
browser_discovery.py — Browser-based Attack Surface Discovery 2.0 오케스트레이터.

역할: 브라우저에서 실제 오가는 Request/XHR/Fetch/Form/Header/Cookie/API 를 안전하게 수집하고,
JS/네트워크 endpoint·SPA route·입력점으로 정규화하여 기존 Attack Surface Planner 로 넘긴다.

안전 원칙: 기본 비활성화(ENABLE_BROWSER_DISCOVERY=false). GET/Navigation 중심,
상태 변경 클릭/제출 금지, 민감정보 마스킹, 응답 원문 미저장. 예산 초과 시 partial result.
Playwright 는 필요 시에만 지연 import — 미설치/비활성 시에도 모듈 import 는 항상 성공.
"""
from __future__ import annotations

import hashlib
from urllib.parse import urlparse

from . import discovery_policy as policy
from . import request_recorder as rec
from . import js_endpoint_extractor as jse
from . import discovery3 as d3
from .discovery_models import (DiscoveryJob, DiscoveryResult, DiscoveryTaskStatus,
                               DiscoveryWorkerInterface)

# 입력점 소스 태그
SOURCE = "browser_discovery"
_STD_HEADERS = {"host", "user-agent", "accept", "accept-encoding", "accept-language",
                "connection", "content-length", "content-type", "referer", "origin",
                "cache-control", "pragma", "sec-fetch-mode", "sec-fetch-site",
                "sec-fetch-dest", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                "upgrade-insecure-requests", "dnt", "te"}


def _iid(*parts) -> str:
    return "bd_" + hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _looks_like_id(seg: str) -> bool:
    s = seg or ""
    if s.isdigit():
        return True
    if len(s) >= 8 and all(c in "0123456789abcdef-" for c in s.lower()):
        return True
    return False


def _path_param_points(url: str, method: str, authed: bool) -> list[dict]:
    """경로 세그먼트 중 id 처럼 보이는 값을 path parameter 후보로."""
    out = []
    try:
        segs = [s for s in urlparse(url).path.split("/") if s]
    except Exception:
        return out
    for i, seg in enumerate(segs):
        if _looks_like_id(seg):
            name = segs[i - 1] if i > 0 else "path"
            out.append({"parameter_name": name, "parameter_location": "path",
                        "sample_value": seg})
    return out


def normalize_requests_to_inputs(requests: list, base_url: str = "",
                                 authenticated: bool = False) -> list[dict]:
    """마스킹된 요청 기록 → 기존 입력점 구조로 정규화(중복 제거)."""
    seen: dict[str, dict] = {}

    def _add(endpoint, method, name, location, sample, content_type, evidence):
        iid = _iid(endpoint, method, location, name)
        if iid in seen or not name:
            return
        seen[iid] = {
            "input_id": iid,
            "source": SOURCE,
            "endpoint": endpoint,
            "url": endpoint,                       # planner 호환(url 키)
            "method": (method or "GET").upper(),
            "param": name,                          # planner 호환(param 키)
            "parameter_name": name,
            "parameter_location": location,
            "sample_value": sample,
            "content_type": content_type or "",
            "auth_state": "authenticated" if authenticated else "anonymous",
            "authenticated": bool(authenticated),
            "discovered_by": SOURCE,
            "evidence": evidence,
        }

    for r in requests or []:
        ep = r.get("url", "")
        method = r.get("method", "GET")
        ct = r.get("content_type", "")
        multipart = "multipart/form-data" in (ct or "").lower()
        is_gql = "graphql" in (ep or "").lower()
        for qp in r.get("query_parameters") or []:
            _add(ep, method, qp.get("name"), "query", qp.get("value"), ct, "browser query")
        for fd in r.get("form_data") or []:
            loc = "multipart" if multipart else "form"
            _add(ep, method, fd.get("name"), loc, fd.get("value"), ct, "browser form")
        jb = r.get("json_body")
        if isinstance(jb, dict):
            gql_vars = jb.get("variables") if is_gql else None
            if isinstance(gql_vars, dict):
                for k, v in gql_vars.items():
                    _add(ep, method, k, "graphql_variable", v, ct, "graphql variable")
            for k, v in jb.items():
                if is_gql and k in ("query", "variables", "operationName"):
                    if k == "operationName":
                        _add(ep, method, "operationName", "body_json", v, ct, "graphql op")
                    continue
                _add(ep, method, k, "body_json", v, ct, "browser json body")
        # custom 헤더 입력점(X-* 등 비표준)
        for hk, hv in (r.get("request_headers") or {}).items():
            if (hk or "").lower() not in _STD_HEADERS:
                _add(ep, method, hk, "header", hv, ct, "custom header")
        # cookie 입력점(값은 마스킹)
        if r.get("cookies"):
            _add(ep, method, "cookie", "cookie", rec.MASK, ct, "cookie surface")
        # path parameter 후보
        for pp in _path_param_points(ep, method, authenticated):
            _add(ep, method, pp["parameter_name"], "path", pp["sample_value"], ct, "path param")

    return list(seen.values())


def collect_graphql_ws(requests: list, endpoints: list) -> dict:
    """GraphQL / WebSocket 후보 수집(introspection/message capture 는 기본 미수행)."""
    graphql, websockets = {}, {}
    for r in requests or []:
        url = r.get("url", "")
        if "graphql" in url.lower():
            jb = r.get("json_body") if isinstance(r.get("json_body"), dict) else {}
            graphql.setdefault(url, {
                "endpoint": url, "method": r.get("method", "POST"),
                "operationName": jb.get("operationName"),
                "has_variables": bool(jb.get("variables")),
                "introspection": False,   # 기본 수행 안 함
                "discovered_by": SOURCE,
            })
    for e in endpoints or []:
        ep = e.get("endpoint", "")
        if e.get("is_graphql") or "graphql" in ep.lower():
            graphql.setdefault(ep, {"endpoint": ep, "method": "POST", "introspection": False,
                                    "discovered_by": "js_static"})
        if e.get("is_websocket") or ep.lower().startswith(("ws://", "wss://")):
            websockets.setdefault(ep, {
                "endpoint": ep, "protocol": "wss" if ep.lower().startswith("wss") else "ws",
                "initiator": e.get("source_file", ""),
                "message_capture": policy.websocket_message_capture_enabled(),
                "discovered_by": SOURCE,
            })
    out = {}
    if policy.graphql_enabled():
        out["graphql"] = list(graphql.values())
    if policy.websocket_enabled():
        out["websockets"] = list(websockets.values())
    return out


def assemble_result(job: DiscoveryJob, raw_requests: list, page_sources: list | None = None,
                    *, blocked_actions: list | None = None, errors: list | None = None,
                    authenticated: bool = False, pages_visited: int = 0,
                    status: str = DiscoveryTaskStatus.DONE,
                    runtime_raw: list | None = None, storage_raw: dict | None = None,
                    dom_events: list | None = None, runtime_forms_raw: list | None = None,
                    hidden_api_assets: dict | None = None,
                    dom_raw: list | None = None,
                    jwt_candidates: list | None = None) -> DiscoveryResult:
    """수집 원시데이터 → 정규화된 DiscoveryResult (순수·결정적).

    v3 추가 입력(모두 선택): runtime_raw(런타임 후킹 endpoint), storage_raw(스토리지 키),
    dom_events(이벤트 핸들러), runtime_forms_raw(동적 form), hidden_api_assets(robots/sitemap 등).
    """
    b = policy.budget()
    recorder = rec.RequestRecorder(max_requests=b["max_requests"])
    for raw in raw_requests or []:
        recorder.add(raw)
    requests = recorder.records
    base = job.base_url

    endpoints: dict[tuple, dict] = {}
    routes: dict[str, dict] = {}
    for src in page_sources or []:
        text = src.get("text", "") if isinstance(src, dict) else str(src)
        fname = src.get("url", "") if isinstance(src, dict) else ""
        for e in jse.extract_endpoints(text, fname):
            e.setdefault("source", "static_js"); e.setdefault("confidence", e.get("confidence", 0.6))
            e.setdefault("runtime", False)
            endpoints[(e["method_hint"], e["endpoint"])] = e
        for e in d3.resolve_js_concat_endpoints(text, fname):   # 1-2 변수조합 endpoint
            endpoints.setdefault((e["method_hint"], e["endpoint"]), e)
        for rt in jse.extract_spa_routes(text, fname):
            routes[rt["route"]] = rt
    # 네트워크에서 관측된 endpoint 도 후보에 추가
    for r in requests:
        key = (r["method"], r["url"])
        if key not in endpoints and r["url"]:
            endpoints[key] = {"endpoint": r["url"], "method_hint": r["method"],
                              "source_file": r.get("initiator", ""), "source_line": 0,
                              "confidence": 0.7, "reason": "observed network request",
                              "source": "observed_network",
                              "is_api_candidate": r["is_api"], "is_websocket": False,
                              "is_graphql": "graphql" in r["url"].lower(), "runtime": False}
    # 1-1 런타임 후킹 + 1-3 Hidden API endpoint 병합
    for e in d3.normalize_runtime_endpoints(runtime_raw, base):
        endpoints.setdefault((e["method_hint"], e["endpoint"]), e)
    for e in d3.discover_hidden_apis(hidden_api_assets or {}, base):
        endpoints.setdefault((e["method_hint"], e["endpoint"]), e)
    endpoint_list = list(endpoints.values())

    inputs = normalize_requests_to_inputs(requests, base, authenticated)
    # 1-5 런타임 form 입력점 + 1-4 스토리지 참고 표면(값 마스킹) 병합
    storage = d3.normalize_storage(storage_raw or {})
    inputs = inputs + d3.normalize_runtime_forms(runtime_forms_raw, base) \
        + d3.storage_input_points(storage, base)
    interaction = d3.extract_interaction_points(dom_events)      # 1-6
    api_graph = d3.build_api_relationship_graph(endpoint_list)    # 1-7
    replay = d3.mark_replay_candidates(requests)                  # 1-9
    # DOM Snapshot 3.5 — 구조화 스냅샷 + Request↔DOM 상관
    dom_snapshots = [d3.normalize_dom_snapshot(dr) for dr in (dom_raw or [])]
    request_dom_links = d3.correlate_requests_dom(requests, dom_snapshots)
    dom_forms = sum(len(s.get("forms", [])) for s in dom_snapshots)
    gql_ws = collect_graphql_ws(requests, endpoint_list)
    blocked = blocked_actions or []
    runtime_hooks = sum(1 for e in endpoint_list if e.get("runtime"))

    summary = {
        "enabled": True,
        "pages_visited": pages_visited,
        "requests": len(requests),
        "xhr_fetch": recorder.summary()["xhr_fetch"],
        "api_candidates": sum(1 for e in endpoint_list if e.get("is_api_candidate")),
        "js_endpoints": len(endpoint_list),
        "runtime_hooks": runtime_hooks,
        "hidden_apis": sum(1 for e in endpoint_list
                           if e.get("source") in ("openapi", "sitemap", "robots", "manifest",
                                                  "well_known", "graphql")),
        "new_input_points": len(inputs),
        "spa_routes": len(routes),
        "graphql_candidates": len(gql_ws.get("graphql", [])),
        "websocket_candidates": len(gql_ws.get("websockets", [])),
        "storage_keys": (len(storage.get("local_storage_keys", []))
                         + len(storage.get("session_storage_keys", []))
                         + len(storage.get("cookie_names", []))),
        "has_jwt": storage.get("has_jwt", False),
        "jwt_candidates": list(jwt_candidates or [])[:10],   # JWT 오프라인 분석용(형식 토큰만)
        "interaction_points": len(interaction),
        "api_nodes": api_graph.get("summary", {}).get("api_nodes", 0),
        "api_edges": api_graph.get("summary", {}).get("api_edges", 0),
        "replay_candidates": len(replay),
        "dom_snapshots": len(dom_snapshots),
        "dom_forms": dom_forms,
        "request_dom_links": len(request_dom_links),
        "authenticated_crawl": bool(authenticated),
        "blocked_clicks": len(blocked),
        "dropped_requests": recorder.summary()["dropped"],
        "status": status,
    }
    res = DiscoveryResult(job_id=job.job_id, status=status, summary=summary,
                          requests=requests, endpoints=endpoint_list, inputs=inputs,
                          routes=list(routes.values()), blocked_actions=blocked,
                          errors=errors or [], storage=storage,
                          interaction_points=interaction, api_graph=api_graph,
                          replay_candidates=replay, dom_snapshots=dom_snapshots,
                          request_dom_links=request_dom_links)
    res.summary["graphql"] = gql_ws.get("graphql", [])
    res.summary["websockets"] = gql_ws.get("websockets", [])
    return res


def to_injection_points(inputs: list) -> list[dict]:
    """정규화 입력점 → active_probing 이 소비하는 injection point 형식으로 변환.

    능동 점검이 실제로 주입 가능한 위치(query/body_json/form/graphql_variable/multipart)만
    (url, method) 로 묶어 params dict 로 만든다. header/cookie/path 는 기존 probe 루프가
    주입 대상으로 삼지 않으므로 여기서는 제외(보고서에는 그대로 표기됨).
    """
    from urllib.parse import urlparse, urlunparse
    groups: dict[tuple, dict] = {}
    for i in inputs or []:
        loc = i.get("parameter_location")
        if loc not in ("query", "body_json", "form", "graphql_variable", "multipart"):
            continue
        name = i.get("parameter_name") or i.get("param")
        if not name:
            continue
        ep = i.get("endpoint", "") or ""
        pu = urlparse(ep)
        clean = urlunparse((pu.scheme, pu.netloc, pu.path, "", "", ""))
        method = (i.get("method") or "GET").upper()
        m = "GET" if loc == "query" else (method if method in ("POST", "PUT", "PATCH") else "POST")
        key = (clean, m)
        g = groups.setdefault(key, {"method": m, "url": clean, "params": {},
                                    "source": "browser_discovery", "csrf_fields": []})
        if name not in g["params"]:
            sv = i.get("sample_value")
            g["params"][name] = ("test" if sv in (None, "", "***MASKED***") else str(sv)[:40])
    return [g for g in groups.values() if g["params"]]


def merge_results(results: list, job_id: str = "merged") -> DiscoveryResult:
    """여러 host 의 DiscoveryResult 를 하나로 병합(보고서 반영용)."""
    merged = DiscoveryResult(job_id=job_id, status=DiscoveryTaskStatus.DONE,
                             summary={"enabled": True})
    keys_sum = ("pages_visited", "requests", "xhr_fetch", "api_candidates", "new_input_points",
                "spa_routes", "graphql_candidates", "websocket_candidates", "blocked_clicks",
                "dropped_requests", "js_endpoints", "runtime_hooks", "hidden_apis",
                "storage_keys", "interaction_points", "api_nodes", "api_edges",
                "replay_candidates", "dom_snapshots", "dom_forms", "request_dom_links")
    for k in keys_sum:
        merged.summary[k] = 0
    authed = has_jwt = False
    merged_nodes, merged_edges = [], []
    for r in results or []:
        s = r.summary or {}
        for k in keys_sum:
            merged.summary[k] += int(s.get(k, 0) or 0)
        authed = authed or bool(s.get("authenticated_crawl"))
        has_jwt = has_jwt or bool((r.storage or {}).get("has_jwt"))
        merged.requests.extend(r.requests or [])
        merged.endpoints.extend(r.endpoints or [])
        merged.inputs.extend(r.inputs or [])
        merged.routes.extend(r.routes or [])
        merged.blocked_actions.extend(r.blocked_actions or [])
        merged.errors.extend(r.errors or [])
        merged.interaction_points.extend(r.interaction_points or [])
        merged.replay_candidates.extend(r.replay_candidates or [])
        merged.dom_snapshots.extend(r.dom_snapshots or [])
        merged.request_dom_links.extend(r.request_dom_links or [])
        merged_nodes.extend((r.api_graph or {}).get("nodes", []))
        merged_edges.extend((r.api_graph or {}).get("edges", []))
        merged.summary.setdefault("graphql", []).extend(s.get("graphql", []) or [])
        merged.summary.setdefault("websockets", []).extend(s.get("websockets", []) or [])
    merged.storage = {"has_jwt": has_jwt}
    merged.api_graph = {"nodes": merged_nodes, "edges": merged_edges,
                        "summary": {"api_nodes": len(merged_nodes), "api_edges": len(merged_edges)}}
    merged.summary["authenticated_crawl"] = authed
    merged.summary["has_jwt"] = has_jwt
    merged.summary["status"] = DiscoveryTaskStatus.DONE
    return merged


def to_planner_points(inputs: list) -> list[dict]:
    """정규화 입력점 → Attack Surface Planner 가 소비하는 point 목록(v3: 발견 메타 동반).

    Planner 는 param/url/method/authenticated 로 점수화하며, 추가 메타(discovery_source·
    confidence·interaction_type·runtime·auth_state·browser_context·storage_present·
    api_relationship)는 우선순위 판단 참고용으로 그대로 전달한다(로직 변경 없음)."""
    out = []
    for i in inputs or []:
        name = i.get("param") or i.get("parameter_name")
        if not name:
            continue
        out.append({
            "param": name, "url": i.get("endpoint", ""), "method": i.get("method", "GET"),
            "authenticated": bool(i.get("authenticated")),
            "parameter_location": i.get("parameter_location"),
            "source": SOURCE,
            # v3 Planner 전달 메타
            "discovery_source": i.get("source") or i.get("discovered_by") or SOURCE,
            "confidence": i.get("confidence"),
            "runtime": bool(i.get("runtime")),
            "auth_state": i.get("auth_state") or ("authenticated" if i.get("authenticated") else "anonymous"),
            "browser_context": True,
            "interaction_type": i.get("interaction_type"),
        })
    return out


# ── Playwright 실행 경로(지연 import, 방어적) ────────────────────────────────────
_LAUNCH_ARGS = ["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu",
                "--ignore-certificate-errors", "--disable-dev-shm-usage"]


async def _launch_chromium(pw):
    """번들 Chromium → 시스템 Chrome 채널 → executable_path 순으로 시도(견고한 실행).

    Ubuntu 신버전 등 번들 Chromium 미지원 환경에서 시스템 Google Chrome 로 폴백한다.
    env override: PLAYWRIGHT_CHROMIUM_CHANNEL, PLAYWRIGHT_CHROMIUM_EXECUTABLE.
    """
    import os as _os
    # 단일출구(egress): 활성 시 브라우저도 i7 SOCKS5 를 경유해 모든 요청이 i7 로 나가게 한다.
    _proxy = None
    try:
        import egress as _eg
        _proxy = _eg.playwright_proxy()
    except Exception:
        _proxy = None
    strategies: list[dict] = []
    ch = _os.getenv("PLAYWRIGHT_CHROMIUM_CHANNEL")
    ex = _os.getenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
    if ch:
        strategies.append({"channel": ch})
    if ex:
        strategies.append({"executable_path": ex})
    strategies.append({})                              # 번들 Chromium
    strategies.append({"channel": "chrome"})           # 시스템 Google Chrome
    for _p in ("/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
               "/usr/bin/chromium", "/usr/bin/chromium-browser"):
        if _os.path.exists(_p):
            strategies.append({"executable_path": _p})
    last = None
    for kw in strategies:
        try:
            _lk = dict(kw)
            if _proxy:
                _lk["proxy"] = _proxy
            return await pw.chromium.launch(headless=True, args=_LAUNCH_ARGS, **_lk)
        except Exception as e:
            last = e
            continue
    raise RuntimeError(f"chromium launch 실패(번들/시스템 Chrome 모두): {last}")


async def _stable_evaluate(page, js: str, base_url: str = "", retries: int = 3):
    """네비게이션으로 실행 컨텍스트가 파괴돼도 스냅샷을 강건하게 수집.
    'Execution context was destroyed' 오류 시 로드 안정화 대기 후 재시도하고,
    마지막 직전 시도에서 base_url 로 복귀해 컨텍스트를 되살린다. SAFE(읽기 전용 evaluate)."""
    last = None
    for attempt in range(retries):
        try:
            # DOM 안정화 대기(타임아웃은 무시 — best effort)
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=3000)
            except Exception:
                pass
            return await page.evaluate(js)
        except Exception as e:
            last = e
            msg = str(e)
            if "Execution context was destroyed" in msg or "navigation" in msg.lower():
                # 컨텍스트 파괴 → 잠깐 대기 후 재시도, 막판엔 base_url 로 복귀
                try:
                    await page.wait_for_timeout(400)
                except Exception:
                    pass
                if attempt == retries - 2 and base_url:
                    try:
                        await page.goto(base_url, wait_until="domcontentloaded", timeout=8000)
                    except Exception:
                        pass
                continue
            break   # 그 외 오류는 재시도 무의미
    raise last if last else RuntimeError("evaluate failed")


async def run_browser_job(job: DiscoveryJob) -> DiscoveryResult:
    """실제 브라우저로 안전 탐색(활성 시). 실패해도 예외를 던지지 않고 결과에 기록."""
    from . import auth_browser_crawler as abc
    b = policy.budget()
    raw_requests: list = []
    page_sources: list = []
    blocked: list = []
    errors: list = []
    runtime_raw: list = []
    dom_events: list = []
    runtime_forms_raw: list = []
    storage_raw: dict = {}
    hidden_api_assets: dict = {}
    dom_raw: list = []
    jwt_candidates: list = []
    authenticated = False
    pages_visited = 0
    caps = job.capabilities or {}
    try:
        from playwright.async_api import async_playwright
    except Exception as e:  # Playwright 미설치 등
        return DiscoveryResult(job_id=job.job_id, status=DiscoveryTaskStatus.FAILED,
                               summary={"enabled": True, "status": DiscoveryTaskStatus.FAILED},
                               errors=[f"playwright unavailable: {e}"])
    try:
        async with async_playwright() as pw:
            browser = await _launch_chromium(pw)
            context = await browser.new_context()
            # 1-1 런타임 후킹 스크립트를 모든 페이지 로드 前에 주입
            if caps.get("runtime_hook", True):
                try:
                    await context.add_init_script(d3.INIT_HOOK_SCRIPT)
                except Exception:
                    pass
            page = await context.new_page()

            def _on_request(req):
                try:
                    raw_requests.append({
                        "url": req.url, "method": req.method,
                        "resource_type": req.resource_type,
                        "request_headers": dict(req.headers), "post_data": req.post_data or "",
                        "frame_url": req.frame.url if req.frame else "",
                        "initiator": "", "is_navigation": req.is_navigation_request(),
                    })
                except Exception:
                    pass

            def _on_response(resp):
                try:
                    for rr in raw_requests:
                        if rr.get("url") == resp.url and "response_status" not in rr:
                            rr["response_status"] = resp.status
                            rr["response_headers"] = dict(resp.headers)
                            rr["content_type"] = resp.headers.get("content-type", "")
                            break
                except Exception:
                    pass

            page.on("request", _on_request)
            page.on("response", _on_response)

            authenticated = await abc.maybe_login(context, page, job)
            pages_visited, blocked = await abc.safe_crawl(
                page, job, budget=b, page_sources=page_sources,
                dom_raw=(dom_raw if caps.get("dom_snapshot", True) else None))

            # 1-1/1-4/1-5/1-6 런타임 후킹·스토리지·동적 form·이벤트 스냅샷 수집
            try:
                snap = await _stable_evaluate(page, d3.COLLECT_SNAPSHOT_JS, base_url=job.base_url)
                rt = snap.get("runtime") or {}
                runtime_raw = rt.get("endpoints") or []
                dom_events = rt.get("events") or []
                runtime_forms_raw = rt.get("forms") or []
                storage_raw = {"localStorage": snap.get("localStorage"),
                               "sessionStorage": snap.get("sessionStorage"),
                               "cookies": snap.get("cookies"), "hasJWT": snap.get("hasJWT")}
                jwt_candidates = snap.get("jwtTokens") or []
            except Exception as _se:
                errors.append(f"snapshot error: {_se}")

            # 1-3 Hidden API 자산 수집(robots/sitemap/manifest/.well-known)
            if caps.get("hidden_api", True):
                hidden_api_assets = await _fetch_hidden_assets(context, job.base_url)

            await browser.close()
        status = DiscoveryTaskStatus.DONE
    except Exception as e:
        errors.append(f"browser error: {e}")
        status = DiscoveryTaskStatus.FAILED

    return assemble_result(job, raw_requests, page_sources, blocked_actions=blocked,
                           errors=errors, authenticated=authenticated,
                           pages_visited=pages_visited, status=status,
                           runtime_raw=runtime_raw, storage_raw=storage_raw,
                           dom_events=dom_events, runtime_forms_raw=runtime_forms_raw,
                           hidden_api_assets=hidden_api_assets, dom_raw=dom_raw,
                           jwt_candidates=jwt_candidates)


async def _fetch_hidden_assets(context, base_url: str) -> dict:
    """robots.txt·sitemap.xml·manifest·openapi·graphql 등 정적 자산을 조회(안전 GET)."""
    from urllib.parse import urljoin
    assets: dict = {}
    targets = {
        "robots": "/robots.txt", "sitemap": "/sitemap.xml",
        "manifest": "/manifest.json", "well_known": "/.well-known/security.txt",
        "openapi": "/openapi.json", "swagger": "/swagger.json",
    }
    for name, path in targets.items():
        try:
            resp = await context.request.get(urljoin(base_url, path), timeout=8000)
            if resp.ok:
                txt = await resp.text()
                if txt and len(txt) < 200000:
                    assets[name] = txt
        except Exception:
            continue
    return assets


class LocalDiscoveryWorker(DiscoveryWorkerInterface):
    """Eoseureum Main Process 내부에서 동작하는 로컬 Worker(향후 원격 Worker 로 교체 가능)."""

    async def run_async(self, job: DiscoveryJob) -> DiscoveryResult:
        if not policy.enabled():
            return DiscoveryResult(job_id=job.job_id, status=DiscoveryTaskStatus.DONE,
                                   summary={"enabled": False, "status": "SKIPPED"})
        return await run_browser_job(job)

    def run(self, job: DiscoveryJob) -> DiscoveryResult:
        import asyncio
        return asyncio.get_event_loop().run_until_complete(self.run_async(job))
