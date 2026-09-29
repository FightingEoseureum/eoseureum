"""test_browser_discovery.py — Browser-based Attack Surface Discovery 2.0 (결정적·mock 기반).

실제 Playwright 브라우저 테스트는 optional marker(browser)로 분리하고, 기본 테스트는
mock request/response/page 소스 기반으로 결정적으로 수행한다.
"""
import os, sys, io, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import discovery_worker as dw
from discovery_worker import request_recorder as rr
from discovery_worker import js_endpoint_extractor as jse
from discovery_worker import discovery_policy as policy
from discovery_worker import auth_browser_crawler as abc
from discovery_worker.discovery_models import (DiscoveryJob, DiscoveryResult,
                                               DiscoveryTaskStatus)


# ── 1. Request Recorder 마스킹 ────────────────────────────────────────────────
def test_request_recorder_masking():
    raw = {
        "url": "https://a.example.com/api/login?token=abc123&q=hello",
        "method": "POST", "resource_type": "xhr",
        "request_headers": {"Authorization": "Bearer x.y.z", "Cookie": "sid=secret",
                            "X-Tenant": "acme", "Content-Type": "application/json"},
        "response_status": 200, "response_headers": {"content-type": "application/json"},
        "post_data": json.dumps({"username": "u", "password": "p@ss", "note": "hi"}),
        "content_type": "application/json",
    }
    r = rr.build_record(raw)
    assert r["request_headers"]["Authorization"] == rr.MASK
    assert r["request_headers"]["Cookie"] == rr.MASK
    assert r["request_headers"]["X-Tenant"] == "acme"     # 비민감 헤더 보존
    # query token 마스킹, q 보존
    qp = {p["name"]: p["value"] for p in r["query_parameters"]}
    assert qp["token"] == rr.MASK and qp["q"] == "hello"
    # json body password 마스킹, note 보존
    assert r["json_body"]["password"] == rr.MASK and r["json_body"]["note"] == "hi"
    assert r["is_xhr"] is True


def test_recorder_no_response_body_stored():
    raw = {"url": "https://a.example.com/x", "method": "GET", "resource_type": "document",
           "response_length": 4096}
    r = rr.build_record(raw)
    assert "response_body" not in r and "body" not in r
    assert r["response_length"] == 4096   # 길이만 저장


# ── 2. JS Endpoint Extractor ──────────────────────────────────────────────────
def test_js_endpoint_extraction():
    js = """
      fetch('/api/users');
      axios.post('/api/orders', data);
      var x = new XMLHttpRequest(); x.open('GET','/api/v2/items');
      $.ajax({url:'/rest/data'});
      new WebSocket('wss://a.example.com/ws');
      const q = '/api/graphql';
      <form action="/submit-form">
    """
    eps = jse.extract_endpoints(js, "app.js")
    found = {(e["endpoint"], e["method_hint"]) for e in eps}
    assert ("/api/users", "GET") in found
    assert ("/api/orders", "POST") in found
    assert ("/api/v2/items", "GET") in found
    assert any(e["is_websocket"] for e in eps)
    assert any(e["is_graphql"] for e in eps)
    assert all(e["source_file"] == "app.js" for e in eps)
    assert any(e["is_api_candidate"] for e in eps)


def test_spa_route_extraction():
    js = """
      <Route path="/admin/panel" />
      { path: '/dashboard' }
      routes = [{ path: 'settings' }]
      <a href="#/profile/edit">
      history.pushState(null, '', '/reports/2024')
    """
    routes = {r["route"] for r in jse.extract_spa_routes(js, "router.js")}
    assert "/admin/panel" in routes
    assert "/dashboard" in routes
    assert "#/profile/edit" in routes
    # auth_required_guess
    admin = [r for r in jse.extract_spa_routes(js) if r["route"] == "/admin/panel"][0]
    assert admin["auth_required_guess"] is True


# ── 3. Safe Click Exploration ─────────────────────────────────────────────────
def test_safe_click_blocking():
    els = [
        {"text": "홈", "href": "/home", "element_type": "a"},
        {"text": "삭제", "href": "/x", "element_type": "button"},
        {"text": "Logout", "href": "/logout", "element_type": "a"},
        {"text": "결제하기", "href": "/pay", "element_type": "button"},
        {"text": "제품 보기", "href": "/products", "element_type": "a"},
        {"text": "Save", "href": "#", "element_type": "button[type=submit]"},
    ]
    plan = abc.plan_safe_clicks(els)
    safe_texts = {e["text"] for e in plan["safe"]}
    blocked_texts = {b["element"] for b in plan["blocked"]}
    assert "홈" in safe_texts and "제품 보기" in safe_texts
    assert "삭제" in blocked_texts and "Logout" in blocked_texts
    assert "결제하기" in blocked_texts and "Save" in blocked_texts


def test_policy_is_safe_click_state_methods():
    assert policy.is_safe_navigation("GET") is True
    assert policy.is_safe_navigation("POST") is False
    assert policy.is_safe_click(text="회원 탈퇴")["safe"] is False


# ── 4. Discovery Policy Budget ────────────────────────────────────────────────
def test_recorder_budget_limit():
    recorder = rr.RequestRecorder(max_requests=2)
    for i in range(5):
        recorder.add({"url": f"https://a.example.com/{i}", "method": "GET",
                      "resource_type": "xhr"})
    assert len(recorder.records) == 2
    assert recorder.summary()["dropped"] == 3


def test_default_flags_disabled(monkeypatch):
    for k in ("ENABLE_BROWSER_DISCOVERY", "ENABLE_AUTH_BROWSER_CRAWL"):
        monkeypatch.delenv(k, raising=False)
    assert policy.enabled() is False
    assert policy.auth_crawl_enabled() is False
    # graphql/websocket 후보 수집은 기본 ON, message capture 는 기본 OFF
    assert policy.graphql_enabled() is True
    assert policy.websocket_message_capture_enabled() is False


# ── 5. GraphQL / WebSocket 후보 수집 ──────────────────────────────────────────
def test_graphql_websocket_candidates():
    reqs = [rr.build_record({"url": "https://a.example.com/graphql", "method": "POST",
                             "resource_type": "fetch", "content_type": "application/json",
                             "post_data": json.dumps({"operationName": "Me", "query": "{me}"})})]
    eps = [{"endpoint": "wss://a.example.com/live", "is_websocket": True, "method_hint": "WS"}]
    out = dw.collect_graphql_ws(reqs, eps)
    assert any(g["endpoint"].endswith("/graphql") for g in out["graphql"])
    assert out["graphql"][0]["introspection"] is False   # introspection 기본 미수행
    assert any(w["endpoint"].endswith("/live") for w in out["websockets"])


# ── 6. Request → Input Point Normalization ────────────────────────────────────
def test_request_to_input_point_normalization():
    reqs = [
        rr.build_record({"url": "https://a.example.com/api/users?role=admin", "method": "GET",
                         "resource_type": "xhr", "request_headers": {"X-Api-Key": "k"}}),
        rr.build_record({"url": "https://a.example.com/api/orders/1029/items", "method": "GET",
                         "resource_type": "xhr", "request_headers": {}}),
        rr.build_record({"url": "https://a.example.com/graphql", "method": "POST",
                         "resource_type": "fetch", "content_type": "application/json",
                         "post_data": json.dumps({"query": "{}", "variables": {"id": 5}})}),
    ]
    inputs = dw.normalize_requests_to_inputs(reqs, "https://a.example.com")
    locs = {i["parameter_location"] for i in inputs}
    assert "query" in locs and "path" in locs and "graphql_variable" in locs and "header" in locs
    assert all(i["source"] == "browser_discovery" for i in inputs)
    # planner point 변환
    pts = dw.to_planner_points(inputs)
    assert pts and all("param" in p and "url" in p for p in pts)


def test_browser_points_feed_attack_surface_planner():
    import attack_surface_planner as asp
    reqs = [rr.build_record({"url": "https://a.example.com/api/account?userId=1",
                             "method": "GET", "resource_type": "xhr", "request_headers": {}})]
    pts = dw.to_planner_points(dw.normalize_requests_to_inputs(reqs))
    plan = asp.plan_attack_surface(pts)
    assert plan["analyzed"]
    # userId 는 Object Reference 로 분류되어야 함(IDOR 표면)
    assert any(a["attack_surface_type"] == "Object Reference" for a in plan["analyzed"])


# ── 7. assemble_result 통합(결정적) ──────────────────────────────────────────
def test_assemble_result_masks_and_summarizes():
    job = DiscoveryJob(job_id="j", base_url="https://a.example.com", scope=["example.com"])
    raw = [{"url": "https://a.example.com/api/x?token=abc", "method": "GET",
            "resource_type": "xhr", "request_headers": {"Cookie": "sid=z"},
            "response_status": 200}]
    pages = [{"url": "https://a.example.com/app.js", "text": "fetch('/api/hidden')"}]
    blocked = [{"element": "삭제", "reason": "상태 변경 키워드"}]
    res = dw.assemble_result(job, raw, pages, blocked_actions=blocked, authenticated=True,
                             pages_visited=3)
    assert res.summary["requests"] == 1 and res.summary["authenticated_crawl"] is True
    assert res.summary["blocked_clicks"] == 1 and res.summary["pages_visited"] == 3
    # token 마스킹 확인 & cookie surface 존재
    assert any(i["parameter_location"] == "cookie" for i in res.inputs)
    assert any(i["sample_value"] == rr.MASK for i in res.inputs
               if i["parameter_name"] == "token")


# ── 8. ENABLE_BROWSER_DISCOVERY=false 회귀 + apply_to_analysis ────────────────
def test_disabled_regression_and_apply(monkeypatch):
    monkeypatch.delenv("ENABLE_BROWSER_DISCOVERY", raising=False)
    assert dw.enabled() is False
    # apply_to_analysis 는 결과 키를 기록하고 planner points 반환
    job = DiscoveryJob(job_id="j", base_url="https://a.example.com")
    res = dw.assemble_result(job, [{"url": "https://a.example.com/api/x?q=1", "method": "GET",
                                    "resource_type": "xhr", "request_headers": {}}], [])
    analysis = {}
    pts = dw.apply_to_analysis(analysis, res)
    assert "browser_discovery_summary" in analysis
    assert "browser_discovery_inputs" in analysis
    assert isinstance(pts, list)


# ── 9. Worker CLI JSON 입출력 ─────────────────────────────────────────────────
def test_worker_cli_json_io(monkeypatch):
    monkeypatch.delenv("ENABLE_BROWSER_DISCOVERY", raising=False)  # 기본 비활성 → SKIPPED
    from discovery_worker import run_job
    with tempfile.TemporaryDirectory() as td:
        jf = os.path.join(td, "job.json")
        of = os.path.join(td, "out.json")
        with open(jf, "w", encoding="utf-8") as f:
            json.dump({"job_id": "cli", "base_url": "https://a.example.com",
                       "scope": ["example.com"]}, f)
        rc = run_job.main(["--job-file", jf, "--out", of])
        assert rc == 0
        out = json.load(open(of, encoding="utf-8"))
        assert out["job_id"] == "cli"
        assert out["status"] in DiscoveryTaskStatus.ALL
        assert out["summary"]["enabled"] is False   # 비활성 → SKIPPED


# ── 10. 모델 JSON round-trip ─────────────────────────────────────────────────
def test_models_roundtrip():
    job = DiscoveryJob(job_id="j", base_url="u", scope=["a"], auth={"username": "x"})
    assert DiscoveryJob.from_dict(job.to_dict()).base_url == "u"
    res = DiscoveryResult(job_id="j", summary={"requests": 2})
    assert DiscoveryResult.from_dict(res.to_dict()).summary["requests"] == 2


# ── 10b. Request → active_probing injection point 변환 ───────────────────────
def test_to_injection_points_conversion():
    reqs = [
        rr.build_record({"url": "https://a.example.com/api/users?role=admin&q=x",
                         "method": "GET", "resource_type": "xhr", "request_headers": {}}),
        rr.build_record({"url": "https://a.example.com/api/orders", "method": "POST",
                         "resource_type": "fetch", "content_type": "application/json",
                         "post_data": json.dumps({"item": 1, "qty": 2})}),
        # header/cookie/path 위치는 능동 점검 대상에서 제외되어야 함
        rr.build_record({"url": "https://a.example.com/api/o/55", "method": "GET",
                         "resource_type": "xhr", "request_headers": {"X-Api-Key": "k",
                                                                     "Cookie": "s=1"}}),
    ]
    inputs = dw.normalize_requests_to_inputs(reqs, "https://a.example.com")
    ipts = dw.to_injection_points(inputs)
    # query 지점은 GET, body_json 지점은 POST
    get_pt = [p for p in ipts if p["method"] == "GET" and p["url"].endswith("/api/users")]
    post_pt = [p for p in ipts if p["method"] == "POST" and p["url"].endswith("/api/orders")]
    assert get_pt and set(get_pt[0]["params"]) >= {"role", "q"}
    assert post_pt and set(post_pt[0]["params"]) >= {"item", "qty"}
    # 모든 injection point 는 active_probing 형식(url/method/params/source) 준수
    for p in ipts:
        assert {"url", "method", "params", "source"} <= set(p)
        assert p["source"] == "browser_discovery"
    # header/cookie/path 위치는 injection point 로 만들지 않음(url 기반 param 만)
    assert not any("55" in str(p["params"]) for p in ipts)


def test_active_probing_registry_merge():
    import active_probing as ap
    ap.clear_browser_injection_points("scanX")
    pts = [{"method": "GET", "url": "https://a.example.com/api/x", "params": {"role": "admin"},
            "source": "browser_discovery", "csrf_fields": []}]
    ap.register_browser_injection_points("scanX", "a.example.com", pts)
    got = ap._get_browser_injection_points("scanX", "a.example.com")
    assert got and got[0]["params"] == {"role": "admin"}
    # 다른 host/scan 은 격리
    assert ap._get_browser_injection_points("scanX", "other.com") == []
    ap.clear_browser_injection_points("scanX")
    assert ap._get_browser_injection_points("scanX", "a.example.com") == []


def test_merge_results_accumulates():
    j = DiscoveryJob(job_id="j", base_url="https://a.example.com")
    r1 = dw.assemble_result(j, [{"url": "https://a.example.com/api/x?a=1", "method": "GET",
                                 "resource_type": "xhr", "request_headers": {}}], [], pages_visited=2)
    r2 = dw.assemble_result(j, [{"url": "https://b.example.com/api/y?b=2", "method": "GET",
                                 "resource_type": "xhr", "request_headers": {}}], [], pages_visited=3)
    m = dw.merge_results([r1, r2], job_id="scan1")
    assert m.summary["pages_visited"] == 5
    assert m.summary["requests"] == 2
    assert len(m.inputs) == len(r1.inputs) + len(r2.inputs)


# ══ Discovery 3.0 ═══════════════════════════════════════════════════════════
from discovery_worker import discovery3 as d3


def test_v3_runtime_endpoint_normalization():
    raw = [{"url": "/api/runtime/me", "source": "runtime_fetch", "method": "GET"},
           {"url": "/dashboard", "source": "runtime_pushState", "method": "GET"},
           {"url": "wss://a.example.com/live", "source": "runtime_ws", "method": "WS"},
           {"url": "javascript:void(0)", "source": "runtime_fetch"}]  # 무시돼야 함
    out = d3.normalize_runtime_endpoints(raw, "https://a.example.com")
    eps = {e["endpoint"] for e in out}
    assert "https://a.example.com/api/runtime/me" in eps
    assert any(e["is_websocket"] for e in out)
    assert all(e["runtime"] and e["confidence"] > 0 and e["source"] for e in out)
    assert not any("javascript:" in e["endpoint"] for e in out)


def test_v3_js_concat_dataflow():
    js = 'const api="/api"; fetch(api+"/user/"+id); axios.get(api+"/orders")'
    out = d3.resolve_js_concat_endpoints(js, "app.js")
    eps = {e["endpoint"] for e in out}
    assert "/api/user/" in eps and "/api/orders" in eps
    assert all(e["source"] == "js_concat" for e in out)


def test_v3_hidden_api_discovery():
    assets = {"robots": "Allow: /api/admin\nSitemap: https://a.example.com/sitemap.xml",
              "sitemap": "<urlset><url><loc>https://a.example.com/api/report</loc></url></urlset>",
              "openapi": '{"paths":{"/api/v2/pay":{},"/api/v2/users":{}}}',
              "graphql": "x"}
    out = d3.discover_hidden_apis(assets, "https://a.example.com")
    srcs = {e["source"] for e in out}
    assert "openapi" in srcs and "sitemap" in srcs and "robots" in srcs and "graphql" in srcs
    assert any("/api/v2/pay" in e["endpoint"] for e in out)


def test_v3_storage_masked_no_values():
    raw = {"localStorage": ["token", "theme"], "sessionStorage": ["cart"],
           "cookies": ["sid"], "hasJWT": True}
    st = d3.normalize_storage(raw)
    assert st["local_storage_keys"] == ["token", "theme"]     # 키만
    assert st["has_jwt"] is True
    # storage 입력점은 값이 항상 마스킹
    pts = d3.storage_input_points(st)
    assert pts and all(p["sample_value"] == rr.MASK for p in pts)
    assert {p["parameter_location"] for p in pts} <= {"localStorage", "sessionStorage", "cookie"}


def test_v3_api_relationship_graph():
    eps = [{"endpoint": "https://x/api/users", "method_hint": "GET"},
           {"endpoint": "https://x/api/users/42", "method_hint": "GET"},
           {"endpoint": "https://x/api/users/42/orders", "method_hint": "GET"}]
    g = d3.build_api_relationship_graph(eps)
    assert g["summary"]["api_edges"] >= 3
    tos = {e["to"] for e in g["edges"]}
    assert "/api/users/{id}" in tos and "/api/users/{id}/orders" in tos
    assert any(e["relation"] == "by_id" for e in g["edges"])


def test_v3_replay_candidates_get_only():
    reqs = [rr.build_record({"url": "https://x/api/a", "method": "GET", "resource_type": "xhr",
                             "request_headers": {}}),
            rr.build_record({"url": "https://x/api/b", "method": "POST", "resource_type": "fetch",
                             "request_headers": {}, "post_data": "x=1"})]
    rep = d3.mark_replay_candidates(reqs)
    assert len(rep) == 1 and rep[0]["method"] == "GET"   # POST 는 replay 후보 제외


def test_v3_interaction_points_no_autoclick():
    ev = [{"tag": "button", "text": "메뉴", "handlers": ["onclick"]}]
    ip = d3.extract_interaction_points(ev)
    assert ip and ip[0]["interaction_type"] == "onclick"
    assert "자동 클릭" in ip[0]["note"]


def test_v3_assemble_and_planner_meta():
    job = DiscoveryJob(job_id="j", base_url="https://a.example.com", scope=["example.com"])
    raw = [{"url": "https://a.example.com/api/x?q=1", "method": "GET", "resource_type": "xhr",
            "request_headers": {}}]
    res = dw.assemble_result(job, raw,
                             [{"url": "https://a.example.com/app.js", "text": "fetch('/api/hidden')"}],
                             runtime_raw=[{"url": "/api/rt", "source": "runtime_fetch", "method": "GET"}],
                             storage_raw={"localStorage": ["jwt"], "hasJWT": True},
                             dom_events=[{"tag": "a", "text": "x", "handlers": ["onclick"]}],
                             hidden_api_assets={"openapi": '{"paths":{"/api/v2/z":{}}}'})
    s = res.summary
    assert s["runtime_hooks"] >= 1 and s["hidden_apis"] >= 1
    assert s["storage_keys"] >= 1 and s["has_jwt"] is True
    assert s["api_nodes"] >= 1 and s["interaction_points"] >= 1
    # Planner 전달 메타 존재(로직 변경 아님, 참고 메타)
    pts = dw.to_planner_points(res.inputs)
    assert pts and "discovery_source" in pts[0] and "browser_context" in pts[0]


def test_v3_models_roundtrip_new_fields():
    r = DiscoveryResult(job_id="j", storage={"has_jwt": True}, api_graph={"nodes": [1]},
                        interaction_points=[{"x": 1}], replay_candidates=[{"y": 2}])
    r2 = DiscoveryResult.from_dict(r.to_dict())
    assert r2.storage["has_jwt"] is True and r2.api_graph["nodes"] == [1]
    job = DiscoveryJob(job_id="j", base_url="u")
    assert DiscoveryJob.from_dict(job.to_dict()).capabilities.get("runtime_hook") is True


# ── 11. Report Summary 렌더링(본문 + 부록) ───────────────────────────────────
def test_report_browser_discovery_render(monkeypatch):
    monkeypatch.setenv("REPORT_SHOW_ENGINE_INTERNAL", "true")   # 엔진내부 섹션(브라우저 발견)은 옵션
    import report
    from docx import Document
    from docx.text.paragraph import Paragraph
    from docx.table import Table
    from tests.test_report_v4_ux import _rich
    a = _rich()
    job = DiscoveryJob(job_id="j", base_url="https://t.example.com", scope=["example.com"])
    raw = [{"url": "https://t.example.com/api/users?role=admin", "method": "GET",
            "resource_type": "xhr", "request_headers": {"Cookie": "sid=z"}, "response_status": 200}]
    res = dw.assemble_result(job, raw, [{"url": "https://t.example.com/a.js",
                                         "text": "fetch('/api/hidden')"}],
                             blocked_actions=[{"element": "삭제", "reason": "상태 변경"}],
                             pages_visited=2)
    dw.apply_to_analysis(a, res)
    buf = report.generate_report({"domain": "t.example.com", "analysis": a,
                                  "created_at": "2026-07-01", "results": []})
    doc = Document(io.BytesIO(buf.getvalue()))
    parts = []

    def walk(c, p):
        for ch in p:
            if ch.tag.endswith("}p"):
                parts.append(Paragraph(ch, c).text)
            elif ch.tag.endswith("}tbl"):
                for r in Table(ch, c).rows:
                    for cc in r.cells:
                        parts.append(cc.text)
    walk(doc, doc.element.body)
    txt = "\n".join(parts)
    assert "Browser Discovery Summary" in txt
    assert "Browser Discovery 상세" in txt          # Developer Appendix
    assert "차단된 위험 클릭" in txt
