"""고도화A ①②③ 프로브 end-to-end 회귀 테스트 — 실제 로컬 mock 서버로 탐지 로직 검증.

①  클라이언트 가드 우회(동의 필드 미강제)  ②  JS 노출 토큰 인증우회  ③  JSONP 오용
각각 '취약' mock 과 '안전' mock 을 두어 오탐 0 도 확인.
"""
import asyncio

import aiohttp
from aiohttp import web

import active_probing as ap


def _run(coro):
    return asyncio.run(coro)


async def _serve(routes):
    app = web.Application()
    for method, path, handler in routes:
        app.router.add_route(method, path, handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}"


# ── ① 클라이언트 가드 우회(동의 필드 미강제) ──────────────────────────────────────
def test_consent_bypass_confirmed_and_safe():
    async def t():
        async def submit_vuln(request):   # agree 유무 무관하게 수락(미강제) = 취약
            return web.Response(text="접수 완료 감사합니다")

        async def submit_safe(request):   # agree 없으면 거부 = 안전
            data = await request.post()
            if not data.get("agree"):
                return web.Response(text="오류: 필수 동의 항목이 누락되었습니다")
            return web.Response(text="접수 완료")

        runner, base = await _serve([("POST", "/vuln", submit_vuln),
                                     ("POST", "/safe", submit_safe)])
        try:
            conn = aiohttp.TCPConnector()
            async with aiohttp.ClientSession(connector=conn) as s:
                pts_vuln = [{"method": "POST", "url": base + "/vuln",
                             "params": {"agree": "on", "msg": "hi"}, "source": "form"}]
                res_v = await ap._probe_clientside_guard_bypass(s, base, pts_vuln, scan_id="t")
                pts_safe = [{"method": "POST", "url": base + "/safe",
                             "params": {"agree": "on", "msg": "hi"}, "source": "form"}]
                res_s = await ap._probe_clientside_guard_bypass(s, base, pts_safe, scan_id="t")
        finally:
            await runner.cleanup()
        assert res_v and res_v["confirmed"] and res_v["type"] == "consent_bypass"
        assert res_s is None   # 안전 서버는 미확증(오탐 0)
    _run(t())


# ── ② JS 노출 토큰 → 인증 우회 ────────────────────────────────────────────────────
def test_js_token_auth_bypass():
    async def t():
        async def home(request):
            return web.Response(text='<script src="/app.js"></script>', content_type="text/html")

        async def appjs(request):
            return web.Response(text='var auto_login="TOKxYz123456abc"; url="/member/auto_login";',
                                content_type="application/javascript")

        async def auto_login(request):
            # 토큰이 오면 세션 쿠키 발급(=인증 획득) → 취약
            if request.query.get("auto_login") or request.query.get("token"):
                r = web.Response(text="ok")
                r.set_cookie("SESSIONID", "issued-abc")
                return r
            return web.Response(text="no token")

        runner, base = await _serve([("GET", "/", home), ("GET", "/app.js", appjs),
                                     ("GET", "/member/auto_login", auto_login)])
        try:
            conn = aiohttp.TCPConnector()
            async with aiohttp.ClientSession(connector=conn) as s:
                res = await ap._probe_js_auth_token(s, base, scan_id="t")
        finally:
            await runner.cleanup()
        assert res and res["confirmed"] and res["type"] == "js_token_auth_bypass"
    _run(t())


# ── ③ JSONP 오용 ─────────────────────────────────────────────────────────────────
def test_jsonp_misuse_confirmed():
    async def t():
        async def home(request):
            return web.Response(
                text='<script>$.ajax({url:"/api/me", dataType:"jsonp", callback:"cb"});</script>',
                content_type="text/html")

        async def api_me(request):
            cb = request.query.get("callback") or request.query.get("cb") or "cb"
            # 콜백으로 감싼 민감데이터 반환 = JSONP 오용
            return web.Response(text=f'{cb}({{"email":"a@b.com","session":"xx"}})',
                                content_type="application/javascript")

        runner, base = await _serve([("GET", "/", home), ("GET", "/api/me", api_me)])
        try:
            conn = aiohttp.TCPConnector()
            async with aiohttp.ClientSession(connector=conn) as s:
                res = await ap._probe_jsonp_misuse(s, base, points=[], scan_id="t")
        finally:
            await runner.cleanup()
        assert res and res["confirmed"] and res["type"] == "jsonp_misuse"
        assert res["has_sensitive"] is True   # email/session 감지
    _run(t())


# ── ④ URL 내 민감 토큰 노출(CWE-598) ─────────────────────────────────────────────
def test_token_in_url_leak():
    disc = ["http://t.example/page?access_token=AbC123xyz789&x=1",
            "http://t.example/ok?id=5"]
    res = _run(ap._probe_sensitive_token_in_url(None, "http://t.example", points=[],
                                                discovered_urls=disc))
    assert res and res["confirmed"] and res["type"] == "token_in_url"
    assert res["param"] == "access_token"


def test_token_in_url_no_false_positive():
    disc = ["http://t.example/ok?id=5&page=2&sort=name"]
    res = _run(ap._probe_sensitive_token_in_url(None, "http://t.example", points=[],
                                                discovered_urls=disc))
    assert res is None


# ── ⑤ 미인증 특권 콘텐츠 ──────────────────────────────────────────────────────────
def test_unauth_privileged_content():
    async def t():
        async def manage_status(request):   # 세션 없이 관리 콘텐츠 렌더 = 취약
            data = await request.post()
            v = data.get("old_domain", "x")
            return web.Response(text=f"<table><td>네임서버 관리</td><td>{v}</td></table>",
                                content_type="text/html")

        async def safe_admin(request):       # 로그인 유도 = 안전
            return web.Response(text="<form><input type=password name=pw>로그인이 필요합니다</form>",
                                content_type="text/html")

        runner, base = await _serve([("POST", "/manage/nameserver/status", manage_status),
                                     ("GET", "/admin/panel", safe_admin)])
        try:
            conn = aiohttp.TCPConnector()
            async with aiohttp.ClientSession(connector=conn) as s:
                pts = [{"method": "POST", "url": base + "/manage/nameserver/status",
                        "params": {"old_domain": "test.com"}, "source": "form"}]
                res = await ap._probe_unauth_privileged_content(s, base, pts,
                          discovered_urls=[base + "/admin/panel"], scan_id="t")
        finally:
            await runner.cleanup()
        assert res and res["confirmed"] and res["type"] == "unauth_privileged_content"
    _run(t())


# ── JSON 바디 주입(모던 API) ─────────────────────────────────────────────────────
def test_json_injection_sqli_and_safe():
    async def t():
        async def vuln_login(request):   # 홑따옴표 홀수(구문깨짐)면 DB 에러, 짝수/무주입은 정상(실제 SQLi 거동)
            try: body = await request.json()
            except Exception: body = {}
            if str(body.get("email", "")).count("'") % 2 == 1:
                return web.Response(status=500, text="SQLITE_ERROR: unrecognized token near \"'\"")
            return web.Response(text='{"ok":true}', content_type="application/json")
        async def safe_api(request):
            return web.Response(text='{"ok":true}', content_type="application/json")
        runner, base = await _serve([("POST", "/rest/user/login", vuln_login),
                                     ("POST", "/api/safe", safe_api)])
        try:
            conn = aiohttp.TCPConnector()
            async with aiohttp.ClientSession(connector=conn) as s:
                pv = [{"method": "GET", "url": base + "/rest/user/login", "params": {}, "source": "js_endpoint"}]
                rv = await ap._probe_json_injection(s, base, pv, scan_id="t")
                ps = [{"method": "GET", "url": base + "/api/safe", "params": {}, "source": "js_endpoint"}]
                rs = await ap._probe_json_injection(s, base, ps, scan_id="t")
        finally:
            await runner.cleanup()
        assert rv and rv["confirmed"] and rv["type"].startswith("json_sqli")
        assert rs is None
    _run(t())


# ── 입력점 우선순위: 주입 유망 포인트가 앞으로(프로브 points[:12] 안에 들어오는지) ─────────
def test_extract_points_prioritizes_injectable():
    async def t():
        # app.js 에 일반 GET 표면 20개 + 실파라미터 search 엔드포인트 1개(맨 끝) 마이닝
        bulk = "".join(f'fetch("/api/Thing{i}");\n' for i in range(20))
        appjs = bulk + 'this.http.get(`${h}/rest/products/search?q=${e}`);\n'
        async def home(request):
            return web.Response(text='<html><script src="/app.js"></script></html>',
                                content_type="text/html")
        async def js(request):
            return web.Response(text=appjs, content_type="application/javascript")
        runner, base = await _serve([("GET", "/", home), ("GET", "/app.js", js)])
        try:
            conn = aiohttp.TCPConnector()
            async with aiohttp.ClientSession(connector=conn) as s:
                pts = await ap._extract_injection_points(s, base)
        finally:
            await runner.cleanup()
        # search(실파라미터 q)는 마이닝 순서상 맨 끝이지만, 우선순위 정렬로 앞쪽(<12)에 와야
        # SQLi 프로브(points[:12])가 실제로 테스트한다.
        idx = next((i for i, p in enumerate(pts)
                    if p.get("url", "").endswith("/rest/products/search")), 999)
        assert idx < 12, f"search 포인트가 {idx}번째 — 프로브 슬라이스 밖"
    _run(t())


# ── GraphQL 쿼리 인자 SQLi(introspection 표적) ────────────────────────────────────
import json as _json

_GQL_INTRO_RESP = _json.dumps({"data": {"__schema": {
    "queryType": {"name": "Query"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "user",
             "type": {"kind": "OBJECT", "name": "User", "ofType": None},
             "args": [{"name": "id", "type": {"kind": "SCALAR", "name": "String", "ofType": None}}]},
            {"name": "ping",
             "type": {"kind": "SCALAR", "name": "String", "ofType": None},
             "args": []},
        ]},
        {"name": "User", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID", "ofType": None}, "args": []}]},
    ],
}}})


def _gql_app(vulnerable: bool):
    async def handler(request):
        payload = await request.json()
        q = payload.get("query", "")
        if "__schema" in q:
            return web.Response(text=_GQL_INTRO_RESP, content_type="application/json")
        # user(id: "...") 리졸버 시뮬레이션
        import re as _re
        mm = _re.search(r'id:\s*"((?:[^"\\]|\\.)*)"', q)
        val = (mm.group(1) if mm else "").replace('\\"', '"')
        if vulnerable and val.count("'") % 2 == 1:   # 홀수 홑따옴표 → 구문파괴 → DB 에러
            return web.Response(
                text=_json.dumps({"errors": [{"message":
                    "sqlite3.OperationalError: near \"'\": syntax error"}]}),
                content_type="application/json")
        return web.Response(text=_json.dumps({"data": {"user": {"id": "1"}}}),
                            content_type="application/json")
    return handler


def test_graphql_injection_confirmed_and_safe():
    async def t():
        runner, base = await _serve([("POST", "/graphql", _gql_app(vulnerable=True))])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                rv = await ap._probe_graphql_injection(s, base, [], scan_id="t")
        finally:
            await runner.cleanup()
        assert rv and rv["confirmed"] and rv["type"] == "graphql_sqli"
        assert rv["param"] == "user.id"

        runner2, base2 = await _serve([("POST", "/graphql", _gql_app(vulnerable=False))])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                rs = await ap._probe_graphql_injection(s, base2, [], scan_id="t")
        finally:
            await runner2.cleanup()
        assert rs is None
    _run(t())


def test_gql_injectable_fields_skips_nonstring_required():
    intro = _json.dumps({"data": {"__schema": {
        "queryType": {"name": "Query"},
        "types": [{"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "search", "type": {"kind": "SCALAR", "name": "String"},
             "args": [{"name": "q", "type": {"kind": "SCALAR", "name": "String"}}]},
            {"name": "count", "type": {"kind": "SCALAR", "name": "Int"},
             "args": [{"name": "n", "type": {"kind": "NON_NULL", "name": None,
                       "ofType": {"kind": "SCALAR", "name": "Int"}}}]},
        ]}],
    }}})
    fields = ap._gql_injectable_fields(intro)
    names = {f["field"] for f in fields}
    assert "search" in names           # String 인자 → 주입 대상
    assert "count" not in names        # 필수 Int 인자 → 스킵


# ── webpack 런타임 청크맵 → 청크 fetch → 엔드포인트 마이닝(구형 빌드 갭) ───────────────
def test_webpack_chunk_mining_end_to_end():
    """청크가 HTML 에 없고 런타임 __webpack_require__.u 로만 로드되는 구형 빌드에서,
    런타임 청크맵으로 청크 URL 재구성→fetch→그 안의 API 엔드포인트가 입력점으로 발견되는지."""
    async def t():
        async def home(request):
            return web.Response(
                text='<html><head><script src="/runtime.js"></script>'
                     '<script src="/main.js"></script></head></html>',
                content_type="text/html")
        async def runtime(request):
            return web.Response(
                text='var t={};t.p="/";t.u=function(e){return e+"."+{5:"deadbeef"}[e]+".chunk.js"};',
                content_type="application/javascript")
        async def main_js(request):
            return web.Response(text='console.log("app");', content_type="application/javascript")
        async def chunk5(request):
            # 이 청크(HTML 미참조)에만 존재하는 API 엔드포인트
            return web.Response(text='this.http.get("/rest/secret/report?id=1");',
                                content_type="application/javascript")
        routes = [("GET", "/", home), ("GET", "/runtime.js", runtime),
                  ("GET", "/main.js", main_js), ("GET", "/5.deadbeef.chunk.js", chunk5)]
        runner, base = await _serve(routes)
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                pts = await ap._extract_injection_points(s, base)
        finally:
            await runner.cleanup()
        # 청크 안에만 있던 /rest/secret/report 가 재구성·fetch·마이닝되어 입력점으로 등장해야
        assert any(p.get("url", "").endswith("/rest/secret/report") for p in pts), \
            "webpack 청크 재구성으로 발견된 엔드포인트 없음"
    _run(t())


# ── GraphQL 배칭/별칭 증폭(리소스 제한 부재) ──────────────────────────────────────
def _gql_dos_app(allow_batch: bool, allow_alias: bool):
    async def handler(request):
        payload = await request.json()
        # 배칭: 본문이 배열이면
        if isinstance(payload, list):
            if not allow_batch:
                return web.Response(status=400,
                    text=_json.dumps({"errors": [{"message": "Batching is not allowed"}]}),
                    content_type="application/json")
            return web.Response(
                text=_json.dumps([{"data": {"__typename": "Query"}} for _ in payload]),
                content_type="application/json")
        q = payload.get("query", "")
        import re as _re
        aliases = _re.findall(r'(a\d+)\s*:\s*__typename', q)
        if aliases:
            if not allow_alias and len(aliases) > 5:
                return web.Response(status=400,
                    text=_json.dumps({"errors": [{"message": "Query complexity limit exceeded"}]}),
                    content_type="application/json")
            data = {a: "Query" for a in aliases}
            return web.Response(text=_json.dumps({"data": data}), content_type="application/json")
        return web.Response(text=_json.dumps({"data": {"__typename": "Query"}}),
                            content_type="application/json")
    return handler


def test_graphql_dos_batching_and_alias():
    async def t():
        # 배칭·별칭 모두 허용 → 확정
        runner, base = await _serve([("POST", "/graphql", _gql_dos_app(True, True))])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                r = await ap._probe_graphql_dos(s, base, [], scan_id="t")
        finally:
            await runner.cleanup()
        assert r and r["confirmed"] and r["type"] == "graphql_dos"
        assert "배치" in r["evidence"] and "별칭" in r["evidence"]

        # 배칭만 허용 → 확정(배치 벡터만)
        runner2, base2 = await _serve([("POST", "/graphql", _gql_dos_app(True, False))])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                r2 = await ap._probe_graphql_dos(s, base2, [], scan_id="t")
        finally:
            await runner2.cleanup()
        assert r2 and r2["confirmed"] and "배치" in r2["evidence"] and "별칭" not in r2["evidence"]

        # 둘 다 제한 → 미검출
        runner3, base3 = await _serve([("POST", "/graphql", _gql_dos_app(False, False))])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                r3 = await ap._probe_graphql_dos(s, base3, [], scan_id="t")
        finally:
            await runner3.cleanup()
        assert r3 is None
    _run(t())


# ── GraphQL 필드 제안 누출(Did you mean) ─────────────────────────────────────────
def _gql_suggest_app(suggestions_on: bool):
    import re as _re
    async def handler(request):
        payload = await request.json()
        q = payload.get("query", "") if isinstance(payload, dict) else ""
        if _re.search(r'__typenam(?!e)', q):   # 오타 필드(뒤에 e 없음)만
            if suggestions_on:
                return web.Response(text=_json.dumps({"errors": [{"message":
                    'Cannot query field "__typenam" on type "Query". Did you mean "__typename"?'}]}),
                    content_type="application/json")
            return web.Response(text=_json.dumps({"errors": [{"message":
                'Cannot query field "__typenam" on type "Query".'}]}),
                content_type="application/json")
        return web.Response(text=_json.dumps({"data": {"__typename": "Query"}}),
                            content_type="application/json")
    return handler


def test_graphql_field_suggestion_leak():
    async def t():
        runner, base = await _serve([("POST", "/graphql", _gql_suggest_app(True))])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                r = await ap._probe_graphql_field_suggestion(s, base, [], scan_id="t")
        finally:
            await runner.cleanup()
        assert r and r["confirmed"] and r["type"] == "graphql_field_suggestion"
        assert "__typename" in r["evidence"]

        runner2, base2 = await _serve([("POST", "/graphql", _gql_suggest_app(False))])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                r2 = await ap._probe_graphql_field_suggestion(s, base2, [], scan_id="t")
        finally:
            await runner2.cleanup()
        assert r2 is None
    _run(t())


# ── GraphQL 지시자 오버로딩(directive overloading) ────────────────────────────────
def _gql_directive_app(has_limit: bool):
    async def handler(request):
        payload = await request.json()
        q = payload.get("query", "") if isinstance(payload, dict) else ""
        n = q.count("@eoseureum")
        if n >= 2:
            if has_limit and n > 50:   # 지시자 개수 제한 있음
                return web.Response(text=_json.dumps({"errors": [{"message":
                    "Query exceeds maximum directive limit"}]}), content_type="application/json")
            # 제한 없음: 미존재 지시자로 검증 에러(하지만 전부 파싱됨)
            return web.Response(text=_json.dumps({"errors": [{"message":
                'Unknown directive "@eoseureum".'}]}), content_type="application/json")
        return web.Response(text=_json.dumps({"data": {"__typename": "Query"}}),
                            content_type="application/json")
    return handler


def test_graphql_directive_overload():
    async def t():
        # 제한 없음 → 확정
        runner, base = await _serve([("POST", "/graphql", _gql_directive_app(has_limit=False))])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                r = await ap._probe_graphql_directive_overload(s, base, [], scan_id="t")
        finally:
            await runner.cleanup()
        assert r and r["confirmed"] and r["type"] == "graphql_directive_overload"

        # 제한 있음 → 미검출
        runner2, base2 = await _serve([("POST", "/graphql", _gql_directive_app(has_limit=True))])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                r2 = await ap._probe_graphql_directive_overload(s, base2, [], scan_id="t")
        finally:
            await runner2.cleanup()
        assert r2 is None
    _run(t())


# ── Service Worker / WASM 공격표면 발견(end-to-end) ──────────────────────────────
def test_sw_wasm_discovery_end_to_end():
    """PWA: HTML 에 안 보이는 엔드포인트가 (a)service worker precache, (b)WASM 데이터섹션에
    있을 때, _extract_injection_points 가 SW·WASM 을 수집·마이닝해 입력점으로 발견하는지."""
    async def t():
        async def home(request):
            return web.Response(
                text='<html><head><script>'
                     'navigator.serviceWorker.register("/sw.js");'
                     'WebAssembly.instantiateStreaming(fetch("/app.wasm"));'
                     '</script></head></html>',
                content_type="text/html")
        async def sw(request):
            # precache 매니페스트에만 있는 API 라우트
            return web.Response(
                text='precacheAndRoute([{url:"/rest/pwa-secret",revision:"1"}]);'
                     'self.addEventListener("fetch",e=>fetch("/api/sw-route"));',
                content_type="application/javascript")
        async def wasm(request):
            # WASM 데이터섹션에 박힌 API 경로(널 구분 클린 런)
            body = b"\x00asm\x01\x00\x00\x00" + b"\x00/rest/wasm-endpoint\x00" + b"\xff\x00filler"
            return web.Response(body=body, content_type="application/wasm")
        runner, base = await _serve([("GET", "/", home), ("GET", "/sw.js", sw),
                                     ("GET", "/app.wasm", wasm)])
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as s:
                pts = await ap._extract_injection_points(s, base)
        finally:
            await runner.cleanup()
        urls = [p.get("url", "") for p in pts]
        assert any(u.endswith("/rest/pwa-secret") for u in urls), "SW precache 엔드포인트 미발견"
        assert any(u.endswith("/api/sw-route") for u in urls), "SW fetch 라우트 미발견"
        assert any(u.endswith("/rest/wasm-endpoint") for u in urls), "WASM 임베드 엔드포인트 미발견"
    _run(t())


# ── JWT alg:none 위조·수락 능동 실증 ──────────────────────────────────────────────
import base64 as _b64, hmac as _hmac, hashlib as _hashlib

def _b64u(b):
    return _b64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _make_hs256(payload: dict, secret: bytes = b"secret") -> str:
    h = _b64u(_json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    p = _b64u(_json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64u(_hmac.new(secret, f"{h}.{p}".encode(), _hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"

def _jwt_verify(tok: str, accept_none: bool) -> bool:
    parts = tok.split(".")
    if len(parts) < 2:
        return False
    try:
        hdr = _json.loads(_b64.urlsafe_b64decode(parts[0] + "=="))
    except Exception:
        return False
    alg = str(hdr.get("alg", "")).lower()
    if alg == "none":
        return accept_none                       # 취약 서버만 수락
    if alg == "hs256" and len(parts) == 3:
        expect = _b64u(_hmac.new(b"secret", f"{parts[0]}.{parts[1]}".encode(), _hashlib.sha256).digest())
        return _hmac.compare_digest(expect, parts[2])
    return False

def _jwt_app(accept_none: bool):
    async def handler(request):
        tok = request.cookies.get("auth", "")
        if tok and _jwt_verify(tok, accept_none):
            return web.Response(text="AUTHENTICATED: welcome admin — 여기는 보호된 대시보드 데이터입니다 " * 3)
        return web.Response(status=401, text="Unauthorized")
    return handler

def _run_jwt(accept_none):
    async def t():
        runner, base = await _serve([("GET", "/", _jwt_app(accept_none)),
                                     ("GET", "/dash", _jwt_app(accept_none))])
        valid = _make_hs256({"sub": "admin", "role": "user"})
        cookies = [{"raw": f"auth={valid}", "name": "auth", "value": valid}]
        try:
            res = await ap._probe_jwt_alg_none_forgery(base, cookies, points=[], scan_id="t")
        finally:
            await runner.cleanup()
        return res
    return _run(t())

def test_jwt_alg_none_forgery_confirmed_and_safe():
    vuln = _run_jwt(accept_none=True)
    assert vuln and vuln["confirmed"] and vuln["type"] == "jwt_alg_none"
    safe = _run_jwt(accept_none=False)
    assert safe is None


# ── JWT alg confusion(RS256→HS256, JWKS 공개키 오용) ─────────────────────────────
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives import serialization as _ser, hashes as _hashes
from cryptography.hazmat.primitives.asymmetric import padding as _padding

def _rs256_make(payload: dict, priv):
    h = _b64u(_json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    p = _b64u(_json.dumps(payload, separators=(",", ":")).encode())
    sig = priv.sign(f"{h}.{p}".encode(), _padding.PKCS1v15(), _hashes.SHA256())
    return f"{h}.{p}.{_b64u(sig)}"

def _jwks_from_pub(pub):
    nums = pub.public_numbers()
    def i2b(x):
        return _b64u(x.to_bytes((x.bit_length() + 7) // 8, "big"))
    return {"keys": [{"kty": "RSA", "use": "sig", "kid": "k1",
                      "n": i2b(nums.n), "e": i2b(nums.e), "alg": "RS256"}]}

def _confusion_app(vulnerable: bool, priv, pub):
    # 취약 서버: 헤더 alg 를 신뢰 → HS256 이면 '공개키 PEM'을 시크릿으로 HMAC 검증(오용)
    pub_pem = pub.public_bytes(_ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo)
    async def jwks(request):
        return web.Response(text=_json.dumps(_jwks_from_pub(pub)), content_type="application/json")
    async def handler(request):
        tok = request.cookies.get("auth", "")
        parts = tok.split(".")
        ok = False
        if len(parts) == 3:
            try:
                hdr = _json.loads(_b64.urlsafe_b64decode(parts[0] + "=="))
                alg = str(hdr.get("alg", "")).upper()
                signing = f"{parts[0]}.{parts[1]}".encode()
                sigb = _b64.urlsafe_b64decode(parts[2] + "==")
                if alg == "RS256":
                    pub.verify(sigb, signing, _padding.PKCS1v15(), _hashes.SHA256()); ok = True
                elif alg == "HS256" and vulnerable:
                    # 순진한 라이브러리: 공개키 PEM 을 HMAC 시크릿으로 사용(취약)
                    exp = _hmac.new(pub_pem, signing, _hashlib.sha256).digest()
                    ok = _hmac.compare_digest(exp, sigb)
            except Exception:
                ok = False
        if ok:
            return web.Response(text="AUTHENTICATED: 관리자 대시보드 보호 데이터입니다 " * 4)
        return web.Response(status=401, text="Unauthorized")
    return handler, jwks

def _run_confusion(vulnerable):
    async def t():
        priv = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        handler, jwks = _confusion_app(vulnerable, priv, pub)
        runner, base = await _serve([("GET", "/", handler), ("GET", "/dash", handler),
                                     ("GET", "/.well-known/jwks.json", jwks)])
        valid = _rs256_make({"sub": "admin", "role": "user"}, priv)
        cookies = [{"raw": f"auth={valid}", "name": "auth", "value": valid}]
        try:
            async with aiohttp.ClientSession() as s:
                res = await ap._probe_jwt_alg_confusion(s, base, cookies, points=[], scan_id="t")
        finally:
            await runner.cleanup()
        return res
    return _run(t())

def test_jwt_alg_confusion_confirmed_and_safe():
    vuln = _run_confusion(vulnerable=True)
    assert vuln and vuln["confirmed"] and vuln["type"] == "jwt_alg_confusion"
    safe = _run_confusion(vulnerable=False)
    assert safe is None


# ── 세션 고정(로그인 전후 세션 ID 회전) ─────────────────────────────────────────────
import types as _types

def _sessfix_app(rotate: bool):
    async def login_get(request):
        r = web.Response(
            text='<form method="post" action="/login">'
                 '<input name="username"><input name="password"></form>',
            content_type="text/html")
        r.set_cookie("SESSIONID", "anon-fixed-abc123")   # 익명 세션 발급
        return r
    async def login_post(request):
        data = await request.post()
        if not (data.get("username") and data.get("password")):
            return web.Response(status=200, text="login failed")
        r = web.Response(status=302, headers={"Location": "/dashboard"}, text="")
        if rotate:
            r.set_cookie("SESSIONID", "rotated-new-xyz789")   # 로그인 시 세션 회전(안전)
        # 취약: 회전 안 함(Set-Cookie 없음) → 익명 세션 그대로 인증됨
        return r
    return login_get, login_post

def _run_sessfix(rotate):
    async def t():
        lg, lp = _sessfix_app(rotate)
        runner, base = await _serve([("GET", "/login", lg), ("POST", "/login", lp)])
        cfg = _types.SimpleNamespace(
            enable_auth_scan=True, auth_login_url=base + "/login",
            auth_username="victim", auth_password="pw",
            auth_username_field="auto", auth_password_field="auto",
            auth_success_pattern="auto", request_timeout=8.0)
        try:
            import authenticated_scan as _as
            res = await _as.detect_session_fixation(cfg, base)
        finally:
            await runner.cleanup()
        return res
    return _run(t())

def test_session_fixation_confirmed_and_safe():
    vuln = _run_sessfix(rotate=False)      # 미회전 → 세션 고정
    assert vuln and vuln["confirmed"] and "SESSIONID" in vuln["cookie_names"]
    safe = _run_sessfix(rotate=True)       # 회전 → 안전
    assert safe is None


# ── 세션 만료/로그아웃 무효화(CWE-613) ─────────────────────────────────────────────
def _logout_app(invalidate_server_side: bool):
    valid = set()          # 서버측 유효 세션 저장소
    counter = {"n": 0}
    def authed(request):
        sid = request.cookies.get("SESSIONID", "")
        return bool(sid) and sid in valid
    async def login_get(request):
        return web.Response(
            text='<form method="post" action="/login">'
                 '<input name="username"><input name="password"></form>',
            content_type="text/html")
    async def login_post(request):
        data = await request.post()
        if not (data.get("username") and data.get("password")):
            return web.Response(text="login failed")
        counter["n"] += 1
        sid = f"sess-{counter['n']}-abc"
        valid.add(sid)
        r = web.Response(status=302, headers={"Location": "/dashboard"}, text="")
        r.set_cookie("SESSIONID", sid)
        return r
    async def home(request):
        if authed(request):
            return web.Response(text='인증됨 — 관리 대시보드 <a href="/logout">로그아웃</a> ' * 4,
                                content_type="text/html")
        return web.Response(text="로그인이 필요합니다", content_type="text/html")
    async def logout(request):
        sid = request.cookies.get("SESSIONID", "")
        if invalidate_server_side:
            valid.discard(sid)                  # 서버측 파기(안전)
        # 취약: 클라이언트 쿠키만 클리어, 서버측 유지
        r = web.Response(status=302, headers={"Location": "/login"}, text="")
        r.set_cookie("SESSIONID", "", max_age=0)
        return r
    return [("GET", "/login", login_get), ("POST", "/login", login_post),
            ("GET", "/", home), ("GET", "/dashboard", home), ("GET", "/logout", logout)]

def _run_logout(invalidate):
    async def t():
        runner, base = await _serve(_logout_app(invalidate))
        cfg = _types.SimpleNamespace(
            enable_auth_scan=True, auth_login_url=base + "/login",
            auth_username="u", auth_password="p",
            auth_username_field="auto", auth_password_field="auto",
            auth_success_pattern="auto", request_timeout=8.0)
        try:
            import authenticated_scan as _as
            res = await _as.detect_logout_invalidation(cfg, base)
        finally:
            await runner.cleanup()
        return res
    return _run(t())

def test_logout_invalidation_confirmed_and_safe():
    vuln = _run_logout(invalidate=False)    # 서버측 미무효화 → 옛 토큰 유효
    assert vuln and vuln["confirmed"] and "SESSIONID" in vuln["cookie_names"]
    safe = _run_logout(invalidate=True)     # 서버측 파기 → 옛 토큰 거부
    assert safe is None


# ── 세션 절대 타임아웃(과도한 수명/만료 부재) ───────────────────────────────────────
def _timeout_app(cookie_setter):
    async def login_get(request):
        return web.Response(
            text='<form method="post" action="/login">'
                 '<input name="username"><input name="password"></form>',
            content_type="text/html")
    async def login_post(request):
        data = await request.post()
        if not (data.get("username") and data.get("password")):
            return web.Response(text="login failed")
        r = web.Response(status=302, headers={"Location": "/dashboard"}, text="")
        cookie_setter(r)
        return r
    return [("GET", "/login", login_get), ("POST", "/login", login_post)]

def _run_timeout(cookie_setter):
    async def t():
        runner, base = await _serve(_timeout_app(cookie_setter))
        cfg = _types.SimpleNamespace(
            enable_auth_scan=True, auth_login_url=base + "/login",
            auth_username="u", auth_password="p",
            auth_username_field="auto", auth_password_field="auto",
            auth_success_pattern="auto", request_timeout=8.0)
        try:
            import authenticated_scan as _as
            res = await _as.detect_session_timeout_weakness(cfg, base)
        finally:
            await runner.cleanup()
        return res
    return _run(t())

def test_session_timeout_weaknesses_and_safe():
    # (a) JWT 만료(exp) 없음 → 확정
    jwt_no_exp = f"{_b64u(_json.dumps({'alg':'HS256','typ':'JWT'}).encode())}.{_b64u(_json.dumps({'sub':'admin'}).encode())}.sig"
    r1 = _run_timeout(lambda resp: resp.set_cookie("token", jwt_no_exp))
    assert r1 and r1["confirmed"] and r1["kind"] == "jwt_no_exp"

    # (b) 과도한 쿠키 절대 수명(90일 > 30일 임계) → 확정
    r2 = _run_timeout(lambda resp: resp.set_cookie("SESSIONID", "abc123", max_age=90 * 86400))
    assert r2 and r2["confirmed"] and r2["kind"] == "cookie_excessive"

    # (c) 안전: 세션 쿠키(비영속) + JWT 짧은 만료
    import time as _t
    jwt_ok = f"{_b64u(_json.dumps({'alg':'HS256','typ':'JWT'}).encode())}.{_b64u(_json.dumps({'sub':'u','iat':int(_t.time()),'exp':int(_t.time())+1800}).encode())}.sig"
    r3 = _run_timeout(lambda resp: resp.set_cookie("SESSIONID", jwt_ok))   # max-age 없음(세션 쿠키)
    assert r3 is None


# ── 유휴 세션 타임아웃(대기 후 세션 유효) ─────────────────────────────────────────
def _idle_app(expire_after_idle: bool):
    valid = {"v": True}
    def authed(request):
        sid = request.cookies.get("SESSIONID", "")
        return bool(sid) and valid["v"]
    async def login_get(request):
        return web.Response(text='<form method="post" action="/login"><input name="username"><input name="password"></form>', content_type="text/html")
    async def login_post(request):
        data = await request.post()
        if not (data.get("username") and data.get("password")):
            return web.Response(text="login failed")
        valid["v"] = True
        r = web.Response(status=302, headers={"Location": "/dashboard"}, text="")
        r.set_cookie("SESSIONID", "sess-idle-1")
        return r
    _reqs = {"n": 0}
    async def home(request):
        # 유휴 만료 시뮬: 인증 성공 후 첫 재검증(대기 후) 요청에서 만료시킴
        if authed(request):
            _reqs["n"] += 1
            if expire_after_idle and _reqs["n"] >= 2:   # 로그인 확인(1) 다음 재검증(2)에서 만료
                valid["v"] = False
                return web.Response(status=401, text="Unauthorized")
            return web.Response(text="인증됨 — 대시보드 보호 데이터 " * 4)
        return web.Response(status=401, text="Unauthorized")
    return [("GET", "/login", login_get), ("POST", "/login", login_post), ("GET", "/", home), ("GET", "/dashboard", home)]

def _run_idle(expire):
    async def t():
        runner, base = await _serve(_idle_app(expire))
        cfg = _types.SimpleNamespace(enable_auth_scan=True, auth_login_url=base + "/login",
            auth_username="u", auth_password="p", auth_username_field="auto", auth_password_field="auto",
            auth_success_pattern="auto", request_timeout=8.0)
        import os
        os.environ["SESSION_IDLE_WAIT_SEC"] = "1"   # 1초 유휴 대기(테스트)
        try:
            import authenticated_scan as _as
            return await _as.detect_idle_session_timeout(cfg, base)
        finally:
            os.environ.pop("SESSION_IDLE_WAIT_SEC", None)
            await runner.cleanup()
    return _run(t())

def test_session_idle_timeout_confirmed_and_safe():
    weak = _run_idle(expire=False)     # 유휴 후에도 유효 → 확정
    assert weak and weak["confirmed"] and weak["wait_sec"] == 1 and "SESSIONID" in weak["cookie_names"]
    safe = _run_idle(expire=True)      # 유휴 후 만료 → 미검출
    assert safe is None


# ── gRPC-web 서비스 발견/확증 ──────────────────────────────────────────────────
def test_grpc_web_discovery_confirmed_and_safe():
    async def t():
        # 취약(발견): JS 에 grpc-web 신호 + /api.UserService/GetUser 경로, POST 시 grpc-status 응답
        async def home_vuln(request):
            return web.Response(
                content_type="text/html",
                text=('<html><body><script>'
                      'const c = new GrpcWebClientBase();'
                      'const P = "/api.UserService/GetUser";'
                      'c.rpcCall(P, req, {}, methodInfo, cb);'
                      '</script></body></html>'))

        async def grpc_ep(request):
            # 실제 gRPC-web 서버처럼 grpc-status 헤더 + application/grpc-web content-type
            return web.Response(
                body=b"\x80\x00\x00\x00\x10",
                headers={"Content-Type": "application/grpc-web+proto",
                         "grpc-status": "12", "grpc-message": "unknown method"})

        async def home_safe(request):
            return web.Response(content_type="text/html",
                                text="<html><body><h1>일반 페이지</h1></body></html>")

        rv, base_v = await _serve([("GET", "/", home_vuln),
                                   ("POST", "/api.UserService/GetUser", grpc_ep)])
        rs, base_s = await _serve([("GET", "/", home_safe)])
        try:
            async with aiohttp.ClientSession() as s:
                vuln = await ap._probe_grpc_web(s, base_v)
                safe = await ap._probe_grpc_web(s, base_s)
        finally:
            await rv.cleanup()
            await rs.cleanup()
        return vuln, safe

    vuln, safe = _run(t())
    assert vuln and vuln["confirmed"] and vuln["type"] == "grpc_web_service"
    assert "/api.UserService/GetUser" in vuln["url"]
    assert safe is None


# ── h2c(평문 HTTP/2) 업그레이드 감지 ─────────────────────────────────────────────
def test_h2c_upgrade_confirmed_and_safe():
    async def t():
        async def handle(reader, writer, *, accept):
            try:
                await asyncio.wait_for(reader.read(1024), timeout=3)
            except Exception:
                pass
            if accept:
                resp = (b"HTTP/1.1 101 Switching Protocols\r\n"
                        b"Connection: Upgrade\r\nUpgrade: h2c\r\n\r\n")
            else:
                resp = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            writer.write(resp)
            try:
                await writer.drain()
                writer.close()
            except Exception:
                pass

        srv_v = await asyncio.start_server(
            lambda r, w: handle(r, w, accept=True), "127.0.0.1", 0)
        srv_s = await asyncio.start_server(
            lambda r, w: handle(r, w, accept=False), "127.0.0.1", 0)
        pv = srv_v.sockets[0].getsockname()[1]
        ps = srv_s.sockets[0].getsockname()[1]
        try:
            vuln = await ap._probe_h2c(f"http://127.0.0.1:{pv}")
            safe = await ap._probe_h2c(f"http://127.0.0.1:{ps}")
        finally:
            srv_v.close()
            srv_s.close()
        return vuln, safe

    vuln, safe = _run(t())
    assert vuln and vuln["confirmed"] and vuln["type"] == "h2c_smuggling"
    assert safe is None
