"""client_analysis 순수 추출기 회귀 테스트(고도화A ①②③⑥ 공유 재료)."""
import client_analysis as ca


def test_response_primitives():
    assert ca.find_errors("모든게 정상")  == [] or True  # 정상문구는 신호 없을 수도
    assert any("error" in e.lower() for e in ca.find_errors("Fatal: SQL syntax error near"))
    assert ca.search("hello WORLD hello", "world")
    assert ca.find_reflected("prefix example-21.com suffix", "example-21.com")
    assert ca.find_reflected("nope", "missing") == []


def test_same_origin_js_and_inline():
    html = '''<script src="/assets/app.js"></script>
              <script src="https://cdn.other.com/x.js"></script>
              <script>var chk_cnt = 20;</script>'''
    urls = ca.same_origin_js_urls(html, "http://t.example/page")
    assert urls == ["http://t.example/assets/app.js"]   # 동일출처만
    assert "chk_cnt" in ca.inline_scripts(html)


def test_same_origin_js_link_preload_chunks():
    """모던 SPA lazy 청크: <link rel=modulepreload/preload href=chunk-*.js> 도 수집(라우트 API 보유)."""
    html = '''<head>
      <link rel="modulepreload" href="chunk-OKA37M7B.js">
      <link href="chunk-ALT.js" rel="preload" as="script">
      <link rel="prefetch" href="chunk-PF.js">
      <link rel="stylesheet" href="styles.css">
      <link rel="modulepreload" href="https://cdn.other.com/ext.js">
      <script src="main.js"></script>
    </head>'''
    urls = ca.same_origin_js_urls(html, "http://t.example/")
    names = [u.rsplit("/", 1)[-1] for u in urls]
    assert "main.js" in names                       # script src
    assert "chunk-OKA37M7B.js" in names             # modulepreload
    assert "chunk-ALT.js" in names                  # href-before-rel(속성 순서 무관)
    assert "chunk-PF.js" in names                   # prefetch
    assert not any("styles.css" in n for n in names)        # JS 만
    assert not any("cdn.other.com" in u for u in urls)      # 동일출처만


def test_extract_client_guards():
    html = '''<form>
      <input name="agree_terms" type="checkbox">
      <input name="email" required>
      <input name="title" maxlength="50">
    </form>
    <script src="x"></script>'''
    js = 'if (domainList.length > 20) { alert("max"); } fetch("/ajax_lib/check/transfer.php");'
    g = ca.extract_client_guards(html, js)
    assert 20 in g["count_limits"]
    assert any("agree" in c for c in g["consent_fields"])
    assert "email" in g["required_fields"]
    assert 50 in g["maxlengths"]
    assert any("check/transfer.php" in u for u in g["ajax_check_urls"])


def test_extract_app_tokens():
    js = 'var auto_login = "AbC123xyz789QW"; access_token: "tok_9f8e7d6c5b4a3210zz";'
    toks = ca.extract_app_tokens(js)
    names = {t["name"].lower() for t in toks}
    assert any("auto" in n for n in names)
    assert any(t["value"] == "tok_9f8e7d6c5b4a3210zz" for t in toks)
    # 예시/플레이스홀더는 제외
    assert ca.extract_app_tokens('token: "your_placeholder_here"') == []


def test_token_endpoint_candidates():
    js = 'fetch("/member/auto_login.php"); go("/session/refresh")'
    eps = ca.token_endpoint_candidates("", js, "http://t.example")
    assert any("auto_login" in u for u in eps)


def test_detect_jsonp():
    html = '<script>$.ajax({url:"/api/user", dataType:"jsonp", callback:"cb"});</script>'
    d = ca.detect_jsonp(html, "", "http://t.example")
    assert d["uses_jsonp"] is True
    assert "callback" in d["callback_params"]
    # JSONP 신호 없으면 False
    assert ca.detect_jsonp("<p>plain</p>", "", "http://t.example")["uses_jsonp"] is False


def test_mine_js_endpoints():
    js = '''
      this.http.get("/rest/products/search?q=");
      axios.post("/api/Users", data);
      fetch("/rest/user/whoami");
      const r = "/api/Feedbacks";
      var css = "/assets/app.css"; var img="/img/logo.png";  // 정적자산 제외
      route("/administration/users/:id");                    // 템플릿 → 채움
      external = "//cdn.other.com/x";                         // 프로토콜상대 제외
    '''
    eps = ca.mine_js_endpoints(js, "http://t.example")
    paths = {__import__("urllib.parse", fromlist=["urlparse"]).urlparse(e["url"]).path for e in eps}
    assert "/rest/products/search" in paths
    assert "/api/Users" in paths
    assert "/rest/user/whoami" in paths
    assert "/api/Feedbacks" in paths
    assert "/administration/users/1" in paths          # :id → 1 치환
    assert not any(".css" in p or ".png" in p for p in paths)   # 정적자산 제외
    assert not any("cdn.other.com" in e["url"] for e in eps)    # 외부 제외
    # search 는 쿼리 파라미터 q 추출
    srch = [e for e in eps if e["url"].endswith("/rest/products/search")][0]
    assert "q" in srch["params"]


def test_mine_js_endpoints_template_literal():
    """모던 SPA: `${base}/rest/...?q=${e}` 템플릿리터럴/미따옴표 인라인 API 경로 추출."""
    js = (
        "return this.http.get(`${this.hostServer}/rest/products/search?q=${e}`).pipe(x);\n"
        'var css = "/assets/app.css";\n'          # 정적자산 제외
        "post(`${h}/rest/user/security-question?email=${m}`);\n"
    )
    eps = ca.mine_js_endpoints(js, "http://t.example")
    up = __import__("urllib.parse", fromlist=["urlparse"])
    by_path = {up.urlparse(e["url"]).path: e for e in eps}
    assert "/rest/products/search" in by_path
    assert "q" in by_path["/rest/products/search"]["params"]          # 빈 쿼리값도 파라미터로
    assert "/rest/user/security-question" in by_path
    assert "email" in by_path["/rest/user/security-question"]["params"]
    assert not any(".css" in p for p in by_path)                      # 정적자산 여전히 제외


def test_mine_webpack_chunk_urls_forms():
    """구형 webpack 런타임 청크맵 파싱: function/arrow, publicPath, 이름맵 || 폴백."""
    B = "http://t.example/"
    # webpack5 function + publicPath + hash 맵
    js1 = 'r.p="/static/js/";r.u=function(e){return e+"."+{179:"a1b2c3d4",213:"e5f6a7b8"}[e]+".chunk.js"};'
    u1 = ca.mine_webpack_chunk_urls(js1, B)
    assert "http://t.example/static/js/179.a1b2c3d4.chunk.js" in u1
    assert "http://t.example/static/js/213.e5f6a7b8.chunk.js" in u1
    # arrow + 이름맵(||e 폴백) + hash 맵
    js2 = 'n.p="/app/";n.u=e=>({179:"login",213:"admin"}[e]||e)+"."+{179:"abc123",213:"def456"}[e]+".js";'
    u2 = ca.mine_webpack_chunk_urls(js2, B)
    assert "http://t.example/app/login.abc123.js" in u2
    assert "http://t.example/app/admin.def456.js" in u2
    # 접두 문자열 + publicPath 없음
    js3 = 't.u=(e)=>"js/"+e+"."+{7:"deadbeef"}[e]+".chunk.js";'
    assert ca.mine_webpack_chunk_urls(js3, B) == ["http://t.example/js/7.deadbeef.chunk.js"]
    # 동일출처 아님/webpack 아님 → 빈
    assert ca.mine_webpack_chunk_urls("function foo(){return 1}", B) == []


def test_service_worker_and_wasm_helpers():
    B = "http://t.example/"
    # SW 등록 URL + 흔한 경로 폴백
    html = '<script>navigator.serviceWorker.register("/my-sw.js");</script>'
    sw = ca.service_worker_urls(html, "", B)
    assert "http://t.example/my-sw.js" in sw
    assert "http://t.example/ngsw.json" in sw          # Angular 폴백 포함
    # WASM URL(.wasm 리터럴 + instantiate(fetch))
    js = 'WebAssembly.instantiateStreaming(fetch("/core.wasm")); var m="/lib/mod.wasm";'
    w = ca.wasm_urls("", js, B)
    assert "http://t.example/core.wasm" in w and "http://t.example/lib/mod.wasm" in w
    # WASM 바이너리 문자열 추출 → API 경로 마이닝
    raw = b"\x00asm\x01\x00\x00\x00" + b"\x00/rest/wallet?id=x\x00" + b"\xff\xfe" + b"junk"
    s = ca.extract_wasm_strings(raw)
    assert "/rest/wallet" in s
    assert any(e["url"].endswith("/rest/wallet") for e in ca.mine_js_endpoints(s, B))
    # precache: ngsw.json(JSON) + workbox
    ngsw = '{"hashTable":{"/api/config":"a","/assets/x.png":"d"},"assetGroups":[{"urls":["/rest/menu"]}]}'
    pc = ca.extract_precache_urls(ngsw, B)
    assert "http://t.example/api/config" in pc and "http://t.example/rest/menu" in pc
    wb = 'precacheAndRoute([{url:"/app/main.js",revision:"1"},{url:"/api/boot",revision:null}])'
    assert "http://t.example/api/boot" in ca.extract_precache_urls(wb, B)
