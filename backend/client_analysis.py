"""
client_analysis.py — 클라이언트측(HTML/JS) 정적 분석 + 응답 분석 원시함수.

목적: "클라이언트/AJAX 검증은 있으나 서버가 미강제"(CWE-602)·"JS 노출 토큰"·"JSONP 오용"
같은 비즈니스로직/설정 취약점을 능동 프로브가 실증하기 위한 재료를 순수 함수로 추출한다.
신규 탐지·판정 없음 — 추출·분석 헬퍼만(요청 미전송). 능동 프로브가 이 결과로 서버측을 실증한다.

응답 분석 원시함수(find_errors/search/find_reflected)는 여러 프로브가 공유한다(중복 제거).
"""
from __future__ import annotations

import re
import urllib.parse

# ── 응답 분석 원시함수(공유) ─────────────────────────────────────────────────────
_ERROR_RE = re.compile(
    r"(error|invalid|exception|stack\s*trace|traceback|not\s+found|forbidden|unauthorized|"
    r"bad\s+request|internal\s+server\s+error|service\s+unavailable|permission\s+denied|"
    r"sql\s+syntax|warning[: ]|fatal[: ]|parse\s+error|denied|실패|오류|에러|권한\s*없|접근\s*거부)",
    re.IGNORECASE)


def find_errors(doc: str, max_hits: int = 20) -> list[str]:
    """응답에서 오류/거부 신호 스니펫을 수집(중복 제거). 한국어 신호 포함."""
    if not isinstance(doc, str) or not doc:
        return []
    out, seen = [], set()
    for m in _ERROR_RE.finditer(doc):
        s = re.sub(r"\s+", " ", doc[max(0, m.start() - 80):m.end() + 80]).strip()
        if s not in seen:
            seen.add(s)
            out.append(s)
        if len(out) >= max_hits:
            break
    return out


def search(doc: str, query: str, ctx: int = 80, max_hits: int = 25) -> list[str]:
    """대소문자 무시 검색 → 매치 주변 컨텍스트 스니펫."""
    if not isinstance(doc, str) or not query:
        return []
    out = []
    for i, m in enumerate(re.finditer(re.escape(query), doc, re.IGNORECASE)):
        out.append(re.sub(r"\s+", " ", doc[max(0, m.start() - ctx):m.end() + ctx]).strip())
        if i + 1 >= max_hits:
            break
    return out


def find_reflected(doc: str, pattern: str, ctx: int = 50, max_hits: int = 10) -> list[str]:
    """정확 문자열이 응답에 반영됐는지 + 주변 컨텍스트(반사 기반 확증용)."""
    if not isinstance(doc, str) or not pattern:
        return []
    out = []
    for i, m in enumerate(re.finditer(re.escape(pattern), doc)):
        out.append(doc[max(0, m.start() - ctx):m.end() + ctx])
        if i + 1 >= max_hits:
            break
    return out


# ── JS 수집 ──────────────────────────────────────────────────────────────────
_JS_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)
_INLINE_JS_RE = re.compile(r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)
# 모던 SPA(Angular/esbuild/webpack)는 lazy 청크를 <script src> 아닌
# <link rel="modulepreload|preload|prefetch" href="chunk-*.js"> 로 참조한다.
# 이 청크에 로그인 등 라우트별 API 엔드포인트가 들어있어(main.js 엔 없음) 반드시 수집해야 함.
_LINK_JS_RE = re.compile(
    r'<link\b[^>]*\brel=["\'](?:modulepreload|preload|prefetch)["\'][^>]*'
    r'\bhref=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)
# href 가 rel 앞에 오는 경우도 대응(속성 순서 무관)
_LINK_JS_RE_ALT = re.compile(
    r'<link\b[^>]*\bhref=["\']([^"\']+\.js(?:\?[^"\']*)?)["\'][^>]*'
    r'\brel=["\'](?:modulepreload|preload|prefetch)["\']', re.IGNORECASE)


def same_origin_js_urls(html: str, base_url: str, cap: int = 40) -> list[str]:
    """HTML 에서 동일 출처 외부 JS URL 목록(절대화). <script src> + <link rel=preload/modulepreload>."""
    if not html:
        return []
    host = urllib.parse.urlparse(base_url).netloc
    out, seen = [], set()
    for rx in (_JS_SRC_RE, _LINK_JS_RE, _LINK_JS_RE_ALT):
        for m in rx.finditer(html):
            u = urllib.parse.urljoin(base_url, m.group(1))
            if urllib.parse.urlparse(u).netloc == host and u not in seen:
                seen.add(u)
                out.append(u)
            if len(out) >= cap:
                return out
    return out


def inline_scripts(html: str) -> str:
    """인라인 <script> 본문을 이어붙여 반환(가드/토큰 스캔용)."""
    if not html:
        return ""
    return "\n".join(m.group(1) for m in _INLINE_JS_RE.finditer(html))


# ── 클라이언트 전용 가드 추출(CWE-602 후보) ──────────────────────────────────────
# 개수/길이 제한: JS 의 `xxx.length > N`, `cnt > N`, `> N`(제한 문맥), input maxlength.
_JS_COUNT_LIMIT_RE = re.compile(
    r'(?:\.length|_cnt|_count|cnt|count|len|size|max)\s*[<>]=?\s*(\d{1,4})', re.IGNORECASE)
_MAXLENGTH_RE = re.compile(r'maxlength=["\'](\d{1,5})["\']', re.IGNORECASE)
# 필수/동의 체크: name 에 agree/consent/terms/필수 동의 등.
_CONSENT_FIELD_RE = re.compile(
    r'name=["\']([^"\']*(?:agree|consent|terms|policy|privacy|약관|동의)[^"\']*)["\']', re.IGNORECASE)
# 클라이언트측 필수 표시(required 속성) — required 와 name 의 순서 무관.
_INPUT_TAG_RE = re.compile(r'<input\b[^>]*>', re.IGNORECASE)
_TAG_NAME_RE = re.compile(r'\bname=["\']([^"\']+)["\']', re.IGNORECASE)


def _required_field_names(html: str) -> list[str]:
    out = []
    for m in _INPUT_TAG_RE.finditer(html or ""):
        tag = m.group(0)
        if re.search(r'\brequired\b', tag, re.IGNORECASE):
            nm = _TAG_NAME_RE.search(tag)
            if nm:
                out.append(nm.group(1))
    return out
# AJAX 프리체크 엔드포인트: /ajax*/check/*, *check*.php, /validate, /verify.
_AJAX_CHECK_URL_RE = re.compile(
    r'["\'](/[^"\']*(?:ajax[^"\']*(?:check|valid|verify)|(?:check|valid|verify)[^"\']*)\.(?:php|jsp|do|json|asp[x]?))["\']',
    re.IGNORECASE)


def extract_client_guards(html: str, js_text: str) -> dict:
    """HTML+JS 에서 '클라이언트 전용 가드' 후보를 추출한다(서버측 미강제 여부는 프로브가 실증).
    반환: {count_limits:[int], consent_fields:[name], required_fields:[name],
           maxlengths:[(name?,int)], ajax_check_urls:[path]}"""
    blob = (html or "") + "\n" + (js_text or "")
    count_limits = sorted({int(x) for x in _JS_COUNT_LIMIT_RE.findall(blob)
                           if 1 <= int(x) <= 5000})
    consent = sorted({m.group(1) for m in _CONSENT_FIELD_RE.finditer(html or "")})
    required = sorted(set(_required_field_names(html or "")))
    maxlengths = sorted({int(x) for x in _MAXLENGTH_RE.findall(html or "") if 1 <= int(x) <= 100000})
    ajax = sorted({m.group(1) for m in _AJAX_CHECK_URL_RE.finditer(blob)})
    return {
        "count_limits": count_limits[:10],
        "consent_fields": consent[:10],
        "required_fields": required[:10],
        "maxlengths": maxlengths[:10],
        "ajax_check_urls": ajax[:10],
    }


# ── 앱 세션/자동로그인 토큰 추출(JS 노출 토큰 → 인증우회 후보) ──────────────────────
# 클라우드 시크릿과 별개로, 앱이 클라이언트에 심는 자동로그인/세션 토큰류.
_APP_TOKEN_RE = re.compile(
    r'(?P<key>auto[_\-]?login|autologin|access[_\-]?token|session[_\-]?(?:id|key|token)|'
    r'login[_\-]?(?:key|token)|auth[_\-]?token|remember[_\-]?token|api[_\-]?token)'
    r'["\']?\s*[:=]\s*["\'](?P<val>[A-Za-z0-9._\-]{12,})["\']', re.IGNORECASE)
# 토큰을 소비할 만한 엔드포인트(자동로그인/세션).
_TOKEN_ENDPOINT_RE = re.compile(
    r'["\'](/[^"\']*(?:auto[_\-]?login|autologin|login|session|sso|token)[^"\']*)["\']', re.IGNORECASE)


def extract_app_tokens(js_text: str) -> list[dict]:
    """JS 에서 자동로그인/세션 토큰 후보를 추출. 반환: [{name, value, preview}]"""
    out, seen = [], set()
    for m in _APP_TOKEN_RE.finditer(js_text or ""):
        key, val = m.group("key"), m.group("val")
        if val.lower() in ("true", "false", "null", "undefined", "function"):
            continue
        if re.search(r'(example|placeholder|dummy|xxxx|your[_\-]?)', val, re.IGNORECASE):
            continue
        if val in seen:
            continue
        seen.add(val)
        preview = (val[:6] + "…" + val[-4:]) if len(val) > 12 else val
        out.append({"name": key, "value": val, "preview": preview})
        if len(out) >= 10:
            break
    return out


def token_endpoint_candidates(html: str, js_text: str, base_url: str) -> list[str]:
    """토큰을 소비할 만한 엔드포인트 후보(자동로그인/세션) 절대 URL."""
    blob = (html or "") + "\n" + (js_text or "")
    out, seen = [], set()
    for m in _TOKEN_ENDPOINT_RE.finditer(blob):
        u = urllib.parse.urljoin(base_url, m.group(1))
        if u not in seen:
            seen.add(u)
            out.append(u)
        if len(out) >= 10:
            break
    return out


# ── JSONP 오용 탐지 재료 ─────────────────────────────────────────────────────────
# JSONP 사용 힌트: callback=/jsonp=/jsonpCallback= 파라미터, $.ajax({dataType:'jsonp'}).
_JSONP_PARAM_RE = re.compile(r'["\']?(callback|jsonp|jsoncallback|jsonpcallback|cb)["\']?\s*[:=]',
                             re.IGNORECASE)
_JSONP_DATATYPE_RE = re.compile(r'dataType\s*:\s*["\']jsonp["\']', re.IGNORECASE)
_JSONP_URL_RE = re.compile(r'["\'](/[^"\']*\?[^"\']*(?:callback|jsonp)=[^"\']*)["\']', re.IGNORECASE)
# JSONP 사용이 감지되면 ajax 설정의 url:"/path" 도 후보 엔드포인트로 본다.
_AJAX_URL_RE = re.compile(r'\burl\s*:\s*["\'](/[^"\']+)["\']', re.IGNORECASE)


# ── JS 번들 API 엔드포인트 마이닝 (SPA/JS 앱 공격표면 확보 = API_SYNTHESIZED) ──────
# SPA(Angular/React 등)는 실제 엔드포인트가 JS 번들 안에만 있어 정적 HTML 추출로는 표면이
# 거의 안 보인다. JS 에서 fetch/axios/HttpClient 호출과 API 경로 리터럴을 뽑아 입력점화한다.
_STATIC_EXT_RE = re.compile(r'\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|json)$',
                            re.IGNORECASE)
# API 성격 경로 프리픽스(노이즈 억제 — 이 접두면 리터럴만으로도 채택)
_API_PREFIX_RE = re.compile(
    r'^/(api|rest|graphql|gql|v\d+|admin|manage|user|account|auth|login|logout|'
    r'session|token|order|basket|cart|product|member|payment|kcp|'
    r'profile|search|upload|file|download|feedback|complain|track|report|config|setting|'
    r'internal|service|ajax|actuator|swagger|openapi)', re.IGNORECASE)
# 호출 문맥(fetch/axios/http.get/url:) — 이 문맥이면 접두 무관하게 채택
_JS_CALL_RE = re.compile(
    r'(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|patch|delete)|\burl\s*[:=]|open\s*\(\s*["\'][A-Z]+["\']\s*,)'
    r'\s*\(?\s*["\'`](/[^"\'`\s]{1,200})["\'`]', re.IGNORECASE)
# 일반 절대경로 리터럴
_PATH_LITERAL_RE = re.compile(r'["\'`](/[a-zA-Z0-9_][a-zA-Z0-9_\-./{}:%~]{1,180})["\'`]')
# 인라인 API 경로(따옴표 미포함/템플릿리터럴 대응): `${base}/rest/...?q=${e}` 처럼 base 변수 접두 +
# 쿼리스트링이 붙는 모던 SPA URL 을 포착한다. API 성격 접두로 시작하는 경로만 채택(노이즈 억제).
_API_PATH_INLINE_RE = re.compile(
    r'(?<![\w.])(/(?:api|rest|graphql|gql|v\d+|admin|manage|user|account|auth|login|logout|'
    r'session|token|order|basket|cart|product|member|payment|kcp|profile|search|upload|file|'
    r'download|feedback|complain|track|report|config|setting|internal|service|ajax|actuator|'
    r'swagger|openapi)[a-zA-Z0-9_\-./{}:%~]*(?:\?[a-zA-Z0-9_\-.=&%]*)?)', re.IGNORECASE)


def mine_js_endpoints(js_text: str, base_url: str, cap: int = 80) -> list[dict]:
    """JS 본문에서 API 엔드포인트를 추출해 active_probing 입력점(point) 스키마로 반환한다.
    반환 point: {method, url, params, source='js_endpoint', csrf_fields:[]}
    - 채택 기준: (a) fetch/axios/http/url: 호출 문맥의 경로, 또는 (b) API 성격 접두 경로.
    - 정적 자산·프로토콜상대(//)·중복은 제외. 쿼리에 파라미터가 있으면 params 로 추출."""
    if not js_text:
        return []
    host = urllib.parse.urlparse(base_url).netloc
    cands: set = set()
    for m in _JS_CALL_RE.finditer(js_text):
        cands.add(m.group(1))
    for m in _PATH_LITERAL_RE.finditer(js_text):
        p = m.group(1)
        if _API_PREFIX_RE.match(p):
            cands.add(p)
    # 템플릿리터럴/미따옴표 인라인 API 경로(모던 SPA URL 빌더 대응)
    for m in _API_PATH_INLINE_RE.finditer(js_text):
        cands.add(m.group(1))
    out: list[dict] = []
    seen: set = set()
    for raw in cands:
        raw = raw.strip()
        if not raw.startswith("/") or raw.startswith("//"):
            continue
        pr = urllib.parse.urlparse(raw)
        path = pr.path
        if not path or _STATIC_EXT_RE.search(path):
            continue
        # Angular/템플릿 파라미터(/users/:id, /users/{id})는 샘플값으로 치환해 실제 요청 가능화
        path_filled = re.sub(r'(:[A-Za-z_]\w*|\{[^/}]+\})', "1", path)
        url = urllib.parse.urljoin(base_url, path_filled)
        if urllib.parse.urlparse(url).netloc != host:
            continue
        params = {k: (v[0] if (v and v[0]) else "test")
                  for k, v in urllib.parse.parse_qs(pr.query, keep_blank_values=True).items()}
        key = (path_filled, tuple(sorted(params)))
        if key in seen:
            continue
        seen.add(key)
        out.append({"method": "GET", "url": url.split("?")[0], "params": params,
                    "source": "js_endpoint", "csrf_fields": []})
        if len(out) >= cap:
            break
    return out


# ── webpack 런타임 청크맵 파싱(구형 빌드: 청크가 HTML 미참조) ──────────────────────────
# 구형 webpack 은 lazy 청크를 <link>/<script> 로 미리 참조하지 않고, 런타임의
# __webpack_require__.u(chunkId) 가 { id: "hash" } 맵으로 파일명을 계산해 동적 로드한다.
# 이 청크에 라우트별 API 엔드포인트가 있어(main 엔 없음) URL 을 재구성해 마이닝 대상에 넣는다.
# publicPath(.p) 문자열 리터럴 추출
_WP_PUBLICPATH_RE = re.compile(r'\.p\s*=\s*["\']([^"\']*)["\']')
# .u = function(e){return ...js"}  또는  .u = e => ...js"   (파일명은 항상 .js" 로 끝남)
_WP_U_FUNC_RE = re.compile(
    r'\.u\s*=\s*(?:function\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{\s*return\s+|'
    r'\(\s*([A-Za-z_$][\w$]*)\s*\)\s*=>\s*|([A-Za-z_$][\w$]*)\s*=>\s*)'
    r'(.*?\.js)["\']',
    re.DOTALL)
# 객체 리터럴 맵: { 179:"abc", 213:"def" } / { "179":"abc" }
_WP_MAP_ENTRY_RE = re.compile(r'["\']?(\d+)["\']?\s*:\s*["\']([^"\']*)["\']')


def _wp_split_top_plus(expr: str) -> list[str]:
    """`+` 로 이어진 최상위 토큰 분리(문자열/중괄호/괄호 내부의 + 는 무시)."""
    toks, buf, depth = [], [], 0
    quote = None
    i = 0
    while i < len(expr):
        c = expr[i]
        if quote:
            buf.append(c)
            if c == "\\" and i + 1 < len(expr):
                buf.append(expr[i + 1]); i += 2; continue
            if c == quote:
                quote = None
        elif c in "\"'`":
            quote = c; buf.append(c)
        elif c in "{[(":
            depth += 1; buf.append(c)
        elif c in "}])":
            depth -= 1; buf.append(c)
        elif c == "+" and depth == 0:
            toks.append("".join(buf).strip()); buf = []
        else:
            buf.append(c)
        i += 1
    if buf:
        toks.append("".join(buf).strip())
    return [t for t in toks if t]


def _wp_eval_token(tok: str, chunk_id: str, id_var: str) -> str:
    """단일 토큰을 주어진 chunk_id 로 평가: 문자열리터럴 / id변수 / {맵}[id]."""
    t = tok.strip()
    # 문자열 리터럴
    if len(t) >= 2 and t[0] in "\"'`" and t[-1] == t[0]:
        return t[1:-1]
    # 순수 id 변수(괄호 포함 가능)
    if t.strip("()") == id_var:
        return str(chunk_id)
    # {맵}[var]  또는  ({맵}[var]||var)
    if "{" in t and "}" in t:
        obj = t[t.index("{"): t.rindex("}") + 1]
        m = dict(_WP_MAP_ENTRY_RE.findall(obj))
        if chunk_id in m:
            return m[chunk_id]
        # ||var / ||e 폴백이면 id 자체
        if "||" in t:
            return str(chunk_id)
        return ""
    return ""


def mine_webpack_chunk_urls(js_text: str, base_url: str, cap: int = 40) -> list[str]:
    """webpack 런타임에서 lazy 청크 URL 을 재구성(동일 출처, 최대 cap 개).
    __webpack_require__.u 템플릿 + id→hash 맵을 평가해 파일명을 만든다."""
    if not js_text:
        return []
    mu = _WP_U_FUNC_RE.search(js_text)
    if not mu:
        return []
    id_var = mu.group(1) or mu.group(2) or mu.group(3) or "e"
    template = mu.group(4)  # 예: "static/js/"+e+"."+{179:"abc"}[e]+".chunk"  (.js 는 그룹에 포함)
    template = template + '"'  # 닫는 따옴표 복원(정규식이 .js 까지만 캡처)
    tokens = _wp_split_top_plus(template)
    if not tokens:
        return []
    # 청크 id 집합 = 템플릿 내 맵들의 키 합집합(해시 맵의 키가 청크 id)
    chunk_ids: set = set()
    for t in tokens:
        if "{" in t and "}" in t:
            obj = t[t.index("{"): t.rindex("}") + 1]
            for k, _v in _WP_MAP_ENTRY_RE.findall(obj):
                chunk_ids.add(k)
    if not chunk_ids:
        return []
    pm = _WP_PUBLICPATH_RE.search(js_text)
    public_path = pm.group(1) if pm else ""
    host = urllib.parse.urlparse(base_url).netloc
    urls, seen = [], set()
    for cid in sorted(chunk_ids, key=lambda x: int(x)):
        fname = "".join(_wp_eval_token(t, cid, id_var) for t in tokens)
        if not fname.endswith(".js"):
            continue
        full = urllib.parse.urljoin(base_url, public_path + fname)
        if urllib.parse.urlparse(full).netloc != host or full in seen:
            continue
        seen.add(full)
        urls.append(full)
        if len(urls) >= cap:
            break
    return urls


# ── Service Worker / WASM 공격표면 발견 ────────────────────────────────────────
# PWA 는 service worker(precache 매니페스트·fetch 라우트)와 WASM(데이터 섹션에 박힌
# API 경로/URL 문자열)에 정적 HTML 로는 안 보이는 엔드포인트를 담는다. 이를 수집·마이닝한다.
_SW_REGISTER_RE = re.compile(
    r'serviceWorker\s*\.\s*register\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE)
# 흔한 SW 파일명(등록 코드가 난독화돼 안 잡힐 때의 폴백). Angular=ngsw-worker.js/ngsw.json.
_SW_COMMON_PATHS = ["/sw.js", "/service-worker.js", "/serviceworker.js",
                    "/ngsw-worker.js", "/ngsw.json", "/firebase-messaging-sw.js",
                    "/workbox-sw.js", "/pwa-sw.js"]
_WASM_URL_RE = re.compile(r'["\'`]([^"\'`]+\.wasm(?:\?[^"\'`]*)?)["\']', re.IGNORECASE)
# WebAssembly.instantiateStreaming(fetch("..."))  같이 .wasm 확장자 없이 fetch 되는 경우도
_WASM_FETCH_RE = re.compile(
    r'instantiate(?:Streaming)?\s*\(\s*(?:await\s+)?fetch\s*\(\s*["\'`]([^"\'`]+)["\']', re.IGNORECASE)


def _same_origin_abs(cands, base_url: str, cap: int) -> list:
    host = urllib.parse.urlparse(base_url).netloc
    out, seen = [], set()
    for c in cands:
        u = urllib.parse.urljoin(base_url, c)
        if urllib.parse.urlparse(u).netloc == host and u not in seen:
            seen.add(u)
            out.append(u)
        if len(out) >= cap:
            break
    return out


def service_worker_urls(html: str, js_text: str, base_url: str, cap: int = 8) -> list:
    """service worker 스크립트/매니페스트 URL(동일 출처): 등록 코드 + 흔한 경로 폴백."""
    blob = (html or "") + "\n" + (js_text or "")
    cands = [m.group(1) for m in _SW_REGISTER_RE.finditer(blob)]
    cands += _SW_COMMON_PATHS
    return _same_origin_abs(cands, base_url, cap)


def wasm_urls(html: str, js_text: str, base_url: str, cap: int = 6) -> list:
    """WebAssembly 모듈(.wasm) URL(동일 출처): .wasm 리터럴 + instantiate(fetch(...)) 문맥."""
    blob = (html or "") + "\n" + (js_text or "")
    cands = [m.group(1) for m in _WASM_URL_RE.finditer(blob)]
    cands += [m.group(1) for m in _WASM_FETCH_RE.finditer(blob)]
    # .wasm 아닌 fetch 문맥 URL 은 실제 wasm 인지 확실치 않으므로 .wasm 확장자만 우선
    cands = [c for c in cands if ".wasm" in c.lower()] + [c for c in cands if ".wasm" not in c.lower()]
    return _same_origin_abs(cands, base_url, cap)


def extract_wasm_strings(data: bytes, min_len: int = 5, max_bytes: int = 3_000_000) -> str:
    """WASM(또는 임의 바이너리)에서 출력가능 ASCII 런을 추출해 개행으로 결합.
    데이터 섹션에 박힌 API 경로/URL 문자열을 mine_js_endpoints 로 재활용하기 위함."""
    if not data:
        return ""
    data = data[:max_bytes]
    runs, cur = [], []
    for b in data:
        if 0x20 <= b <= 0x7E:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                runs.append(bytes(cur).decode("ascii", "ignore"))
            cur = []
    if len(cur) >= min_len:
        runs.append(bytes(cur).decode("ascii", "ignore"))
    return "\n".join(runs)


def extract_precache_urls(sw_text: str, base_url: str, cap: int = 200) -> list:
    """service worker 의 precache 매니페스트에서 URL 추출.
    - workbox: precacheAndRoute([{url:"...",revision:...}]) / __WB_MANIFEST
    - Angular ngsw.json(JSON): hashTable 키·urls 배열
    - 일반 {url:"/path"} 항목
    반환: 동일 출처 절대 URL 목록(정적자산 포함 — 라우트 발견용, API 필터는 상위 mine 이 수행)."""
    if not sw_text:
        return []
    cands = []
    # ngsw.json 등 JSON 매니페스트
    stripped = sw_text.lstrip()
    if stripped[:1] in "{[":
        try:
            import json as _j
            d = _j.loads(sw_text)
            if isinstance(d, dict):
                ht = d.get("hashTable")
                if isinstance(ht, dict):
                    cands += list(ht.keys())
                for grp in (d.get("assetGroups") or []):
                    cands += (grp.get("urls") or []) if isinstance(grp, dict) else []
                if isinstance(d.get("urls"), list):
                    cands += d["urls"]
        except Exception:
            pass
    # workbox / 일반 {url:"..."} 항목
    cands += [m.group(1) for m in re.finditer(r'url\s*:\s*["\'`]([^"\'`]+)["\']', sw_text)]
    return _same_origin_abs([c for c in cands if isinstance(c, str) and c.startswith("/")],
                            base_url, cap)


def detect_jsonp(html: str, js_text: str, base_url: str) -> dict:
    """JSONP 사용 신호와 후보 엔드포인트를 추출(서버측 실증은 프로브가 수행).
    반환: {uses_jsonp:bool, callback_params:[name], endpoints:[url]}"""
    blob = (html or "") + "\n" + (js_text or "")
    cb_params = sorted({m.group(1).lower() for m in _JSONP_PARAM_RE.finditer(blob)})
    endpoints, seen = [], set()
    for m in _JSONP_URL_RE.finditer(blob):
        u = urllib.parse.urljoin(base_url, m.group(1))
        if u not in seen:
            seen.add(u)
            endpoints.append(u)
        if len(endpoints) >= 10:
            break
    uses = bool(cb_params) or bool(_JSONP_DATATYPE_RE.search(blob)) or bool(endpoints)
    # JSONP 사용이 감지되면 ajax url:"/path" 도 후보에 추가(콜백 없이 참조된 엔드포인트 보완).
    if uses:
        for m in _AJAX_URL_RE.finditer(blob):
            u = urllib.parse.urljoin(base_url, m.group(1))
            if u not in seen:
                seen.add(u)
                endpoints.append(u)
            if len(endpoints) >= 12:
                break
    return {"uses_jsonp": uses, "callback_params": cb_params[:8], "endpoints": endpoints}
