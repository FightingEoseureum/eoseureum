"""
authenticated_scan.py — 인증 스캔 (단일 계정 로그인 + same-origin 크롤).

안전 최우선 원칙:
  - 제공된 단 1개 계정으로만 1회 로그인 시도한다(브루트포스 아님).
  - 운영 영향/계정 변경/파괴적 동작 금지(GET/로그인 POST 만 수행).
  - 계정 잠금 징후("account locked", "계정 잠금", "too many attempts",
    "locked out") 감지 시 즉시 중단하고 reason 에 기록한다.
  - 크롤은 same-origin 으로 제한, 최대 auth_max_pages, request_timeout 적용.
  - 전체 요청은 CompositeRateLimiter(global=global_rps, auth=auth_rps) 로 제한
    (≤10rps + ≤auth_rps).
  - 비밀번호는 로그/반환값에 평문으로 노출하지 않는다(mask).

네트워크 입출력은 테스트가 monkeypatch 할 수 있도록 모듈 함수
(_http_get / _http_post) 로 분리한다.
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.parse

from probes.utils.rate_limiter import RateLimiter, CompositeRateLimiter
from probes.utils.sanitization import mask_value
import adaptive_throttle as _gov   # safe 모드 전역 rate 거버너


def _safe_rps(rps: float) -> float:
    """거버너 설치 시 인증스캔 rps 를 해당 단계 상한으로 클램프(Safe: 5 / PROOF: auth 단계)."""
    lim = _gov.stage("auth")
    if lim is not None:
        try:
            return min(float(rps), float(lim.max_rps))
        except Exception:
            return rps
    return rps

# 계정 잠금 징후 문구 (소문자 비교)
_LOCK_HINTS = (
    "account locked",
    "계정 잠금",
    "계정이 잠",
    "too many attempts",
    "too many login",
    "locked out",
    "account has been locked",
    "account is locked",
)

# 로그인 성공 추정 키워드
_SUCCESS_KEYWORDS = (
    "logout",
    "log out",
    "sign out",
    "signout",
    "dashboard",
    "profile",
    "admin",
    "my account",
    "로그아웃",
    "마이페이지",
)

# 로그인 실패 추정 문구
_FAILURE_KEYWORDS = (
    "invalid",
    "incorrect",
    "failed",
    "wrong password",
    "login failed",
    "authentication failed",
    "아이디 또는 비밀번호",
    "잘못된",
    "로그인 실패",
)

# 폼 username/password 필드 자동 탐지용 패턴
_USER_FIELD_HINTS = ("user", "username", "email", "login", "id", "userid", "uid", "account")
_PASS_FIELD_HINTS = ("password", "pass", "passwd", "pwd")


# ── 네트워크부 (monkeypatch 가능) ─────────────────────────────────────────────

async def _http_get(session, url: str, timeout: float = 8.0):
    """GET 요청. 반환: (status, body, headers_dict). 예외는 (0,"",{}) 로 흡수."""
    try:
        async with session.get(url, allow_redirects=False,
                               timeout=_timeout(timeout)) as r:
            return r.status, await r.text(errors="ignore"), dict(r.headers)
    except Exception:
        return 0, "", {}


async def _http_post(session, url: str, data: dict, timeout: float = 8.0):
    """로그인 POST 요청. 반환: (status, body, headers_dict)."""
    try:
        async with session.post(url, data=data, allow_redirects=False,
                                timeout=_timeout(timeout)) as r:
            return r.status, await r.text(errors="ignore"), dict(r.headers)
    except Exception:
        return 0, "", {}


async def _http_request(session, method: str, url: str, data: dict | None = None,
                        timeout: float = 8.0):
    """임의 메서드 요청(PUT/PATCH/DELETE/POST/GET). 반환: (status, body, headers_dict)."""
    m = (method or "GET").upper()
    if m == "GET":
        return await _http_get(session, url, timeout)
    if m == "POST":
        return await _http_post(session, url, data or {}, timeout)
    try:
        async with session.request(m, url, data=data or {}, allow_redirects=False,
                                   timeout=_timeout(timeout)) as r:
            return r.status, await r.text(errors="ignore"), dict(r.headers)
    except Exception:
        return 0, "", {}


def _make_session(timeout: float = 8.0):
    """aiohttp 세션 생성 (쿠키 유지). 테스트는 _make_session 을 monkeypatch."""
    from probes.utils.http_client import make_session
    return make_session(timeout=timeout)


def _timeout(timeout: float):
    try:
        import aiohttp
        return aiohttp.ClientTimeout(total=timeout)
    except Exception:
        return None


# ── 헬퍼 ─────────────────────────────────────────────────────────────────────

def _has_lock_hint(text: str) -> bool:
    if not text:
        return False
    low = text.lower()
    return any(h.lower() in low for h in _LOCK_HINTS)


def _same_origin(base_url: str, url: str) -> bool:
    try:
        b = urllib.parse.urlparse(base_url)
        u = urllib.parse.urlparse(url)
        return (u.scheme, u.netloc) == (b.scheme, b.netloc)
    except Exception:
        return False


def _resolve(base: str, href: str) -> str:
    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
        return ""
    if href.startswith("http"):
        return href
    return urllib.parse.urljoin(base, href)


def _parse_forms(base_url: str, body: str) -> list[dict]:
    """HTML 폼 파싱 → injection point dict 목록.
    형식: {"method","url","params","source","csrf_fields"}."""
    points: list[dict] = []
    if not body:
        return points
    for fm in re.finditer(r"<form([^>]*)>(.*?)</form>", body, re.IGNORECASE | re.DOTALL):
        attrs, inner = fm.group(1), fm.group(2)
        am = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
        mm = re.search(r'method=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        action = am.group(1) if am else ""
        method = (mm.group(1) if mm else "GET").upper()
        form_url = _resolve(base_url, action) if action else base_url
        params: dict = {}
        csrf_fields: list = []
        for im in re.finditer(r"<input([^>]*)/?>", inner, re.IGNORECASE):
            ia = im.group(1)
            n = re.search(r'name=["\']([^"\']+)["\']', ia, re.IGNORECASE)
            v = re.search(r'value=["\']([^"\']*)["\']', ia, re.IGNORECASE)
            t = re.search(r'type=["\']([^"\']+)["\']', ia, re.IGNORECASE)
            tp = (t.group(1) if t else "text").lower()
            if not n:
                continue
            nm = n.group(1)
            if tp == "hidden" and re.search(r"(csrf|token|nonce|_token|authenticity)", nm, re.IGNORECASE):
                csrf_fields.append(nm)
            if tp in ("submit", "button", "image"):
                # named submit/button 은 값과 함께 전송해야 서버 게이팅(isset(Submit) 등) 통과 → 취약코드 실행.
                params[nm] = v.group(1) if v else nm
            elif tp not in ("reset", "file"):
                params[nm] = v.group(1) if v else ("test@test.com" if tp == "email" else "test")
        for tm in re.finditer(r"<textarea([^>]*)>", inner, re.IGNORECASE):
            n = re.search(r'name=["\']([^"\']+)["\']', tm.group(1), re.IGNORECASE)
            if n:
                params[n.group(1)] = "test"
        for sm in re.finditer(r"<select([^>]*)>", inner, re.IGNORECASE):
            n = re.search(r'name=["\']([^"\']+)["\']', sm.group(1), re.IGNORECASE)
            if n:
                params[n.group(1)] = "1"
        if params:
            points.append({
                "method": method, "url": form_url, "params": params,
                "source": "form", "csrf_fields": csrf_fields,
            })
    return points


def _parse_links(base_url: str, body: str) -> tuple[list[str], list[dict]]:
    """링크(href) 수집 + query parameter 주입 지점 수집.
    반환: (crawl_urls, query_points)."""
    urls: list[str] = []
    points: list[dict] = []
    if not body:
        return urls, points
    seen_links: set = set()
    seen_q: set = set()
    for lm in re.finditer(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE):
        full = _resolve(base_url, lm.group(1))
        if not full:
            continue
        if full not in seen_links:
            seen_links.add(full)
            urls.append(full)
        p = urllib.parse.urlparse(full)
        if p.query:
            params = {k: v[0] for k, v in urllib.parse.parse_qs(p.query).items()}
            if params:
                clean = f"{p.scheme}://{p.netloc}{p.path}"
                key = (clean, tuple(sorted(params.keys())))
                if key not in seen_q:
                    seen_q.add(key)
                    points.append({
                        "method": "GET", "url": clean, "params": params,
                        "source": "query", "csrf_fields": [],
                    })
    return urls, points


def _detect_login_fields(login_form: dict | None, config) -> tuple[str | None, str | None, dict]:
    """username/password 필드명 자동 탐지.
    config.auth_username_field/password_field 가 "auto" 면 폼에서 추론.
    반환: (user_field, pass_field, base_params(폼의 기본 파라미터 복사))."""
    user_field = getattr(config, "auth_username_field", "auto") or "auto"
    pass_field = getattr(config, "auth_password_field", "auto") or "auto"
    base_params: dict = {}
    params = (login_form or {}).get("params") or {}
    base_params = dict(params)

    if user_field == "auto":
        user_field = None
        for k in params:
            kl = k.lower()
            if any(h in kl for h in _USER_FIELD_HINTS):
                user_field = k
                break
    if pass_field == "auto":
        pass_field = None
        for k in params:
            kl = k.lower()
            if any(h in kl for h in _PASS_FIELD_HINTS):
                pass_field = k
                break
    return user_field, pass_field, base_params


def _judge_login_success(pre_body: str, status: int, body: str, headers: dict,
                         login_url: str, success_pattern: str) -> bool:
    """로그인 성공 판정.
    - 명시 패턴(auth_success_pattern != "auto") 매칭
    - 3xx 리다이렉트(URL 변화) + Location 이 로그인 페이지 아님
    - Set-Cookie 에 세션/JWT 토큰
    - 성공 키워드(logout/dashboard/profile/admin/my account)
    - 실패 메시지 소실(로그인 폼 응답에 있던 실패 문구가 사라짐)
    """
    low_body = (body or "").lower()

    if success_pattern and success_pattern != "auto":
        try:
            if re.search(success_pattern, body or "", re.IGNORECASE):
                return True
        except re.error:
            if success_pattern.lower() in low_body:
                return True

    # Set-Cookie 에 세션/JWT
    set_cookie = ""
    for k, v in (headers or {}).items():
        if k.lower() == "set-cookie":
            set_cookie += str(v)
    sc_low = set_cookie.lower()
    if any(t in sc_low for t in ("session", "sessid", "sid=", "jwt", "token", "auth")):
        return True

    # 리다이렉트 (URL 변화) — 로그인 페이지로 되돌아가는 것이 아니면 성공으로 추정
    if status in (301, 302, 303, 307, 308):
        loc = ""
        for k, v in (headers or {}).items():
            if k.lower() == "location":
                loc = str(v)
        if loc and "login" not in loc.lower() and "signin" not in loc.lower():
            return True

    # 성공 키워드
    if any(kw in low_body for kw in _SUCCESS_KEYWORDS):
        return True

    # 실패 메시지 소실: 이전(로그인 폼) 응답엔 실패 문구가 있었는데 이번 응답엔 없음
    pre_low = (pre_body or "").lower()
    pre_fail = any(f in pre_low for f in _FAILURE_KEYWORDS)
    now_fail = any(f in low_body for f in _FAILURE_KEYWORDS)
    if status == 200 and body and not now_fail and pre_fail:
        return True

    return False


def _result(logged_in: bool, session, urls, forms, reason: str) -> dict:
    return {
        "logged_in": logged_in,
        "session": session,
        "urls": urls or [],
        "forms": forms or [],
        "reason": reason,
    }


# ── 세션 고정(Session Fixation) 실증 — 로그인 전후 세션 ID 회전 비교 ──────────────────
# 세션 고정: 로그인 성공 후에도 서버가 세션 식별자를 재발급(회전)하지 않으면, 공격자가 미리
# 심어둔(피해자에게 고정시킨) 세션 ID 가 그대로 '인증된 세션'이 되어 계정을 탈취할 수 있다.
# 실증: 익명 세션 쿠키값을 기록 → 실제 로그인 성공 → 같은 쿠키값이 유지되면(미회전) 확증.
_SESSION_NAME_RE = re.compile(
    r"(session|sessid|jsessionid|phpsessid|asp\.?net_sessionid|connect\.sid|^sid$|_ss$|"
    r"laravel_session|ci_session|remember|auth|jwt|token|access|bearer)", re.IGNORECASE)


def _jar_cookies(session) -> dict:
    """세션 쿠키 jar 의 현재 {name: value} 스냅샷."""
    out = {}
    try:
        for c in session.cookie_jar:
            out[c.key] = c.value
    except Exception:
        pass
    return out


async def detect_session_fixation(config, base_url: str) -> dict | None:
    """로그인 전후 세션 ID 회전을 비교해 세션 고정을 실증.
    판정: 익명 세션 쿠키가 존재 + 로그인 성공 + 동일 쿠키가 로그인 후에도 같은 값(미회전) → 확증."""
    if not getattr(config, "enable_auth_scan", False):
        return None
    login_url = getattr(config, "auth_login_url", "") or ""
    username = getattr(config, "auth_username", "") or ""
    password = getattr(config, "auth_password", "") or ""
    if not (login_url and username and password):
        return None
    timeout = float(getattr(config, "request_timeout", 8.0) or 8.0)
    import aiohttp as _ah
    # IP 호스트(127.0.0.1 등)도 쿠키 저장되도록 unsafe jar 사용(기본 jar 는 IP 쿠키 폐기).
    session = _ah.ClientSession(
        cookie_jar=_ah.CookieJar(unsafe=True),
        timeout=_ah.ClientTimeout(total=timeout),
        headers={"User-Agent": "Mozilla/5.0 (Eoseureum Scanner)"},
    )
    try:
        _, login_body, _ = await _http_get(session, login_url, timeout=timeout)
        pre = _jar_cookies(session)
        pre_sess = {k: v for k, v in pre.items() if v and _SESSION_NAME_RE.search(k)}
        if not pre_sess:
            return None   # 익명 세션 식별자가 없으면 고정시킬 대상이 없음(판정 불가)

        forms_on_page = _parse_forms(login_url, login_body)
        login_form = None
        for f in forms_on_page:
            keys = {k.lower() for k in (f.get("params") or {})}
            if any(any(h in k for h in _USER_FIELD_HINTS) for k in keys) and \
               any(any(h in k for h in _PASS_FIELD_HINTS) for k in keys):
                login_form = f
                break
        user_field, pass_field, base_params = _detect_login_fields(login_form, config)
        if not user_field or not pass_field:
            return None

        post_url = (login_form or {}).get("url") or login_url
        data = dict(base_params)
        data[user_field] = username
        data[pass_field] = password
        st, body, headers = await _http_post(session, post_url, data, timeout=timeout)

        success_pattern = getattr(config, "auth_success_pattern", "auto") or "auto"
        if not _judge_login_success(login_body, st, body, headers, login_url, success_pattern):
            return None   # 로그인 실패 → 회전 여부 판정 불가(오탐 방지)

        post = _jar_cookies(session)
        # 익명 때의 세션 쿠키가 로그인 후에도 '같은 값'이면 미회전 = 세션 고정
        fixated = [n for n, v in pre_sess.items() if post.get(n) == v]
        if fixated:
            return {
                "confirmed": True,
                "login_url": login_url,
                "cookie_names": fixated,
                "sample": {n: (pre_sess[n][:8] + "…") for n in fixated},
            }
        return None
    except Exception:
        return None
    finally:
        try:
            await session.close()
        except Exception:
            pass


# ── 세션 만료/로그아웃 무효화 검증 (CWE-613) ──────────────────────────────────────
# 로그아웃 후에도 서버가 세션을 '서버측'에서 무효화하지 않고 클라이언트 쿠키만 지우면,
# 탈취/기록된 옛 세션 토큰이 계속 유효하다(로그아웃 무효화 실패 = 세션 만료 부족).
# 실증: 로그인→토큰 확보→로그아웃 실행→옛 토큰 재전송해도 여전히 인증되면 확증.
_LOGOUT_PATHS = ["/logout", "/signout", "/sign-out", "/logoff", "/api/logout",
                 "/auth/logout", "/api/auth/logout", "/users/sign_out", "/account/logout"]
_LOGOUT_HREF_RE = re.compile(
    r'(?:href|action)\s*=\s*["\']([^"\']*(?:logout|log-out|signout|sign-out|logoff|sign_out)'
    r'[^"\']*)["\']', re.IGNORECASE)


async def _perform_login(config):
    """AUTH_* 자격증명으로 1회 로그인. 성공 세션·응답을 담은 dict 또는 None(실패). 세션은 호출부가 close.
    통합 엔진(_establish_session) 사용 — 브라우저 우선 → HTTP 폴백(action override·JSON·추가필드)."""
    login_url = getattr(config, "auth_login_url", "") or ""
    username = getattr(config, "auth_username", "") or ""
    password = getattr(config, "auth_password", "") or ""
    if not (login_url and username and password):
        return None
    timeout = float(getattr(config, "request_timeout", 8.0) or 8.0)
    res = await _establish_session(config, login_url, login_url, username, password, timeout)
    if not res.get("session") or not res.get("ok"):
        return None
    return {"session": res["session"], "ok": True, "login_url": login_url,
            "login_body": res.get("login_body", ""), "get_headers": {},
            "post_body": res.get("post_body", ""), "post_headers": res.get("post_headers") or {},
            "post_url": res.get("post_url") or login_url}


def _discover_logout_urls(base_url: str, body: str, ref_url: str) -> list:
    """응답 본문의 로그아웃 링크 + 흔한 경로에서 로그아웃 URL 후보(동일 출처) 수집."""
    urls, seen = [], set()
    for m in _LOGOUT_HREF_RE.finditer(body or ""):
        u = _resolve(ref_url, m.group(1))
        if _same_origin(base_url, u) and u not in seen:
            seen.add(u)
            urls.append(u)
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for p in _LOGOUT_PATHS:
        u = origin + p
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls[:8]


async def detect_logout_invalidation(config, base_url: str) -> dict | None:
    """로그아웃 후 옛 세션 토큰 재사용 가능 여부를 실증(CWE-613).
    판정: 로그인 성공 → 인증/익명 구분되는 페이지 확보 → 강한 로그아웃 신호 확인 →
    옛 토큰 재전송이 여전히 인증 응답이면(익명과 상이) 확증."""
    if not getattr(config, "enable_auth_scan", False):
        return None
    li = await _perform_login(config)
    if not li:
        return None
    session = li["session"]
    timeout = float(getattr(config, "request_timeout", 8.0) or 8.0)
    try:
        if not li["ok"]:
            return None
        sess_cookies = {k: v for k, v in _jar_cookies(session).items()
                        if v and _SESSION_NAME_RE.search(k)}
        if not sess_cookies:
            return None
        cookie_hdr = "; ".join(f"{n}={v}" for n, v in sess_cookies.items())

        import aiohttp as _ah

        async def fetch(url, cookie):
            try:
                async with _ah.ClientSession(
                    cookie_jar=_ah.CookieJar(unsafe=True),
                    timeout=_ah.ClientTimeout(total=timeout),
                    headers={"User-Agent": "Mozilla/5.0 (Eoseureum Scanner)"},
                ) as s2:
                    h = {"Cookie": cookie} if cookie else {}
                    async with s2.get(url, headers=h, allow_redirects=False) as r:
                        return r.status, await r.text(errors="ignore")
            except Exception:
                return 0, ""

        def _like(a, b, ta, tb):
            return ta == tb and abs(len(a) - len(b)) <= max(48, int(0.10 * len(b)) + 1)

        def _unlike(a, b, ta, tb):
            return ta != tb or abs(len(a) - len(b)) > 48

        # 인증/익명이 구분되는 대상 페이지 선정(로그인후 리다이렉트 목적지 → base → 로그인 URL)
        targets = [base_url, li["login_url"]]
        for k, v in (li["post_headers"] or {}).items():
            if k.lower() == "location":
                targets.insert(0, _resolve(li["login_url"], str(v)))
        target = sa = ba = sn = bn = None
        for t in targets:
            if not t or not _same_origin(base_url, t):
                continue
            sa_, ba_ = await fetch(t, cookie_hdr)   # 인증(옛 토큰)
            if sa_ == 0:
                continue
            sn_, bn_ = await fetch(t, "")           # 익명
            if _unlike(ba_, bn_, sa_, sn_):
                target, sa, ba, sn, bn = t, sa_, ba_, sn_, bn_
                break
        if target is None:
            return None   # 인증/익명 구분 가능한 페이지 없음 → 판정 불가

        # 강한 로그아웃 신호(세션쿠키 클리어 or 로그인 리다이렉트) 확인 후 로그아웃 실행
        logout_hit = None
        for lu in _discover_logout_urls(base_url, (li["login_body"] or "") + "\n" + (li["post_body"] or ""),
                                        li["login_url"]):
            try:
                st, _lb, hdrs = await _http_get(session, lu, timeout=timeout)
            except Exception:
                continue
            sc = loc = ""
            for k, v in (hdrs or {}).items():
                kl = k.lower()
                if kl == "set-cookie":
                    sc += str(v)
                elif kl == "location":
                    loc = str(v)
            cleared = bool(_SESSION_NAME_RE.search(sc) and
                           ("max-age=0" in sc.lower() or "expires=thu, 01 jan 1970" in sc.lower()
                            or "=;" in sc.replace(" ", "")))
            to_login = st in (301, 302, 303, 307, 308) and bool(
                re.search(r'(login|signin|sign-in)', loc, re.IGNORECASE))
            if st in (200, 301, 302, 303, 307, 308) and (cleared or to_login):
                logout_hit = lu
                break
        if not logout_hit:
            return None   # 확실한 로그아웃 엔드포인트 미확인 → 판정 불가(오탐 방지)

        # 로그아웃 후 옛 토큰 재전송 — 여전히 인증(익명과 상이)이면 서버측 미무효화
        s2, b2 = await fetch(target, cookie_hdr)
        if _like(b2, ba, s2, sa) and _unlike(b2, bn, s2, sn):
            return {
                "confirmed": True, "url": target, "logout_url": logout_hit,
                "cookie_names": list(sess_cookies.keys()),
            }
        return None
    except Exception:
        return None
    finally:
        await _close(session)


# ── 세션 타임아웃(절대 수명) 검증 (CWE-613) ────────────────────────────────────────
# 유휴 타임아웃은 실제 대기 없이 실증 불가하지만, '절대 세션 수명'은 인증 후 발급된 토큰 자체에
# 인코딩돼 있어 대기 없이 측정 가능하다: JWT 의 exp(없음/과도) 또는 세션 쿠키의 Max-Age/Expires.
# (관찰형 플래그가 아니라 '측정된 수명값'이므로 근거가 구체적)
_JWT_RE_TS = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')


def _jwt_payload(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        s = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(s))
    except Exception:
        return None


def _cookie_lifetime_seconds(morsel) -> int | None:
    """SimpleCookie Morsel 의 Max-Age/Expires → 절대 수명(초). 세션 쿠키(비영속)면 None."""
    try:
        ma = morsel["max-age"]
        if ma is not None and str(ma).strip().lstrip("+-").isdigit():
            return int(str(ma).strip())
    except Exception:
        pass
    try:
        exp = morsel["expires"]
        if exp:
            import email.utils as _eu
            import calendar
            ts = _eu.parsedate_tz(exp)
            if ts:
                epoch = calendar.timegm(ts[:9]) - (ts[9] or 0)
                return int(epoch - time.time())
    except Exception:
        pass
    return None


def _session_morsels_from_headers(*header_dicts) -> dict:
    """응답 헤더의 Set-Cookie 에서 세션류 쿠키 Morsel 추출(뒤 응답이 우선=인증 상태)."""
    from http.cookies import SimpleCookie
    out = {}
    for h in header_dicts:
        sc = (h or {}).get("Set-Cookie") or (h or {}).get("set-cookie") or ""
        if not sc:
            continue
        try:
            c = SimpleCookie()
            c.load(sc)
        except Exception:
            continue
        for k, morsel in c.items():
            if _SESSION_NAME_RE.search(k):
                out[k] = morsel
    return out


async def detect_session_timeout_weakness(config, base_url: str) -> dict | None:
    """인증 세션 토큰의 절대 수명을 측정해 과도/부재를 실증.
    JWT: exp 없음 또는 exp-iat 가 임계 초과. 쿠키: Max-Age/Expires 절대수명이 임계 초과."""
    if not getattr(config, "enable_auth_scan", False):
        return None
    li = await _perform_login(config)
    if not li:
        return None
    session = li["session"]
    try:
        if not li["ok"]:
            return None
        try:
            jwt_max_h = float(os.getenv("SESSION_JWT_MAX_HOURS", "24") or 24)
        except (TypeError, ValueError):
            jwt_max_h = 24.0
        try:
            cookie_max_d = float(os.getenv("SESSION_COOKIE_MAX_DAYS", "30") or 30)
        except (TypeError, ValueError):
            cookie_max_d = 30.0

        morsels = _session_morsels_from_headers(li.get("get_headers"), li.get("post_headers"))
        # 인증 세션 쿠키(값+속성) — jar 값도 병합(헤더 누락 대비)
        jar_vals = _jar_cookies(session)

        # 1) JWT 세션 토큰 절대 수명
        for name, val in list(jar_vals.items()) + [(k, m.value) for k, m in morsels.items()]:
            if not (val and _SESSION_NAME_RE.search(name)):
                continue
            m = _JWT_RE_TS.search(val)
            if not m:
                continue
            payload = _jwt_payload(m.group(0))
            if payload is None:
                continue
            exp = payload.get("exp")
            if not exp:
                return {"confirmed": True, "kind": "jwt_no_exp", "cookie": name}
            iat = payload.get("iat") or payload.get("nbf")
            life = (exp - iat) if iat else (exp - time.time())
            if life > jwt_max_h * 3600:
                return {"confirmed": True, "kind": "jwt_excessive", "cookie": name,
                        "hours": round(life / 3600, 1)}

        # 2) 불투명 세션 쿠키 절대 수명(영속 쿠키의 과도한 Max-Age/Expires)
        for name, morsel in morsels.items():
            life = _cookie_lifetime_seconds(morsel)
            if life is not None and life > cookie_max_d * 86400:
                return {"confirmed": True, "kind": "cookie_excessive", "cookie": name,
                        "days": round(life / 86400, 1)}
        return None
    except Exception:
        return None
    finally:
        await _close(session)


# ── 유휴 세션 타임아웃(Idle Session Timeout) 능동 실증 (CWE-613) ──────────────────
# 유휴 만료는 시간 의존이라 대기 없이 실증 불가 → opt-in(env SESSION_IDLE_WAIT_SEC>0) 능동 테스트.
# 로그인 → 인증 확인 → 지정 시간 '무활동' 대기 → 같은 토큰 재전송이 여전히 인증되면,
# 유휴 만료가 최소 그 대기 시간보다 김(또는 없음)을 실증한다(측정된 하한).
async def detect_idle_session_timeout(config, base_url: str) -> dict | None:
    import asyncio as _aio
    if not getattr(config, "enable_auth_scan", False):
        return None
    try:
        wait_sec = int(os.getenv("SESSION_IDLE_WAIT_SEC", "0") or 0)
    except (TypeError, ValueError):
        wait_sec = 0
    if wait_sec <= 0:
        return None
    wait_sec = min(wait_sec, 3600)   # 최대 1시간(스캔 지연 상한)
    li = await _perform_login(config)
    if not li:
        return None
    session = li["session"]
    timeout = float(getattr(config, "request_timeout", 8.0) or 8.0)
    try:
        if not li["ok"]:
            return None
        sess = {k: v for k, v in _jar_cookies(session).items() if v and _SESSION_NAME_RE.search(k)}
        if not sess:
            return None
        cookie_hdr = "; ".join(f"{n}={v}" for n, v in sess.items())
        import aiohttp as _ah

        async def fetch(url, cookie):
            try:
                async with _ah.ClientSession(cookie_jar=_ah.CookieJar(unsafe=True),
                                             timeout=_ah.ClientTimeout(total=timeout),
                                             headers={"User-Agent": "Mozilla/5.0 (Eoseureum Scanner)"}) as s2:
                    h = {"Cookie": cookie} if cookie else {}
                    async with s2.get(url, headers=h, allow_redirects=False) as r:
                        return r.status, await r.text(errors="ignore")
            except Exception:
                return 0, ""

        def _like(a, b, ta, tb):
            return ta == tb and abs(len(a) - len(b)) <= max(48, int(0.10 * len(b)) + 1)

        def _unlike(a, b, ta, tb):
            return ta != tb or abs(len(a) - len(b)) > 48

        targets = [base_url, li["login_url"]]
        for k, v in (li["post_headers"] or {}).items():
            if k.lower() == "location":
                targets.insert(0, _resolve(li["login_url"], str(v)))
        target = sa = ba = sn = bn = None
        for t in targets:
            if not t or not _same_origin(base_url, t):
                continue
            sa_, ba_ = await fetch(t, cookie_hdr)     # 인증 기준선
            if sa_ == 0:
                continue
            sn_, bn_ = await fetch(t, "")             # 익명 기준선
            if _unlike(ba_, bn_, sa_, sn_):
                target, sa, ba, sn, bn = t, sa_, ba_, sn_, bn_
                break
        if target is None:
            return None   # 인증/익명 구분 페이지 없음 → 판정 불가

        await _aio.sleep(wait_sec)   # 무활동(유휴) 대기

        s2, b2 = await fetch(target, cookie_hdr)      # 유휴 후 옛 토큰 재전송
        if _like(b2, ba, s2, sa) and _unlike(b2, bn, s2, sn):
            return {"confirmed": True, "url": target, "wait_sec": wait_sec,
                    "cookie_names": list(sess.keys())}
        return None
    except Exception:
        return None
    finally:
        await _close(session)


# ── 메인 진입점 ────────────────────────────────────────────────────────────────

async def _http_post_json(session, url: str, payload: dict, timeout: float = 8.0):
    """JSON 본문 로그인 POST. 반환: (status, body, headers_dict)."""
    try:
        async with session.post(url, json=payload, allow_redirects=False,
                                timeout=_timeout(timeout)) as r:
            return r.status, await r.text(errors="ignore"), dict(r.headers)
    except Exception:
        return 0, "", {}


# ── 브라우저 로그인(playwright) — JS/SPA·클라이언트 해시PW·동적 토큰 자동 처리 ──────────
async def browser_login(config, login_url: str, username: str, password: str,
                        timeout: float = 15.0) -> dict:
    """실제 브라우저로 로그인 페이지를 열어 자격증명을 입력·제출한다.

    폼 action 이 HTML 에 없거나(SPA/JS fetch), 비밀번호가 클라이언트에서 해시/암호화되거나,
    CSRF/디바이스 토큰이 동적으로 주입되는 경우도 브라우저가 실제 JS 를 실행하므로 그대로 처리된다.
    반환: {"ok", "cookies": [playwright cookie...], "final_url", "body", "reason"}.
    """
    if not (login_url and username and password):
        return {"ok": False, "reason": "no credentials"}
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return {"ok": False, "reason": "playwright unavailable"}

    u_sel = (getattr(config, "auth_username_selector", "") or "").strip()
    p_sel = (getattr(config, "auth_password_selector", "") or "").strip()
    s_sel = (getattr(config, "auth_submit_selector", "") or "").strip()
    tmo = int(max(8.0, float(timeout or 15.0)) * 1000)
    cookies: list = []
    final_url = login_url
    body = ""
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
            ctx = await browser.new_context(ignore_https_errors=True,
                                            user_agent="Mozilla/5.0 (Eoseureum Scanner)")
            page = await ctx.new_page()
            try:
                await page.goto(login_url, wait_until="domcontentloaded", timeout=tmo)
                # 1) 비밀번호 필드(명시 셀렉터 우선, 없으면 type=password 자동)
                pfield = p_sel or "input[type=password]"
                await page.fill(pfield, password, timeout=tmo)
                # 2) 사용자 필드(명시 우선, 없으면 흔한 후보 자동 탐지)
                if u_sel:
                    await page.fill(u_sel, username, timeout=tmo)
                else:
                    ufilled = False
                    for sel in ("input[type=email]", "input[type=text]", "input[type=tel]",
                                "input[name*='user' i]", "input[name*='email' i]",
                                "input[name*='id' i]", "input[autocomplete='username']"):
                        try:
                            if await page.locator(sel).count() > 0:
                                await page.fill(sel, username, timeout=4000)
                                ufilled = True
                                break
                        except Exception:
                            continue
                    if not ufilled:
                        await browser.close()
                        return {"ok": False, "reason": "username field not found"}
                # 3) 제출(명시 셀렉터 → submit 버튼 후보 → Enter)
                submitted = False
                if s_sel:
                    try:
                        await page.click(s_sel, timeout=tmo); submitted = True
                    except Exception:
                        pass
                if not submitted:
                    for sel in ("button[type=submit]", "input[type=submit]",
                                "button:has-text('로그인')", "button:has-text('Login')",
                                "button:has-text('Sign in')", "button:has-text('Log in')"):
                        try:
                            if await page.locator(sel).count() > 0:
                                await page.click(sel, timeout=5000); submitted = True; break
                        except Exception:
                            continue
                if not submitted:
                    try:
                        await page.press(pfield, "Enter")
                    except Exception:
                        pass
                try:
                    await page.wait_for_load_state("networkidle", timeout=tmo)
                except Exception:
                    pass
                final_url = page.url
                cookies = await ctx.cookies()
                try:
                    body = await page.content()
                except Exception:
                    body = ""
            finally:
                await browser.close()
    except Exception as e:
        return {"ok": False, "reason": f"browser login error: {type(e).__name__}"}

    # 성공 판정: 세션성 쿠키 발급 or 로그인 URL 이탈
    has_sess = any(_SESSION_NAME_RE.search(c.get("name", "") or "") for c in cookies)
    fl = (final_url or "").lower()
    moved = ("login" not in fl and "signin" not in fl and final_url != login_url)
    ok = bool(has_sess or moved)
    return {"ok": ok, "cookies": cookies, "final_url": final_url, "body": body,
            "reason": "browser login ok" if ok else "browser login uncertain (no session/redirect)"}


def _session_from_browser_cookies(cookies: list, timeout: float = 8.0):
    """playwright 쿠키를 aiohttp 세션 쿠키 jar 로 옮긴다(이후 크롤에 인증 세션으로 사용)."""
    session = _make_session(timeout=timeout)
    try:
        from yarl import URL
        for c in cookies or []:
            name = c.get("name"); val = c.get("value")
            if not name:
                continue
            dom = (c.get("domain") or "").lstrip(".")
            path = c.get("path") or "/"
            scheme = "https" if c.get("secure") else "http"
            ref = URL(f"{scheme}://{dom}{path}") if dom else None
            try:
                session.cookie_jar.update_cookies({name: val}, response_url=ref)
            except Exception:
                try:
                    session.cookie_jar.update_cookies({name: val})
                except Exception:
                    pass
    except Exception:
        pass
    return session


async def _http_form_login(config, login_url: str, username: str, password: str,
                           timeout: float, limiter=None, stop_on_lock: bool = True) -> dict:
    """HTTP 폼 로그인: 폼 action 자동탐지 + `auth_login_action`(override) + form/json 본문 +
    `auth_extra_fields`(토큰 등 추가필드)."""
    session = _make_session(timeout=timeout)
    try:
        if limiter:
            await limiter.acquire()
        _status, login_body, _ = await _http_get(session, login_url, timeout=timeout)
        if stop_on_lock and _has_lock_hint(login_body):
            await _close(session)
            return {"session": None, "ok": False, "method": "http",
                    "reason": "account lock hint before login"}
        forms_on_page = _parse_forms(login_url, login_body)
        login_form = None
        for f in forms_on_page:
            keys = {k.lower() for k in (f.get("params") or {})}
            if any(any(h in k for h in _USER_FIELD_HINTS) for k in keys) and \
               any(any(h in k for h in _PASS_FIELD_HINTS) for k in keys):
                login_form = f
                break
        user_field, pass_field, base_params = _detect_login_fields(login_form, config)
        if not user_field or not pass_field:
            await _close(session)
            return {"session": None, "ok": False, "method": "http",
                    "reason": "could not detect username/password fields"}
        # 실제 요청 URL: 사용자 지정(override) > 폼 action > 로그인 페이지 URL
        post_url = (getattr(config, "auth_login_action", "") or "").strip() \
            or (login_form or {}).get("url") or login_url
        data = dict(base_params)
        data[user_field] = username
        data[pass_field] = password
        for k, v in (getattr(config, "auth_extra_fields", None) or {}).items():
            data[str(k)] = v
        if limiter:
            await limiter.acquire()
        body_mode = (getattr(config, "auth_login_body_mode", "form") or "form").lower()
        if body_mode == "json":
            st, body, headers = await _http_post_json(session, post_url, data, timeout=timeout)
        else:
            st, body, headers = await _http_post(session, post_url, data, timeout=timeout)
        if stop_on_lock and _has_lock_hint(body):
            await _close(session)
            return {"session": None, "ok": False, "method": "http",
                    "reason": "account lock hint during login"}
        ok = _judge_login_success(login_body, st, body, headers, login_url,
                                  getattr(config, "auth_success_pattern", "auto") or "auto")
        if not ok:
            await _close(session)
            return {"session": None, "ok": False, "method": "http",
                    "reason": f"login failed for {mask_value(username)}"}
        return {"session": session, "ok": True, "reason": "http login ok", "method": "http",
                "login_body": login_body, "post_body": body, "post_headers": headers,
                "post_url": post_url}
    except Exception as e:
        await _close(session)
        return {"session": None, "ok": False, "method": "http", "reason": f"login error: {e}"}


async def _browser_path(config, login_url: str, username: str, password: str,
                        timeout: float) -> dict:
    """브라우저 로그인 → aiohttp 세션(쿠키 이관)."""
    bl = await browser_login(config, login_url, username, password, timeout)
    if not bl.get("ok"):
        return {"session": None, "ok": False, "method": "browser",
                "reason": f"browser login failed: {bl.get('reason')}"}
    session = _session_from_browser_cookies(bl.get("cookies") or [], timeout)
    return {"session": session, "ok": True, "reason": "browser login ok", "method": "browser",
            "login_body": "", "post_body": bl.get("body") or "", "post_headers": {},
            "post_url": bl.get("final_url") or login_url}


async def _establish_session(config, base_url: str, login_url: str, username: str,
                             password: str, timeout: float, limiter=None,
                             stop_on_lock: bool = True) -> dict:
    """통합 로그인. method: 'http'(폼만) / 'browser'(브라우저만) / 'auto'(기본: HTTP 우선 → 실패 시 브라우저).

    'auto' 가 HTTP 우선인 이유: 표준 폼은 빠른 HTTP 로 처리하고, HTTP 가 실패하는
    JS/SPA·클라이언트 해시PW·동적 토큰 케이스에서만 브라우저로 승격한다(기존 동작 보존).
    반환: {"session","ok","reason","method","login_body","post_body","post_headers","post_url"}.
    """
    method = (getattr(config, "auth_login_method", "auto") or "auto").lower()
    if method == "browser":
        return await _browser_path(config, login_url, username, password, timeout)
    http_res = await _http_form_login(config, login_url, username, password,
                                      timeout, limiter=limiter, stop_on_lock=stop_on_lock)
    if http_res.get("ok") or method == "http":
        return http_res
    # auto: HTTP 실패 → 브라우저 승격(JS/SPA·해시PW·토큰)
    br = await _browser_path(config, login_url, username, password, timeout)
    return br if br.get("ok") else http_res


async def perform_login_and_crawl(config, base_url: str) -> dict:
    """단일 계정으로 로그인 후 same-origin 크롤 수행.

    반환: {"logged_in", "session", "urls", "forms", "reason"}.
    """
    # 인증 스캔 비활성 / 계정 미제공 → 생략.
    if not getattr(config, "enable_auth_scan", False):
        return _result(False, None, [], [], "auth scan disabled")
    login_url = getattr(config, "auth_login_url", "") or ""
    username = getattr(config, "auth_username", "") or ""
    password = getattr(config, "auth_password", "") or ""
    if not (login_url and username and password):
        return _result(False, None, [], [], "no credentials provided")

    timeout = float(getattr(config, "request_timeout", 8.0) or 8.0)
    same_origin = bool(getattr(config, "same_origin_only", True))
    max_pages = int(getattr(config, "auth_max_pages", 50) or 50)
    success_pattern = getattr(config, "auth_success_pattern", "auto") or "auto"
    stop_on_lock = bool(getattr(config, "stop_on_account_lock_hint", True))

    # rate limiter: 전역 + auth_rps 결합
    global_rps = _safe_rps(float(getattr(config, "global_rps", 10.0) or 10.0))
    auth_rps = float(getattr(config, "auth_rps", 2.0) or 2.0)
    limiter = CompositeRateLimiter(RateLimiter(global_rps), RateLimiter(auth_rps))

    # 1~3) 통합 로그인(브라우저 우선 → HTTP 폴백: action override·JSON본문·추가필드)
    res = await _establish_session(config, base_url, login_url, username, password,
                                   timeout, limiter=limiter, stop_on_lock=stop_on_lock)
    if not res.get("ok"):
        return _result(False, None, [], [], res.get("reason") or "login failed")
    session = res["session"]
    try:
        # 4) 로그인 성공 → same-origin 크롤
        urls, forms = await _crawl(session, base_url, login_url, res.get("post_body") or "",
                                   max_pages, same_origin, timeout, limiter, stop_on_lock)
        return _result(True, session, urls, forms, f"login successful ({res.get('method')})")
    except Exception as e:
        await _close(session)
        return _result(False, None, [], [], f"auth crawl error: {e}")


_LOGOUT_URL_RE = re.compile(r'(?:logout|log-?out|log_out|logoff|sign-?out|sign_out)', re.IGNORECASE)


def _is_logout_url(u: str) -> bool:
    """로그아웃/로그오프/사인아웃 URL 여부. 인증 크롤이 이런 URL 을 방문하면 스스로 로그아웃돼
    이후 인증 세션(쿠키)이 무효가 되고 인증 영역 점검이 전부 로그인으로 튕긴다 → 절대 방문 금지."""
    return bool(u and _LOGOUT_URL_RE.search(str(u)))


# 보안 태세(IDS/WAF·보안수준) 제어 링크. 인증 크롤이 이런 링크를 따라가면 대상의 방어를 켜거나
# (예: DVWA security.php?phpids=on → 이후 모든 페이로드가 "Hacking attempt" 로 차단) 취약 수준을
# 바꿔 스캔 전체의 탐지를 무력화하고 대상 상태를 변경한다(비파괴 위배) → 크롤 방문 금지.
_SECURITY_CONTROL_URL_RE = re.compile(
    r'/security\.php(?:$|\?)|/(?:security|settings|config|admin)/(?:level|mode|waf|ids|phpids)'
    r'|[?&](?:phpids|security_?level|seclev(?:_submit)?|ids_?mode|waf(?:_?mode)?|security_?mode)=',
    re.IGNORECASE)


def _is_security_control_url(u: str) -> bool:
    """보안 제어(IDS/WAF/보안수준 토글) URL 여부 — 인증 크롤 방문 금지(자기 탐지 무력화·상태변경 방지)."""
    return bool(u and _SECURITY_CONTROL_URL_RE.search(str(u)))


def _skip_crawl_url(u: str) -> bool:
    """크롤이 방문하면 안 되는 URL(로그아웃 자기-DoS · 보안설정 토글)."""
    return _is_logout_url(u) or _is_security_control_url(u)


async def _crawl(session, base_url, login_url, initial_body, max_pages,
                 same_origin, timeout, limiter, stop_on_lock) -> tuple[list, list]:
    """로그인된 세션으로 same-origin BFS 크롤. 폼/링크/query 주입 지점 수집.
    ★ 로그아웃 URL 은 큐에 절대 넣지 않는다(방문 시 세션이 로그아웃돼 인증 점검이 무력화됨)."""
    visited: set = set()
    crawl_urls: list = []
    forms: list = []
    forms_seen: set = set()

    def _add_forms(new_pts: list):
        for pt in new_pts:
            key = (pt.get("method", "GET"), pt.get("url", ""),
                   tuple(sorted((pt.get("params") or {}).keys())))
            if key in forms_seen:
                continue
            forms_seen.add(key)
            forms.append(pt)

    # 시작 페이지: 로그인 후 응답 본문(있으면) + base_url
    seeds: list = []
    if base_url:
        seeds.append(base_url)
    if login_url and login_url not in seeds:
        seeds.append(login_url)
    queue: list = list(seeds)

    # 로그인 응답 본문에서 즉시 폼/링크 수집(추가 요청 없이)
    if initial_body:
        _add_forms(_parse_forms(login_url, initial_body))
        link_urls, q_pts = _parse_links(login_url, initial_body)
        _add_forms(q_pts)
        for u in link_urls:
            if u and u not in queue and not _skip_crawl_url(u):
                queue.append(u)

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if not url or url in visited:
            continue
        if _skip_crawl_url(url):
            continue   # 로그아웃/보안설정 토글 URL 방문 금지 — 세션·탐지력 보존
        if same_origin and not _same_origin(base_url, url):
            continue
        visited.add(url)
        crawl_urls.append(url)

        await limiter.acquire()
        st, body, _hdr = await _http_get(session, url, timeout=timeout)
        if stop_on_lock and _has_lock_hint(body):
            break
        if not body:
            continue

        _add_forms(_parse_forms(url, body))
        link_urls, q_pts = _parse_links(url, body)
        _add_forms(q_pts)
        for u in link_urls:
            if not u or u in visited or u in queue or _skip_crawl_url(u):
                continue
            if same_origin and not _same_origin(base_url, u):
                continue
            if len(visited) + len(queue) >= max_pages:
                break
            queue.append(u)

    return crawl_urls, forms


async def _login_only(config, login_url, username, password, timeout, limiter, stop_on_lock):
    """단일 계정 1회 로그인 → (session, ok, reason). 크롤은 하지 않는다.
    통합 엔진(_establish_session) 사용 — 브라우저 우선 → HTTP 폴백(action override·JSON·추가필드)."""
    res = await _establish_session(config, login_url, login_url, username, password,
                                   timeout, limiter=limiter, stop_on_lock=stop_on_lock)
    return res.get("session"), bool(res.get("ok")), res.get("reason") or ""


async def verify_idor_dual_account(config, base_url: str, idor_candidates: list[dict]) -> dict:
    """계정 A/B 로 IDOR 후보를 '읽기 전용'으로 교차 검증(비파괴).

    필요 설정: auth_login_url, auth_username/password(A), auth_username_b/password_b(B).
    반환: {"performed", "reason", "results"[], "summary"{}}.
    """
    import candidate_verification as cv

    login_url = getattr(config, "auth_login_url", "") or ""
    ua = getattr(config, "auth_username", "") or ""
    pa = getattr(config, "auth_password", "") or ""
    ub = getattr(config, "auth_username_b", "") or ""
    pb = getattr(config, "auth_password_b", "") or ""
    if not (login_url and ua and pa and ub and pb):
        return {"performed": False, "reason": "두 번째 테스트 계정(B) 미설정 — IDOR 교차검증 생략",
                "results": [], "summary": cv.summarize_verification(len(idor_candidates or []), 0, [])}

    timeout = float(getattr(config, "request_timeout", 8.0) or 8.0)
    stop_on_lock = bool(getattr(config, "stop_on_account_lock_hint", True))
    global_rps = _safe_rps(float(getattr(config, "global_rps", 10.0) or 10.0))
    auth_rps = float(getattr(config, "auth_rps", 2.0) or 2.0)
    limiter = CompositeRateLimiter(RateLimiter(global_rps), RateLimiter(auth_rps))

    sess_a, ok_a, ra = await _login_only(config, login_url, ua, pa, timeout, limiter, stop_on_lock)
    if not ok_a:
        return {"performed": False, "reason": f"계정 A 로그인 실패: {ra}",
                "results": [], "summary": cv.summarize_verification(len(idor_candidates or []), 0, [])}
    sess_b, ok_b, rb = await _login_only(config, login_url, ub, pb, timeout, limiter, stop_on_lock)
    if not ok_b:
        await _close(sess_a)
        return {"performed": False, "reason": f"계정 B 로그인 실패: {rb}",
                "results": [], "summary": cv.summarize_verification(len(idor_candidates or []), 0, [])}

    async def get_a(url):
        await limiter.acquire()
        st, body, hdr = await _http_get(sess_a, url, timeout=timeout)
        return {"status": st, "body": body, "headers": hdr}

    async def get_b(url):
        await limiter.acquire()
        st, body, hdr = await _http_get(sess_b, url, timeout=timeout)
        return {"status": st, "body": body, "headers": hdr}

    try:
        results = await cv.verify_idor_candidates(
            idor_candidates, get_a, get_b,
            owner_identity=[ua], cross_identity=[ub],
            max_targets=int(getattr(config, "idor_verify_max", 20) or 20),
        )
    finally:
        await _close(sess_a)
        await _close(sess_b)

    summary = cv.summarize_verification(
        len(idor_candidates or []), len(results), [r.get("grade") for r in results])
    return {"performed": True, "reason": "IDOR 교차검증 수행", "results": results, "summary": summary}


async def _verify_one_write(aw, c: dict, sess_a, sess_b, limiter, timeout: float,
                            stop_on_lock: bool) -> dict | None:
    """단일 후보에 대한 '수정-후-원복' 교차검증. A 소유 데이터만 건드리고 항상 원복한다."""
    view_url = c.get("view_url") or c.get("url")
    method = c.get("method") or "POST"
    url = c.get("url")
    params = dict(c.get("params") or {})
    field = c.get("mutable_field")

    # 1) A 소유/접근 확인 + 현재 값 캡처(원복 정확도↑)
    await limiter.acquire()
    a_st, a_body, _ = await _http_get(sess_a, view_url, timeout=timeout)
    if stop_on_lock and _has_lock_hint(a_body):
        return {"candidate": {"url": url, "method": method, "field": field},
                "grade": None, "reason": "계정 잠금 징후 — 중단"}
    a_owns = 200 <= a_st < 300
    if not a_owns:
        return {"candidate": {"url": url, "method": method, "field": field},
                "grade": None, "reason": f"A 소유/접근 미확인(status {a_st})"}
    # D-b1: 대상 필드만이 아니라 '모든 폼 필드의 실제 현재값'을 A 응답에서 캡처한다.
    # (기존엔 비대상 필드를 폼 파싱 placeholder('test' 등)로 전송/원복해 A 데이터를 영구 손상시켰음)
    original_state = {}
    for _k in params:
        _v = aw.extract_field_value(a_body, _k)
        original_state[_k] = _v if _v is not None else params.get(_k, "")
    original_value = original_state.get(field, params.get(field, ""))
    marker = aw.write_marker(str(url) + str(field))

    # 2) B(타 계정)가 수정 시도 — 대상 필드만 marker, 나머지는 A 의 '실제 원본값' 유지(placeholder 금지)
    modified = dict(original_state)
    modified[field] = marker
    await limiter.acquire()
    b_st, _b_body, _ = await _http_request(sess_b, method, url, modified, timeout=timeout)

    # 3) A 재조회로 marker 반영 여부 확인
    readback = None
    await limiter.acquire()
    a2_st, a2_body, _ = await _http_get(sess_a, view_url, timeout=timeout)
    if 200 <= a2_st < 300:
        readback = marker in (a2_body or "")

    # 4) 원복: B 가 '명시적으로 차단(401/403/405)'된 경우가 아니면 항상 원복을 시도한다.
    #    302 성공 등으로 실제 변경 여부가 불확실할 수 있는데, 원복은 A 의 '원본값 재기록'이라
    #    미변경 시에도 무해하므로, 데이터 무결성을 위해 폭넓게 원복한다(SAFE 원칙).
    #    원복 후 marker 잔존 여부를 재조회로 검증하고, 원복 불가 케이스는 조용히 넘기지 않고 표면화한다.
    reverted = None
    revert_warning = None
    _b_blocked = b_st in (401, 403, 405)
    if not _b_blocked:
        try:
            await limiter.acquire()
            rv_st, _, _ = await _http_request(sess_a, method, url, dict(original_state), timeout=timeout)
            reverted = 200 <= rv_st < 400
            # 원복 검증: A 재조회에 marker 가 남아있으면 원복 실패로 판정
            await limiter.acquire()
            v_st, v_body, _ = await _http_get(sess_a, view_url, timeout=timeout)
            if 200 <= v_st < 300 and marker in (v_body or ""):
                reverted = False
        except Exception:
            reverted = False
        if reverted is False:
            revert_warning = (f"자동 원복 실패(status/검증 불통) — 대상 필드 '{field}' 를 수동으로 "
                              f"원본값('{str(original_value)[:60]}')으로 되돌려 주세요.")

    grade = aw.judge_write_authz(b_st, readback, a_owns)
    reason = ("B 가 A 소유 데이터를 수정함 — 쓰기 권한 통제 실패" if grade == "CONFIRMED_WRITE"
              else "B 수정 요청 수락(반영 미확정) — 수동 확인 권장" if grade == "POSSIBLE"
              else "B 차단/미반영 — 취약 아님")
    return {"candidate": {"url": url, "method": method, "field": field},
            "grade": grade, "b_status": b_st, "readback_marker": readback,
            "reverted": reverted, "revert_warning": revert_warning, "reason": reason}


async def verify_write_authz_dual_account(config, base_url: str,
                                          write_candidates: list) -> dict:
    """계정 A/B 로 '쓰기 권한 통제'를 검증한다(수정-후-원복, 본인 소유 데이터만, 비파괴).

    - A/B 두 테스트 계정이 모두 설정돼 있어야 수행(없으면 performed=False).
    - 각 후보: A 소유 확인 → B 가 수정 시도 → A 재조회로 반영 확인 → A 가 원복.
    - 삭제는 기본 미수행(되돌리기 불가). 제3자 데이터는 대상이 아니다.
    반환: {"performed","reason","results"[],"summary"{tested,confirmed,possible}}
    """
    import authz_write as aw

    login_url = getattr(config, "auth_login_url", "") or ""
    ua = getattr(config, "auth_username", "") or ""
    pa = getattr(config, "auth_password", "") or ""
    ub = getattr(config, "auth_username_b", "") or ""
    pb = getattr(config, "auth_password_b", "") or ""
    empty = {"tested": 0, "confirmed": 0, "possible": 0}
    if not (login_url and ua and pa and ub and pb):
        return {"performed": False,
                "reason": "쓰기 권한 검증 생략 — A/B 두 테스트 계정 필요",
                "results": [], "summary": empty}

    allow_destructive = bool(getattr(config, "write_authz_allow_delete", False))
    cands = [c for c in (write_candidates or [])
             if aw.safety_guard(c, allow_destructive=allow_destructive)[0]]
    if not cands:
        return {"performed": False, "reason": "안전하게 검증 가능한 쓰기 후보 없음",
                "results": [], "summary": empty}

    timeout = float(getattr(config, "request_timeout", 8.0) or 8.0)
    stop_on_lock = bool(getattr(config, "stop_on_account_lock_hint", True))
    global_rps = _safe_rps(float(getattr(config, "global_rps", 10.0) or 10.0))
    auth_rps = float(getattr(config, "auth_rps", 2.0) or 2.0)
    limiter = CompositeRateLimiter(RateLimiter(global_rps), RateLimiter(auth_rps))
    max_targets = int(getattr(config, "idor_verify_max", 20) or 20)

    sess_a, ok_a, ra = await _login_only(config, login_url, ua, pa, timeout, limiter, stop_on_lock)
    if not ok_a:
        return {"performed": False, "reason": f"계정 A 로그인 실패: {ra}",
                "results": [], "summary": empty}
    sess_b, ok_b, rb = await _login_only(config, login_url, ub, pb, timeout, limiter, stop_on_lock)
    if not ok_b:
        await _close(sess_a)
        return {"performed": False, "reason": f"계정 B 로그인 실패: {rb}",
                "results": [], "summary": empty}

    results = []
    try:
        for c in cands[:max_targets]:
            r = await _verify_one_write(aw, c, sess_a, sess_b, limiter, timeout, stop_on_lock)
            if r:
                results.append(r)
    finally:
        await _close(sess_a)
        await _close(sess_b)

    confirmed = sum(1 for r in results if r.get("grade") == "CONFIRMED_WRITE")
    possible = sum(1 for r in results if r.get("grade") == "POSSIBLE")
    return {"performed": True, "reason": "쓰기 권한 교차검증 수행(수정-후-원복)",
            "results": results,
            "summary": {"tested": len(results), "confirmed": confirmed, "possible": possible}}


async def verify_bfla_matrix(config, base_url: str, endpoints: list) -> dict:
    """BFLA(Broken Function-Level Authorization) 인가 매트릭스 검증(읽기 전용·비파괴).

    특권(관리/내부/기능) 엔드포인트마다 익명/계정B/계정A 로 GET 접근을 관측해,
    낮은 권한이 접근 가능한지 판정한다. 상태 변경 없음(GET 만) → SAFE.
    - 익명 접근은 자격증명 없이 항상 시도(missing-auth 강제 브라우징).
    - A/B 는 자격증명이 있을 때만 로그인(있을수록 매트릭스가 풍부).
    반환: {"performed","reason","results"[],"matrix"{},"summary"{tested,confirmed,possible}}
    """
    import authz_matrix as am

    empty = {"tested": 0, "confirmed": 0, "possible": 0}
    if not endpoints:
        return {"performed": False, "reason": "특권 엔드포인트 없음 — BFLA 검증 생략",
                "results": [], "matrix": am.build_matrix([]), "summary": empty}

    login_url = getattr(config, "auth_login_url", "") or ""
    ua = getattr(config, "auth_username", "") or ""
    pa = getattr(config, "auth_password", "") or ""
    ub = getattr(config, "auth_username_b", "") or ""
    pb = getattr(config, "auth_password_b", "") or ""
    role_a = getattr(config, "auth_role_a", "") or ""
    role_b = getattr(config, "auth_role_b", "") or ""
    timeout = float(getattr(config, "request_timeout", 8.0) or 8.0)
    stop_on_lock = bool(getattr(config, "stop_on_account_lock_hint", True))
    global_rps = _safe_rps(float(getattr(config, "global_rps", 10.0) or 10.0))
    auth_rps = float(getattr(config, "auth_rps", 2.0) or 2.0)
    limiter = CompositeRateLimiter(RateLimiter(global_rps), RateLimiter(auth_rps))
    max_targets = int(getattr(config, "idor_verify_max", 20) or 20)

    sess_a = sess_b = None
    if login_url and ua and pa:
        sess_a, ok_a, _ = await _login_only(config, login_url, ua, pa, timeout, limiter, stop_on_lock)
        if not ok_a:
            sess_a = None
    if login_url and ub and pb:
        sess_b, ok_b, _ = await _login_only(config, login_url, ub, pb, timeout, limiter, stop_on_lock)
        if not ok_b:
            sess_b = None
    anon = _make_session(timeout=timeout)

    async def _cls(sess, url):
        if sess is None:
            return None
        await limiter.acquire()
        st, body, _ = await _http_get(sess, url, timeout=timeout)
        return am.classify_access(st, body)

    results = []
    try:
        for ep in endpoints[:max_targets]:
            url = ep.get("url")
            if not url:
                continue
            await limiter.acquire()
            _an_st, _an_body, _ = await _http_get(anon, url, timeout=timeout)
            anon_cls = am.classify_access(_an_st, _an_body)
            b_cls = await _cls(sess_b, url)
            a_cls = await _cls(sess_a, url)
            grade, cat, reason = am.judge_bfla(anon_cls, b_cls, a_cls, role_a, role_b)
            results.append({"endpoint": ep, "anon": anon_cls, "b": b_cls, "a": a_cls,
                            "grade": grade, "category": cat, "reason": reason})
    finally:
        await _close(sess_a)
        await _close(sess_b)
        await _close(anon)

    return {"performed": True,
            "reason": "BFLA 인가 매트릭스 검증 수행(읽기 전용)",
            "results": results, "matrix": am.build_matrix(results),
            "summary": am.summarize(results)}


async def _close(session):
    try:
        if session is not None and hasattr(session, "close"):
            res = session.close()
            if hasattr(res, "__await__"):
                await res
    except Exception:
        pass
