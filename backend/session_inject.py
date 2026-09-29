"""session_inject.py — 세션 주입 인증(캡챠·OTP·SSO 대상용).

사람이 브라우저로 1회 로그인(캡챠/OTP 수동 통과)한 뒤 그 '인증된 세션'을 스캐너가 재사용한다.
로그인 폼을 건너뛰고, 대상 호스트로 나가는 모든 요청에 사용자가 제공한 인증 헤더(예:
`Authorization: JWT <token>`)·쿠키를 주입한다.

per-scan 격리: contextvar. 미설치 시 headers_for()=빈 dict → 기존 동작 무영향.
보안: 주입 헤더/쿠키는 '대상 호스트(및 서브도메인)'로 나가는 요청에만 붙인다 — 제3자 호스트(CDN 등)
로 세션 토큰이 유출되지 않도록 스코프를 강제한다.
"""
from __future__ import annotations

import contextvars
import urllib.parse

_ctx: contextvars.ContextVar = contextvars.ContextVar("eos_session_inject", default=None)


def host_from_target(target: str) -> str:
    """대상 문자열(도메인 또는 URL)에서 스코프 기준 호스트명을 추출한다.
    'app.example.com' / 'https://app.example.com/x' → 'app.example.com'. install(host=) 에 사용."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "http://" + t
    return (urllib.parse.urlparse(t).hostname or (target or "").strip()).lower()


def parse_headers(raw) -> dict:
    """사용자 입력(문자열 여러 줄 'Key: Value' 또는 dict)을 헤더 dict 로 파싱."""
    if isinstance(raw, dict):
        return {str(k).strip(): str(v).strip() for k, v in raw.items() if str(k).strip()}
    out: dict = {}
    if not raw:
        return out
    for line in str(raw).replace("\r", "").split("\n"):
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        v = v.strip()
        if k:
            out[k] = v
    return out


def _cookie_string(cookies) -> str:
    """쿠키 입력(문자열 'a=1; b=2' 또는 dict)을 Cookie 헤더 문자열로."""
    if not cookies:
        return ""
    if isinstance(cookies, dict):
        return "; ".join(f"{k}={v}" for k, v in cookies.items() if k)
    return str(cookies).strip()


def install(headers=None, cookies=None, host: str = "") -> dict | None:
    """세션 주입 설치. headers: dict/문자열, cookies: dict/문자열, host: 대상 호스트(스코프 제한).
    유효한 헤더/쿠키가 없으면 설치하지 않고 None 반환."""
    h = parse_headers(headers)
    ck = _cookie_string(cookies)
    if ck and "Cookie" not in {k.title() for k in h}:
        h["Cookie"] = ck
    if not h:
        return None
    th = (host or "").strip().lower()
    try:
        # host 에 스킴이 섞여오면 hostname 만 추출
        if "://" in th or "/" in th:
            th = urllib.parse.urlparse(th if "://" in th else "http://" + th).hostname or th
    except Exception:
        pass
    state = {"headers": h, "host": th}
    _ctx.set(state)
    return state


def update_headers(new_headers) -> dict | None:
    """설치된 세션의 헤더를 갱신(예: refresh 로 재발급한 Authorization 교체). 미설치면 None.

    ★ 제자리(in-place) 변경 — contextvar 재할당이 아니라 기존 headers dict 를 mutate 한다.
    asyncio 태스크는 생성 시 컨텍스트를 '얕게' 복사하므로, install 이후 만들어진 모든 프로브
    태스크가 같은 headers dict 객체를 공유한다 → in-place update 는 전 태스크에 즉시 반영되지만
    _ctx.set(새객체) 는 호출한 태스크에만 보이고 다른 태스크엔 안 보인다(격리). 그래서 mutate 필수."""
    st = _ctx.get()
    if not st:
        return None
    nh = parse_headers(new_headers)
    if not nh:
        return st
    st["headers"].update(nh)   # 같은 키(Authorization 등)는 새 값으로 교체 — 공유 dict 제자리 변경
    return st


def uninstall() -> None:
    _ctx.set(None)


def current() -> dict | None:
    return _ctx.get()


def _in_scope(url: str, target_host: str) -> bool:
    if not target_host:
        return True   # 대상 호스트 미상 → 보수적으로 허용(하지만 install 은 항상 host 지정 권장)
    try:
        h = (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return False
    return h == target_host or h.endswith("." + target_host)


def headers_for(url: str) -> dict:
    """해당 URL(대상 호스트/서브도메인)에 주입할 인증 헤더. 미설치·스코프밖이면 빈 dict."""
    st = _ctx.get()
    if not st:
        return {}
    if not _in_scope(url, st.get("host", "")):
        return {}   # 제3자 호스트 → 토큰 미주입(유출 방지)
    return dict(st["headers"])


def active() -> bool:
    return _ctx.get() is not None
