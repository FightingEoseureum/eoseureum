"""
input_points.py — 입력점 발굴/표준화 (순수 함수, 네트워크 없음).

HTML 에서 form/input/textarea/select 와 GET 쿼리 파라미터를 표준 입력점으로 추출하고,
검색창/로그인/관리자/API 컨텍스트를 분류한다. 능동 점검(XSS/SQLi)·인증 후 크롤링이 공통으로 사용.

표준 입력점 구조:
  {
    "url": str, "method": "GET|POST", "param": str, "input_type": str,
    "source": "query|form|hidden|textarea|select|json|crawler",
    "context": "search|login|generic|admin|api", "authenticated": bool,
  }
"""
from __future__ import annotations

import re
import urllib.parse

_SEARCH_NAMES = {"q", "query", "search", "keyword", "find", "s", "term", "keywords"}
_SEARCH_HINT_RE = re.compile(r"search|query|keyword|find|검색", re.IGNORECASE)
_ADMIN_HINT_RE = re.compile(r"admin|administrator|manage|관리자", re.IGNORECASE)

_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_ATTR_RE = lambda attr: re.compile(attr + r'\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_ACTION_RE = _ATTR_RE("action")
_METHOD_RE = _ATTR_RE("method")
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_TEXTAREA_RE = re.compile(r"<textarea\b[^>]*>", re.IGNORECASE)
_SELECT_RE = re.compile(r"<select\b[^>]*>", re.IGNORECASE)
_NAME_RE = _ATTR_RE("name")
_TYPE_RE = _ATTR_RE("type")
_ID_RE = _ATTR_RE("id")
_PLACEHOLDER_RE = _ATTR_RE("placeholder")
_VALUE_RE = _ATTR_RE("value")


def classify_context(name: str = "", input_type: str = "", placeholder: str = "",
                     action: str = "", url: str = "", has_password: bool = False) -> str:
    """입력점 컨텍스트 분류: search / login / admin / api / generic."""
    blob = " ".join([name or "", placeholder or "", action or "", url or ""]).lower()
    if has_password or (input_type or "").lower() == "password":
        return "login"
    if (name or "").lower() in _SEARCH_NAMES or _SEARCH_HINT_RE.search(blob):
        return "search"
    if "/api/" in blob or blob.endswith(".json") or ".json?" in blob:
        return "api"
    if _ADMIN_HINT_RE.search(blob):
        return "admin"
    return "generic"


def _attr(tag: str, rx) -> str:
    m = rx.search(tag)
    return m.group(1) if m else ""


def parse_forms(html: str, page_url: str, authenticated: bool = False) -> list[dict]:
    """HTML 의 모든 form 에서 표준 입력점을 추출한다(form/hidden/textarea/select)."""
    points: list[dict] = []
    if not html:
        return points
    for fm in _FORM_RE.finditer(html):
        # form 헤더(여는 태그)에서 action/method
        head_end = html.find(">", fm.start())
        head = html[fm.start():head_end + 1] if head_end != -1 else ""
        action = _attr(head, _ACTION_RE) or page_url
        method = (_attr(head, _METHOD_RE) or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"
        try:
            form_url = urllib.parse.urljoin(page_url, action)
        except Exception:
            form_url = page_url
        body = fm.group(1)

        # 폼 내 password 존재 여부 → 로그인 폼 판정
        has_password = bool(re.search(r'type\s*=\s*["\']password["\']', body, re.IGNORECASE))

        def _emit(name, itype, source):
            if not name:
                return
            ctx = classify_context(name=name, input_type=itype,
                                   action=action, url=form_url, has_password=has_password)
            points.append({
                "url": form_url, "method": method, "param": name,
                "input_type": itype or "text",
                "source": source, "context": ctx, "authenticated": authenticated,
            })

        for tag in _INPUT_RE.findall(body):
            itype = (_attr(tag, _TYPE_RE) or "text").lower()
            if itype in ("submit", "button", "image", "reset"):
                continue
            name = _attr(tag, _NAME_RE)
            ph = _attr(tag, _PLACEHOLDER_RE)
            src = "hidden" if itype == "hidden" else "form"
            if name:
                ctx = classify_context(name=name, input_type=itype, placeholder=ph,
                                       action=action, url=form_url, has_password=has_password)
                points.append({
                    "url": form_url, "method": method, "param": name,
                    "input_type": itype, "source": src,
                    "context": ctx, "authenticated": authenticated,
                })
        for tag in _TEXTAREA_RE.findall(body):
            _emit(_attr(tag, _NAME_RE), "textarea", "textarea")
        for tag in _SELECT_RE.findall(body):
            _emit(_attr(tag, _NAME_RE), "select", "select")
    return points


def query_input_points(url: str, authenticated: bool = False) -> list[dict]:
    """URL 의 GET 쿼리 파라미터를 표준 입력점으로 추출한다."""
    if not url:
        return []
    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        return []
    points = []
    for k in urllib.parse.parse_qs(p.query):
        clean = f"{p.scheme}://{p.netloc}{p.path}" if p.scheme else url.split("?", 1)[0]
        points.append({
            "url": clean, "method": "GET", "param": k, "input_type": "text",
            "source": "query",
            "context": classify_context(name=k, url=url),
            "authenticated": authenticated,
        })
    return points


def is_login_form_points(points: list[dict]) -> bool:
    """입력점 묶음에 password 입력(=로그인 폼)이 있는지."""
    return any((p.get("input_type") or "").lower() == "password"
               or p.get("context") == "login" for p in (points or []))


def extract_input_points(html: str, page_url: str, authenticated: bool = False) -> list[dict]:
    """페이지 HTML + URL 에서 표준 입력점 전체를 추출(GET 쿼리 + form/input)."""
    pts = query_input_points(page_url, authenticated) + parse_forms(html, page_url, authenticated)
    # (method, url, param, source) 기준 중복 제거
    seen, out = set(), []
    for p in pts:
        key = (p["method"], p["url"], p["param"], p["source"])
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def search_input_points(points: list[dict]) -> list[dict]:
    return [p for p in points if p.get("context") == "search"]


def login_form_points(points: list[dict]) -> list[dict]:
    return [p for p in points if p.get("context") == "login"]
