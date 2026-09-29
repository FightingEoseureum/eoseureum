"""
request_recorder.py — 브라우저 네트워크 요청을 '마스킹된 메타데이터'로만 기록한다.

원칙: 원문(response body)은 저장하지 않는다. 민감 헤더/쿠키/토큰/자격증명은 저장 전 마스킹한다.
Playwright 의존 없음 — 오케스트레이터가 추출한 순수 dict 를 입력받아 결정적으로 동작한다.
"""
from __future__ import annotations

import json
import re as _re
from urllib.parse import urlparse, parse_qsl

MASK = "***MASKED***"
_BODY_LIMIT = 512   # post_data 저장 길이 제한

SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie", "proxy-authorization",
    "x-api-key", "x-auth-token", "x-access-token", "x-csrf-token",
}
SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "token", "access_token", "refresh_token",
    "session", "sessionid", "session_id", "api_key", "apikey", "secret",
    "jwt", "authorization", "auth", "credential", "client_secret",
}
_JWT_RX = _re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
_XHR_TYPES = {"xhr", "fetch"}


def _is_sensitive_key(k: str) -> bool:
    kl = (k or "").strip().lower()
    return any(s == kl or s in kl for s in SENSITIVE_KEYS)


def mask_value(key: str, value):
    if _is_sensitive_key(key):
        return MASK
    if isinstance(value, str) and _JWT_RX.match(value.strip()):
        return MASK
    return value


def mask_headers(headers: dict | None) -> dict:
    out = {}
    for k, v in (headers or {}).items():
        kl = (k or "").strip().lower()
        if kl in SENSITIVE_HEADERS:
            out[k] = MASK
        elif isinstance(v, str) and _JWT_RX.match(v.strip()):
            out[k] = MASK
        else:
            out[k] = v
    return out


def _mask_raw_body(text: str) -> str:
    """원본 POST 바디 문자열에서 민감 파라미터 값을 마스킹(urlencoded·JSON 모두).
    (기존엔 파싱된 json_body/form_data 만 마스킹하고 원본 post_data 는 평문 저장 → username/password 노출)."""
    if not text:
        return ""

    def _url_sub(m):
        return m.group(1) + "=" + (MASK if _is_sensitive_key(m.group(1)) else m.group(2))

    def _json_sub(m):
        return '"%s":"%s"' % (m.group(1), MASK if _is_sensitive_key(m.group(1)) else m.group(2))

    text = _re.sub(r"([A-Za-z0-9_\-.\[\]]+)=([^&\s]*)", _url_sub, text)
    text = _re.sub(r'"([^"]+)"\s*:\s*"([^"]*)"', _json_sub, text)
    return text


def mask_params(params) -> list:
    """[(k, v), ...] 또는 dict → 마스킹된 [{name, value}] 목록."""
    items = params.items() if isinstance(params, dict) else (params or [])
    return [{"name": k, "value": mask_value(k, v)} for k, v in items]


def _parse_json_masked(text: str):
    try:
        obj = json.loads(text)
    except Exception:
        return None
    def walk(o):
        if isinstance(o, dict):
            return {k: (MASK if _is_sensitive_key(k) else walk(v)) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(x) for x in o]
        if isinstance(o, str) and _JWT_RX.match(o.strip()):
            return MASK
        return o
    return walk(obj)


def build_record(raw: dict) -> dict:
    """브라우저에서 추출한 raw 요청 정보(dict)를 마스킹된 기록으로 변환.

    raw 키(모두 선택): url, method, resource_type, request_headers, response_status,
    response_headers, content_type, post_data, initiator, frame_url, redirect_chain,
    response_length, timing.
    """
    r = raw or {}
    url = r.get("url", "") or ""
    method = (r.get("method") or "GET").upper()
    rtype = (r.get("resource_type") or "").lower()
    content_type = (r.get("content_type")
                    or (r.get("response_headers") or {}).get("content-type", "")) or ""

    # Query parameters
    q = parse_qsl(urlparse(url).query, keep_blank_values=True)
    query_params = mask_params(q)

    # Post data → json / form
    post_data = r.get("post_data") or ""
    json_body = None
    form_data = []
    if post_data:
        jb = _parse_json_masked(post_data)
        if jb is not None:
            json_body = jb
        elif "application/x-www-form-urlencoded" in content_type or "=" in post_data:
            form_data = mask_params(parse_qsl(post_data, keep_blank_values=True))

    return {
        "url": url,
        "method": method,
        "resource_type": rtype,
        "request_headers": mask_headers(r.get("request_headers")),
        "response_status": r.get("response_status"),
        "response_headers": mask_headers(r.get("response_headers")),
        "content_type": content_type,
        "post_data": (lambda _m: _m[:_BODY_LIMIT] + ("…" if len(_m) > _BODY_LIMIT else ""))(
            _mask_raw_body(post_data)) if post_data else "",
        "json_body": json_body,
        "query_parameters": query_params,
        "form_data": form_data,
        "cookies": MASK if any((k or "").lower() == "cookie"
                               for k in (r.get("request_headers") or {})) else None,
        "initiator": r.get("initiator", ""),
        "frame_url": r.get("frame_url", ""),
        "is_xhr": rtype == "xhr",
        "is_fetch": rtype == "fetch",
        "is_api": rtype in _XHR_TYPES or "/api/" in url or "application/json" in content_type,
        "redirect_chain": r.get("redirect_chain", []),
        "response_length": r.get("response_length"),
        "timing": r.get("timing"),
    }


class RequestRecorder:
    """수집 세션 동안 요청 기록을 누적(예산 상한 적용)."""

    def __init__(self, max_requests: int = 1000):
        self.max_requests = max_requests
        self.records: list[dict] = []
        self.dropped = 0

    def add(self, raw: dict) -> bool:
        if len(self.records) >= self.max_requests:
            self.dropped += 1
            return False
        self.records.append(build_record(raw))
        return True

    def summary(self) -> dict:
        xhr = sum(1 for r in self.records if r["is_xhr"] or r["is_fetch"])
        api = sum(1 for r in self.records if r["is_api"])
        return {"requests": len(self.records), "xhr_fetch": xhr, "api_candidates": api,
                "dropped": self.dropped}
