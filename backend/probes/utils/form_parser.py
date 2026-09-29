"""probes/utils/form_parser.py — HTML 폼 파싱 (로그인 폼 탐지 등)."""
from __future__ import annotations

import re

_LOGIN_FIELD_RE = re.compile(r'name=["\'](user(?:name)?|email|id|login|uid)["\']', re.IGNORECASE)
_PASS_FIELD_RE = re.compile(r'name=["\'](pass(?:word)?|pwd)["\']', re.IGNORECASE)


def is_login_form(point: dict) -> bool:
    """주입 지점(폼)이 로그인 폼인지: username/email + password 필드 동시 보유."""
    params = {k.lower() for k in (point.get("params") or {})}
    user_keys = {"username", "user", "email", "login", "id", "userid", "uid"}
    pw_keys = {"password", "pass", "passwd", "pwd"}
    return bool(params & user_keys) and bool(params & pw_keys)


def find_login_points(points: list[dict]) -> list[dict]:
    return [p for p in (points or []) if is_login_form(p)]


def has_login_form_html(body: str) -> bool:
    if not body:
        return False
    return bool(_LOGIN_FIELD_RE.search(body) and _PASS_FIELD_RE.search(body))
