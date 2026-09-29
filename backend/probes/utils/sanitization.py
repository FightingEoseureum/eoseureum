"""probes/utils/sanitization.py — 비밀번호/토큰/쿠키 등 민감값 마스킹."""
from __future__ import annotations

import re

_KV_RE = re.compile(
    r'\b(password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie|set-cookie)\b\s*[=:]\s*([^\s,&;]+)',
    re.IGNORECASE,
)


def mask_secrets(text: str) -> str:
    """문자열 내 password/token/cookie 등의 값을 마스킹한다."""
    if not text:
        return text or ""
    def _rep(m):
        return f"{m.group(1)}=***"
    return _KV_RE.sub(_rep, str(text))


def mask_value(value: str, keep: int = 2) -> str:
    """단일 비밀값 마스킹 (앞 keep 글자만 노출)."""
    if not value:
        return ""
    s = str(value)
    if len(s) <= keep:
        return "*" * len(s)
    return s[:keep] + "*" * (len(s) - keep)
