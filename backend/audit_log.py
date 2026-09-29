"""
audit_log.py — 보안 감사 로그(append-only) v1.

스캔 시작·설정 변경·자격증명 변경·보고서 내보내기 등 보안 민감 행위를 append-only JSONL 로
기록한다(누가·언제·무엇을). 민감값(비밀번호/토큰)은 절대 기록하지 않는다.
"""
from __future__ import annotations

import json
import pathlib
from datetime import datetime

_LOG = pathlib.Path(__file__).parent / "audit.jsonl"
_SENSITIVE = ("password", "passwd", "pwd", "token", "secret", "key", "credential")


import re as _re

# URL userinfo(스킴://user:pass@host)의 자격증명 부분 마스킹용
_URL_USERINFO_RE = _re.compile(r"(\w+://)[^/@\s:]+:[^/@\s]+@")


def _scrub_str(v: str) -> str:
    v = _URL_USERINFO_RE.sub(r"\1***:***@", v)   # URL 내 user:pass 마스킹
    return v[:300] + "…" if len(v) > 300 else v


def _scrub(d: dict) -> dict:
    """감사 detail 마스킹. 중첩 dict/list 까지 재귀(중첩 secret 누출 방지) + 문자열 값의 URL userinfo 마스킹."""
    out = {}
    for k, v in (d or {}).items():
        if any(s in str(k).lower() for s in _SENSITIVE):
            out[k] = "***"
        elif isinstance(v, dict):
            out[k] = _scrub(v)
        elif isinstance(v, list):
            out[k] = [_scrub(x) if isinstance(x, dict)
                      else (_scrub_str(x) if isinstance(x, str) else x) for x in v]
        elif isinstance(v, str):
            out[k] = _scrub_str(v)
        else:
            out[k] = v
    return out


def log(action: str, *, user: str = "", role: str = "", target: str = "", **fields) -> None:
    """감사 이벤트 기록(실패해도 앱 흐름 방해 없음)."""
    entry = {"ts": datetime.now().isoformat(timespec="seconds"), "action": action,
             "user": user, "role": role, "target": target, "detail": _scrub(fields)}
    try:
        with open(_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def recent(limit: int = 100) -> list:
    """최근 감사 이벤트(관리자 조회용)."""
    try:
        lines = _LOG.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out = []
    for ln in lines[-limit:]:
        try:
            out.append(json.loads(ln))
        except Exception:
            continue
    return list(reversed(out))
