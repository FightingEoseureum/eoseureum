"""
probes/utils/credential_loader.py — known credential 검증용 자격증명 로더.

안전 정책:
  - 자격증명은 외부 파일(config.auth_credential_file, "user:pass" 한 줄당 1개)에서만
    대량 로드한다. Eoseureum 내부에 대량 사전을 하드코딩하지 않는다.
  - 내장 기본 샘플은 최대 10개 이하의 잘 알려진 기본 계정뿐이며, 이는
    enable_safe_bruteforce=True 일 때만 사용한다(꺼져 있으면 빈 목록).
  - 최대 개수는 config.max_auth_credentials(상한 1000)로 강제한다.
"""
from __future__ import annotations

import os

# 내장 기본 샘플 (잘 알려진 기본 계정 — 최대 10개 이하). safe_bruteforce 시에만 사용.
_DEFAULT_SAMPLE: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
    ("admin", "1234"),
]

# 하드 상한 (config 가 더 큰 값을 줘도 이 이상은 절대 로드하지 않음)
_HARD_MAX = 1000


def _parse_line(line: str) -> tuple[str, str] | None:
    """ "user:pass" 한 줄을 (user, pass) 로 파싱. '#' 주석/빈 줄은 무시."""
    s = (line or "").rstrip("\n").rstrip("\r")
    if not s or s.lstrip().startswith("#"):
        return None
    if ":" not in s:
        return None
    user, _, pw = s.partition(":")
    return (user, pw)


def _load_file(path: str, limit: int) -> list[tuple[str, str]]:
    """자격증명 파일 로드(한 줄당 user:pass). 최대 limit 개까지만. 중복 제거."""
    if not path or limit <= 0 or not os.path.isfile(path):
        return []
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                pair = _parse_line(line)
                if pair is None:
                    continue
                if pair in seen:
                    continue
                seen.add(pair)
                out.append(pair)
                if len(out) >= limit:
                    break
    except Exception:
        return []
    return out


def load_credentials(config) -> list[tuple[str, str]]:
    """known credential 검증용 자격증명 목록 로드.

    우선순위:
      1) config.auth_credential_file 이 있으면 파일에서 최대 max_auth_credentials 개 로드.
      2) 파일이 없거나 비어있고 enable_safe_bruteforce=True 면 내장 샘플(≤10) 사용.
      3) 그 외에는 빈 목록.

    어떤 경우에도 반환 개수는 min(max_auth_credentials, 1000) 이하로 제한된다.
    """
    limit = int(getattr(config, "max_auth_credentials", 0) or 0)
    limit = max(0, min(limit, _HARD_MAX))
    if limit <= 0:
        return []

    safe_bruteforce = bool(getattr(config, "enable_safe_bruteforce", False))

    path = getattr(config, "auth_credential_file", "") or ""
    file_creds = _load_file(path, limit)
    if file_creds:
        return file_creds[:limit]

    # 파일이 없거나 비어있는 경우: safe_bruteforce 시에만 내장 샘플(≤10) 사용.
    if safe_bruteforce:
        return _DEFAULT_SAMPLE[:min(limit, len(_DEFAULT_SAMPLE))]

    return []
