"""
secrets_store.py — 자격증명/민감값 암호화 저장(at-rest) v1.

Fernet(AES) 대칭키로 암호화한다. 키는 env EOSEUREUM_SECRET_KEY(우선) 또는 backend/.secret_key
파일(자동 생성, 0600)에서 로드. 평문을 파일/로그에 남기지 않는다.

용도: 인증 크롤 자격증명(AUTH_PASSWORD 등)을 프로세스 재시작에도 유지하되 평문 저장 회피.
런타임 사용 시에만 복호화한다.
"""
from __future__ import annotations

import json
import os
import pathlib

_KEY_FILE = pathlib.Path(__file__).parent / ".secret_key"
_STORE_FILE = pathlib.Path(__file__).parent / "secrets.enc"
_cache_key = None


def _fernet():
    global _cache_key
    try:
        from cryptography.fernet import Fernet
    except Exception:
        return None
    key = os.getenv("EOSEUREUM_SECRET_KEY")
    if not key:
        if _cache_key:
            key = _cache_key
        elif _KEY_FILE.exists():
            key = _KEY_FILE.read_text().strip()
        else:
            key = Fernet.generate_key().decode()
            try:
                _KEY_FILE.write_text(key)
                os.chmod(_KEY_FILE, 0o600)
            except Exception:
                pass
        _cache_key = key
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        return None


def available() -> bool:
    return _fernet() is not None


def encrypt(plaintext: str) -> str | None:
    f = _fernet()
    if not f or plaintext is None:
        return None
    try:
        return f.encrypt(str(plaintext).encode()).decode()
    except Exception:
        return None


def decrypt(token: str) -> str | None:
    f = _fernet()
    if not f or not token:
        return None
    try:
        return f.decrypt(token.encode()).decode()
    except Exception:
        return None


def mask(value: str) -> str:
    """로그/응답 노출용 마스킹."""
    if not value:
        return ""
    return "***" + (value[-2:] if len(value) > 4 else "")


# ── 암호화 저장소(파일) — 키/값 ─────────────────────────────────────────────
def save_secret(name: str, plaintext: str) -> bool:
    """이름으로 암호값 저장(재시작에도 유지). 평문 미저장."""
    f = _fernet()
    if not f:
        return False
    data = _load_raw()
    if plaintext:
        data[name] = encrypt(plaintext)
    else:
        data.pop(name, None)
    try:
        _STORE_FILE.write_text(json.dumps(data))
        os.chmod(_STORE_FILE, 0o600)
        return True
    except Exception:
        return False


def load_secret(name: str) -> str | None:
    tok = _load_raw().get(name)
    return decrypt(tok) if tok else None


def has_secret(name: str) -> bool:
    return name in _load_raw()


def _load_raw() -> dict:
    try:
        if _STORE_FILE.exists():
            return json.loads(_STORE_FILE.read_text())
    except Exception:
        pass
    return {}
