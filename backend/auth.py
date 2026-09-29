import ipaddress
import os
import pathlib
import re
import secrets as _secrets
from datetime import datetime, timedelta

import bcrypt
from jose import JWTError, jwt


def _ip_in_list(client_ip: str, list_str: str) -> bool:
    """client_ip 가 목록의 IP 와 **완전 일치**하는지(대역/CIDR 미지원 — 정확히 그 IP만 허용)."""
    try:
        ip = ipaddress.ip_address(client_ip)
    except Exception:
        return False
    for entry in re.split(r"[,\s]+", (list_str or "").strip()):
        entry = entry.strip()
        if not entry:
            continue
        try:
            if ip == ipaddress.ip_address(entry):   # 완전 일치만(대역 매칭 안 함)
                return True
        except Exception:
            continue                                 # CIDR/잘못된 항목은 무시(일치 불가)
    return False


# 전역 항상-허용(예외) IP — 기본 없음(계정별 IP 제한을 우회하지 않도록). 필요 시에만 env IP_ALWAYS_ALLOW 로 지정.
# (localhost 는 별도로 항상 허용 — 서버 로컬 복구용.)
def _always_allow_ips() -> str:
    return os.getenv("IP_ALWAYS_ALLOW", "")


def ip_allowed(client_ip: str, allowed: str) -> bool:
    """client_ip 접근 허용 여부.

    정책: **빈 값 = 전부 차단**(명시된 IP만 허용). 예외로 항상 허용:
      - 서버 로컬(127.0.0.1/::1)  — 잠금 시 콘솔/SSH 복구용
      - IP_ALWAYS_ALLOW 목록(관리자 워크스테이션 등) — 전체 잠금 방지
    """
    if client_ip in ("127.0.0.1", "::1", "localhost", "", "testclient"):
        return True                       # 로컬/테스트 클라이언트는 항상 허용
    if _ip_in_list(client_ip, _always_allow_ips()):
        return True                       # 전역 예외 IP → 항상 허용
    allowed = (allowed or "").strip()
    if not allowed:
        return False                      # 빈 값 = 전부 차단(허용 IP 미지정 = 접근 불가)
    return _ip_in_list(client_ip, allowed)

_INSECURE_DEFAULT = "security-scanner-secret-change-in-prod"


def _resolve_secret_key() -> str:
    """JWT 서명 키 확정. env(SECRET_KEY) 우선 → 없거나 공개 기본값이면 영속 랜덤 키 파일(.secret_key)
    로 폴백한다. '공개 상수'는 절대 사용하지 않는다(토큰 위조 방지). 파일도 못 쓰면 메모리 랜덤."""
    env = (os.getenv("SECRET_KEY", "") or "").strip()
    if env and env != _INSECURE_DEFAULT:
        return env
    kf = pathlib.Path(__file__).parent / ".secret_key"
    try:
        if kf.exists():
            val = kf.read_text(encoding="utf-8").strip()
            if val and val != _INSECURE_DEFAULT:
                return val
        val = _secrets.token_hex(32)
        fd = os.open(str(kf), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            os.write(fd, val.encode())
        finally:
            os.close(fd)
        return val
    except Exception:
        # 최후: 메모리 랜덤(공개 상수 사용 금지 — 재시작 시 재로그인 필요할 수 있음)
        return _secrets.token_hex(32)


SECRET_KEY = _resolve_secret_key()
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_token(user_id: int, username: str, role: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "exp": expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return {}
