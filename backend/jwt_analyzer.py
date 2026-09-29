"""
jwt_analyzer.py — JWT 취약점 분석 v1 (오프라인·무해).

스캔 중 수집된 JWT(쿠키/스토리지/Authorization 헤더)를 오프라인으로 분석한다. 네트워크
전송·토큰 위조 없이 정적으로만 판정하므로 SAFE 이며, 특히 '약한 시크릿 크랙'은 HMAC 를
직접 재계산해 서명이 일치하는지 수학적으로 증명(무오탐)한다.

점검 항목:
  - alg=none 허용 헤더            → 서명 검증 없이 위조 가능(High)
  - 약한 HS256/384/512 시크릿    → 사전 대입으로 서명 재현 성공 시 임의 토큰 위조(Critical, 실증)
  - 민감 정보가 payload 평문 노출  → 정보 노출(Medium)
  - 만료(exp) 없음/과도하게 김     → 세션 관리 취약(Low)

판정 근거만 생성하며, 최종 판정/Severity 는 기존 파이프라인 규약을 따른다.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

# 흔한 약한 시크릿(오프라인 사전 — 과하지 않게 선별)
WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "admin", "jwt", "key", "test",
    "your-256-bit-secret", "your_jwt_secret", "supersecret", "mysecret", "secretkey",
    "s3cr3t", "qwerty", "letmein", "default", "jwtsecret", "token", "private",
    "0000", "1234", "password1", "root", "hmac", "signingkey", "sign", "app_secret",
]

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_SENSITIVE_CLAIM = re.compile(r"(password|passwd|pwd|ssn|credit|card|secret|api[_-]?key|"
                              r"private[_-]?key|social)", re.I)


def _b64url_decode(seg: str) -> bytes:
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def decode_jwt(token: str) -> dict | None:
    """서명 검증 없이 header/payload 만 디코드(정적 분석용)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    return {"header": header, "payload": payload,
            "signing_input": parts[0] + "." + parts[1], "signature": parts[2]}


def crack_hs_secret(token: str, wordlist: list[str] | None = None) -> str | None:
    """HS256/384/512 서명을 사전 대입으로 재현. 성공 시 시크릿 반환(무오탐 증명)."""
    dec = decode_jwt(token)
    if not dec:
        return None
    alg = str(dec["header"].get("alg", "")).upper()
    hashmap = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    if alg not in hashmap:
        return None
    try:
        want = _b64url_decode(dec["signature"])
    except Exception:
        return None
    msg = dec["signing_input"].encode()
    for secret in (wordlist or WEAK_SECRETS):
        mac = hmac.new(secret.encode(), msg, hashmap[alg]).digest()
        if hmac.compare_digest(mac, want):
            return secret
    return None


def analyze_token(token: str, *, source: str = "", wordlist: list[str] | None = None) -> list[dict]:
    """단일 JWT 분석 → finding dict 목록."""
    dec = decode_jwt(token)
    if not dec:
        return []
    findings = []
    alg = str(dec["header"].get("alg", "")).upper()
    payload = dec["payload"]
    masked = token[:12] + "…" + token[-6:]

    # alg=none
    if alg in ("NONE", ""):
        findings.append(_f("JWT alg=none 서명 검증 우회 가능", "jwt", "HIGH", "CONFIRMED_RESPONSE",
                           f"JWT 헤더 alg={alg or '(빈값)'} — 서명 없이 토큰 위조 가능. 출처: {source} ({masked})",
                           "서버가 alg=none 토큰을 거부하도록 검증하고, 허용 알고리즘을 서버측에서 고정하십시오."))

    # 약한 HS 시크릿(크랙 성공 = 실증)
    secret = crack_hs_secret(token, wordlist)
    if secret is not None:
        findings.append(_f("JWT 약한 서명 시크릿(HMAC 크랙)", "jwt", "CRITICAL", "CONFIRMED_RESPONSE",
                           f"HS 서명 시크릿 '{secret}' 로 서명 재현 성공 — 임의 사용자/권한 토큰 위조 가능. "
                           f"출처: {source} ({masked})",
                           "충분히 긴 무작위 시크릿(≥256bit)으로 교체하고 시크릿을 안전하게 보관·주기적 교체하십시오."))

    # 민감 클레임 노출
    hits = [k for k in payload.keys() if _SENSITIVE_CLAIM.search(str(k))]
    if hits:
        findings.append(_f("JWT payload 민감 정보 노출", "jwt", "MEDIUM", "MANUAL_REVIEW",
                           f"JWT payload 에 민감해 보이는 클레임: {', '.join(hits[:5])}. "
                           f"JWT payload 는 base64 로 누구나 복호 가능. 출처: {source} ({masked})",
                           "JWT payload 에 민감정보를 담지 말고 서버측 세션/참조 토큰으로 대체하십시오."))

    # 만료 없음
    if "exp" not in payload:
        findings.append(_f("JWT 만료(exp) 미설정", "jwt", "LOW", "MANUAL_REVIEW",
                           f"JWT 에 exp 클레임이 없어 토큰이 무기한 유효할 수 있음. 출처: {source} ({masked})",
                           "적절한 만료(exp)를 설정하고 refresh 토큰 회전을 적용하십시오."))
    return findings


def _f(title, family, severity, confidence, evidence, reco) -> dict:
    return {"title": title, "family": family, "severity": severity, "confidence": confidence,
            "judgment": "취약", "evidence_detail": evidence, "recommendation": reco,
            "vuln_type": "jwt", "source": "jwt_analyzer"}


def find_jwts(text: str) -> list[str]:
    """문자열(쿠키/스토리지/헤더 덤프)에서 JWT 후보 추출."""
    if not text:
        return []
    seen, out = set(), []
    for m in _JWT_RE.findall(text):
        if m not in seen and decode_jwt(m):
            seen.add(m); out.append(m)
    return out


def analyze(tokens_or_texts: list[str], *, source: str = "scan",
            wordlist: list[str] | None = None) -> list[dict]:
    """여러 소스 문자열/토큰에서 JWT 를 찾아 분석. 동일 토큰 중복 제거."""
    findings, seen = [], set()
    for blob in tokens_or_texts or []:
        toks = [blob] if decode_jwt(blob) else find_jwts(blob)
        for t in toks:
            if t in seen:
                continue
            seen.add(t)
            findings.extend(analyze_token(t, source=source, wordlist=wordlist))
    return findings
