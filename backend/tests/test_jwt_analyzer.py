"""test_jwt_analyzer.py — JWT 오프라인 취약점 분석 검증(무해·무오탐 크랙)."""
import os, sys, base64, hashlib, hmac, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import jwt_analyzer as ja


def _b64(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).decode().rstrip("=")


def _make_jwt(header: dict, payload: dict, secret: str | None) -> str:
    h = _b64(json.dumps(header).encode())
    p = _b64(json.dumps(payload).encode())
    signing = f"{h}.{p}"
    if secret is None:
        return f"{signing}."
    alg = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[header["alg"]]
    sig = _b64(hmac.new(secret.encode(), signing.encode(), alg).digest())
    return f"{signing}.{sig}"


def test_decode_jwt():
    t = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "role": "user"}, "secret")
    dec = ja.decode_jwt(t)
    assert dec and dec["header"]["alg"] == "HS256" and dec["payload"]["role"] == "user"
    assert ja.decode_jwt("not.a.jwt.token") is None


def test_crack_weak_secret_is_proven():
    # 약한 시크릿 'secret' 로 서명된 토큰 → 크랙 성공(무오탐: HMAC 재현)
    t = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, "secret")
    assert ja.crack_hs_secret(t) == "secret"
    # 강한 시크릿 → 사전에 없음 → 크랙 실패(오탐 없음)
    t2 = _make_jwt({"alg": "HS256"}, {"sub": "1"}, "S#9zQ!v2_Long_Random_9271xkQ")
    assert ja.crack_hs_secret(t2) is None


def test_alg_none_flagged_high():
    t = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "admin"}, None)
    fs = ja.analyze_token(t, source="cookie")
    assert any(f["family"] == "jwt" and f["severity"] == "HIGH" and "none" in f["title"].lower()
               for f in fs)


def test_weak_secret_and_claims_and_exp():
    t = _make_jwt({"alg": "HS256"}, {"sub": "1", "password": "p", "role": "admin"}, "admin")
    fs = ja.analyze_token(t, source="storage")
    sev = {f["severity"] for f in fs}
    assert "CRITICAL" in sev            # 약한 시크릿 크랙 실증
    assert any("민감" in f["title"] for f in fs)   # password 클레임
    assert any(f["severity"] == "LOW" for f in fs)  # exp 없음


def test_find_jwts_and_analyze_dedup():
    t = _make_jwt({"alg": "HS256"}, {"sub": "1"}, "secret")
    blob = f"session={t}; other=abc"
    assert ja.find_jwts(blob) == [t]
    # 동일 토큰 두 소스 → 중복 제거
    fs = ja.analyze([blob, f"Authorization: Bearer {t}"])
    crit = [f for f in fs if f["severity"] == "CRITICAL"]
    assert len(crit) == 1
