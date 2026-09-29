"""JWT 일반 크롤 수집(P2-#5) 회귀 테스트.

_harvest_jwt_texts 가 쿠키 raw·헤더값·URL 에서 텍스트를 모으고, jwt_analyzer.analyze 가
그 텍스트에서 JWT(alg=none 등)를 추출·분석하는지 확인.
"""
import base64
import json

import main
import jwt_analyzer as ja


def _b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


def _jwt_none():
    # alg=none 토큰(서명부 빈값)
    return f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': 'admin', 'role': 'admin'})}."


def test_harvest_from_cookie_raw():
    tok = _jwt_none()
    host_results = [{"services": [{"http_info": {
        "cookies": [{"name": "session", "raw": f"session={tok}; Path=/; HttpOnly"}],
        "headers": {"Server": "nginx"}, "url": "http://t/",
    }}]}]
    texts = main._harvest_jwt_texts(host_results)
    assert any(tok in t for t in texts)
    # analyze 가 텍스트에서 JWT 추출 → alg=none 탐지
    findings = ja.analyze(texts, source="test")
    assert any("alg=none" in f.get("title", "") for f in findings)


def test_harvest_from_authorization_header():
    tok = _jwt_none()
    host_results = [{"services": [{"http_info": {
        "cookies": [], "headers": {"Authorization": f"Bearer {tok}"}, "url": "http://t/",
    }}]}]
    texts = main._harvest_jwt_texts(host_results)
    assert any(tok in t for t in texts)


def test_harvest_empty_no_crash():
    assert main._harvest_jwt_texts([]) == []
    assert main._harvest_jwt_texts([{"services": [{"http_info": {}}]}]) == []
