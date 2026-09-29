"""
golden.py — 정확도 벤치마크 골든셋(알려진 취약 실습 앱 기준 '기대 결과').

공개된 교육용 취약 앱의 알려진 취약점 클래스를 기대 결과로 정의한다. 스캔은 사용자가 직접
실행하고, evaluate 가 그 결과(analysis JSON)를 이 골든셋과 대조해 정탐/오탐/누락을 산출한다.

주의: 오직 '본인이 정당한 권한을 보유'하거나 벤더가 공개한 실습 대상에만 사용한다.
"""
from __future__ import annotations

# 각 항목: {family, note, path(선택), severity_min(선택)}
# exhaustive=True 이면 '이 목록 외 발견 = 오탐 후보'로 엄격 채점.
GOLDEN = {
    "testfire": {
        "match": ["testfire.net", "altoromutual"],
        "label": "Altoro Mutual (demo.testfire.net)",
        "exhaustive": False,
        # 최소 baseline 외에도 실제로 흔히 잡히는 '정상' 부가발견(오탐 아님) — precision 측정 시 제외.
        "allowed_extra": ["clickjacking", "csrf", "swagger", "tls", "https",
                          "cookie", "cors", "idor", "api_audit"],
        "expected": [
            {"family": "sqli", "note": "로그인/검색 SQL Injection"},
            {"family": "xss", "note": "검색 파라미터 반사형 XSS"},
            {"family": "server", "note": "서버/헤더 정보 노출"},
        ],
    },
    "dvwa": {
        "match": ["dvwa", "127.0.0.1:8080", "10.20.100.24:8080"],
        "label": "DVWA (Damn Vulnerable Web App)",
        "exhaustive": False,
        "expected": [
            {"family": "sqli", "note": "SQL Injection (id 파라미터)"},
            {"family": "xss", "note": "Reflected/Stored/DOM XSS"},
            {"family": "csrf", "note": "CSRF (비밀번호 변경)"},
            {"family": "command_injection", "note": "Command Injection (ping)"},
            {"family": "file_upload", "note": "파일 업로드"},
            {"family": "path_traversal", "note": "File Inclusion(LFI)"},
        ],
    },
    "juiceshop": {
        "match": ["juice-shop", "juiceshop", "juice", "127.0.0.1:3000", "10.20.100.24:3000"],
        "label": "OWASP Juice Shop",
        "exhaustive": False,
        # 무인증에서 흔히 잡히는 정상 부가발견(오탐 아님) — precision 측정 시 제외.
        "allowed_extra": ["swagger", "token_in_url", "cors", "clickjacking", "csrf",
                          "server", "https", "sensitive_path"],
        "expected": [
            {"family": "sqli", "note": "로그인 SQL Injection (/rest/user/login)"},
            {"family": "xss", "note": "검색/기타 XSS"},
            {"family": "idor", "note": "IDOR/BOLA (basket/order) — 인증 필요"},
        ],
    },
    "bwapp": {
        "match": ["bwapp", "bee-box"],
        "label": "bWAPP",
        "exhaustive": False,
        "expected": [
            {"family": "sqli", "note": "SQL Injection"},
            {"family": "xss", "note": "XSS (reflected/stored)"},
            {"family": "command_injection", "note": "OS Command Injection"},
            {"family": "ssti", "note": "Server-Side Template Injection"},
            {"family": "path_traversal", "note": "Path Traversal/LFI"},
            {"family": "csrf", "note": "CSRF"},
        ],
    },
}


def resolve_golden(target: str, custom: dict | None = None) -> dict | None:
    """target 문자열(도메인/이름) 또는 custom dict 로 골든셋을 찾는다."""
    if custom and custom.get("expected"):
        return {"label": custom.get("label", target), "exhaustive": bool(custom.get("exhaustive")),
                "expected": custom["expected"], "match": custom.get("match", [])}
    t = (target or "").strip().lower()
    if t in GOLDEN:
        return GOLDEN[t]
    for _key, g in GOLDEN.items():
        if any(m in t for m in g.get("match", [])):
            return g
    return None


def available() -> list:
    return [{"key": k, "label": v["label"], "expected": len(v["expected"])}
            for k, v in GOLDEN.items()]
