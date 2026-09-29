"""passive_audit.py — Safe 모드 '패시브 우선'(S3): 추가 요청 0으로 하드닝 미흡 검출.

목적(사용자 목적): 서버에 무리를 주지 않으면서 최대한 많은 취약점을 찾는다. 크롤/프로브가 이미 받아둔
응답 코퍼스([[response-cache]] 스냅샷)만으로 '보안 응답 헤더 미흡·쿠키 플래그 미흡'을 사이트 단위로
통합 검출한다 — 네트워크 요청을 단 한 번도 추가로 보내지 않는다.

중복 배제(중요): 이미 능동 프로브가 다루는 항목은 제외한다.
  - X-Frame-Options / CSP frame-ancestors → 클릭재킹 프로브가 담당(제외)
  - SameSite 쿠키 → CSRF 프로브가 담당(제외)
  - Server/X-Powered-By 버전노출 → 버전식별 소견이 담당(제외)
여기서는 '아직 어디서도 소견화하지 않는' 순수 패시브 하드닝만 본다:
  HSTS · X-Content-Type-Options(nosniff) · Referrer-Policy · Permissions-Policy · CSP 부재 · Secure/HttpOnly 쿠키.

판정은 '헤더 부재'라는 사실뿐(오탐 0). 심각도는 하드닝 수준(Low/Info)이며 '참고(discovery)'로 분류해
확정 취약점 카운트를 부풀리지 않는다. 각 클래스는 1건으로 통합(영향 URL 수·샘플 첨부).
"""
from __future__ import annotations

import urllib.parse


def _ci(headers: dict) -> dict:
    """헤더 키를 소문자로 정규화(대소문자 무관 조회)."""
    out = {}
    for k, v in (headers or {}).items():
        out[str(k).lower()] = v
    return out


def _is_html_2xx(status: int, h: dict) -> bool:
    if not (200 <= int(status or 0) < 300):
        return False
    ct = (h.get("content-type", "") or "").lower()
    return "text/html" in ct or ct == ""   # HTML 또는 미표기(문서로 간주)


# (헤더키, 표시명, 심각도, 설명, 권고, https전용?)
_HEADER_CHECKS = [
    ("strict-transport-security", "HSTS(Strict-Transport-Security)", "Low",
     "HSTS 헤더가 없어 SSL Strip/다운그레이드 공격에 노출될 수 있습니다(전송 구간 보호 미흡).",
     "HTTPS 응답에 Strict-Transport-Security: max-age=31536000; includeSubDomains 적용.", True),
    ("content-security-policy", "CSP(Content-Security-Policy)", "Low",
     "CSP 헤더가 설정되지 않아 XSS/데이터 인젝션에 대한 심층 방어가 없습니다.",
     "콘텐츠 출처를 제한하는 CSP 정책 도입(script-src 'self' 등, nonce/hash 기반 권장).", False),
    ("x-content-type-options", "X-Content-Type-Options(nosniff)", "Low",
     "nosniff 미설정으로 MIME 스니핑 기반 공격(콘텐츠 오해석)에 노출될 수 있습니다.",
     "모든 응답에 X-Content-Type-Options: nosniff 적용.", False),
    ("referrer-policy", "Referrer-Policy", "Low",
     "Referrer-Policy 미설정으로 외부로 민감한 URL(토큰 포함 가능)이 Referer 로 유출될 수 있습니다.",
     "Referrer-Policy: strict-origin-when-cross-origin 등 적용.", False),
    ("permissions-policy", "Permissions-Policy", "Info",
     "Permissions-Policy 미설정 — 카메라/마이크/geolocation 등 브라우저 기능 접근 제한이 없습니다(하드닝).",
     "필요 기능만 허용하는 Permissions-Policy 적용.", False),
]


def _sample(urls: list, n: int = 5) -> list:
    return sorted(set(urls))[:n]


def audit(corpus: dict, base_url: str = "") -> list[dict]:
    """코퍼스({url: (status, body, headers)}) → 통합 하드닝 discovery_item 목록(추가 요청 0)."""
    if not corpus:
        return []
    host = ""
    try:
        host = urllib.parse.urlparse(base_url).hostname or ""
    except Exception:
        host = ""
    if not host:   # 스킴 없는 도메인 문자열 등 → 그대로 사용
        host = (base_url or "").split("/")[0]

    # 클래스별 영향 URL 수집
    missing = {key: [] for key, *_ in _HEADER_CHECKS}
    cookie_insecure = []   # (url, [문제])
    pages = 0

    for url, resp in corpus.items():
        try:
            status, _body, headers = resp
        except Exception:
            continue
        h = _ci(headers)
        if not _is_html_2xx(status, h):
            continue
        pages += 1
        is_https = url.lower().startswith("https://")
        for key, name, sev, desc, rec, https_only in _HEADER_CHECKS:
            if https_only and not is_https:
                continue
            if key not in h:
                missing[key].append(url)
        # 쿠키 플래그(Secure/HttpOnly만 — SameSite 는 CSRF 프로브 담당이라 제외)
        sc = h.get("set-cookie", "")
        if sc:
            low = sc.lower()
            probs = []
            if is_https and "secure" not in low:
                probs.append("Secure")
            if "httponly" not in low:
                probs.append("HttpOnly")
            if probs:
                cookie_insecure.append((url, probs))

    if pages == 0:
        return []

    items: list[dict] = []

    def _mk(title, severity, evidence, recommendation, urls):
        return {
            "title": f"[하드닝] {title}",
            "host": host, "port": None,
            "finding_type": "discovery", "judgment": "참고",
            "confidence": "PASSIVE", "severity": severity,
            "scan_category": "web",
            "owasp": "A05:2021 - 보안 설정 오류",
            "cwe": "CWE-693",
            "affected_endpoints": _sample(urls, 8),
            "evidence_detail": evidence + (
                f" (영향 페이지 {len(set(urls))}건, 예: " + ", ".join(_sample(urls, 3)) + ")"
                if urls else ""),
            "recommendation": recommendation,
            "_passive": True,
        }

    for key, name, sev, desc, rec, https_only in _HEADER_CHECKS:
        urls = missing.get(key) or []
        if urls:
            items.append(_mk(f"{name} 미설정", sev, desc, rec, urls))

    if cookie_insecure:
        # 어떤 플래그가 빠졌는지 집계
        flag_counts = {}
        for _u, probs in cookie_insecure:
            for p in probs:
                flag_counts[p] = flag_counts.get(p, 0) + 1
        urls = [u for u, _ in cookie_insecure]
        detail = ("응답 쿠키에 보안 플래그 미흡: "
                  + ", ".join(f"{k} 누락 {v}건" for k, v in flag_counts.items())
                  + ". 세션 탈취/전송 노출 위험.")
        items.append(_mk("쿠키 보안 플래그(Secure/HttpOnly) 미흡", "Low", detail,
                         "인증/세션 쿠키에 Secure·HttpOnly 플래그 적용(HTTPS 강제).", urls))

    return items
