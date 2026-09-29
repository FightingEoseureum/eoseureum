"""Safe 모드 패시브 감사(S3) — 코퍼스만으로 하드닝 미흡 검출, 중복 배제·오탐 0."""
import passive_audit as pa


def _corpus(entries):
    # entries: list of (url, status, headers)
    return {u: (s, "<html>ok</html>", h) for (u, s, h) in entries}


def test_empty_corpus_no_items():
    assert pa.audit({}, "http://t/") == []


def test_missing_headers_consolidated():
    c = _corpus([
        ("https://t/a", 200, {"Content-Type": "text/html"}),
        ("https://t/b", 200, {"Content-Type": "text/html"}),
    ])
    items = pa.audit(c, "https://t/")
    titles = [i["title"] for i in items]
    # HSTS·CSP·nosniff·Referrer-Policy·Permissions-Policy 각 1건(통합)
    assert any("HSTS" in t for t in titles)
    assert any("CSP" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)
    assert any("Referrer-Policy" in t for t in titles)
    # 통합: 각 클래스는 1건씩만
    assert len([t for t in titles if "HSTS" in t]) == 1
    # 전부 참고(discovery)·오탐 아님
    for i in items:
        assert i["finding_type"] == "discovery" and i["judgment"] == "참고"
        assert i["_passive"] is True


def test_all_headers_present_no_items():
    good = {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    c = _corpus([("https://t/a", 200, good)])
    # 쿠키도 안전
    assert pa.audit(c, "https://t/") == []


def test_case_insensitive_headers():
    c = _corpus([("https://t/a", 200, {
        "content-type": "text/html",
        "strict-transport-security": "max-age=1",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    })])
    assert pa.audit(c, "https://t/") == []   # 소문자 헤더도 인식


def test_hsts_only_on_https():
    c = _corpus([("http://t/a", 200, {
        "Content-Type": "text/html",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    })])
    items = pa.audit(c, "http://t/")
    # HTTP 이므로 HSTS 는 지적하지 않음(https 전용)
    assert not any("HSTS" in i["title"] for i in items)


def test_insecure_cookie_flags():
    c = _corpus([("https://t/a", 200, {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=1",
        "Content-Security-Policy": "x",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "x",
        "Set-Cookie": "sid=abc; Path=/",   # Secure·HttpOnly 없음
    })])
    items = pa.audit(c, "https://t/")
    cookie = [i for i in items if "쿠키" in i["title"]]
    assert len(cookie) == 1
    assert "Secure" in cookie[0]["evidence_detail"] and "HttpOnly" in cookie[0]["evidence_detail"]


def test_non_html_and_non_2xx_skipped():
    c = _corpus([
        ("https://t/a.png", 200, {"Content-Type": "image/png"}),   # 비 HTML
        ("https://t/err", 500, {"Content-Type": "text/html"}),      # 비 2xx
    ])
    assert pa.audit(c, "https://t/") == []


def test_secure_cookie_ok_on_https():
    c = _corpus([("https://t/a", 200, {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=1",
        "Content-Security-Policy": "x",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "x",
        "Set-Cookie": "sid=abc; Secure; HttpOnly; SameSite=Lax",
    })])
    assert pa.audit(c, "https://t/") == []
