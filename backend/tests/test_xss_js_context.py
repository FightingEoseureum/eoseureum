"""
test_xss_js_context.py — 인라인 <script> JS 문자열 컨텍스트 반사 XSS 탐지 검증.

모듈: backend/active_probing.py :: _probe_xss_js_context / _js_context_breakout

핵심 불변식(Root-Me web-client ch32 계열):
  - 값이 <script> var x = '<반사>'; 처럼 JS 문자열 안으로 반사되면, HTML 페이로드
    (<svg onload>)는 실행 안 됨 → 따옴표 탈출(';alert()//) 페이로드로만 탐지 가능.
  - 따옴표가 원문 반사되면(탈출 성공) confirmed. 백슬래시/엔티티 인코딩되면 미탐(오탐 배제).
  - JS 컨텍스트가 아닌(HTML 본문) 반사는 이 probe 가 잡지 않는다(게이트).

실행:
  cd backend && venv_linux/bin/python -m pytest tests/test_xss_js_context.py -q
"""
import os
import sys
import asyncio
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import active_probing as ap  # noqa: E402


def _num(url: str) -> str:
    q = urllib.parse.urlparse(url).query
    return urllib.parse.parse_qs(q).get("number", [""])[0]


def _install_get(reflector):
    """active_probing._get 를 모의로 교체. reflector(value)->html 로 응답 구성."""
    async def fake_get(session, url, **kw):
        html = reflector(_num(url))
        return 200, html, {"Content-Type": "text/html; charset=UTF-8"}
    ap._get = fake_get
    # Playwright 검증은 이 테스트 환경에서 비활성(정적 탈출 확인 경로를 테스트)
    async def no_pw(*a, **k):
        return None
    ap._playwright_verify_xss = no_pw


def _run(reflector):
    _install_get(reflector)
    pt = {"url": "http://t/ch/", "params": {"number": "42"}, "method": "GET", "source": "query"}
    return asyncio.run(ap._probe_xss_js_context(None, [pt], scan_id=""))


def test_js_string_context_reflected_detected():
    """ch32 재현: var number = '<값 원문 반사>'; → ';alert()// 탈출 탐지."""
    def refl(v):
        return ("<html><body><h1>x</h1>"
                "<script>\n var random = Math.random()*99;\n"
                f" var number = '{v}';\n if(random==number){{}}\n</script></body></html>")
    res = _run(refl)
    assert res is not None, "JS 문자열 컨텍스트 XSS 미탐지"
    assert res["type"] == "reflected_js_context"
    assert res["confirmed"] is True
    assert res["context"] in ("squote", "squote_sub")
    assert ap._XSS_JS_MARKER in res["payload"]


def _fully_safe(v: str) -> str:
    """따옴표 백슬래시 이스케이프 + 각괄호까지 엔티티 인코딩(진짜 안전한 출력)."""
    return (v.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')
             .replace("<", "&lt;").replace(">", "&gt;").replace("/", "&#47;"))


def test_backslash_escaped_quote_not_flagged():
    """따옴표 이스케이프 + 각괄호 인코딩(진짜 안전) → 어떤 컨텍스트로도 탈출 불가 → 미탐."""
    def refl(v):
        return f"<html><script>var number = '{_fully_safe(v)}';</script></html>"
    assert _run(refl) is None


def test_entity_encoded_quote_not_flagged():
    """따옴표/각괄호 모두 엔티티 인코딩 → 미탐(오탐 배제)."""
    def refl(v):
        safe = (v.replace("'", "&#39;").replace('"', "&quot;")
                 .replace("<", "&lt;").replace(">", "&gt;"))
        return f"<html><script>var number = '{safe}';</script></html>"
    assert _run(refl) is None


def test_html_context_not_handled_here():
    """값이 <script> 밖(HTML 본문)에만 반사되면 이 probe 는 관여 안 함(게이트)."""
    def refl(v):
        return f"<html><body><div>you said: {v}</div><script>var t=1;</script></body></html>"
    assert _run(refl) is None


def test_script_close_breakout_detected():
    """값이 필터로 따옴표만 막고 </script> 는 허용하는 경우 script_close 페이로드로 탐지."""
    def refl(v):
        # 따옴표는 이스케이프하지만 </script> 는 그대로 두는 취약 패턴
        safe = v.replace("'", "\\'").replace('"', '\\"')
        return f"<html><script>var number = '{safe}';</script></html>"
    # 위는 quote 를 막으므로 squote/dquote 는 미탐이어야 하고, script_close 원문이 body 에 존재
    res = _run(refl)
    # </script> 가 그대로 반사되면 script_close 로 탐지됨
    assert res is not None and res["context"] == "script_close"
