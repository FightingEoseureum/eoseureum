"""
test_xss_attr_context.py — 따옴표 HTML 속성값 탈출 반사 XSS 탐지 검증.

모듈: backend/active_probing.py :: _probe_xss_attr_context / _attr_breakout

핵심 불변식(Root-Me web-client ch26 계열):
  - 값이 <a href='?p=<반사>'> 처럼 따옴표 속성값으로 반사되고, <,> 는 인코딩되지만
    구분 따옴표(')가 raw 반사되면 → autofocus+onfocus 이벤트핸들러 주입으로 자동 실행.
  - 따옴표가 &#39;/&quot; 로 인코딩되면 미탐(오탐 배제).
  - 속성 컨텍스트가 아니면(값이 태그 밖 텍스트로만 반사) 이 probe 는 관여 안 함(게이트).

실행:
  cd backend && venv_linux/bin/python -m pytest tests/test_xss_attr_context.py -q
"""
import os
import sys
import asyncio
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import active_probing as ap  # noqa: E402


def _p(url):
    q = urllib.parse.urlparse(url).query
    return urllib.parse.parse_qs(q).get("p", [""])[0]


def _run(reflector):
    async def fake_get(session, url, **kw):
        return 200, reflector(_p(url)), {"Content-Type": "text/html; charset=UTF-8"}
    ap._get = fake_get
    async def no_pw(*a, **k):
        return None
    ap._playwright_verify_xss = no_pw
    pt = {"url": "http://t/ch/", "params": {"p": "home"}, "method": "GET", "source": "query"}
    return asyncio.run(ap._probe_xss_attr_context(None, [pt], scan_id=""))


def _ch26_encode(v: str) -> str:
    """ch26 재현: <,>,\" 는 인코딩하되 ' 는 raw 로 둔다."""
    return v.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def test_single_quote_attr_breakout_detected():
    """ch26: <a href='?p=<값>'> 에서 ' raw → autofocus onfocus 주입 탐지."""
    def refl(v):
        return f"<p>The page <a href='?p={_ch26_encode(v)}'>{_ch26_encode(v)}</a> not found.</p>"
    res = _run(refl)
    assert res is not None, "속성 탈출 XSS 미탐지"
    assert res["type"] == "reflected_attr_context"
    assert res["confirmed"] is True
    assert res["context"] == "attr_squote"


def test_fully_encoded_quote_not_flagged():
    """' 까지 &#39; 로 인코딩하면 탈출 불가 → 미탐(오탐 배제)."""
    def refl(v):
        safe = _ch26_encode(v).replace("'", "&#39;")
        return f"<a href='?p={safe}'>{safe}</a>"
    assert _run(refl) is None


def test_text_context_not_handled_here():
    """값이 태그 밖 텍스트로만 반사되면 이 probe 는 관여 안 함(게이트)."""
    def refl(v):
        return f"<div>you searched: {_ch26_encode(v)}</div>"
    assert _run(refl) is None


def test_double_quote_attr_breakout_detected():
    """쌍따옴표 속성에서 \" raw 반사 시 dquote 컨텍스트로 탐지."""
    def refl(v):
        # " 는 raw, ' 인코딩, <> 인코딩
        safe = v.replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;")
        return f'<input value="{safe}">'
    res = _run(refl)
    assert res is not None and res["context"] == "attr_dquote"
