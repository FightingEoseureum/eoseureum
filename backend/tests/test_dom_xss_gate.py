"""test_dom_xss_gate.py — DOM 기반 XSS 탐지 게이트(클라이언트측 URL 싱크) 검증.
응답 반사가 없어도 URL→innerHTML 싱크면 브라우저 검증으로 진행, 일반 페이지는 억제."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import active_probing as ap

# XSS-2 형: URLSearchParams → innerHTML (클라이언트측 DOM 싱크)
DOM_BODY = ("<div id='vuln'></div><script>var x=new URLSearchParams(location.search);"
            "document.getElementById('vuln').innerHTML = x.get('param');</script>")
NORMAL_BODY = "<html><body>hello world, no dom sink here</body></html>"
DOCWRITE_BODY = "<script>document.write(location.hash)</script>"


def _dom_based(body):
    return bool(ap._URL_DOM_SOURCE.search(body) and ap._DOM_WRITE_SINK.search(body))


def _proceeds(payload, body):
    reflected = False
    dom_based = _dom_based(body)
    if not reflected and not dom_based:
        return False
    if dom_based and not reflected:
        is_event = "onerror" in payload.lower() or "onload" in payload.lower()
        if not is_event and not ap._SCRIPT_EXEC_SINK.search(body):
            return False
    return True


def test_dom_sink_detected():
    assert _dom_based(DOM_BODY) is True
    assert _dom_based(NORMAL_BODY) is False        # 일반 페이지는 억제(오탐 방지)


def test_event_payload_proceeds_on_innerhtml_sink():
    img = next(p for p in ap._XSS_PAYLOADS if "onerror" in p.lower())
    assert _proceeds(img, DOM_BODY) is True         # <img onerror> → 브라우저 검증 진행


def test_script_payload_skipped_on_innerhtml_only():
    scr = next(p for p in ap._XSS_PAYLOADS if p.lower().startswith("<script"))
    assert _proceeds(scr, DOM_BODY) is False        # innerHTML 은 <script> 미실행 → 스킵


def test_script_payload_proceeds_on_documentwrite_sink():
    # document.write 싱크는 <script> 실행 가능 → script 페이로드도 진행
    scr = next(p for p in ap._XSS_PAYLOADS if p.lower().startswith("<script"))
    assert _proceeds(scr, DOCWRITE_BODY) is True
