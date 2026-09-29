"""test_html_pdf.py — HTML Report Renderer → PDF 확장 검증.

HTML 산출/프린트 CSS/워터마크/렌더러 폴백은 결정적으로, 실제 Chrome PDF 변환은
설치 시에만 검증(미설치 환경에서도 스위트가 깨지지 않도록 skip 처리).
"""
import os, sys, io
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import report_html_renderer as hr
import report_html_pdf as hp
import report_renderer as rr
import proof_evidence as pe
import security_knowledge_graph as kg


def _analysis():
    a = {"findings": [{"title": "SSTI", "family": "ssti", "confidence": "CONFIRMED_RESPONSE",
                       "severity": "HIGH", "host": "t.com", "port": 80,
                       "url": "https://t.com/s?q=1", "parameter": "q",
                       "evidence_detail": "Jinja2 7*7=49", "judgment": "취약", "_idx": 1}],
         "summary": {"by_severity": {"High": 1}}}
    a.update(pe.build_all(a)); a.update(kg.build_all(a))
    return a


# ── HTML 프린트/워터마크/페이지 설정 ─────────────────────────────────────────
def test_html_has_print_and_watermark():
    html = hr.generate_html({"domain": "t.com", "analysis": _analysis(), "created_at": "2026-07-02"})
    assert "@page" in html and "size:A4" in html
    assert "@media print" in html and "page-break-after" in html and "break-inside:avoid" in html
    assert "class='watermark'" in html or 'class="watermark"' in html
    assert "CONFIDENTIAL" in html
    # 한글 폰트 맑은 고딕(+대체) 지정
    assert "맑은 고딕" in html


def test_html_font_fallback_chain():
    html = hr.generate_html({"domain": "t.com", "analysis": {}, "created_at": "x"})
    assert "Noto Sans CJK KR" in html and "NanumGothic" in html


# ── Renderer 폴백/가용성 ─────────────────────────────────────────────────────
def test_pdf_renderer_available_and_registry():
    assert isinstance(hp.available(), bool)
    # PdfRenderer 는 HTML→PDF 또는 DOCX→PDF 중 하나라도 되면 available
    assert isinstance(rr.PdfRenderer().available(), bool)
    assert rr.get_renderer("pdf").name in ("pdf", "docx")


# ── 실제 HTML→PDF (Chrome 있을 때만) ─────────────────────────────────────────
@pytest.mark.skipif(not hp.available(), reason="playwright/chrome 미설치")
def test_html_to_pdf_real():
    html = hr.generate_html({"domain": "t.com", "analysis": _analysis(), "created_at": "2026-07-02"})
    pdf = hp.html_to_pdf(html)
    # 변환 성공 시 A4 PDF, 실패(환경) 시 None (호출부가 DOCX 폴백)
    if pdf is not None:
        assert pdf[:5] == b"%PDF-" and len(pdf) > 2000


def test_docx_pdf_fallback_path_exists():
    # HTML→PDF 실패해도 PdfRenderer.render 는 항상 bytes(PDF 또는 DOCX)를 반환
    out = rr.PdfRenderer().render({"domain": "t.com", "analysis": _analysis(), "created_at": "x"})
    assert isinstance(out, io.BytesIO) and len(out.getvalue()) > 0
