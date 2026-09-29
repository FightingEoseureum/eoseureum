"""
report_renderer.py — Report Renderer Interface v1.

python-docx 의 표현 한계를 고려해, 향후 HTML/CSS·PDF 렌더러로 자연스럽게 확장 가능하도록
Renderer 추상 인터페이스를 둔다. 현재는 DocxRenderer 만 실제 동작(기존 report.generate_report
위임). HtmlRenderer/PdfRenderer 는 인터페이스 스텁(향후 구현).
"""
from __future__ import annotations


class ReportRenderer:
    """보고서 렌더러 공통 인터페이스."""
    name = "base"
    ext = "bin"

    def render(self, scan: dict):  # pragma: no cover - 추상
        raise NotImplementedError

    def available(self) -> bool:
        return True


class DocxRenderer(ReportRenderer):
    """DOCX 렌더러 — 기존 report.generate_report 에 위임(현재 기본)."""
    name = "docx"
    ext = "docx"

    def render(self, scan: dict):
        import report
        return report.generate_report(scan)   # io.BytesIO


class HtmlRenderer(ReportRenderer):
    """HTML/CSS 렌더러 v1 — 상용 컨설팅 디자인(카드/섀도/라운드/그라디언트/플로우/차트막대).
    theme 기반, KG/Proof/Attack Story/Dashboard 포함. HTML→PDF 확장 가능 구조."""
    name = "html"
    ext = "html"

    def available(self) -> bool:
        try:
            import report_html_renderer  # noqa: F401
            return True
        except Exception:
            return False

    def render(self, scan: dict):
        import io
        import report_html_renderer as _h
        html = _h.generate_html(scan)
        return io.BytesIO(html.encode("utf-8"))


class PdfRenderer(ReportRenderer):
    """PDF 렌더러 — HTML(CSS)→PDF 우선(상용 디자인), 실패 시 DOCX→PDF(LibreOffice) 폴백."""
    name = "pdf"
    ext = "pdf"

    def available(self) -> bool:
        try:
            import report_html_pdf
            if report_html_pdf.available():
                return True
        except Exception:
            pass
        try:
            import report_pdf
            return report_pdf.pdf_available()
        except Exception:
            return False

    def render(self, scan: dict):
        import io
        # 1) HTML(CSS)→PDF 우선
        try:
            import report_html_renderer as _h
            import report_html_pdf as _hp
            html = _h.generate_html(scan)
            pdf = _hp.html_to_pdf(html)
            if pdf:
                return io.BytesIO(pdf)
        except Exception:
            pass
        # 2) DOCX→PDF 폴백
        try:
            import report
            import report_pdf
            buf = report.generate_report(scan)
            pdf = report_pdf.convert_docx_to_pdf(buf.getvalue())
            return io.BytesIO(pdf) if pdf else buf
        except Exception:
            import report
            return report.generate_report(scan)


_REGISTRY = {"docx": DocxRenderer, "html": HtmlRenderer, "pdf": PdfRenderer}


def get_renderer(fmt: str = "docx") -> ReportRenderer:
    """포맷명으로 렌더러 인스턴스 반환(미지원/미구현이면 DOCX 폴백)."""
    cls = _REGISTRY.get((fmt or "docx").lower(), DocxRenderer)
    r = cls()
    return r if r.available() else DocxRenderer()


def available_formats() -> list:
    return [name for name, cls in _REGISTRY.items() if cls().available()]
