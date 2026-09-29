"""
report_html_pdf.py — HTML → PDF (Playwright/Headless Chrome).

HTML/CSS 기반 Professional Report 를 A4 PDF 로 출력한다. 표지 full-page, page break 제어,
header/footer + page number, CONFIDENTIAL 워터마크(HTML 측 고정 요소), 배경/카드 유지
(print_background), 한글 폰트(맑은 고딕→시스템 대체) 적용.

브라우저 구동은 browser_compat 로 시스템 Chrome 폴백(Ubuntu 26.04 번들 chromium 미지원 대비).
실패 시 None 반환 → 호출부가 DOCX→PDF 로 폴백.
"""
from __future__ import annotations

import html as _html

_TITLE = "Eoseureum · AI Security Assessment Report"


def available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


def _templates(title: str):
    t = _html.escape(title)
    header = (f"<div style='width:100%;font-size:8px;color:#94a3b8;padding:0 10mm;'>"
              f"<span>{t}</span></div>")
    footer = ("<div style='width:100%;font-size:8px;color:#94a3b8;padding:0 10mm;"
              "display:flex;justify-content:space-between;align-items:center;'>"
              f"<span>{t}</span>"
              "<span style='color:#dc2626;font-weight:700;'>CONFIDENTIAL</span>"
              "<span>Page <span class='pageNumber'></span> / <span class='totalPages'></span></span>"
              "</div>")
    return header, footer


async def html_to_pdf_async(html: str, title: str = _TITLE) -> bytes | None:
    """HTML 문자열 → A4 PDF bytes. 실패 시 None."""
    try:
        import browser_compat  # noqa: F401  (시스템 Chrome 폴백 패치)
    except Exception:
        pass
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return None
    header, footer = _templates(title)
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu"])
            page = await (await browser.new_context()).new_page()
            await page.set_content(html, wait_until="networkidle")
            pdf = await page.pdf(
                format="A4", print_background=True, prefer_css_page_size=False,
                display_header_footer=True, header_template=header, footer_template=footer,
                margin={"top": "16mm", "bottom": "14mm", "left": "10mm", "right": "10mm"})
            await browser.close()
            return pdf if pdf else None
    except Exception:
        return None


def html_to_pdf(html: str, title: str = _TITLE) -> bytes | None:
    """동기 래퍼(이벤트 루프 밖에서 호출용). 루프 내부에서는 html_to_pdf_async 를 await."""
    import asyncio
    try:
        return asyncio.run(html_to_pdf_async(html, title))
    except RuntimeError:
        # 이미 실행 중인 이벤트 루프 안 — 별도 스레드에서 새 루프로 실행
        import concurrent.futures

        def _run():
            return asyncio.run(html_to_pdf_async(html, title))
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            return ex.submit(_run).result()
    except Exception:
        return None
