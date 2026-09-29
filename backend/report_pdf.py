"""
report_pdf.py — DOCX → PDF 변환 (Professional Report Design v6).

LibreOffice(soffice) 헤드리스 변환을 사용한다. Windows/Linux 모두 지원하며,
변환 도구가 없거나 실패하면 None 을 반환해 호출부가 DOCX 만 제공하도록 한다.
새 취약점/엔진 로직 없음 — 산출물 형식 변환만.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile


def _find_soffice() -> str | None:
    """soffice/libreoffice 실행 파일 경로 탐색(PATH + 일반 설치 경로)."""
    env = os.getenv("SOFFICE_PATH")
    if env and os.path.exists(env):
        return env
    for name in ("soffice", "libreoffice"):
        p = shutil.which(name)
        if p:
            return p
    for cand in (
        "/usr/bin/soffice", "/usr/bin/libreoffice",
        "/usr/lib/libreoffice/program/soffice",
        "/opt/libreoffice/program/soffice",
        r"C:\Program Files\LibreOffice\program\soffice.exe",
        r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
    ):
        if os.path.exists(cand):
            return cand
    return None


def pdf_available() -> bool:
    return _find_soffice() is not None


def convert_docx_to_pdf(docx_bytes: bytes, *, timeout: int = 120) -> bytes | None:
    """DOCX 바이트 → PDF 바이트. 변환 도구 없음/실패 시 None."""
    soffice = _find_soffice()
    if not soffice or not docx_bytes:
        return None
    tmp = tempfile.mkdtemp(prefix="eoseureum_pdf_")
    try:
        src = os.path.join(tmp, "report.docx")
        with open(src, "wb") as f:
            f.write(docx_bytes)
        # 헤드리스 변환(별도 프로파일로 동시 실행 충돌 방지)
        profile = os.path.join(tmp, "lo_profile")
        cmd = [soffice, "--headless", "--norestore",
               f"-env:UserInstallation=file://{profile}",
               "--convert-to", "pdf", "--outdir", tmp, src]
        subprocess.run(cmd, capture_output=True, timeout=timeout)
        pdf_path = os.path.join(tmp, "report.pdf")
        if os.path.exists(pdf_path):
            with open(pdf_path, "rb") as f:
                return f.read()
        return None
    except Exception:
        return None
    finally:
        try:
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            pass
