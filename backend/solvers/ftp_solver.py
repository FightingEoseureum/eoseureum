"""solvers/ftp_solver.py — FTP 배너/익명 접속/TLS 기존 정보 분석(능동 점검 없음)."""
from __future__ import annotations
from .base import BaseSolver


class FtpSolver(BaseSolver):
    name = "ftp_solver"
    technique = "ftp"
    chain_name = "FTP Service Chain"
    recommend = "익명 접속 차단·FTPS(TLS) 적용 점검(파일 다운로드/업로드 미수행)"
    handles = ("ftp",)
