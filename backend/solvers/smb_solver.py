"""solvers/smb_solver.py — SMB 서명/Guest 허용 기존 정보 분석(파일 접근 미수행)."""
from __future__ import annotations
from .base import BaseSolver


class SmbSolver(BaseSolver):
    name = "smb_solver"
    technique = "smb"
    chain_name = "File Sharing Service Chain"
    recommend = "SMB Signing 활성·익명/Guest 접근 차단·공유 권한 점검(파일 열람 미수행)"
    handles = ("smb", "nfs", "file_sharing")
