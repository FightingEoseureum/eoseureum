"""solvers/upload_solver.py — 파일 업로드 후보의 통제 증거 상관분석(실제 업로드/웹쉘 금지)."""
from __future__ import annotations
from .base import BaseSolver


class UploadSolver(BaseSolver):
    name = "upload_solver"
    technique = "file_upload"
    chain_name = "File Upload Chain"
    recommend = "서버측 확장자/MIME/매직바이트 검증 + 실행 불가 경로 저장(웹쉘 업로드 미수행)"
    handles = ("file_upload", "file_handling", "upload")
