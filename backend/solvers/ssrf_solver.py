"""solvers/ssrf_solver.py — SSRF 후보(서버측 URL 페치) 증거 상관분석(자동 요청 전송 금지)."""
from __future__ import annotations
from .base import BaseSolver


class SsrfSolver(BaseSolver):
    name = "ssrf_solver"
    technique = "ssrf"
    chain_name = "SSRF Chain"
    recommend = "아웃바운드 목적지 화이트리스트 + 내부망/메타데이터 차단(자동 요청 미수행)"
    handles = ("ssrf", "url_fetch", "external_fetch")
