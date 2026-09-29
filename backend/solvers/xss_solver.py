"""solvers/xss_solver.py — XSS 경로의 기존 브라우저 실증 증거를 상관분석(신규 탐색 없음)."""
from __future__ import annotations
from .base import BaseSolver


class XssSolver(BaseSolver):
    name = "xss_solver"
    technique = "xss"
    chain_name = "XSS Evidence Chain"
    recommend = "입력 검증/출력 인코딩 적용, 반사 지점 점검(기존 alert 실증 증거 활용)"
    handles = ("xss", "search_function")
