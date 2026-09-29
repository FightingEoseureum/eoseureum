"""solvers/redirect_solver.py — Open Redirect 경로의 Location 반환 증거 상관분석(비파괴)."""
from __future__ import annotations
from .base import BaseSolver


class RedirectSolver(BaseSolver):
    name = "redirect_solver"
    technique = "open_redirect"
    chain_name = "Open Redirect Chain"
    recommend = "리다이렉트 대상 화이트리스트/상대경로 강제(외부 도메인 차단)"
    handles = ("open_redirect", "redirect")
