"""solvers/csrf_solver.py — CSRF 경로의 토큰/SameSite/상태변경성 위험도 증거 상관분석.

자동 확정 금지 — 상태 변경 요청 미수행. 위험도 평가 결과만 상관분석한다.
"""
from __future__ import annotations
from .base import BaseSolver, INSUFFICIENT_EVIDENCE


class CsrfSolver(BaseSolver):
    name = "csrf_solver"
    technique = "csrf"
    chain_name = "CSRF Risk Chain"
    recommend = "CSRF 토큰/SameSite/Origin 검증 적용(상태 변경 미수행, 위험도만)"
    handles = ("csrf", "state_change")

    def _assess(self, ctx: dict) -> dict:
        out = super()._assess(ctx)
        # CSRF 는 자동 확정 금지 — 강한 증거여도 '수동 검토' 권고 유지
        if out["solver_result"] not in (INSUFFICIENT_EVIDENCE,):
            out["execution_summary"] += " CSRF 는 자동 확정하지 않으며 위험도 평가만 수행."
        return out
