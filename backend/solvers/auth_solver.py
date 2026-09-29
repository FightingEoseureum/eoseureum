"""solvers/auth_solver.py — 인증/로그인 우회 경로의 안전 점검 증거 상관분석(브루트포스/잠금 금지)."""
from __future__ import annotations
from .base import BaseSolver, INSUFFICIENT_EVIDENCE


class AuthSolver(BaseSolver):
    name = "auth_solver"
    technique = "auth_bypass"
    chain_name = "Auth Bypass Chain"
    recommend = "로그인 폼 안전 점검(폼당 시도 제한, 계정 잠금 금지) 결과 검토 — 수동 검증 권고"
    handles = ("auth_bypass", "authentication", "login")

    def _assess(self, ctx: dict) -> dict:
        out = super()._assess(ctx)
        # 인증 우회는 안전 점검 특성상 단독 확정 금지 — 수동 검토 권고 유지
        out["execution_summary"] += " 인증 우회는 안전 점검 범위(브루트포스/잠금 유발 없음)."
        return out
