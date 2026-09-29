"""solvers/idor_solver.py — IDOR 경로의 기존 교차계정 증거를 상관분석/보강(신규 탐색 없음)."""
from __future__ import annotations
from .base import BaseSolver, EVIDENCE_CORRELATED


class IdorSolver(BaseSolver):
    name = "idor_solver"
    technique = "idor"
    chain_name = "IDOR Evidence Chain"
    recommend = "객체 조회 시 로그인 사용자-객체 소유자 매핑 검증(교차계정 검증 결과 활용)"
    handles = ("idor", "object_reference", "access_control")

    def _assess(self, ctx: dict) -> dict:
        out = super()._assess(ctx)
        # 기존 IDOR 교차검증 결과가 있으면 체인 상관분석으로 명시(신규 검증 수행 안 함)
        cv = (ctx.get("context") or {}).get("candidate_verification") or {}
        idor = cv.get("idor") or {}
        if idor.get("promoted"):
            out["solver_result"] = EVIDENCE_CORRELATED
            out["execution_summary"] += (
                f" 기존 교차계정 검증 승격 {idor.get('promoted')}건과 인증 후 영역을 "
                f"IDOR Evidence Chain 으로 연결.")
        return out
