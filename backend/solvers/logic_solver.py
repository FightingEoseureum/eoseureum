"""solvers/logic_solver.py — Business Logic 후보(가격/권한/포인트) 증거 상관분석(값 변조 미수행)."""
from __future__ import annotations
from .base import BaseSolver


class LogicSolver(BaseSolver):
    name = "logic_solver"
    technique = "business_logic"
    chain_name = "Business Logic Chain"
    recommend = "민감 값 서버측 재검증(권한/소유/범위). 자동 값 변조는 수행하지 않음"
    handles = ("business_logic", "logic")
