"""solvers/sqli_solver.py — SQLi 경로의 기존 SQLMap/에러 증거를 상관분석(신규 탐색 없음).

Time-based/덤프/os-shell/file-read 는 수행하지 않으며 증거로 사용하지 않는다.
"""
from __future__ import annotations
from .base import BaseSolver


class SqliSolver(BaseSolver):
    name = "sqli_solver"
    technique = "sqli"
    chain_name = "SQLi Evidence Chain"
    recommend = "파라미터화 쿼리 적용, SQLMap injectable 증거 검토(덤프/쉘 미수행)"
    handles = ("sqli", "sql_injection")
