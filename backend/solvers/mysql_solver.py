"""solvers/mysql_solver.py — DB(MySQL/PG/MSSQL/Mongo) 외부 노출/버전 기존 정보 분석(쿼리 미수행)."""
from __future__ import annotations
from .base import BaseSolver


class MysqlSolver(BaseSolver):
    name = "mysql_solver"
    technique = "mysql"
    chain_name = "Database Service Chain"
    recommend = "DB 외부 노출 차단(방화벽/내부망)·최소 권한·전송 암호화 점검(쿼리/덤프 미수행)"
    handles = ("mysql", "postgresql", "mssql", "mongodb", "oracle", "database")
