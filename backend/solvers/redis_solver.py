"""solvers/redis_solver.py — Redis/Memcached/ES 인증·보호모드 기존 정보 분석(명령 미수행)."""
from __future__ import annotations
from .base import BaseSolver


class RedisSolver(BaseSolver):
    name = "redis_solver"
    technique = "redis"
    chain_name = "Data Exposure Service Chain"
    recommend = "인증(requirepass) 활성·Protected Mode 활성·외부 노출 차단 점검(명령 실행 미수행)"
    handles = ("redis", "memcached", "elasticsearch", "data_exposure")
