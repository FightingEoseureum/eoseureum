"""solvers/docker_solver.py — Docker 데몬 노출/인증 기존 정보 분석(컨테이너 조작 미수행)."""
from __future__ import annotations
from .base import BaseSolver


class DockerSolver(BaseSolver):
    name = "docker_solver"
    technique = "docker"
    chain_name = "Container Service Chain"
    recommend = "Docker API 외부 노출 차단·TLS 상호 인증 적용 점검(컨테이너 생성/조작 미수행)"
    handles = ("docker", "container")
