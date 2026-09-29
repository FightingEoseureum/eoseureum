"""solvers/k8s_solver.py — Kubernetes API/kubelet 노출 기존 정보 분석(클러스터 조작 미수행)."""
from __future__ import annotations
from .base import BaseSolver


class K8sSolver(BaseSolver):
    name = "k8s_solver"
    technique = "k8s"
    chain_name = "Container Orchestration Chain"
    recommend = "API Server/kubelet 익명 접근 차단·RBAC 적용 점검(워크로드 배포/조작 미수행)"
    handles = ("k8s", "kubernetes", "kubelet")
