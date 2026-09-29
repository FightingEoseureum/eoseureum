"""solvers/ssh_solver.py — SSH 설정/알고리즘/인증 방식 기존 정보 분석(능동 점검 없음)."""
from __future__ import annotations
from .base import BaseSolver


class SshSolver(BaseSolver):
    name = "ssh_solver"
    technique = "ssh"
    chain_name = "SSH Service Chain"
    recommend = "비밀번호 로그인 비활성·키 기반 인증, 약한 KEX/cipher 제거 점검(무차별 인증 금지)"
    handles = ("ssh", "rdp", "ldap", "telnet", "authentication")
