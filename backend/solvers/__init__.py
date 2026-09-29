"""solvers 패키지 — 공격 경로 전용 증거 강화 Solver 모음."""
from .base import (
    BaseSolver, EVIDENCE_CORRELATED, EVIDENCE_SUPPORTED,
    INSUFFICIENT_EVIDENCE, NO_EVIDENCE,
)
from .idor_solver import IdorSolver
from .xss_solver import XssSolver
from .sqli_solver import SqliSolver
from .csrf_solver import CsrfSolver
from .logic_solver import LogicSolver
from .upload_solver import UploadSolver
from .redirect_solver import RedirectSolver
from .ssrf_solver import SsrfSolver
from .auth_solver import AuthSolver
# Service Security Framework v1 — 서비스 Solver(기존 정보 분석 전용)
from .ssh_solver import SshSolver
from .ftp_solver import FtpSolver
from .smtp_solver import SmtpSolver
from .smb_solver import SmbSolver
from .mysql_solver import MysqlSolver
from .redis_solver import RedisSolver
from .docker_solver import DockerSolver
from .k8s_solver import K8sSolver

BUILTIN_SOLVERS = [
    IdorSolver, XssSolver, SqliSolver, CsrfSolver, LogicSolver,
    UploadSolver, RedirectSolver, SsrfSolver, AuthSolver,
    SshSolver, FtpSolver, SmtpSolver, SmbSolver, MysqlSolver,
    RedisSolver, DockerSolver, K8sSolver,
]

__all__ = ["BaseSolver", "BUILTIN_SOLVERS", "EVIDENCE_CORRELATED",
           "EVIDENCE_SUPPORTED", "INSUFFICIENT_EVIDENCE", "NO_EVIDENCE"]
