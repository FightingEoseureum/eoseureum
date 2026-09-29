"""agents 패키지 — Multi-Agent Solver (기존 증거 해석·보강 전용)."""
from .base_agent import BaseAgent
from . import idor, xss, sqli, auth, logic, upload, ssrf, redirect
from . import service as _service   # Service Security Framework v2

# family → Agent 클래스 목록(기본 Agent Group)
FAMILY_AGENTS = {
    "idor": idor.AGENTS,
    "xss": xss.AGENTS,
    "sqli": sqli.AGENTS,
    "auth": auth.AGENTS,
    "logic": logic.AGENTS,
    "business_logic": logic.AGENTS,
    "upload": upload.AGENTS,
    "file_upload": upload.AGENTS,
    "ssrf": ssrf.AGENTS,
    "redirect": redirect.AGENTS,
    "open_redirect": redirect.AGENTS,
}
# 서비스 Agent Group(ssh/ftp/smb/mysql/redis/docker/k8s/smtp) 병합
FAMILY_AGENTS.update(_service.SERVICE_FAMILY_AGENTS)

__all__ = ["BaseAgent", "FAMILY_AGENTS"]
