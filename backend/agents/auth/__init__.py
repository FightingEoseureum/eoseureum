"""agents/auth — Auth Agent Group (로그인 표면/세션/자격증명 정책 해석, 브루트포스 금지)."""
from __future__ import annotations
from ..base_agent import BaseAgent, ctx_authed


class LoginSurfaceAgent(BaseAgent):
    name = "login_surface_agent"
    role = "로그인 표면 분석"
    family = "auth"
    recommend = "로그인 폼 안전 점검(폼당 시도 제한) 결과 검토 — 수동 검증 권고"

    def _observe(self, ctx):
        return {"observation": "로그인 표면 경로 — 안전 점검 범위(브루트포스/계정 잠금 유발 없음)",
                "limitation": "인증 우회는 단독 자동 확정하지 않음(수동 검토)"}


class SessionContextAgent(BaseAgent):
    name = "session_context_agent"
    role = "세션 컨텍스트 분석"
    family = "auth"
    recommend = "세션 쿠키 속성(HttpOnly/Secure/SameSite) 점검"

    def _observe(self, ctx):
        return {"observation": "세션 발급/유지 컨텍스트 분석",
                "impact_note": "세션 보호 미흡 시 세션 탈취/고정 위험"}


class CredentialPolicyAgent(BaseAgent):
    name = "credential_policy_agent"
    role = "자격증명 정책 분석"
    family = "auth"
    recommend = "계정 잠금/속도 제한/약한 자격증명 정책 점검(자동 시도 없음)"

    def _observe(self, ctx):
        return {"observation": "자격증명 정책 관점 분석(자동 크리덴셜 스터핑 미수행)",
                "limitation": "credential stuffing/bruteforce 는 정책상 금지"}


AGENTS = [LoginSurfaceAgent, SessionContextAgent, CredentialPolicyAgent]
