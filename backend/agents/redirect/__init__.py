"""agents/redirect — Redirect Agent Group (네비게이션/returnURL 파라미터 해석, 비파괴)."""
from __future__ import annotations
from ..base_agent import BaseAgent, ctx_level


class NavigationParameterAgent(BaseAgent):
    name = "navigation_parameter_agent"
    role = "네비게이션 파라미터 분석"
    family = "redirect"
    recommend = "redirect/next 파라미터의 외부 도메인 허용 여부 확인"

    def _observe(self, ctx):
        lvl = ctx_level(ctx)
        obs = ("Location 헤더에 외부 도메인 반환 증거 존재" if lvl >= 3
               else "리다이렉트 대상 검증 여부 수동 확인 필요")
        return {"observation": obs, "impact_note": "오픈 리다이렉트로 피싱/세션 탈취 우회 가능"}


class ReturnUrlAgent(BaseAgent):
    name = "return_url_agent"
    role = "returnURL 분석"
    family = "redirect"
    recommend = "returnUrl/goto 화이트리스트 또는 상대경로 강제 확인"

    def _observe(self, ctx):
        return {"observation": "returnUrl/goto 파라미터 관점 분석",
                "limitation": "비파괴 — 리다이렉트 따라가기 자동 수행 없음"}


AGENTS = [NavigationParameterAgent, ReturnUrlAgent]
