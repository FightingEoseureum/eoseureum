"""agents/xss — XSS Agent Group (기존 반사/컨텍스트/브라우저 실증 증거 해석)."""
from __future__ import annotations
from ..base_agent import BaseAgent, ctx_level, ctx_detail


class ReflectionAgent(BaseAgent):
    name = "reflection_agent"
    role = "반사 분석"
    family = "xss"
    recommend = "반사 지점 출력 인코딩 적용 여부 확인"

    def _observe(self, ctx):
        return {"observation": "입력값이 응답에 반사되는 지점으로 분석됨",
                "impact_note": "반사 입력이 인코딩 없이 출력되면 스크립트 실행 위험"}


class ContextAgent(BaseAgent):
    name = "context_agent"
    role = "출력 컨텍스트 분석"
    family = "xss"
    recommend = "HTML/속성/스크립트 컨텍스트별 인코딩 적용"

    def _observe(self, ctx):
        return {"observation": "HTML body 컨텍스트에서 실행 가능한 위치로 분석됨",
                "limitation": "정적 분석 기반 — 실제 실행은 브라우저 증거로 확인"}


class BrowserEvidenceAgent(BaseAgent):
    name = "browser_evidence_agent"
    role = "브라우저 실증 분석"
    family = "xss"
    recommend = "Playwright alert 실증 증거 검토(추가 실행 없음)"

    def _observe(self, ctx):
        lvl = ctx_level(ctx)
        if lvl >= 3:
            obs = "Playwright alert 발생 증거 존재 — 브라우저 실행 실증(Rule Engine Level 3)"
        else:
            obs = "브라우저 실행 증거 미확보 — 반사만 관찰(수동 확인 필요)"
        return {"observation": obs, "confidence_note": f"증거 수준 {lvl} (Agent 변경 불가)"}


AGENTS = [ReflectionAgent, ContextAgent, BrowserEvidenceAgent]
