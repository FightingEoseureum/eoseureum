"""agents/ssrf — SSRF Agent Group (외부 URL/콜백 파라미터/내부 타겟 가드 해석, 자동 요청 금지)."""
from __future__ import annotations
from ..base_agent import BaseAgent


class ExternalUrlParameterAgent(BaseAgent):
    name = "external_url_parameter_agent"
    role = "외부 URL 파라미터 분석"
    family = "ssrf"
    recommend = "서버측 URL 페치 파라미터의 목적지 화이트리스트 확인"

    def _observe(self, ctx):
        return {"observation": "url/uri 등 서버측 페치 파라미터 존재 분석(자동 요청 미수행)",
                "impact_note": "검증 미흡 시 내부망 요청(SSRF) 가능"}


class CallbackParameterAgent(BaseAgent):
    name = "callback_parameter_agent"
    role = "콜백 파라미터 분석"
    family = "ssrf"
    recommend = "webhook/callback 대상 검증 및 내부 주소 차단 확인"

    def _observe(self, ctx):
        return {"observation": "webhook/callback 파라미터 관점 분석"}


class InternalTargetGuardAgent(BaseAgent):
    name = "internal_target_guard_agent"
    role = "내부 타겟 가드 분석"
    family = "ssrf"
    recommend = "169.254.169.254/127.0.0.1 등 내부/메타데이터 접근 차단 확인"

    def _observe(self, ctx):
        return {"observation": "내부망/메타데이터 타겟 보호 관점 분석(실 요청 전송 없음)",
                "limitation": "자동 외부/내부 요청 전송 금지 — 후보/설계 검토"}


AGENTS = [ExternalUrlParameterAgent, CallbackParameterAgent, InternalTargetGuardAgent]
