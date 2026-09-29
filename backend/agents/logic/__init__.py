"""agents/logic — Business Logic Agent Group (역할/금액/상태전이 해석, 값 변조 미수행)."""
from __future__ import annotations
from ..base_agent import BaseAgent


class RoleParameterAgent(BaseAgent):
    name = "role_parameter_agent"
    role = "역할 파라미터 분석"
    family = "logic"
    recommend = "role/isAdmin 등 권한 파라미터의 서버측 권한 재검증 확인"

    def _observe(self, ctx):
        return {"observation": "권한 관련 파라미터(role/admin/permission) 존재 분석",
                "impact_note": "서버 검증 미흡 시 권한 상승 가능"}


class PriceAmountAgent(BaseAgent):
    name = "price_amount_agent"
    role = "금액 파라미터 분석"
    family = "logic"
    recommend = "price/amount/discount/point 서버측 재계산·검증 확인"

    def _observe(self, ctx):
        return {"observation": "금액/수량/할인 파라미터 존재 분석(값 변조 자동 수행 안 함)",
                "impact_note": "금액 변조 시 금전적 피해 가능"}


class StateTransitionAgent(BaseAgent):
    name = "state_transition_agent"
    role = "상태 전이 분석"
    family = "logic"
    recommend = "주문/승인 등 상태 전이 순서·권한 검증 확인"

    def _observe(self, ctx):
        return {"observation": "상태 전이(승인/결제 단계) 관점 분석",
                "limitation": "상태 변경 요청은 수행하지 않음(설계 검토 권고)"}


AGENTS = [RoleParameterAgent, PriceAmountAgent, StateTransitionAgent]
