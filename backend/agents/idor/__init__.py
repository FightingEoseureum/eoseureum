"""agents/idor — IDOR Agent Group (기존 객체참조/교차계정 증거 해석·보강)."""
from __future__ import annotations
from ..base_agent import BaseAgent, ctx_level, ctx_authed, ctx_detail


class ObjectReferenceAgent(BaseAgent):
    name = "object_reference_agent"
    role = "객체 참조 분석"
    family = "idor"
    recommend = "객체 식별자 값 치환에 대한 서버측 권한 검증 여부 수동 확인"

    def _observe(self, ctx):
        d = ctx_detail(ctx)
        return {"observation": "객체 식별자(예: accountId/orderId) 파라미터가 경로에 존재함" +
                (f" — 근거: {d[:120]}" if d else ""),
                "evidence_refs": (ctx.get("attack_path") or {}).get("evidence_refs", [])[:3],
                "impact_note": "객체 단위 접근제어 미흡 시 타 사용자 객체 접근 가능"}


class AccessControlAgent(BaseAgent):
    name = "access_control_agent"
    role = "접근 제어 분석"
    family = "idor"
    recommend = "객체 조회 시 로그인 사용자-객체 소유자 매핑 검증"

    def _observe(self, ctx):
        lvl = ctx_level(ctx)
        note = ("교차 계정 응답에 타 사용자 식별정보 노출 증거 존재(Rule Engine Level 3)"
                if lvl >= 3 else "소유자 검증 여부에 대한 추가 증거 필요")
        return {"observation": f"접근 제어 관점: {note}",
                "confidence_note": f"증거 수준 {lvl} (Agent 변경 불가)"}


class AuthContextAgent(BaseAgent):
    name = "auth_context_agent"
    role = "인증 컨텍스트 분석"
    family = "idor"
    recommend = "인증 세션 기반 교차계정 검증(기존 안전 경로) 결과 검토"

    def _observe(self, ctx):
        authed = ctx_authed(ctx)
        if authed:
            obs = "인증 후 영역 경로 — 교차계정 검증 컨텍스트 유효"
            lim = "상태 변경 없이 읽기 전용 비교만(자동 공격 없음)"
        else:
            obs = "인증 후 영역이 아니므로 자동 검증 제한 — 수동 검증 필요"
            lim = "비인증 컨텍스트에서는 IDOR 자동 실증 제한"
        return {"observation": obs, "limitation": lim}


AGENTS = [ObjectReferenceAgent, AccessControlAgent, AuthContextAgent]
