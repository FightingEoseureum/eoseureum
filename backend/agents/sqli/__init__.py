"""agents/sqli — SQLi Agent Group (기존 파라미터/에러/SQLMap 증거 해석, 덤프·쉘 금지)."""
from __future__ import annotations
from ..base_agent import BaseAgent, ctx_level, ctx_detail


class ParameterContextAgent(BaseAgent):
    name = "parameter_context_agent"
    role = "파라미터 컨텍스트 분석"
    family = "sqli"
    recommend = "해당 파라미터의 파라미터화 쿼리 적용 여부 확인"

    def _observe(self, ctx):
        return {"observation": "입력 파라미터가 쿼리에 사용되는 컨텍스트로 분석됨"}


class SqlErrorAgent(BaseAgent):
    name = "sql_error_agent"
    role = "SQL 에러 분석"
    family = "sqli"
    recommend = "DB 에러 메시지 노출 차단(상세 에러 비표시)"

    def _observe(self, ctx):
        d = ctx_detail(ctx)
        return {"observation": "응답의 DB 에러 단서 분석" + (f" — {d[:120]}" if d else ""),
                "limitation": "에러 반사만으로는 POSSIBLE — 실증은 SQLMap injectable 기준"}


class SqlmapEvidenceAgent(BaseAgent):
    name = "sqlmap_evidence_agent"
    role = "SQLMap 증거 분석"
    family = "sqli"
    recommend = "SQLMap injectable 증거 검토(덤프/os-shell/file-read 미수행)"

    def _observe(self, ctx):
        lvl = ctx_level(ctx)
        obs = ("SQLMap injectable 확인 증거 존재(Rule Engine Level 3, 안전 옵션)" if lvl >= 3
               else "injectable 미확정 — 수동 검증 권고")
        return {"observation": obs, "confidence_note": f"증거 수준 {lvl} (Agent 변경 불가)",
                "limitation": "DB 덤프/파일 I/O/OS 쉘은 수행하지 않음"}


AGENTS = [ParameterContextAgent, SqlErrorAgent, SqlmapEvidenceAgent]
