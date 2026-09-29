"""
agents/base_agent.py — Multi-Agent Solver 공통 인터페이스 / 베이스.

Agent 동작 원칙(코드로 강제):
  - 새로운 Discovery/Payload/네트워크 요청/Bruteforce/상태변경/Shell/Destructive 금지.
    Agent 는 이미 수집된 Attack Path / Solver Result / Evidence Chain / Finding 만 분석·보강.
  - Agent 는 Evidence Level 을 변경할 수 없고(level_changed=False), 취약 여부를 확정할 수 없다
    (출력 구조에 verdict 자체가 없음 + analyze() 가 금지 키를 제거).
  - Rule Engine 과 기존 Evidence Level 이 최종 기준.

공통 입력(ctx): attack_path / solver_result / evidence_chain / attack_surface / finding / context
공통 출력: agent_name / agent_role / observation / evidence_refs / confidence_note /
          recommended_next_step / impact_note / limitation / did_discovery / level_changed
"""
from __future__ import annotations

# Agent 가 절대 반환할 수 없는(=Rule Engine 전용) 키 — evil subclass 방어용
_FORBIDDEN_KEYS = {"verdict", "confirmed", "is_vulnerable", "vulnerable",
                   "evidence_level", "level", "path_confidence", "final_verdict",
                   "severity_final", "confidence_level"}


class BaseAgent:
    name = "base_agent"
    role = "분석"
    family = ""
    recommend = "수동 검토"
    limitation = "기존 증거 해석만 수행(신규 탐색/요청 없음)"

    def analyze(self, ctx: dict) -> dict:
        """공통 진입점 — _observe() 결과에 안전 불변식을 강제한다."""
        try:
            out = self._observe(ctx or {}) or {}
        except Exception as e:
            out = {"observation": f"agent 오류(무시): {e}"}
        # 금지 키 제거(Agent 는 판정/Level 불가)
        for k in list(out.keys()):
            if k in _FORBIDDEN_KEYS:
                out.pop(k, None)
        result = {
            "agent_name": self.name,
            "agent_role": self.role,
            "family": self.family,
            "observation": out.get("observation", ""),
            "evidence_refs": list(out.get("evidence_refs", []) or []),
            "confidence_note": out.get("confidence_note", ""),
            "recommended_next_step": out.get("recommended_next_step", self.recommend),
            "impact_note": out.get("impact_note", ""),
            "limitation": out.get("limitation", self.limitation),
        }
        # 안전 불변식(항상 고정)
        result["did_discovery"] = False
        result["level_changed"] = False
        return result

    # 하위 클래스가 override. ctx 에서 기존 증거를 읽어 관찰 문장을 만든다(판정 금지).
    def _observe(self, ctx: dict) -> dict:
        f = ctx.get("finding") or {}
        path = ctx.get("attack_path") or {}
        level = int((ctx.get("evidence") or {}).get("level",
                    path.get("evidence_level", 0)) or 0)
        return {
            "observation": f"{self.role}: '{path.get('title') or f.get('title','경로')}' 관련 기존 증거 검토",
            "evidence_refs": (path.get("evidence_refs") or [])[:3],
            "confidence_note": f"증거 수준 {level} (Rule Engine 기준, Agent 변경 불가)",
        }


# ── 공통 헬퍼: ctx 에서 자주 쓰는 값 추출 ────────────────────────────────────
def ctx_level(ctx: dict) -> int:
    path = ctx.get("attack_path") or {}
    ev = ctx.get("evidence") or {}
    return int(ev.get("level", path.get("evidence_level", 0)) or 0)


def ctx_authed(ctx: dict) -> bool:
    path = ctx.get("attack_path") or {}
    if "인증 후" in (path.get("title") or ""):
        return True
    f = ctx.get("finding") or {}
    return bool(f.get("authenticated") or f.get("is_verified_idor"))


def ctx_detail(ctx: dict) -> str:
    f = ctx.get("finding") or {}
    path = ctx.get("attack_path") or {}
    return (f.get("evidence_detail") or path.get("possible_impact")
            or path.get("path_summary") or "")
