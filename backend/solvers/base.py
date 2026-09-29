"""
solvers/base.py — Solver 공통 인터페이스 / 베이스 클래스.

Solver 동작 원칙(코드로 강제):
  - 새로운 대규모 탐색/Discovery 금지. 이미 Prioritizer 를 통과한 Attack Path 의
    '기존 증거'만 검토·재검증·상관분석한다(네트워크 I/O 없음).
  - Solver 는 검증 수준(Level)을 '직접 변경할 수 없다'. Level 은 Rule Engine 전담.
    solve() 가 항상 level_changed=False, did_discovery=False 를 보장한다.
  - 출력은 증거 강화(상관/보강) 결과와 권고만. confidence 는 자문(advisory) 값.

공통 입력(ctx): attack_path / attack_surface / technique / evidence / context
공통 출력: solver / solver_result / evidence / confidence / execution_summary /
          recommended_next_step / level_changed / did_discovery
"""
from __future__ import annotations

# solver_result 상수
EVIDENCE_CORRELATED = "EVIDENCE_CORRELATED"   # Level3 등 강한 증거 — 체인으로 상관분석
EVIDENCE_SUPPORTED = "EVIDENCE_SUPPORTED"     # Level2 증거 — 보강 권고
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"  # Level1 관찰 — 재검증 권고(기존 경로)
NO_EVIDENCE = "NO_EVIDENCE"                    # Level0 — 정보성


class BaseSolver:
    """모든 Solver 의 베이스. 하위 클래스는 클래스 속성만 지정하면 된다(파일별 독립 모듈)."""
    name = "base"
    technique = ""
    chain_name = "Evidence Chain"
    recommend = "수동 검토"
    handles: tuple = ()   # 처리 대상(semantic_role / node_type / technique 키워드)

    def solve(self, ctx: dict) -> dict:
        """공통 진입점. _assess() 결과에 안전 불변식을 강제 적용한다."""
        try:
            out = self._assess(ctx or {})
        except Exception as e:
            out = {"solver_result": NO_EVIDENCE, "evidence": [],
                   "execution_summary": f"solver 오류(무시): {e}",
                   "recommended_next_step": self.recommend}
        out.setdefault("solver", self.name)
        out.setdefault("evidence", [])
        out.setdefault("confidence", "advisory")
        out.setdefault("recommended_next_step", self.recommend)
        out.setdefault("solver_result", NO_EVIDENCE)
        out.setdefault("execution_summary", "")
        out.setdefault("chain_name", self.chain_name)
        # 안전 불변식 — Solver 는 Level 변경/Discovery 불가
        out["level_changed"] = False
        out["did_discovery"] = False
        return out

    # 기본 평가: 경로의 증거 수준(Rule Engine 산출)에 따라 상관/보강/재검증 권고.
    def _assess(self, ctx: dict) -> dict:
        ev = ctx.get("evidence") or {}
        level = int(ev.get("level", 0) or 0)
        detail = ev.get("detail", "")
        refs = ev.get("refs", []) or []
        path = ctx.get("attack_path") or {}
        title = path.get("title", "")

        ev_items = []
        if detail:
            ev_items.append(detail[:200])
        ev_items.extend(refs[:3])

        if level >= 3:
            return {
                "solver_result": EVIDENCE_CORRELATED,
                "evidence": ev_items,
                "confidence": "high (advisory)",
                "execution_summary": (
                    f"[{self.name}] Level 3 증거(Rule Engine 확정)를 {self.chain_name} 으로 "
                    f"상관분석. 신규 탐색 없이 기존 증거만 강화."),
                "recommended_next_step": self.recommend,
            }
        if level == 2:
            return {
                "solver_result": EVIDENCE_SUPPORTED,
                "evidence": ev_items,
                "confidence": "medium (advisory)",
                "execution_summary": (
                    f"[{self.name}] Level 2 증거 보강 — 기존 후보/검증 결과 상관분석. "
                    f"최종 Level 은 Rule Engine 결정."),
                "recommended_next_step": self.recommend,
            }
        if level == 1:
            return {
                "solver_result": INSUFFICIENT_EVIDENCE,
                "evidence": ev_items,
                "confidence": "low (advisory)",
                "execution_summary": (
                    f"[{self.name}] Level 1 관찰 — 기존 경로 범위 내 재검증 권고(신규 탐색 금지)."),
                "recommended_next_step": self.recommend,
            }
        return {
            "solver_result": NO_EVIDENCE,
            "evidence": ev_items,
            "confidence": "info (advisory)",
            "execution_summary": f"[{self.name}] 증거 부족 — 정보성.",
            "recommended_next_step": self.recommend,
        }
