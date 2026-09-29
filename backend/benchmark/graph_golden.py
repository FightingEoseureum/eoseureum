"""
graph_golden.py — 그래프 3종 통합(아키텍처 A) '1단계: 골든 스냅샷' 하니스.

목적: attack_graph / attack_path_prioritizer / security_knowledge_graph 의 '현재 출력'을
고정 픽스처로 캡처해 골든(graph_golden.json)으로 저장한다. 이후 통합 리팩터링(2~4단계)에서
매 변경마다 이 골든과 대조해 '사용자에게 보이는 출력이 그대로인지(무회귀)'를 검증한다.

no-self-run-scans 준수: 라이브 스캔 없이 고정 analysis 픽스처로 빌더 함수만 호출한다.
결정적(Date/random 미사용)이므로 재실행 시 동일 출력이어야 한다.

사용:
  python -m benchmark.graph_golden --save     # 현재 출력을 골든으로 저장(리팩터 착수 전 1회)
  python -m benchmark.graph_golden --check     # 현재 출력 vs 골든 대조(회귀 확인)
"""
from __future__ import annotations

import copy
import json
import os

_GOLDEN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "graph_golden.json")


# ── 대표 픽스처(그래프 3종을 모두 exercise) ──────────────────────────────────────
FIXTURE_ANALYSIS = {
    "domain": "bench.example.com",
    "technologies": ["nginx", "php", "mysql"],
    "findings": [
        {"finding_uid": "F1", "title": "SQL 인젝션 (로그인 우회)", "name": "sql_injection",
         "severity": "HIGH", "judgment": "취약", "confidence": "CONFIRMED",
         "host": "bench.example.com", "port": 443, "service": "http",
         "owasp": "A03:2021 - 인젝션", "cwe": "CWE-89",
         "evidence_url": "https://bench.example.com/login",
         "evidence_detail": "로그인 폼에서 인증 우회 확인", "authenticated": False},
        {"finding_uid": "F2", "title": "저장형 XSS", "name": "xss_stored",
         "severity": "HIGH", "judgment": "취약", "confidence": "CONFIRMED_BROWSER",
         "host": "bench.example.com", "port": 443, "service": "http",
         "owasp": "A03:2021 - 인젝션", "cwe": "CWE-79",
         "evidence_url": "https://bench.example.com/board/write",
         "evidence_detail": "게시판에 저장형 XSS", "authenticated": True},
        {"finding_uid": "F3", "title": "관리자 페이지 인증 없이 노출", "name": "admin_panel",
         "severity": "MEDIUM", "judgment": "취약", "confidence": "CONFIRMED",
         "host": "bench.example.com", "port": 443, "service": "http",
         "owasp": "A01:2021 - 접근 제어 취약점", "cwe": "CWE-284",
         "evidence_url": "https://bench.example.com/admin", "authenticated": False},
    ],
    "attack_surface_items": [
        {"finding_uid": "S1", "title": "Swagger/OpenAPI 문서 노출", "severity": "MEDIUM",
         "judgment": "참고", "confidence": "CONFIRMED", "host": "bench.example.com",
         "evidence_url": "https://bench.example.com/swagger-ui.html"},
    ],
    "discovery_items": [
        {"finding_uid": "D1", "title": "IDOR 후보 — 객체 참조", "severity": "MEDIUM",
         "judgment": "참고", "confidence": "MANUAL_REVIEW", "host": "bench.example.com",
         "evidence_url": "https://bench.example.com/api/orders/1"},
    ],
    "attack_surface_plan": {"summary": {"total": 4}},
}


def capture(analysis: dict | None = None) -> dict:
    """세 그래프 빌더를 main.py 와 동일한 순서/데이터흐름으로 실행해 출력 캡처."""
    import attack_graph as ag
    import attack_path_prioritizer as app_
    import security_knowledge_graph as kg

    a = copy.deepcopy(analysis or FIXTURE_ANALYSIS)

    ag_out = ag.build_attack_graph(a)
    a["attack_graph"] = ag_out.get("attack_graph")
    a["attack_paths"] = ag_out.get("attack_paths")
    a["attack_path_summary"] = ag_out.get("attack_path_summary")

    prio = app_.prioritize(
        a.get("attack_paths") or [],
        (a.get("attack_graph") or {}).get("nodes") or [],
        max_paths=5)
    a["prioritized_paths"] = prio.get("selected")
    a["path_priority_summary"] = prio.get("summary")

    kg_out = kg.build_all(a)
    return {"attack_graph": ag_out, "prioritize": prio, "knowledge_graph": kg_out}


def canonical(obj) -> str:
    """결정적 비교용 표준 직렬화(키 정렬, 비직렬화 값은 str)."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)


def save_golden(path: str = _GOLDEN_PATH) -> dict:
    out = capture()
    with open(path, "w", encoding="utf-8") as f:
        f.write(canonical(out))
    return out


def load_golden(path: str = _GOLDEN_PATH):
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def diff_against_golden(path: str = _GOLDEN_PATH) -> dict:
    """현재 출력 vs 골든. 반환 {ok, reason, golden_exists}."""
    golden = load_golden(path)
    if golden is None:
        return {"ok": False, "golden_exists": False, "reason": "골든 없음 — --save 로 먼저 생성"}
    current = canonical(capture())
    if current == golden:
        return {"ok": True, "golden_exists": True, "reason": "일치(무회귀)"}
    # 어느 최상위 키가 달라졌는지 대략 표시
    try:
        g = json.loads(golden)
        c = json.loads(current)
        changed = [k for k in set(g) | set(c) if canonical(g.get(k)) != canonical(c.get(k))]
    except Exception:
        changed = ["(parse 실패)"]
    return {"ok": False, "golden_exists": True,
            "reason": f"출력 변경 감지 — 달라진 최상위 키: {changed}"}


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    mode = sys.argv[1] if len(sys.argv) > 1 else "--check"
    if mode == "--save":
        out = save_golden()
        sizes = {k: (len(json.loads(canonical(v))) if isinstance(v, (dict, list)) else 1)
                 for k, v in out.items()}
        print("골든 저장 완료:", _GOLDEN_PATH)
        ag = out["attack_graph"]
        print(f"  attack_graph: nodes={len(ag['attack_graph']['nodes'])} "
              f"edges={len(ag['attack_graph']['edges'])} paths={len(ag['attack_paths'])}")
        print(f"  prioritize.selected={len(out['prioritize'].get('selected') or [])}")
        kgraph = out["knowledge_graph"].get("security_knowledge_graph") or {}
        print(f"  knowledge_graph keys={list(out['knowledge_graph'].keys())}")
    else:
        r = diff_against_golden()
        print(("OK: " if r["ok"] else "DRIFT: ") + r["reason"])
        sys.exit(0 if r["ok"] else 1)
