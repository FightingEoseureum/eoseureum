# -*- coding: utf-8 -*-
"""그래프 3종 통합(아키텍처 A) 골든 스냅샷 회귀 게이트.

attack_graph / attack_path_prioritizer / security_knowledge_graph 의 출력이
골든(benchmark/graph_golden.json)과 동일한지 검증한다. 통합 리팩터링(2~4단계)에서
'사용자에게 보이는 출력 불변'을 이 테스트가 보장한다. 의도적 변경 시 --save 로 골든 갱신.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.graph_golden import capture, canonical, diff_against_golden


def test_capture_is_deterministic():
    """동일 픽스처 2회 실행 → 완전히 동일(집합 순서 등 비결정성 없음)."""
    assert canonical(capture()) == canonical(capture())


def test_matches_golden():
    """현재 그래프 출력이 골든과 일치(무회귀). 실패 시 의도적 변경이면 --save 로 갱신."""
    r = diff_against_golden()
    assert r["golden_exists"], "골든 파일 없음 — python -m benchmark.graph_golden --save 로 생성"
    assert r["ok"], r["reason"]


def test_capture_shape():
    """캡처 구조가 세 빌더 출력을 모두 포함하는지(하니스 자체 회귀 방지)."""
    out = capture()
    assert set(out.keys()) == {"attack_graph", "prioritize", "knowledge_graph"}
    ag = out["attack_graph"]["attack_graph"]
    assert "nodes" in ag and "edges" in ag
    assert isinstance(out["attack_graph"]["attack_paths"], list)
    assert set(out["knowledge_graph"].keys()) == {
        "security_knowledge_graph", "attack_path_graph", "graph_risk_context"}


if __name__ == "__main__":
    for fn in (test_capture_is_deterministic, test_matches_golden, test_capture_shape):
        try:
            fn(); print("PASS", fn.__name__)
        except AssertionError as e:
            print("FAIL", fn.__name__, e)
