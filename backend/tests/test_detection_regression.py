# -*- coding: utf-8 -*-
"""탐지 로직 회귀 벤치마크를 테스트 스위트의 회귀 게이트로 편입.

payload/판정 로직을 바꿨을 때 탐지율↓ 또는 오탐↑ 가 생기면 여기서 잡힌다.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.detection_regression import run_regression, gate_ok


def test_detection_regression_gate():
    m = run_regression()
    # 오탐 0, 미탐 0 (게이트 임계치)
    assert m["fp"] == 0, f"오탐(FP) 발생: {m['failures']}"
    assert m["fn"] == 0, f"미탐(FN) 발생: {m['failures']}"
    assert m["recall"] == 1.0, f"탐지율 저하: {m}"
    assert m["precision"] == 1.0, f"정밀도 저하: {m}"
    assert m["specificity"] == 1.0, f"오탐가드 저하: {m}"
    assert m["judge_pass"] == m["judge_total"], f"판정함수 회귀: {m['failures']}"
    assert not m["judgment_mismatch"], f"판정 등급 불일치: {m['judgment_mismatch']}"
    assert gate_ok(m)


def test_benchmark_covers_key_techniques():
    """핵심 기법이 벤치마크에 포함돼 있는지(커버리지 자체의 회귀 방지)."""
    m = run_regression()
    techs = set(m["per_tech"].keys())
    for must in ("sql_injection", "xss_reflected", "xss_stored", "ssti", "xxe",
                 "nosql_injection", "deserialization", "api_audit"):
        assert must in techs, f"벤치마크에 {must} 케이스 누락"
    # 양성/음성 케이스가 모두 존재(단방향 데이터셋 방지)
    assert m["tp"] > 0 and m["tn"] > 0


if __name__ == "__main__":
    for fn in (test_detection_regression_gate, test_benchmark_covers_key_techniques):
        try:
            fn(); print("PASS", fn.__name__)
        except AssertionError as e:
            print("FAIL", fn.__name__, e)
