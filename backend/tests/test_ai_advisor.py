# -*- coding: utf-8 -*-
"""ai_advisor(AI 조언+결정적 백스톱) 순수 로직 단위테스트."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ai_advisor as aia


def test_sanitize_ai_order():
    assert aia.sanitize_ai_order([2, 0, 1], 3) == [2, 0, 1]
    assert aia.sanitize_ai_order([2, 2, 0, 9, -1, "x", 1], 3) == [2, 0, 1]  # 중복/범위밖/비정수 제거
    assert aia.sanitize_ai_order("nope", 3) == []
    assert aia.sanitize_ai_order([], 3) == []


def test_reorder_by_ai_no_drop():
    items = ["a", "b", "c", "d"]
    # AI 가 일부만 지정 → 지정분 먼저, 나머지는 기존 순서로 뒤에(누락 없음)
    out = aia.reorder_by_ai(items, [2, 0])
    assert out == ["c", "a", "b", "d"]
    assert sorted(out) == sorted(items)  # 항목 보존


def test_reorder_by_ai_full():
    items = ["a", "b", "c"]
    assert aia.reorder_by_ai(items, [2, 1, 0]) == ["c", "b", "a"]


def test_reorder_by_ai_empty_order_keeps_original():
    items = ["a", "b", "c"]
    assert aia.reorder_by_ai(items, []) == ["a", "b", "c"]
    assert aia.reorder_by_ai(items, [9, -1]) == ["a", "b", "c"]  # 전부 무효 → 원순서


def test_reorder_by_ai_invalid_indices_filtered():
    items = ["a", "b"]
    out = aia.reorder_by_ai(items, [1, 5, 0, 5])
    assert out == ["b", "a"]


def test_extract_json_array():
    assert aia._extract_json_array("여기: [3,0,1] 끝") == [3, 0, 1]
    assert aia._extract_json_array("no array") is None


def test_probe_priority_enabled_env():
    os.environ.pop("ENABLE_AI_PROBE_PRIORITY", None)
    assert aia.probe_priority_enabled() is False
    os.environ["ENABLE_AI_PROBE_PRIORITY"] = "true"
    assert aia.probe_priority_enabled() is True
    os.environ["ENABLE_AI_PROBE_PRIORITY"] = "off"
    assert aia.probe_priority_enabled() is False
    os.environ.pop("ENABLE_AI_PROBE_PRIORITY", None)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
