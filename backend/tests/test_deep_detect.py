# -*- coding: utf-8 -*-
"""deep_detect(NoSQL 판정 / 역직렬화 서명) 순수 로직 단위테스트."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import deep_detect as dd


def test_judge_nosql_operator_basic():
    # 정상 대비 차이 크면 후보
    assert dd.judge_nosql_operator(1000, 1200) is True
    # 차이 작으면 아님
    assert dd.judge_nosql_operator(1000, 1050) is False


def test_judge_nosql_operator_with_control():
    # 주입이 정상과 다르지만 대조군($eq 거짓)과 사실상 같으면 → 동적 콘텐츠(오탐) → False
    assert dd.judge_nosql_operator(1000, 1300, control_len=1290) is False
    # 주입이 정상과도, 대조군과도 다르면 → 연산자 해석 신호 → True
    assert dd.judge_nosql_operator(1000, 1300, control_len=1000) is True


def test_nosql_bracket_params():
    out = dict(dd.nosql_bracket_params("user"))
    assert "user[$ne]" in out
    assert "user[$gt]" in out
    assert "user[$regex]" in out
    assert out["user[$regex]"] == ".*"


def test_detect_serialized_java():
    hits = dd.detect_serialized("token=rO0ABXNyABdqYXZhLnV0aWwu")
    assert any("Java" in h[0] for h in hits)


def test_detect_serialized_php_dotnet_ruby_python():
    assert any("PHP" in h[0] for h in dd.detect_serialized('O:8:"stdClass":1:{s:3:"foo";}'))
    assert any(".NET" in h[0] for h in dd.detect_serialized('<input name="__VIEWSTATE" value="/wEPDw">'))
    assert any("Ruby" in h[0] for h in dd.detect_serialized("data=BAhbBzoGYQ=="))
    assert any("Python" in h[0] for h in dd.detect_serialized("p=gASVCwAAAAAAAAB9"))


def test_detect_serialized_clean():
    assert dd.detect_serialized("just a normal query string q=hello&page=1") == []
    assert dd.detect_serialized("") == []


def test_scan_sources():
    src = {"cookie": "sess=rO0ABXNyZm9v1234", "body": "clean", "vs": '__VIEWSTATE'}
    out = dd.scan_sources_for_serialized(src)
    locs = {o["location"] for o in out}
    assert "cookie" in locs and "vs" in locs
    assert "body" not in locs


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
