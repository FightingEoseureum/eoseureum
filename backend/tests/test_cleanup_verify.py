# -*- coding: utf-8 -*-
"""cleanup_verify(아티팩트 정리 검증 집계) 순수 로직 단위테스트."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cleanup_verify as cv


def test_all_clean():
    fc = {"cleanup_attempted": 2, "cleanup_success": 2, "cleanup_failed": []}
    sx = {"injected": 3, "verified_gone": 3, "cleaned": 1, "residue": []}
    r = cv.build_cleanup_report(fc, sx, [])
    assert r["verified_clean"] is True
    assert r["residue_count"] == 0
    assert r["attempted"] == 5 and r["cleaned"] == 5
    assert cv.has_residue(r) is False
    assert cv.residue_message(r) == ""


def test_stored_xss_residue():
    sx = {"injected": 2, "verified_gone": 1, "cleaned": 0,
          "residue": [{"marker": "M1", "submit_url": "http://t/c", "param": "content"}]}
    r = cv.build_cleanup_report(None, sx, [])
    assert r["verified_clean"] is False
    assert r["residue_count"] == 1
    assert cv.has_residue(r)
    assert "저장형 XSS 마커 1건" in cv.residue_message(r)


def test_write_authz_revert_failure():
    r = cv.build_cleanup_report(None, None, [{"url": "http://t/edit", "field": "title"}])
    assert r["verified_clean"] is False
    assert r["residue_count"] == 1
    assert "원복실패 1건" in cv.residue_message(r)
    assert r["sources"]["write_authz_revert_failed"] == 1


def test_findings_failed_residue():
    fc = {"cleanup_attempted": 1, "cleanup_success": 0,
          "cleanup_failed": [{"title": "Stored XSS", "marker": "m", "endpoints": ["http://t/x"]}]}
    r = cv.build_cleanup_report(fc, None, None)
    assert not r["verified_clean"]
    assert r["residue_count"] == 1
    assert "기타 아티팩트 1건" in cv.residue_message(r)


def test_empty_all_clean():
    r = cv.build_cleanup_report(None, None, None)
    assert r["verified_clean"] is True
    assert r["attempted"] == 0 and r["residue_count"] == 0


def test_mixed_residue_counts():
    sx = {"injected": 5, "verified_gone": 3, "cleaned": 2,
          "residue": [{"marker": "a"}, {"marker": "b"}]}
    r = cv.build_cleanup_report(None, sx, [{"url": "u", "field": "f"}])
    assert r["residue_count"] == 3
    msg = cv.residue_message(r)
    assert "저장형 XSS 마커 2건" in msg and "원복실패 1건" in msg


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
