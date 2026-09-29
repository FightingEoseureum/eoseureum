"""test_sqli_report_reference_policy.py — SQLMap 미확인 → 참고/수동검토(취약 아님)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import external_tools as et

def _sqlmap_no_inj():
    fr = et.parse_sqlmap_failure_reason("all tested parameters do not appear to be injectable. "
                                        "increase values for '--level'/'--risk'", "")
    return {"executed": True, "injectable": False, "parameter": None, "injection_types": [],
            "dbms": None, "payloads": [], "databases": [], "command": "sqlmap -u ...",
            "error": None, "failure_reason": fr}

def test_no_injectable_is_manual_review_not_vuln():
    f = et.build_sqli_finding("http://t/p?content=x", "t", 80, None, _sqlmap_no_inj())
    assert f["sqli_grade"] == "MANUAL_REVIEW"
    assert f["confidence"] == "MANUAL_REVIEW"
    assert f["probe_confirmed"] is False
    assert f["finding_type"] == "discovery"
    assert f["vulnerability"] is False
    assert f["judgment"] == "참고"

def test_no_injectable_title_and_forbidden_phrases():
    f = et.build_sqli_finding("http://t/p?content=x", "t", 80, None, _sqlmap_no_inj())
    assert "참고" in f["title"] and "미확인" in f["title"]
    assert "실증" not in f["title"]
    assert "DB 목록 추출 성공" not in f["title"]
    assert f["severity"] in ("Low", "Info")
    # 실패 사유/다음 검증 권고가 근거에 포함
    assert "미확인" in f["evidence_detail"]

def test_no_injectable_overrides_ghauri_likely():
    # ghauri 가 파라미터/타입을 줬어도 SQLMap 미확인이면 CONFIRMED/LIKELY 아님(참고)
    ghauri = {"param": "uid", "inj_type": "boolean-based blind", "backend": "MySQL", "payload": "x"}
    f = et.build_sqli_finding("http://t/p?uid=1", "t", 80, ghauri, _sqlmap_no_inj())
    assert f["sqli_grade"] == "MANUAL_REVIEW"
    assert f["confidence"] not in ("CONFIRMED", "LIKELY")

def test_grade_helper_manual_review():
    gr = et.grade_sqli(None, _sqlmap_no_inj())
    assert gr["grade"] == "MANUAL_REVIEW"
    assert gr["sqlmap_no_injectable"] is True
