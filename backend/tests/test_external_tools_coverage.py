"""외부도구 Detection Coverage 기록(P2-#7) 회귀 테스트.

analysis["external_tools_status"] 가 detection_coverage.build_coverage 산출물의
external_tools 행으로 정직하게 노출되는지 확인.
"""
import detection_coverage as dc


def test_external_tools_surfaced_in_coverage():
    analysis = {
        "findings": [],
        "external_tools_status": {
            "sqlmap":  {"status": "ran", "label": "실행됨(결과 반영)"},
            "ghauri":  {"status": "available", "label": "실행 시도(결과 없음)"},
            "nuclei":  {"status": "missing", "label": "미설치(건너뜀)"},
            "testssl": {"status": "not_applicable", "label": "대상 없음"},
        },
    }
    cov = dc.build_coverage(analysis)["detection_coverage"]
    ext = {r["tool"]: r["status"] for r in cov["external_tools"]}
    assert ext["sqlmap"] == "ran"
    assert ext["ghauri"] == "available"
    assert ext["nuclei"] == "missing"
    assert ext["testssl"] == "not_applicable"


def test_no_external_status_yields_empty_rows():
    cov = dc.build_coverage({"findings": []})["detection_coverage"]
    assert cov["external_tools"] == []
