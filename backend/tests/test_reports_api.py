"""
test_reports_api.py — /api/reports 목록 로직(inventory.build_report_list) 검증.

엔드포인트는 build_report_list(get_scans_for_user(...)) 를 try/except 로 감싼 래퍼이므로
(빈 입력/예외 → 빈 items = HTTP 200) 핵심 로직을 순수 함수로 검증한다.
실행: cd backend && venv_linux/bin/python -m pytest tests/test_reports_api.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import inventory


def _complete_scan():
    return {
        "scan_id": "9cff85bd-aaa", "domain": "demo.testfire.net", "status": "complete",
        "created_at": "2026-06-18 15:04:43",
        "analysis": {
            "overall_risk": "HIGH",
            "summary": {"vulnerability_count": 5, "by_severity": {"High": 3, "Medium": 1, "Low": 1}},
            "findings": [
                {"confidence": "CONFIRMED"}, {"confidence": "CONFIRMED"}, {"probe_confirmed": True},
                {"confidence": "LIKELY"}, {"confidence": "CONFIRMED"},
            ],
        },
    }


def _failed_scan():
    return {"scan_id": "fail-1", "domain": "t2", "status": "failed",
            "created_at": "2026-06-17 09:00:00", "analysis": None}


# 4) 데이터 없어도 정상(빈 items) — 엔드포인트 200 보장
def test_reports_empty_returns_valid_structure():
    out = inventory.build_report_list([])
    assert out["items"] == []
    assert out["summary"]["total_reports"] == 0
    assert out["summary"]["high_risk_reports"] == 0
    assert out["summary"]["latest_report_at"] == "-"


# 5) scan history 기반 items 생성 + 6) download_url 형식
def test_reports_built_from_scan_history():
    out = inventory.build_report_list([_complete_scan(), _failed_scan()])
    items = out["items"]
    assert len(items) == 2

    rep = next(it for it in items if it["scan_id"] == "9cff85bd-aaa")
    assert rep["target"] == "demo.testfire.net"
    assert rep["risk_level"] == "높음"
    assert rep["total_findings"] == 5
    assert rep["high_count"] == 3 and rep["medium_count"] == 1 and rep["low_count"] == 1
    assert rep["confirmed_count"] == 4   # CONFIRMED 3 + probe_confirmed 1
    assert rep["report_available"] is True
    # download_url 이 기존 export API 형식인지
    assert rep["download_url"] == "/api/scans/9cff85bd-aaa/export"

    # 실패 스캔은 report_available=False
    failed = next(it for it in items if it["scan_id"] == "fail-1")
    assert failed["report_available"] is False
    assert failed["risk_level"] == "-"

    # 요약
    assert out["summary"]["total_reports"] == 1        # 완료 1건만
    assert out["summary"]["high_risk_reports"] == 1
    assert out["summary"]["latest_report_at"] == "2026-06-18 15:04:43"


def test_reports_stopped_scan_is_available():
    scan = {"scan_id": "stop-1", "domain": "t3", "status": "stopped",
            "created_at": "2026-06-18 12:00:00",
            "analysis": {"overall_risk": "MEDIUM", "summary": {"vulnerability_count": 2}}}
    out = inventory.build_report_list([scan])
    assert out["items"][0]["report_available"] is True
    assert out["items"][0]["risk_level"] == "중간"
