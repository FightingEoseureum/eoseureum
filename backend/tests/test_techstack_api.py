"""
test_techstack_api.py — /api/techstack 집계 로직(inventory.build_techstack) 검증.

엔드포인트는 build_techstack(get_scans_for_user(...)) 를 try/except 로 감싼 얇은 래퍼이므로
(빈 입력/예외 → 빈 items 반환 = HTTP 200) 핵심 로직을 순수 함수로 검증한다.
실행: cd backend && venv_linux/bin/python -m pytest tests/test_techstack_api.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import inventory


def _scan_with_tech():
    return {
        "scan_id": "s1", "domain": "demo.testfire.net", "status": "complete",
        "created_at": "2026-06-18 15:04:43",
        "results": [{
            "host": "demo.testfire.net",
            "services": [{"port": 80, "service": "http", "http_info": {"status": 200}}],
            "technologies": [
                {"name": "Apache Tomcat", "confidence": 70,
                 "recommended_probes": ["/manager/html", "/host-manager/html"]},
            ],
        }],
        "analysis": {
            "technologies": [{"name": "Apache Tomcat", "confidence": 70}],
            "findings": [{"host": "demo.testfire.net", "judgment": "취약", "title": "XSS"}],
            "discovery_items": [{
                "host": "demo.testfire.net", "port": 80, "service": "http",
                "tags": ["http", "nmap", "version-detection"],
                "title": "서비스/버전 식별: Apache Tomcat/Coyote JSP engine 1.1 (포트 80)",
                "evidence": ["nmap -sV: http (Apache Tomcat/Coyote JSP engine 1.1)"],
            }],
        },
    }


# 1) 데이터 없어도 정상(빈 items) — 엔드포인트 200 보장
def test_techstack_empty_returns_valid_structure():
    out = inventory.build_techstack([])
    assert out["items"] == []
    assert out["summary"]["total_technologies"] == 0
    assert out["summary"]["total_hosts"] == 0


def test_techstack_handles_scan_without_analysis():
    out = inventory.build_techstack([{"scan_id": "x", "domain": "t", "status": "failed",
                                      "analysis": None, "results": None}])
    assert out["items"] == []


# 2) technologies 매핑 + 3) recommended_checks + nmap 버전 병합
def test_techstack_maps_items_and_merges_nmap_version():
    out = inventory.build_techstack([_scan_with_tech()])
    items = out["items"]
    assert len(items) >= 1
    tomcat = next(it for it in items if it["technology"] == "Apache Tomcat")
    assert tomcat["host"] == "demo.testfire.net"
    assert tomcat["port"] == 80
    assert tomcat["confidence"] == "high"           # 70 → high
    assert "/manager/html" in tomcat["recommended_checks"]
    # nmap -sV 가 같은 기술에 병합되어 버전이 채워짐
    assert tomcat["version"] == "1.1"
    assert "nmap" in tomcat["source"]
    assert tomcat["related_findings"] == 1
    # 요약
    assert out["summary"]["total_hosts"] == 1
    assert out["summary"]["high_confidence"] >= 1


def test_techstack_version_dash_when_unknown():
    scan = {
        "scan_id": "s2", "domain": "t", "status": "complete", "created_at": "2026-06-18 10:00:00",
        "results": [{"host": "t", "services": [{"port": 443, "service": "https", "http_info": {}}],
                     "technologies": [{"name": "nginx", "confidence": 40}]}],
        "analysis": {"technologies": [{"name": "nginx", "confidence": 40}]},
    }
    out = inventory.build_techstack([scan])
    ng = next(it for it in out["items"] if it["technology"] == "nginx")
    assert ng["version"] == "-"
    assert ng["confidence"] == "medium"             # 40 → medium
