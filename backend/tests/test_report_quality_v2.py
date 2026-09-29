"""test_report_quality_v2.py — 보고서 품질 보완 검증.

- Apache-Coyote/1.1 는 Tomcat '가능성'으로만 표기(단정·CVE 매핑 금지)
- 버전 확인된 일반 Server 헤더는 정상 표기
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rule_engine as re_eng


def _svc(server="", xpb=""):
    return {"http_info": {"url": "http://t/", "server": server, "x_powered_by": xpb}}


def test_coyote_marked_as_possibility():
    rule = {"check_type": "server_version"}
    triggered, ev = re_eng._check_rule_with_evidence(rule, _svc(server="Apache-Coyote/1.1"))
    assert triggered
    detail = ev["evidence_detail"]
    assert "가능성" in detail and "Tomcat" in detail
    assert "CVE 매핑 금지" in detail  # 직접 버전 확인 전 단정 금지 명시


def test_plain_server_version_still_reported():
    rule = {"check_type": "server_version"}
    triggered, ev = re_eng._check_rule_with_evidence(rule, _svc(server="nginx/1.18.0"))
    assert triggered
    assert "nginx/1.18.0" in ev["evidence_detail"]
    # Coyote 가 아니므로 '가능성' 비고는 붙지 않음
    assert "Tomcat" not in ev["evidence_detail"]
