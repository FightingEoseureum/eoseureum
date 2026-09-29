"""test_sqli_report_policy.py — SQLi 제목/위험도/신뢰도/표현 정책 검증."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import external_tools as et


def _ghauri(param="uid", inj="boolean-based blind", backend="MySQL", payload="uid=1 AND 1=1", dbs=None):
    return {"param": param, "inj_type": inj, "backend": backend, "title": "",
            "payload": payload, "databases": dbs or [], "grade": "LIKELY"}


def test_ghauri_unknown_not_confirmed_possible():
    # parameter/dbms/type 모두 unknown, payload 없음 → POSSIBLE/Medium (절대 CONFIRMED 금지)
    f = et.build_sqli_finding("http://t/p?x=1", "t", 80,
                              _ghauri(param="unknown", inj="알 수 없음", backend="알 수 없음", payload=""), None)
    assert f["sqli_grade"] == "POSSIBLE"
    assert f["confidence"] != "CONFIRMED"
    assert f["severity"] == "MEDIUM"
    assert f["title"] == "SQL 인젝션 가능성 — 추가 검증 필요"


def test_ghauri_known_is_likely_high():
    f = et.build_sqli_finding("http://t/p?uid=1", "t", 80, _ghauri(), None)
    assert f["sqli_grade"] == "LIKELY"
    assert f["severity"] == "HIGH"
    assert f["title"] == "SQL 인젝션 가능성 확인"


def test_owasp_cwe_mapping_even_when_not_confirmed():
    f = et.build_sqli_finding("http://t/p?x=1", "t", 80, _ghauri(param="unknown", inj="알 수 없음", backend="알 수 없음", payload=""), None)
    assert f["owasp"] == "A03:2021 - 인젝션"
    assert f["cwe"] == "CWE-89"


def test_forbidden_phrases_when_incomplete():
    # sqlmap 미검증 + unknown → '실증 확인' 금지
    f = et.build_sqli_finding("http://t/p?x=1", "t", 80, _ghauri(param="unknown", inj="알 수 없음", backend="알 수 없음", payload=""), None)
    assert "실증 확인" not in f["title"]
    # LIKELY(미검증)도 '실증 확인' 금지
    f2 = et.build_sqli_finding("http://t/p?uid=1", "t", 80, _ghauri(), None)
    assert "실증 확인" not in f2["title"]
    # databases 비어있으면 'DB 목록 추출 성공' 금지
    assert "DB 목록 추출 성공" not in f2["title"]


def test_grade_sqli_helper_levels():
    # 순수 등급 판정 함수
    assert et.grade_sqli(_ghauri(param="unknown", inj="알 수 없음", backend="알 수 없음", payload=""), None)["grade"] == "POSSIBLE"
    assert et.grade_sqli(_ghauri(), None)["grade"] == "LIKELY"
    assert et.grade_sqli(None, {"executed": True, "injectable": True, "parameter": "uid",
                                "injection_types": ["union"], "dbms": "MySQL",
                                "payloads": [], "databases": []})["grade"] == "CONFIRMED"
    # 내부 probe 실증 → CONFIRMED
    assert et.grade_sqli(_ghauri(), None, probe_confirmed=True)["grade"] == "CONFIRMED"
