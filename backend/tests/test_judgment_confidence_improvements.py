"""
test_judgment_confidence_improvements.py
  - CMDi 오탐 제거: 입력 반사 vs 실제 명령 출력 구분
  - SQLi 판정 등급: ghauri=LIKELY / sqlmap=CONFIRMED, 표현 정책
  - SQLMap 출력 파싱
  - soft-404(catch-all) 시그니처 비교

네트워크/서브프로세스 없음(순수 함수 검증).
실행: cd backend && venv_linux/bin/python -m pytest tests/test_judgment_confidence_improvements.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import active_probing as ap
import external_tools as et
from url_discovery import URLDiscoveryEngine


# ── CMDi: 입력 반사는 명령 출력이 아님 ─────────────────────────────────────────
def test_cmdi_reflected_input_is_not_command_output():
    token = ap._CMDI_TOKEN
    payload = f"; echo {token}"
    # demo.testfire.net 처럼 입력이 그대로 반사된 경우 — 'echo TOKEN' 이 응답에 남아있음
    reflected = f"No results were found for the query: test; echo {token}"
    assert ap._cmdi_is_command_output(reflected, "test", payload) is False


def test_cmdi_real_command_output_is_detected():
    token = ap._CMDI_TOKEN
    payload = f"; echo {token}"
    # 실제 셸 실행 시 'echo'/메타문자는 사라지고 토큰만 출력됨
    executed = f"<html><body>{token}\n</body></html>"
    assert ap._cmdi_is_command_output(executed, "test", payload) is True


def test_cmdi_no_token_is_not_output():
    payload = f"; echo {ap._CMDI_TOKEN}"
    assert ap._cmdi_is_command_output("정상 응답, 토큰 없음", "test", payload) is False


# ── SQLi 판정 등급/표현 정책 (신정책: POSSIBLE/LIKELY/CONFIRMED) ────────────────
def test_sqli_ghauri_only_is_likely():
    # parameter + injection type 확인(미실증) → LIKELY (실증/추출성공 표현 금지)
    ghauri_sig = {"param": "uid", "backend": "MySQL", "inj_type": "boolean-based blind",
                  "title": "", "payload": "uid=1 AND 1=1", "databases": [], "grade": "LIKELY"}
    f = et.build_sqli_finding("http://t/p?uid=1", "t", 80, ghauri_sig, None)
    assert f is not None
    assert f["sqli_grade"] == "LIKELY"
    assert f["confidence"] == "LIKELY"
    assert "DB 목록 추출 성공" not in f["title"]
    assert "실증 확인" not in f["title"]
    assert "가능성 확인" in f["title"]
    assert f["probe_confirmed"] is False
    assert f["owasp"] == "A03:2021 - 인젝션" and f["cwe"] == "CWE-89"


def test_sqli_sqlmap_confirmed_with_enumeration():
    sqlmap_res = {"executed": True, "injectable": True, "parameter": "uid",
                  "injection_types": ["boolean-based blind"], "dbms": "MySQL",
                  "payloads": ["uid=1 AND 1234=1234"],
                  "databases": ["information_schema", "altoro"],
                  "command": 'sqlmap -u "http://t/p?uid=1" --batch', "error": None}
    f = et.build_sqli_finding("http://t/p?uid=1", "t", 80, None, sqlmap_res)
    assert f["sqli_grade"] == "CONFIRMED"
    assert f["probe_confirmed"] is True
    assert "실증 확인" in f["title"]
    assert "DB 목록 추출 성공" in f["title"]   # databases 1개 이상 파싱 시에만
    assert f["sqlmap"]["parameter"] == "uid"
    assert "information_schema" in f["evidence_detail"]


def test_sqli_sqlmap_confirmed_without_enumeration_no_success_wording():
    sqlmap_res = {"executed": True, "injectable": True, "parameter": "uid",
                  "injection_types": ["error-based"], "dbms": "MySQL",
                  "payloads": [], "databases": [], "command": "...", "error": None}
    f = et.build_sqli_finding("http://t/p?uid=1", "t", 80, None, sqlmap_res)
    assert f["sqli_grade"] == "CONFIRMED"
    assert "추출 성공" not in f["title"]   # databases 비어 있으면 추출 성공 문구 금지


def test_sqli_ghauri_unknown_is_not_confirmed():
    # parameter/dbms/type 모두 unknown, payload 없음 → POSSIBLE (절대 CONFIRMED 아님)
    ghauri_sig = {"param": "unknown", "backend": "알 수 없음", "inj_type": "알 수 없음",
                  "title": "", "payload": "", "databases": [], "grade": "LIKELY"}
    f = et.build_sqli_finding("http://t/p?x=1", "t", 80, ghauri_sig, None)
    assert f["sqli_grade"] == "POSSIBLE"
    assert f["confidence"] != "CONFIRMED"
    assert f["severity"] == "MEDIUM"
    assert "추가 검증" in f["title"]
    assert "실증 확인" not in f["title"]


def test_sqli_no_signal_returns_none():
    assert et.build_sqli_finding("http://t/p?uid=1", "t", 80, None, None) is None


def test_parse_sqlmap_output_extracts_fields():
    out = """
    sqlmap identified the following injection point(s)
    Parameter: uid (GET)
        Type: boolean-based blind
        Payload: uid=1 AND 1234=1234
    back-end DBMS: MySQL >= 5.0
    available databases [2]:
    [*] information_schema
    [*] altoro
    """
    r = et._parse_sqlmap_output(out)
    assert r["injectable"] is True
    assert r["parameter"].startswith("uid")
    assert "boolean-based blind" in r["injection_types"]
    assert "MySQL" in r["dbms"]
    assert "information_schema" in r["databases"]


def test_parse_sqlmap_output_not_injectable():
    r = et._parse_sqlmap_output("all tested parameters do not appear to be injectable")
    assert r["injectable"] is False
    assert r["parameter"] is None


# ── soft-404(catch-all) 비교 ───────────────────────────────────────────────────
def test_soft404_signature_and_match():
    eng = URLDiscoveryEngine()
    # 존재하지 않는 임의 경로가 동일한 catch-all 본문을 반환하는 사이트를 모사
    body_a = "<html><body>Welcome page</body></html>"
    ln, h = eng._soft404_sig(body_a, "/random")
    eng._soft404 = {"statuses": {200}, "hashes": {h}, "lengths": [ln]}
    # /admin 도 같은 본문 → soft-404 로 판정되어 관리자 페이지 집계 제외 대상
    assert eng._is_soft404(200, body_a, "/admin") is True
    # 명확히 다른(긴) 본문은 soft-404 아님
    assert eng._is_soft404(200, "<html>" + "x" * 500 + "</html>", "/admin") is False


def test_soft404_absent_baseline_returns_false():
    eng = URLDiscoveryEngine()
    eng._soft404 = None
    assert eng._is_soft404(200, "anything", "/admin") is False
