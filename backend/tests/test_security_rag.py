"""
test_security_rag.py — security_rag.retrieve_knowledge 검증.

모듈: backend/security_rag.py
  retrieve_knowledge(finding, technologies=None, attack_chains=None)
    -> {"matched_knowledge": [{"id","title","owasp","cwe","matched_keywords","remediation"}, ...]}

핵심 불변식:
  - 관련 finding 은 올바른 지식 엔트리(id/cwe)에 매칭된다.
  - 매칭이 없으면 {"matched_knowledge": []}.
  - 최대 5개로 제한된다.

실행:
  cd backend && venv_linux/bin/python -m pytest tests/test_security_rag.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import security_rag


def _ids(result):
    return [m["id"] for m in result["matched_knowledge"]]


def _shape_ok(result):
    assert isinstance(result, dict)
    assert isinstance(result["matched_knowledge"], list)
    for m in result["matched_knowledge"]:
        assert set(m.keys()) == {"id", "title", "owasp", "cwe", "matched_keywords", "remediation"}
        assert isinstance(m["matched_keywords"], list)
        assert isinstance(m["remediation"], list)


# ── Clickjacking → CWE-1021 / CLICKJACKING ───────────────────────────────────
def test_clickjacking_matches_cwe_1021():
    finding = {
        "title": "Clickjacking 취약점 — iframe 실제 로드 확인",
        "cwe": "CWE-1021",
        "severity": "LOW",
    }
    result = security_rag.retrieve_knowledge(finding)
    _shape_ok(result)
    ids = _ids(result)
    assert "CLICKJACKING" in ids
    matched = next(m for m in result["matched_knowledge"] if m["id"] == "CLICKJACKING")
    assert matched["cwe"] == "CWE-1021"
    assert matched["remediation"]


# ── TRACE → HTTP Method 지식 ─────────────────────────────────────────────────
def test_trace_method_matches():
    finding = {"title": "위험한 HTTP Method 활성화 (PUT/DELETE/TRACE)"}
    result = security_rag.retrieve_knowledge(finding)
    _shape_ok(result)
    assert "TRACE_METHOD" in _ids(result)


# ── Server 헤더 → Information Disclosure 지식 ────────────────────────────────
def test_server_header_matches_info_disclosure():
    finding = {"title": "서버 소프트웨어 버전 정보 노출 (Server 헤더)"}
    result = security_rag.retrieve_knowledge(finding)
    _shape_ok(result)
    assert "SERVER_HEADER" in _ids(result)


# ── Redis 인증 없는 접근 → REDIS_UNAUTH ──────────────────────────────────────
def test_redis_unauth_matches():
    finding = {
        "title": "Redis 인증 없는 접근",
        "evidence": "6379 unauthenticated",
    }
    result = security_rag.retrieve_knowledge(finding)
    _shape_ok(result)
    ids = _ids(result)
    assert "REDIS_UNAUTH" in ids
    matched = next(m for m in result["matched_knowledge"] if m["id"] == "REDIS_UNAUTH")
    assert matched["cwe"] == "CWE-306"
    assert matched["remediation"]


# ── DNS Zone Transfer → DNS_ZONE_TRANSFER ────────────────────────────────────
def test_dns_zone_transfer_matches():
    finding = {
        "title": "DNS Zone Transfer 허용 (AXFR)",
        "evidence": "axfr zone transfer 영역 전송 가능",
    }
    result = security_rag.retrieve_knowledge(finding)
    _shape_ok(result)
    ids = _ids(result)
    assert "DNS_ZONE_TRANSFER" in ids
    matched = next(m for m in result["matched_knowledge"] if m["id"] == "DNS_ZONE_TRANSFER")
    assert matched["cwe"] == "CWE-200"


# ── 매칭 안 됨 → 빈 결과 ─────────────────────────────────────────────────────
def test_no_match_returns_empty():
    finding = {"title": "전혀 관련 없는 임의 항목 zzz"}
    result = security_rag.retrieve_knowledge(finding)
    assert result == {"matched_knowledge": []}


# ── 최대 5개 제한 ────────────────────────────────────────────────────────────
def test_max_five_results():
    # 다수 지식 엔트리의 키워드를 한꺼번에 포함하는 finding
    finding = {
        "title": "복합 점검 항목",
        "evidence_detail": (
            "sql injection union, reflected xss, stored xss, clickjacking iframe, "
            "trace http method, server 헤더 버전 정보, 에러 페이지 stack trace, "
            "cors access-control-allow-origin, path traversal lfi, ssrf 서버 사이드 요청, "
            "admin 관리자 로그인 폼, swagger openapi, graphql graphiql, actuator heapdump env, "
            "backup 백업 파일, .env 환경변수 파일, .git 노출"
        ),
        "tags": ["sql injection", "xss", "clickjacking"],
    }
    result = security_rag.retrieve_knowledge(finding)
    _shape_ok(result)
    assert len(result["matched_knowledge"]) <= 5
    assert len(result["matched_knowledge"]) == 5


# ── 입력 방어: 비정상 입력에도 빈 결과 ───────────────────────────────────────
def test_defensive_inputs():
    assert security_rag.retrieve_knowledge({}) == {"matched_knowledge": []}
    assert security_rag.retrieve_knowledge(None) == {"matched_knowledge": []}


# ── 기술/체인 보조 매칭이 키워드 매칭과 함께 동작 ────────────────────────────
def test_technology_boost_does_not_break():
    finding = {"title": "서버 버전 정보 노출"}
    result = security_rag.retrieve_knowledge(
        finding,
        technologies=[{"product": "Apache Tomcat", "version": "9.0.30"}],
        attack_chains=[{"id": "ADMIN_SURFACE_CHAIN"}],
    )
    _shape_ok(result)
    assert "SERVER_HEADER" in _ids(result)
