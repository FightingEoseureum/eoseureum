"""
test_attack_chain_engine.py — attack_chain_engine.build_chains 검증.

모듈: backend/attack_chain_engine.py
  build_chains(findings, attack_surface_items=None, discovery_items=None,
               technologies=None) -> {"chains": [chain, ...]}

핵심 불변식:
  - 입력 findings/attack_surface_items 리스트의 개수·각 항목의 severity 를 변경하지 않는다.
  - 매칭되는 체인이 없으면 {"chains": []}.
  - 각 chain dict 는 title/confidence_score/steps/impact/required_conditions/recommendation
    키를 모두 가지며 confidence_score 는 0~100.

실행:
  cd backend && venv_linux/bin/python -m pytest tests/test_attack_chain_engine.py -q
"""
import copy
import os
import sys

# backend 디렉터리를 import 경로에 추가 (tests/ 의 부모)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attack_chain_engine as ace

_REQUIRED_KEYS = {
    "title", "confidence_score", "steps", "impact",
    "required_conditions", "recommendation",
}


def _assert_chain_shape(chain):
    assert _REQUIRED_KEYS.issubset(chain.keys())
    assert isinstance(chain["title"], str)
    assert isinstance(chain["confidence_score"], int)
    assert 0 <= chain["confidence_score"] <= 100
    assert isinstance(chain["steps"], list) and chain["steps"]
    assert isinstance(chain["impact"], str)
    assert isinstance(chain["required_conditions"], list)
    assert isinstance(chain["recommendation"], str)


# ── admin + Tomcat → 관리/Tomcat 체인 ────────────────────────────────────────
def test_admin_surface_with_tomcat_tech_builds_chain():
    surface = [{"title": "Tomcat Manager 접근", "path": "/manager/html",
                "evidence_url": "http://t.example.com/manager/html"}]
    tech = [{"product": "Apache Tomcat", "version": "9.0.30"}]
    result = ace.build_chains([], surface, technologies=tech)

    assert result["chains"], "관리/Tomcat 관련 체인이 1개 이상 생성되어야 한다"
    titles = " ".join(c["title"] for c in result["chains"])
    assert ("Tomcat" in titles) or ("관리 인터페이스" in titles)
    for c in result["chains"]:
        _assert_chain_shape(c)


def test_admin_login_with_server_tech_builds_chain():
    surface = [{"title": "관리자 로그인 페이지", "path": "/admin/login"}]
    tech = [{"product": "nginx", "version": "1.18.0"}]
    result = ace.build_chains([], surface, technologies=tech)
    assert any("관리 인터페이스" in c["title"] for c in result["chains"])


# ── swagger → API 체인 ───────────────────────────────────────────────────────
def test_swagger_surface_builds_api_chain():
    surface = [{"title": "Swagger UI 노출", "path": "/swagger-ui.html"}]
    result = ace.build_chains([], surface)
    assert any("API" in c["title"] for c in result["chains"])
    for c in result["chains"]:
        _assert_chain_shape(c)


# ── 입력 불변성: 개수·severity 변경 금지 ─────────────────────────────────────
def test_inputs_are_not_mutated():
    findings = [
        {"title": "Server 헤더 버전 노출", "severity": "LOW",
         "confidence": "CONFIRMED", "evidence_detail": "Server: Apache/2.4.49"},
        {"title": "에러 페이지 스택 트레이스 노출", "severity": "MEDIUM"},
        {"title": ".git/config 노출", "severity": "HIGH", "probe_confirmed": True},
    ]
    surface = [
        {"title": "관리자 로그인 페이지", "path": "/admin/login"},
        {"title": "Swagger UI", "path": "/swagger-ui.html"},
    ]
    tech = [{"product": "Apache httpd", "version": "2.4.49"}]

    findings_before = copy.deepcopy(findings)
    surface_before = copy.deepcopy(surface)

    ace.build_chains(findings, surface, technologies=tech)

    # 개수 불변
    assert len(findings) == len(findings_before)
    assert len(surface) == len(surface_before)
    # severity 및 전체 내용 불변
    for after, before in zip(findings, findings_before):
        assert after["severity"] == before["severity"]
        assert after == before
    for after, before in zip(surface, surface_before):
        assert after == before


# ── 빈 입력 → {"chains": []} ──────────────────────────────────────────────────
def test_empty_inputs_return_empty_chains():
    assert ace.build_chains([]) == {"chains": []}
    assert ace.build_chains([], [], [], []) == {"chains": []}
    assert ace.build_chains(None, None, None, None) == {"chains": []}


def test_no_match_returns_empty_chains():
    findings = [{"title": "관련 없는 항목", "severity": "LOW"}]
    assert ace.build_chains(findings) == {"chains": []}


# ── 모든 체인 dict 키 형태 검증 ──────────────────────────────────────────────
def test_all_chains_have_required_keys():
    findings = [
        {"title": "Server 헤더 버전 노출", "severity": "LOW", "confidence": "CONFIRMED"},
        {"title": "에러 페이지 노출", "severity": "MEDIUM"},
        {"title": ".env 파일 노출", "severity": "HIGH", "probe_confirmed": True},
        {"title": "Clickjacking 가능(X-Frame-Options 미설정)", "severity": "LOW"},
    ]
    surface = [
        {"title": "Tomcat Manager", "path": "/manager/html"},
        {"title": "관리자 로그인", "path": "/admin/login"},
        {"title": "GraphQL 엔드포인트", "path": "/graphql"},
        {"title": "Spring Boot Actuator env", "path": "/actuator/env"},
    ]
    tech = [{"product": "Apache Tomcat", "version": "9.0.30"}]
    result = ace.build_chains(findings, surface, technologies=tech)
    assert result["chains"]
    for c in result["chains"]:
        _assert_chain_shape(c)
