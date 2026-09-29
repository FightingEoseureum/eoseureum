"""
test_finding_normalizer.py — finding_normalizer.normalize / classify 검증.

모듈: backend/finding_normalizer.py
  normalize(list[dict]) -> {findings, discovery_items, good_items, noise_items, summary}
  classify(f: dict) -> "vulnerability" | "discovery" | "good" | "noise"

핵심 불변식:
  - 단순 경로 발견(ffuf 401/403/302 등)은 discovery 이며 findings 에 포함되지 않는다.
  - 실증(probe_confirmed)·신뢰도(CONFIRMED)가 있는 실제 노출만 vulnerability 로 승격.
  - severity=INFO 라도 취약 승격 시 report_severity 는 "Low".
  - 동일 제목/경로 중복은 하나로 병합.
  - judgment=양호 는 good_items, findings 에는 미포함.
  - summary.vulnerability_count == len(findings) 항상 일치.

실행:
  cd backend && venv_linux/bin/python -m pytest tests/test_finding_normalizer.py -q
"""
import os
import sys

import pytest

# backend 디렉터리를 import 경로에 추가 (tests/ 의 부모)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import finding_normalizer as fn


def _finding(**kw) -> dict:
    """테스트용 finding dict 생성 — 실제 필드명을 사용한다."""
    base = {
        "host": "target.example.com",
        "port": 80,
        "judgment": "취약",
        "severity": "MEDIUM",
        "title": "",
        "confidence": None,
        "probe_confirmed": None,
        "tool_source": None,
        "evidence_detail": "",
        "evidence_url": "",
    }
    base.update(kw)
    return base


# ── classify 단위 케이스 ──────────────────────────────────────────────────────

def test_manager_html_401_not_vulnerability():
    """/manager/html (HTTP 401) → 공격 표면(또는 참고), 취약점 아님."""
    f = _finding(
        title="숨겨진 경로 발견: /manager/html (HTTP 401)",
        severity="MEDIUM",
        tool_source="ffuf",
        evidence_url="http://target.example.com:80/manager/html",
    )
    # 관리 경로(/manager)의 401 → 공격 표면. 어느 쪽이든 취약점은 아님.
    assert fn.classify(f) == "attack_surface"


def test_cgi_bin_302_ffuf_is_discovery():
    """/cgi-bin (HTTP 302), tool_source=ffuf → discovery."""
    f = _finding(
        title="숨겨진 경로 발견: /cgi-bin (HTTP 302)",
        severity="LOW",
        tool_source="ffuf",
        evidence_url="http://target.example.com:80/cgi-bin",
    )
    assert fn.classify(f) == "discovery"


def test_admin_302_is_discovery():
    """/admin (HTTP 302) → discovery (보호된 관리자 경로)."""
    f = _finding(
        title="/admin (HTTP 302)",
        severity="LOW",
        tool_source="ffuf",
        evidence_url="http://target.example.com:80/admin",
    )
    assert fn.classify(f) == "discovery"


def test_admin_200_login_form_is_attack_surface():
    """관리자 페이지 HTTP 200 + 로그인 폼만 확인 → 공격 표면(취약점 아님)."""
    f = _finding(
        title="관리자 페이지 인터넷 노출 (HTTP 200)",
        severity="HIGH",
        confidence="CONFIRMED",
        probe_confirmed=True,
        evidence_detail="HTTP 200, 로그인=있음",
        evidence_url="http://target.example.com:80/admin",
    )
    assert fn.classify(f) == "attack_surface"


def test_admin_unauth_access_is_vulnerability():
    """인증 없이 관리 기능 접근/민감정보 노출 근거가 있으면 → vulnerability 로 승격."""
    f = _finding(
        title="관리자 기능 인증 없이 접근 가능 (HTTP 200)",
        severity="HIGH",
        confidence="CONFIRMED",
        probe_confirmed=True,
        evidence_detail="HTTP 200, 로그인=없음 — 사용자 목록 조회 가능(무인증)",
        evidence_url="http://target.example.com:80/admin",
    )
    assert fn.classify(f) == "vulnerability"


def test_ffuf_simple_403_is_discovery():
    """ffuf 단순 403 결과 → discovery (findings 미포함)."""
    f = _finding(
        title="숨겨진 경로 발견: /private (HTTP 403)",
        severity="LOW",
        tool_source="ffuf",
        evidence_url="http://target.example.com:80/private",
    )
    assert fn.classify(f) == "discovery"


# ── normalize 통합 케이스 ─────────────────────────────────────────────────────

def test_ffuf_simple_results_not_in_findings():
    """ffuf 단순 401/403/302 결과는 findings 에 포함되지 않고 discovery 로 분류된다."""
    items = [
        _finding(title="숨겨진 경로 발견: /manager/html (HTTP 401)", severity="MEDIUM",
                 tool_source="ffuf", evidence_url="http://target.example.com:80/manager/html"),
        _finding(title="숨겨진 경로 발견: /cgi-bin (HTTP 302)", severity="LOW",
                 tool_source="ffuf", evidence_url="http://target.example.com:80/cgi-bin"),
        _finding(title="숨겨진 경로 발견: /private (HTTP 403)", severity="LOW",
                 tool_source="ffuf", evidence_url="http://target.example.com:80/private"),
    ]
    out = fn.normalize(items)
    assert len(out["findings"]) == 0
    assert out["summary"]["vulnerability_count"] == 0
    # /manager/html 401 은 공격 표면, 나머지는 참고 — 합쳐서 3건, 취약점 0건.
    assert len(out["discovery_items"]) + len(out["attack_surface_items"]) == 3


def test_info_severity_promoted_reports_as_low():
    """severity=INFO 항목이 취약 승격 조건을 충족하면 report_severity == 'Low'."""
    f = _finding(
        title="서버 소프트웨어 버전 정보 노출 (Server 헤더)",
        severity="INFO",
        confidence="CONFIRMED",
        evidence_detail="Server: Apache-Coyote/1.1 — 상세 버전 정보 노출 확인됨",
        evidence_url="http://target.example.com:80/",
    )
    out = fn.normalize([f])
    assert len(out["findings"]) == 1
    assert out["findings"][0]["finding_type"] == "vulnerability"
    assert out["findings"][0]["report_severity"] == "Low"


def test_duplicate_findings_merged_to_one():
    """동일 제목/경로 중복 2건 → 하나로 병합(len 1)."""
    common = dict(
        title="서버 소프트웨어 버전 정보 노출 (Server 헤더)",
        severity="LOW",
        confidence="CONFIRMED",
        evidence_detail="Server: Apache-Coyote/1.1 — 상세 버전 정보 노출 확인됨",
        evidence_url="http://target.example.com:80/",
    )
    out = fn.normalize([_finding(**common), _finding(**common)])
    assert len(out["findings"]) == 1
    assert out["summary"]["vulnerability_count"] == 1


def test_good_judgment_goes_to_good_items_not_findings():
    """judgment=양호 항목 → good_items, findings 에는 미포함."""
    f = _finding(
        title="TLS 설정 양호",
        judgment="양호",
        severity="LOW",
        evidence_url="http://target.example.com:80/",
    )
    out = fn.normalize([f])
    assert len(out["findings"]) == 0
    assert len(out["good_items"]) == 1
    assert out["good_items"][0]["finding_type"] == "good"
    assert out["summary"]["good_count"] == 1


def test_vulnerability_count_always_matches_findings_len():
    """summary.vulnerability_count == len(findings) 가 혼합 입력에서도 항상 일치."""
    items = [
        # vulnerability (Server 헤더 버전 노출 — LOW 취약점)
        _finding(title="서버 소프트웨어 버전 정보 노출 (Server 헤더)", severity="LOW",
                 confidence="CONFIRMED",
                 evidence_detail="Server: Apache-Coyote/1.1 — 상세 버전 정보 노출 확인됨",
                 evidence_url="http://target.example.com:80/"),
        # discovery (ffuf)
        _finding(title="숨겨진 경로 발견: /cgi-bin (HTTP 302)", severity="LOW",
                 tool_source="ffuf", evidence_url="http://target.example.com:80/cgi-bin"),
        # good
        _finding(title="TLS 설정 양호", judgment="양호", severity="LOW",
                 evidence_url="http://target.example.com:80/"),
        # noise (404)
        _finding(title="존재하지 않는 경로 (HTTP 404)", severity="LOW",
                 tool_source="ffuf", evidence_url="http://target.example.com:80/missing"),
    ]
    out = fn.normalize(items)
    assert out["summary"]["vulnerability_count"] == len(out["findings"])
    # 혼합 입력 분류가 의도대로 분리되었는지 함께 확인
    assert out["summary"]["vulnerability_count"] == 1
    assert out["summary"]["discovery_count"] == len(out["discovery_items"])
    assert out["summary"]["good_count"] == len(out["good_items"])
    assert out["summary"]["noise_count"] == len(out["noise_items"])


def test_empty_input_returns_empty_buckets():
    """빈 입력에서도 안전하게 빈 버킷/summary 를 반환한다."""
    out = fn.normalize([])
    assert out["findings"] == []
    assert out["summary"]["vulnerability_count"] == 0


def test_classify_is_exported():
    """classify 가 모듈에서 export 되어 직접 호출 가능하다."""
    assert callable(fn.classify)


def test_server_version_disclosure_is_low_vulnerability():
    """서버 버전/배너 정보 노출은 LOW 등급의 정상 취약점으로 분류된다(discovery 아님)."""
    f = {
        "title": "서버 소프트웨어 버전 정보 노출 (Server 헤더)",
        "judgment": "취약", "severity": "LOW", "confidence": "CONFIRMED",
        "evidence_detail": "Server: Apache-Coyote/1.1 [추가 확인] 포트 443에서도 동일 취약점 재현됨",
    }
    assert fn.classify(f) == "vulnerability"
    out = fn.normalize([f])
    assert len(out["findings"]) == 1
    assert out["findings"][0]["report_severity"] == "Low"


def test_hidden_path_401_not_vulnerability():
    """숨겨진 경로(HTTP 401)는 직접적 위협이 아니므로 취약점에 포함되지 않는다."""
    f = {
        "title": "숨겨진 경로 발견: /manager/html (HTTP 401)",
        "judgment": "취약", "severity": "MEDIUM", "confidence": None,
        "probe_confirmed": True, "tool_source": "ffuf",
        "evidence_detail": "URL : http://x:8080/manager/html\nStatus : 401",
    }
    assert fn.classify(f) == "attack_surface"
    out = fn.normalize([f])
    assert len(out["findings"]) == 0
