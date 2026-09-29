"""트렌드(신규/지속/해결) 안정 제목 회귀 테스트.

버그: resolved 판정이 '[포트 80, 443, 8080]' 같은 스캔마다 달라지는 포트 접미사를 포함한
제목을 exact-match 로 비교해, 같은 취약점이 포트 조합만 바뀌어도 '해결(양호)'로 오판되어
확정 취약점이 good_items 로 새어나갔다. finalize_trend + stable_title 로 해결.
"""
import rule_engine as re_mod
from rule_engine import stable_title, finalize_trend


def test_stable_title_strips_port_suffix():
    assert stable_title("CSRF 방어 부재 [포트 80, 443, 8080]") == "CSRF 방어 부재"
    assert stable_title("SQL 인젝션 인증 우회 — 로그인 폼(음성 대조 차등 확증) [포트 80, 8080]") \
        == "SQL 인젝션 인증 우회 — 로그인 폼(음성 대조 차등 확증)"
    # 포트 접미사가 없으면 그대로
    assert stable_title("반사형 XSS (Reflected XSS) 실증 확인") == "반사형 XSS (Reflected XSS) 실증 확인"


def _prev(title):
    return [{"analysis": {"findings": [{"title": title, "judgment": "취약"}]}}]


def test_port_suffix_change_not_false_resolved():
    """이전 스캔은 [포트 80, 8080], 이번은 [포트 80, 443, 8080] — 같은 취약점이므로
    '해결'이 아니라 '지속'으로 판정되고 good_items 오염이 없어야 한다."""
    analysis = {
        "findings": [{
            "title": "SQL 인젝션 인증 우회 — 로그인 폼(음성 대조 차등 확증) [포트 80, 443, 8080]",
            "judgment": "취약",
        }],
        "good_items": [],
        "summary": {"by_type": {}},
    }
    prev = _prev("SQL 인젝션 인증 우회 — 로그인 폼(음성 대조 차등 확증) [포트 80, 8080]")
    finalize_trend(analysis, prev)

    # 해결로 오판되지 않음 → good_items 에 phantom 없음
    assert analysis["good_items"] == []
    assert analysis["resolved_findings_count"] == 0
    assert analysis["persistent_findings_count"] == 1
    assert analysis["new_findings_count"] == 0
    assert analysis["trend"] == "stable"
    # 지속 플래그 부여
    assert analysis["findings"][0]["is_persistent"] is True
    assert analysis["findings"][0]["is_new"] is False


def test_genuinely_resolved_still_reported():
    """이전엔 있었고 이번엔 정말 사라진 취약점만 '해결(양호)'로 good_items 에 표기."""
    analysis = {
        "findings": [{"title": "반사형 XSS 실증 확인", "judgment": "취약"}],
        "good_items": [],
        "summary": {"by_type": {}},
    }
    prev = _prev("Open Redirect 취약점")
    finalize_trend(analysis, prev)

    resolved = [g for g in analysis["good_items"] if g.get("is_resolved")]
    assert len(resolved) == 1
    assert resolved[0]["title"] == "Open Redirect 취약점"
    assert resolved[0]["judgment"] == "양호"
    assert analysis["resolved_findings_count"] == 1
    assert analysis["new_findings_count"] == 1   # 반사형 XSS 는 신규
    assert analysis["trend"] == "stable"          # 신규 1 == 해결 1


def test_first_scan_no_trend_pollution():
    analysis = {"findings": [{"title": "X", "judgment": "취약"}], "good_items": []}
    finalize_trend(analysis, None)
    assert analysis["trend"] == "first_scan"
    assert analysis["good_items"] == []


def test_login_sqli_never_false_resolved():
    """login_sqli 는 rule_engine 이 아니라 main.py 가 생성 → 이전엔 rule_engine current_titles 에
    없어 '항상 해결'로 오판됐다. finalize_trend 는 완전한 findings 를 보므로 오판하지 않아야 한다."""
    analysis = {
        "findings": [
            {"title": "SQL 인젝션 인증 우회 — 로그인 폼(음성 대조 차등 확증) [포트 80, 443, 8080]",
             "judgment": "취약"},
            {"title": "CSRF 방어 부재 — 동적 검증(교차출처 요청 수락) [포트 80, 443, 8080]",
             "judgment": "취약"},
        ],
        "good_items": [],
        "summary": {"by_type": {}},
    }
    prev = [{"analysis": {"findings": [
        {"title": "SQL 인젝션 인증 우회 — 로그인 폼(음성 대조 차등 확증)", "judgment": "취약"},
        {"title": "CSRF 방어 부재 — 동적 검증(교차출처 요청 수락) [포트 80]", "judgment": "취약"},
    ]}}]
    finalize_trend(analysis, prev)
    # 둘 다 지속 — good_items(양호) 오염 없음
    assert analysis["good_items"] == []
    assert analysis["resolved_findings_count"] == 0
    assert analysis["persistent_findings_count"] == 2
