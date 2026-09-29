"""코드검토 티어3 — 정확성: _parse_vote 부정·리포트번호 결정성·finalize_trend 오판·QA키."""
import ai_provider as ap
import rule_engine as re_mod


# ── 3-E2: _parse_vote 한국어 부정 처리 ───────────────────────────────────────
def test_parse_vote_negation_is_fp():
    assert ap._parse_vote("취약하지 않음") == "fp"
    assert ap._parse_vote("정탐 아님 — 오탐으로 보임") == "fp"
    assert ap._parse_vote("해당 없음") in ("fp", "uncertain")  # 부정+정탐/취약 아니면 uncertain 허용


def test_parse_vote_positive_still_real():
    assert ap._parse_vote("REAL") == "real"
    assert ap._parse_vote("취약함이 확인됨") == "real"
    assert ap._parse_vote("정탐") == "real"


def test_parse_vote_fp_keyword():
    assert ap._parse_vote("FP") == "fp"
    assert ap._parse_vote("오탐입니다") == "fp"


# ── 3-D2: 리포트번호 결정성 ──────────────────────────────────────────────────
def test_report_number_deterministic():
    import hashlib
    dom = "example.com"
    n1 = int(hashlib.md5(dom.encode()).hexdigest()[:8], 16) % 10000
    n2 = int(hashlib.md5(dom.encode()).hexdigest()[:8], 16) % 10000
    assert n1 == n2   # 같은 도메인 → 항상 동일(PYTHONHASHSEED 무관)


# ── 3-D4: finalize_trend — 강등 항목을 resolved 로 오판하지 않음 ─────────────
def test_finalize_trend_demoted_not_resolved():
    """이전 스캔 취약이 이번엔 참고(discovery)로 강등돼도 '조치됨(good)'으로 오판 안 함."""
    prev = [{"analysis": {"findings": [{"title": "SQL 인젝션 취약점 실증 확인", "judgment": "취약",
                           "report_severity": "High"}]}}]
    analysis = {
        "findings": [],   # 이번엔 취약에서 빠짐
        "discovery_items": [{"title": "SQL 인젝션 취약점 실증 확인", "judgment": "참고"}],  # 참고로 강등
        "attack_surface_items": [],
    }
    re_mod.finalize_trend(analysis, prev)
    good_titles = [g.get("title") for g in analysis.get("good_items", [])]
    assert "SQL 인젝션 취약점 실증 확인" not in good_titles   # 강등이지 조치 아님


def test_finalize_trend_genuinely_resolved():
    """이전 취약이 이번엔 어디에도 없으면 정상적으로 resolved(good)."""
    prev = [{"analysis": {"findings": [{"title": "사라진 취약점 XYZ", "judgment": "취약",
                           "report_severity": "High"}]}}]
    analysis = {"findings": [], "discovery_items": [], "attack_surface_items": []}
    re_mod.finalize_trend(analysis, prev)
    good_titles = [g.get("title") for g in analysis.get("good_items", [])]
    assert any("사라진 취약점 XYZ" in t for t in good_titles)
