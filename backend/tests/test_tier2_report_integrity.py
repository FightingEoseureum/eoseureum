"""코드검토 티어2 — 오탐/리포트 무결성: 억제FP 제외·유효분포 통일·bare confirmed 강화."""
import report_html_renderer as rhr
import report as rpt
import rule_engine as re_mod
import business_impact_engine as bie


def _analysis_with_suppressed():
    return {
        "findings": [
            {"title": "SQLi", "judgment": "취약", "severity": "High", "cwe": "CWE-89"},
            {"title": "가짜 오탐", "judgment": "취약", "severity": "Critical",
             "cwe": "CWE-79", "_fp_suppressed": True},   # 억제된 오탐
            {"title": "양호항목", "judgment": "양호", "severity": "Low"},
        ],
        "summary": {"by_severity": {"Critical": 1, "High": 1, "Medium": 0, "Low": 0}},
    }


# ── #1: HTML 요약이 억제 오탐을 '확인됨'으로 노출하지 않음 ────────────────────
def test_html_excludes_suppressed_fp():
    html = rhr.generate_html(_analysis_with_suppressed())
    assert "SQLi" in html
    assert "가짜 오탐" not in html          # 억제된 오탐은 고객 요약에 미노출
    # '확인됨' 배지 행 수 = 실제 확정 취약점 수(억제 제외)와 일치해야 함
    assert html.count("확인됨") <= 2         # SQLi 1건(+상태헤더 등), 억제분 미포함


# ── #2: 유효 심각도 분포(_eff_severity_counts)가 억제를 차감 ─────────────────
def test_eff_severity_counts_subtracts_suppressed():
    counts = rpt._eff_severity_counts(_analysis_with_suppressed())
    # 억제된 Critical 1 은 차감 → Critical 0, High 1
    assert counts["Critical"] == 0
    assert counts["High"] == 1


# ── #3: 비즈니스 영향 집계가 억제/양호를 제외 ────────────────────────────────
def test_business_impact_excludes_suppressed_and_good():
    a = {
        "findings": [
            {"title": "명령어 인젝션 실행", "judgment": "취약", "severity": "Critical"},
            {"title": "오탐건", "judgment": "취약", "severity": "Critical", "_fp_suppressed": True},
            {"title": "양호건", "judgment": "양호", "severity": "Low"},
        ],
    }
    bi = bie.build_business_impact(a)
    titles = [it.get("title") for it in bi.get("items", [])]
    assert "오탐건" not in titles and "양호건" not in titles


# ── #4: file_upload 실행 미확인 → 미확정 (위 test_file_upload_rce 와 중복 아님) ─
def test_upload_requires_code_execution():
    assert re_mod._has_concrete_evidence(
        "file_upload", {"uploaded_url": "u", "confirmed": True}) is False
    assert re_mod._has_concrete_evidence(
        "file_upload", {"uploaded_url": "u", "confirmed": True, "code_execution": True}) is True


# ── #5: bare confirmed(증거 신호 없음)는 미확정, 증거 동반 시 확정 ────────────
def test_bare_confirmed_rejected():
    # 신규 키(명시 분기 없음) 가정 — 증거 신호 없는 bare confirmed
    assert re_mod._has_concrete_evidence("session_fixation", {"confirmed": True}) is False
    # evidence 등 신호가 있으면 확정
    assert re_mod._has_concrete_evidence(
        "session_fixation", {"confirmed": True, "evidence": "세션 고정 실증"}) is True
    assert re_mod._has_concrete_evidence(
        "jwt_alg_none", {"confirmed": True, "url": "http://t/", "param": "sid"}) is True
