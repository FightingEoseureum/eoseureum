"""test_report_v7_consulting.py — Report UX v7 (상용 컨설팅 보고서 IA/표현)."""
import os, sys, io
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import report
from docx import Document


def _txt(doc):
    """문서 순서(문단·표 인터리브)대로 텍스트를 추출 — 구간 슬라이스가 실제 배치를 반영."""
    from docx.text.paragraph import Paragraph
    from docx.table import Table
    parts = []

    def walk(container, parent):
        for child in parent:
            if child.tag.endswith("}p"):
                parts.append(Paragraph(child, container).text)
            elif child.tag.endswith("}tbl"):
                tbl = Table(child, container)
                for r in tbl.rows:
                    for c in r.cells:
                        parts.append(c.text)

    walk(doc, doc.element.body)
    return "\n".join(parts)


def _rich():
    from tests.test_report_v4_ux import _rich as r
    return r()


def _gen(analysis=None):
    a = analysis or _rich()
    buf = report.generate_report({"domain": "t.example.com", "analysis": a,
                                  "created_at": "2026-07-01", "results": []})
    return Document(io.BytesIO(buf.getvalue()))


# ── 1. Information Architecture (표지→기밀→목차→Exec→Overview→KeyFindings→
#      AttackStory→RiskMatrix→DetailedFindings→Asset/Service→Recommendations→Appendix) ──
def test_v7_information_architecture_order():
    txt = _txt(_gen())

    def pos(s):
        i = txt.find(s)
        assert i >= 0, f"섹션 누락: {s}"
        return i

    # v8 표준 8단 IA: 표지→기밀→목차→목적→대상→점검항목→총평→발견→상세→대응→부록
    order = [
        "Confidentiality Notice", "Contents",
        "점검 목적", "점검 대상", "점검 항목 및 위험도", "Executive Summary",
        "발견된 취약점", "취약점 상세", "대응방안", "부록",
    ]
    positions = [pos(s) for s in order]
    assert positions == sorted(positions), f"IA 순서 불일치: {positions}"


def test_v7_contents_before_executive_summary():
    txt = _txt(_gen())
    assert txt.find("Contents") < txt.find("Executive Summary")
    assert txt.find("Confidentiality") < txt.find("Contents")


def test_v7_confidentiality_notice_present():
    txt = _txt(_gen())
    assert "Confidentiality Notice" in txt
    assert "대외비" in txt


# ── 2. Executive Summary: 경영 KPI만, 엔진 내부 용어 없음 ─────────────────────
def _second(txt, s):
    """TOC 항목(1회차) 이후 실제 섹션 위치(2회차)."""
    first = txt.find(s)
    return txt.find(s, first + 1)


def test_v7_executive_summary_clean():
    txt = _txt(_gen())
    # TOC 항목을 건너뛰고 실제 섹션 본문 구간만 검사
    exec_region = txt[_second(txt, "Executive Summary"):_second(txt, "발견된 취약점")]
    assert "보안 점수" in exec_region and "종합 위험도" in exec_region
    assert "즉시 조치" in exec_region and "비즈니스 영향" in exec_region
    assert "Scan Target" in exec_region and "Scan Period" in exec_region
    # 엔진/내부 용어는 경영진 요약에 노출되지 않는다
    for term in ("Solver", "Agent", "Planner", "Attack Surface Planner", "Rule Engine",
                 "공격 표면 → 공격 경로"):
        assert term not in exec_region, f"Executive Summary 내부 용어 노출: {term}"


# ── 3. Attack Story: Top 3 + 단순 흐름 ───────────────────────────────────────

# ── 4. Finding Card: Technical Detail 박스 추가(5박스) ───────────────────────
def test_v7_finding_card_technical_detail():
    a = _rich(); doc = Document()
    report._add_observed_view_block(doc, a["findings"][0], a)
    txt = _txt(doc)
    for box in ("관찰 내용", "확보 증거", "비즈니스 영향", "기술 세부", "권장 조치"):
        assert box in txt, f"카드 박스 누락: {box}"
    assert "Technical Detail" in txt


# ── 5. 커버리지 카드(고객용): 총 URL/입력점/관리자/API/완료율/총 Finding ────────
def test_v7_simple_coverage_card():
    doc = Document()
    report._add_simple_coverage_card(doc, {"total_urls": 12, "api_count": 3,
                                           "admin_pages": ["/admin"]}, _rich(), 3)
    txt = _txt(doc)
    for k in ("총 점검 URL", "총 입력점", "발견 관리자 페이지", "발견 API",
              "점검 완료율", "총 Finding"):
        assert k in txt, f"커버리지 항목 누락: {k}"


# ── 6. Recommendations: 로드맵 + 컨설팅 문체 ─────────────────────────────────
def test_v7_recommendations_section():
    txt = _txt(_gen())
    rec_region = txt[_second(txt, "Recommendations"):_second(txt, "Appendix")]
    assert "개선 로드맵" in rec_region or "우선 조치 권고" in rec_region


def test_v7_consulting_reco_expands_terse():
    out = report._consulting_reco("Server Header 제거")
    assert out.endswith("권고합니다.") and len(out) > 30
    # 이미 문장형이면 그대로
    long = "웹 서버 설정을 변경하여 취약점을 제거하실 것을 권고합니다."
    assert report._consulting_reco(long) == long


# ── 7. 엔진 내부 용어는 본문(6장 이전)에 없고 부록에만 ───────────────────────
def test_v7_engine_terms_only_in_appendix():
    txt = _txt(_gen())
    body = txt[:_second(txt, "Appendix")]
    # Solver/Agent 등 엔진 내부 용어는 고객 본문에 노출되지 않는다
    for term in ("idor_solver", "object_reference_agent", "Evidence Chain"):
        assert term not in body, f"본문에 엔진 용어 노출: {term}"


# ── 8. 전체 회귀(v3~v6 핵심 섹션 유지) ───────────────────────────────────────
def test_v7_full_report_intact(monkeypatch):
    monkeypatch.setenv("REPORT_SHOW_ENGINE_INTERNAL", "true")   # 풀 리포트(엔진내부 포함) 검증
    txt = _txt(_gen())
    for sect in ("Security Assessment Report", "Contents", "Executive Summary",
                 "점검 목적", "점검 대상", "점검 항목 및 위험도", "발견된 취약점",
                 "취약점 상세", "대응방안", "부록", "Developer Appendix"):
        assert sect in txt, f"섹션 누락: {sect}"
