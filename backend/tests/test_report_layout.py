"""report.py 레이아웃/문구 개선 회귀 테스트.

- 12) 합성 analysis(취약점 2개)로 generate_report 호출 → docx 생성 성공,
      각 VULN 상세 앞 page_break 존재(취약점 수만큼) 근사 검증.
- 13) 빈/불필요 page_break·연속 빈 문단 과도하지 않은지 근사 검증.
- 14) TRACE 만 검증된 finding → 문서 텍스트에 "PUT 업로드"/"웹쉘"/"RCE" 없음.
"""
import io

from docx import Document

import report


def _base_finding(idx, title, **extra):
    f = {
        "title": title,
        "host": "example.com",
        "port": 443,
        "service": "https",
        "severity": "MEDIUM",
        "report_severity": "Medium",
        "confidence": "CONFIRMED",
        "confidence_score": 80,
        "judgment": "취약",
        "owasp": "A05",
        "recommendation": "보안 설정을 점검하십시오.",
        "evidence_detail": "근거 텍스트 " * 5,
    }
    f.update(extra)
    return f


def _build_scan(findings, summary=None, **analysis_extra):
    analysis = {
        "overall_risk": "MEDIUM",
        "overall_summary": "합성 점검 결과 요약입니다.",
        "findings": findings,
        "summary": summary or {},
    }
    analysis.update(analysis_extra)
    return {
        "domain": "example.com",
        "created_at": "2026-06-11",
        "results": [
            {
                "host": "example.com",
                "ip": "192.0.2.1",
                "scan_mode": "standard",
                "open_ports": [443],
                "services": [],
            }
        ],
        "analysis": analysis,
    }


def _count_page_breaks(doc: Document) -> int:
    """문서 XML 에서 <w:br w:type="page"/> (lastRenderedPageBreak 제외) 개수."""
    xml = doc.element.xml
    # docx page_break 은 w:br 의 w:type="page" 로 표현된다.
    return xml.count('w:type="page"')


def _has_page_break(p) -> bool:
    return 'w:type="page"' in p._p.xml


def _max_consecutive_empty_paragraphs(doc: Document) -> int:
    """연속 '빈 문단' 최대 길이. page_break 를 담은 구조적 문단은 카운트에서 제외
    (item 13 의 대상은 '연속 빈 add_paragraph()' 누적이며, 장 구분 page_break 은 정상)."""
    run = 0
    best = 0
    for p in doc.paragraphs:
        if _has_page_break(p):
            run = 0
            continue
        if p.text.strip() == "":
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def test_12_generate_report_and_page_breaks_per_vuln():
    findings = [
        _base_finding(1, "반사형 XSS 취약점"),
        _base_finding(2, "SQL 인젝션 취약점", report_severity="High"),
    ]
    summary = {
        "vulnerability_count": 2,
        "confirmed_count": 2,
        "by_severity": {"Critical": 0, "High": 1, "Medium": 1, "Low": 0},
    }
    buf = report.generate_report(_build_scan(findings, summary))
    assert isinstance(buf, io.BytesIO)
    data = buf.getvalue()
    assert len(data) > 0

    doc = Document(io.BytesIO(data))
    # 두 번째 취약점 상세 앞에 명시적 page_break 가 들어가야 한다.
    # (첫 취약점은 '6. 세부 분석' 제목이 새 페이지 상단이라 중복 break 금지)
    # 전체 문서엔 여러 page_break 가 있으므로, 취약점 수만큼(>= len-1) 이상 존재해야 한다.
    n_breaks = _count_page_breaks(doc)
    assert n_breaks >= len(findings) - 1
    # 세부 분석 외 표지/장 구분 page_break 까지 포함하면 넉넉히 많아야 한다.
    assert n_breaks >= len(findings)


def test_13_no_excessive_blank_paragraphs():
    findings = [
        _base_finding(1, "반사형 XSS 취약점"),
        _base_finding(2, "CSRF 취약점"),
    ]
    summary = {"vulnerability_count": 2, "confirmed_count": 2}
    buf = report.generate_report(_build_scan(findings, summary))
    doc = Document(io.BytesIO(buf.getvalue()))
    # 연속 빈 문단이 3개 이상 누적되지 않아야 한다.
    assert _max_consecutive_empty_paragraphs(doc) < 3


def test_14_trace_only_no_offensive_assertions():
    f = _base_finding(
        1,
        "위험한 HTTP Method 활성화 (PUT/DELETE/TRACE)",
        severity="MEDIUM",
        report_severity="Medium",
        evidence_detail="실제 동작 검증된 위험 메서드: TRACE",
        recommendation="필요한 HTTP Method 만 허용하십시오.",
        attack_scenario="1. 공격자가 PUT 메서드로 웹쉘 업로드\n2. 원격 코드 실행(RCE) 수행",
        attack_vector="PUT 업로드를 통한 웹쉘 업로드",
    )
    summary = {"vulnerability_count": 1, "confirmed_count": 1}
    buf = report.generate_report(_build_scan([f], summary))
    doc = Document(io.BytesIO(buf.getvalue()))

    full_text = "\n".join(p.text for p in doc.paragraphs)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                full_text += "\n" + cell.text

    assert "PUT 업로드" not in full_text
    assert "웹쉘" not in full_text
    assert "RCE" not in full_text
    # 정제된 제목 표기 확인
    assert "TRACE Method 활성화" in full_text


def test_old_data_no_keyerror():
    """옛 데이터(summary/scan_category 등 없음)에서도 KeyError 없이 생성."""
    f = {
        "title": "오래된 설정 취약점",
        "host": "old.example.com",
        "port": 80,
        "judgment": "취약",
        "severity": "LOW",
    }
    buf = report.generate_report(_build_scan([f]))
    assert isinstance(buf, io.BytesIO)
    assert len(buf.getvalue()) > 0


def test_service_section_present_and_split():
    web = _base_finding(1, "반사형 XSS 취약점", scan_category="web")
    svc = _base_finding(2, "Redis 무인증 노출", scan_category="service",
                        service="redis", port=6379)
    summary = {
        "vulnerability_count": 2,
        "confirmed_count": 2,
        "web_vulnerability_count": 1,
        "service_vulnerability_count": 1,
        "checked_ports": [80, 443, 6379],
    }
    buf = report.generate_report(_build_scan([web, svc], summary))
    doc = Document(io.BytesIO(buf.getvalue()))
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "서비스/포트 보안 점검 결과" in text
