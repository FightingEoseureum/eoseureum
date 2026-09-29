"""보고서 가독성 고도화 회귀 테스트 — 한눈에 보기 카드 + PoC 섹션."""
import io
import zipfile

import report as rpt
import poc_generator as pg


def _docx_text(scan):
    data = rpt.generate_report(scan).getvalue()
    z = zipfile.ZipFile(io.BytesIO(data))
    return z.read("word/document.xml").decode("utf-8", "replace"), len(data)


def _sample_scan():
    analysis = {
        "findings": [{
            "title": "반사형 XSS (Reflected XSS) 실증 확인", "severity": "HIGH",
            "judgment": "취약", "confidence": "CONFIRMED", "cwe": "CWE-79",
            "owasp": "A03:2021", "url": "http://t.example/s?q=1", "type": "xss_reflected",
            "param": "q", "payload": "<script>alert(1)</script>",
            "description": "검색 파라미터에 입력한 스크립트가 그대로 실행됩니다. 세션 탈취에 악용될 수 있습니다.",
            "recommendation": "출력 인코딩을 적용하세요. CSP를 도입하세요.",
        }],
        "summary": {"by_severity": {"High": 1}, "vulnerability_count": 1},
        "discovery_items": [], "good_items": [],
    }
    pg.attach_pocs(analysis)
    return {"domain": "t.example", "created_at": "2026-08-01", "results": [], "analysis": analysis}


def test_report_has_at_a_glance_and_poc():
    scan = _sample_scan()
    xml, size = _docx_text(scan)
    assert size > 10000                      # 유효한 docx
    assert "한눈에 보기" in xml
    assert "무엇이 문제인가" in xml
    assert "왜 위험한가" in xml               # business_impact 없어도 심각도 폴백
    assert "어떻게 조치하나" in xml
    assert "재현 방법" in xml                  # 간결 PoC(재현 방법) 부착됨


def test_at_a_glance_helper_plain_language():
    body = rpt._finding_at_a_glance({
        "description": "무언가 위험한 것. 두번째 문장.", "severity": "HIGH",
        "recommendation": "이렇게 고치세요. 부가설명.", "judgment": "취약"})
    assert "무엇이 문제인가" in body and "왜 위험한가" in body and "어떻게 조치하나" in body
    # 첫 문장만(가독성)
    assert "두번째 문장" not in body
