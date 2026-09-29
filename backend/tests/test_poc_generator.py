"""PoC 생성기 회귀 테스트 — '간결한' 재현 스니펫(3~4줄) 생성 검증."""
import poc_generator as pg


def test_generate_poc_concise_various_types():
    for f in [
        {"title": "SQLi", "type": "sql_injection", "url": "http://t/x", "method": "GET",
         "param": "id", "payload": "1'", "judgment": "취약"},
        {"title": "동의 우회", "type": "consent_bypass", "url": "http://t/c", "method": "POST",
         "param": "agree", "judgment": "취약"},
        {"title": "JSONP", "type": "jsonp_misuse", "url": "http://t/api", "method": "GET",
         "param": "callback", "judgment": "취약"},
    ]:
        src = pg.generate_poc(f)
        assert src and "#" in src               # 비어있지 않고 설명 주석 포함
        assert src.count("\n") <= 4             # 간결(최대 몇 줄)
        assert f["param"] in src                # 대상 파라미터 표기
        assert "requests" not in src            # 장문 파이썬 스크립트 아님


def test_generate_poc_xss_shows_payload_only():
    f = {"type": "xss_reflected", "url": "http://t/s", "method": "GET", "param": "q",
         "payload": "<script>alert('X')</script>", "judgment": "취약"}
    src = pg.generate_poc(f)
    assert "<script>alert('X')</script>" in src   # 삽입 스크립트만 보여도 충분
    assert src.count("\n") <= 3                    # 매우 짧게
    assert "requests" not in src and "VERDICT" not in src


def test_attach_pocs_only_confirmed():
    analysis = {"findings": [
        {"title": "A", "judgment": "취약", "confidence": "CONFIRMED", "url": "http://t", "type": "x"},
        {"title": "B", "judgment": "취약", "confidence": "MANUAL_REVIEW", "url": "http://t"},
        {"title": "C", "judgment": "참고", "url": "http://t"},
    ]}
    n = pg.attach_pocs(analysis)
    assert n == 1
    assert "poc" in analysis["findings"][0]
    assert "poc" not in analysis["findings"][1]   # MANUAL_REVIEW 제외
    assert "poc" not in analysis["findings"][2]   # 참고 제외


def test_generate_poc_empty_finding():
    assert pg.generate_poc({}) == ""     # url 없으면 재현 대상 없음 → 빈 문자열
    assert pg.generate_poc(None) == ""
