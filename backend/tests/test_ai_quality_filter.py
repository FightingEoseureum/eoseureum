"""test_ai_quality_filter.py — AI 분석 문장 품질 필터 검증."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ai_quality as q


def test_devanagari_excluded():
    assert q.ai_text_quality_ok("address करन crucial 분석") is False


def test_placeholder_excluded():
    assert q.ai_text_quality_ok("조치 우선순위 판단 사유") is False
    assert q.ai_text_quality_ok("추가 수동 검증/조치 단계") is False


def test_broken_char_excluded():
    assert q.ai_text_quality_ok("정상 텍스트 � 깨짐") is False


def test_english_overload_excluded():
    assert q.ai_text_quality_ok(
        "this is a fully english sentence about attack chain and crucial remediation steps here") is False


def test_normal_korean_ok():
    assert q.ai_text_quality_ok("반사형 XSS 취약점이 확인되었습니다. 세션 쿠키 탈취 위험이 있습니다.") is True


def test_filter_analysis_strips_bad_and_flags():
    ai = {"provider": "ollama",
          "false_positive_assessment": "조치 우선순위 판단 사유",   # placeholder → 제거
          "business_impact": "address करन",                         # hindi → 제거
          "report_text": "정상적인 한국어 분석 문장입니다."}          # 유지
    out = q.filter_ai_analysis(ai)
    assert out["false_positive_assessment"] == ""
    assert out["business_impact"] == ""
    assert out["report_text"] == "정상적인 한국어 분석 문장입니다."
    assert out["_quality_failed"] is False


def test_filter_analysis_all_bad_flags_failed():
    ai = {"provider": "ollama", "false_positive_assessment": "조치 우선순위 판단 사유",
          "report_text": "address करन"}
    out = q.filter_ai_analysis(ai)
    assert out["_quality_failed"] is True
