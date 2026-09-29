"""
ai_quality.py — AI 분석 문장 품질 필터 (순수 함수).

보고서에 넣기 전 AI 응답 품질을 검사한다. 기준 미달 시 보고서에 출력하지 않고
표준 대체 문구를 사용한다. AI 실패가 전체 보고서 생성 실패로 이어지지 않도록
이 모듈은 예외를 던지지 않는다.
"""
from __future__ import annotations

import re

AI_QUALITY_FALLBACK = "AI 분석 결과가 품질 기준을 충족하지 않아 보고서에서 제외되었습니다."

# 데바나가리(힌디어) 범위 U+0900~U+097F (이스케이프만 사용)
_DEVANAGARI_RE = re.compile("[ऀ-ॿ]")
# 깨진/대체 문자(U+FFFD) 및 제어문자(NUL 등, \t\n\r 제외)
_BROKEN_RE = re.compile("[�\x00-\x08\x0e-\x1f]")

# 채워지지 않은 스키마 예시(placeholder) 문구
_PLACEHOLDERS = (
    "조치 우선순위 판단 사유",
    "추가 수동 검증/조치 단계",
    "오탐 가능성 평가 (근거 포함)",
    "비즈니스 영향 평가",
    "evidence 에 근거한 방어 관점 공격 체인 해석",
    "보고서에 넣을 한국어 서술 요약",
)


def _english_ratio(text: str) -> float:
    words = re.findall(r"[A-Za-z]+|[가-힣]+", text)
    if not words:
        return 0.0
    eng = sum(1 for w in words if re.fullmatch(r"[A-Za-z]+", w))
    return eng / len(words)


def ai_text_quality_ok(text) -> bool:
    """AI 문장이 보고서 출력 품질 기준을 충족하는지 판정."""
    if text is None:
        return False
    t = str(text).strip()
    if not t:
        return False
    if _DEVANAGARI_RE.search(t):
        return False
    if _BROKEN_RE.search(t):
        return False
    if any(ph in t for ph in _PLACEHOLDERS):
        return False
    # 한국어 보고서인데 영어 단어 비율이 과도(0.6 초과)하고 문장이 길면 제외
    if len(t) > 40 and _english_ratio(t) > 0.6:
        return False
    return True


def filter_ai_text(text, fallback: bool = False):
    """품질 통과 시 원문, 미달 시 빈 문자열(fallback=True 면 표준 대체 문구)."""
    if ai_text_quality_ok(text):
        return str(text)
    return AI_QUALITY_FALLBACK if fallback else ""


def filter_ai_analysis(ai: dict) -> dict:
    """ai_analysis dict 의 텍스트 필드를 품질 검사해 미달 항목을 제거한다.

    유효 텍스트가 하나도 없으면 {"_quality_failed": True} 를 표시한다.
    """
    if not isinstance(ai, dict):
        return {}
    text_keys = ("false_positive_assessment", "business_impact", "attack_chain_analysis",
                 "remediation_priority_reason", "report_text")
    out = dict(ai)
    kept = 0
    for k in text_keys:
        if k in out:
            if ai_text_quality_ok(out[k]):
                kept += 1
            else:
                out[k] = ""
    out["_quality_failed"] = (kept == 0)
    return out
