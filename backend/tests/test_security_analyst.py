"""
test_security_analyst.py — security_analyst 모듈 검증.

모듈: backend/security_analyst.py
  async analyze_finding_with_ollama(finding, rag_context, technologies, attack_chains, provider) -> dict
  async analyze_scan_with_ollama(findings, attack_surface_items, discovery_items, technologies, attack_chains, provider) -> dict
  build_finding_prompt(finding, rag_context, technologies, attack_chains) -> str
  build_scan_prompt(...) -> str

핵심 불변식:
  - 입력 finding / findings 는 읽기 전용 (severity/confidence_score/finding_type/개수 불변).
  - JSON 파싱 실패 / NoneProvider / 예외 → provider=="fallback", 스키마의 모든 키 존재.
  - 프롬프트에 방어적 제한사항(변경 금지 / JSON / 익스플로잇·파괴 금지)이 포함.

실행:
  cd backend && venv_linux/bin/python -m pytest tests/test_security_analyst.py -q
"""
import copy
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import security_analyst as sa
from security_analyst import (
    FINDING_KEYS,
    SCAN_KEYS,
    analyze_finding_with_ollama,
    analyze_scan_with_ollama,
    build_finding_prompt,
    build_scan_prompt,
)


# ── 테스트용 가짜 provider ─────────────────────────────────────────────────────

class FakeProvider:
    """name 속성 + async complete 반환값 주입."""

    def __init__(self, name="ollama/llama3.2", response=""):
        self._name = name
        self._response = response

    @property
    def name(self):
        return self._name

    async def complete(self, prompt):
        return self._response


def _trace_finding():
    return {
        "title": "HTTP TRACE 메서드 허용",
        "severity": "LOW",
        "confidence_score": 60,
        "finding_type": "vulnerability",
        "judgment": "취약",
        "evidence": "TRACE / HTTP/1.1 → 200 OK (요청 헤더 echo 확인)",
    }


def _rag_context():
    return {
        "matched_knowledge": [
            {
                "title": "HTTP TRACE / Cross-Site Tracing",
                "description": "TRACE 메서드는 요청을 그대로 반향한다.",
                "remediation": "웹 서버에서 TRACE 메서드를 비활성화하라.",
            }
        ]
    }


_GOOD_FINDING_JSON = json.dumps({
    "false_positive_assessment": "evidence 상 TRACE 응답 확인됨, 오탐 가능성 낮음.",
    "business_impact": "낮음.",
    "attack_chain_analysis": "단독으로는 영향 제한적.",
    "remediation_priority_reason": "낮은 우선순위.",
    "additional_verification_steps": ["TRACE 비활성화 후 재검증"],
    "report_text": "TRACE 메서드 허용 확인.",
})

_GOOD_SCAN_JSON = "여기 결과입니다:\n```json\n" + json.dumps({
    "executive_summary": "요약.",
    "overall_risk_commentary": "코멘트.",
    "top_priorities": ["항목1"],
    "attack_chain_summary": "체인 요약.",
    "operation_team_actions": ["운영 조치"],
    "developer_team_actions": ["개발 조치"],
}) + "\n```"


# ── severity / count 불변 ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_finding_input_immutable():
    finding = _trace_finding()
    before = copy.deepcopy(finding)
    provider = FakeProvider(response=_GOOD_SCAN_JSON)  # JSON 이지만 finding 키와 무관

    await analyze_finding_with_ollama(finding, _rag_context(), provider=provider)

    assert finding == before
    assert finding["severity"] == before["severity"]
    assert finding["confidence_score"] == before["confidence_score"]
    assert finding["finding_type"] == before["finding_type"]


@pytest.mark.asyncio
async def test_scan_input_immutable():
    findings = [_trace_finding(), _trace_finding()]
    before = copy.deepcopy(findings)
    provider = FakeProvider(response=_GOOD_SCAN_JSON)

    await analyze_scan_with_ollama(
        findings, attack_surface_items=[], discovery_items=[],
        technologies=["nginx"], attack_chains=[], provider=provider,
    )

    assert findings == before
    assert len(findings) == len(before) == 2
    for f, b in zip(findings, before):
        assert f["severity"] == b["severity"]
        assert f["confidence_score"] == b["confidence_score"]
        assert f["finding_type"] == b["finding_type"]


# ── JSON 파싱 성공 → provider 반영 ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_finding_parse_success():
    provider = FakeProvider(name="ollama/llama3.2", response=_GOOD_FINDING_JSON)
    result = await analyze_finding_with_ollama(
        _trace_finding(), _rag_context(), provider=provider
    )
    assert result["provider"] == "ollama"
    assert result["model"] == "llama3.2"
    assert result["used_rag"] is True
    assert result["false_positive_assessment"]
    assert isinstance(result["additional_verification_steps"], list)
    assert all(k in result for k in FINDING_KEYS)


@pytest.mark.asyncio
async def test_scan_parse_success_with_codefence():
    provider = FakeProvider(name="ollama/llama3.2", response=_GOOD_SCAN_JSON)
    result = await analyze_scan_with_ollama(
        [_trace_finding()], [], [], ["nginx"], [], provider=provider
    )
    assert result["provider"] == "ollama"
    assert result["model"] == "llama3.2"
    assert isinstance(result["top_priorities"], list)
    assert all(k in result for k in SCAN_KEYS)


# ── JSON 파싱 실패 → fallback ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_finding_parse_failure_fallback():
    provider = FakeProvider(response="이건 JSON 아님")
    result = await analyze_finding_with_ollama(
        _trace_finding(), _rag_context(), provider=provider
    )
    assert result["provider"] == "fallback"
    assert all(k in result for k in FINDING_KEYS)
    # rag_context 의 remediation 이 검증 단계에 반영됨
    assert any("TRACE" in s for s in result["additional_verification_steps"])
    assert result["used_rag"] is True


@pytest.mark.asyncio
async def test_scan_parse_failure_fallback():
    provider = FakeProvider(response="이건 JSON 아님")
    result = await analyze_scan_with_ollama(
        [_trace_finding()], [], [], [], [], provider=provider
    )
    assert result["provider"] == "fallback"
    assert all(k in result for k in SCAN_KEYS)


@pytest.mark.asyncio
async def test_none_provider_fallback():
    provider = FakeProvider(name="none", response=_GOOD_FINDING_JSON)
    result = await analyze_finding_with_ollama(
        _trace_finding(), _rag_context(), provider=provider
    )
    assert result["provider"] == "fallback"
    assert all(k in result for k in FINDING_KEYS)


@pytest.mark.asyncio
async def test_provider_exception_fallback():
    class BoomProvider:
        name = "ollama/llama3.2"

        async def complete(self, prompt):
            raise RuntimeError("connection failed")

    result = await analyze_finding_with_ollama(
        _trace_finding(), _rag_context(), provider=BoomProvider()
    )
    assert result["provider"] == "fallback"
    assert all(k in result for k in FINDING_KEYS)


# ── 프롬프트 제한 ──────────────────────────────────────────────────────────────

def test_build_finding_prompt_constraints():
    prompt = build_finding_prompt(_trace_finding(), _rag_context(),
                                  technologies=["nginx"], attack_chains=[])
    # 핵심 제한 문구
    assert "severity" in prompt
    assert "변경 금지" in prompt
    assert "JSON" in prompt
    # 익스플로잇/파괴 금지 취지
    assert "익스플로잇" in prompt
    assert "파괴" in prompt
    # 새로운 취약점 생성 금지
    assert "새로운 취약점 생성 금지" in prompt
    # evidence 없는 단정 금지 / 수동 검토 필요
    assert "evidence" in prompt
    assert "수동 검토 필요" in prompt
    # TRACE finding 으로 PUT 업로드/RCE 를 단정 생성하라는 지시가 없음.
    # (오히려 그런 미검증 시나리오 생성을 금지하는 문구가 있어야 한다.)
    assert "PUT" in prompt and "단정" in prompt  # 금지 문맥에서 언급
    assert "검증되지 않은 시나리오를 단정" in prompt


def test_build_scan_prompt_constraints():
    prompt = build_scan_prompt(
        [_trace_finding()], [], [], ["nginx"], [], rag_context=_rag_context()
    )
    assert "severity" in prompt
    assert "변경 금지" in prompt
    assert "JSON" in prompt
    assert "익스플로잇" in prompt
    # 개수 정보가 들어가되 입력 개수를 그대로 반영
    assert "개수: 1" in prompt


def test_build_finding_prompt_no_rag():
    prompt = build_finding_prompt(_trace_finding(), {}, technologies=None,
                                  attack_chains=None)
    assert "매칭된 보안 지식 없음" in prompt
    assert "JSON" in prompt
