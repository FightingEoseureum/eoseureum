"""
test_probe_orchestrator.py — probes.orchestrator 검증.

검증 항목:
  - run_probes(ctx) 가 list[ProbeResult] 반환.
  - probe 하나가 실패해도 전체가 중단되지 않음(예외 격리, 정상 결과는 포함).
  - disabled probe 는 실행되지 않음(ScanConfig.enabled 에서 제외).
  - rate_limiter 가 모든 probe 에 전달됨(ctx.rate_limiter 접근 가능).

실행:
  cd backend && venv_linux/bin/python -m pytest tests/test_probe_orchestrator.py -q
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from probes import orchestrator
from probes.base import BaseProbe, ProbeContext, ProbeResult
from probes.config import ScanConfig
from probes.utils.rate_limiter import RateLimiter
from probes.utils.evidence import EvidenceStore


def _run(coro):
    return asyncio.run(coro)


class GoodProbe(BaseProbe):
    name = "good"
    category = "good"
    enabled_by_default = True

    async def run(self, context: ProbeContext):
        return [ProbeResult(title="ok", category=self.category)]


class FailingProbe(BaseProbe):
    name = "boom"
    category = "boom"
    enabled_by_default = True

    async def run(self, context: ProbeContext):
        raise RuntimeError("probe blew up")


class RateLimiterRecordingProbe(BaseProbe):
    name = "rl"
    category = "rl"
    enabled_by_default = True
    seen_rate_limiter = None

    async def run(self, context: ProbeContext):
        # ctx.rate_limiter 접근 가능 여부 기록
        type(self).seen_rate_limiter = context.rate_limiter
        return [ProbeResult(title="rl", category=self.category)]


def _make_ctx(config: ScanConfig | None = None) -> ProbeContext:
    config = config or ScanConfig()
    return ProbeContext(
        target_url="http://example.test",
        host="example.test",
        port=80,
        rate_limiter=RateLimiter(0),
        scan_config=config,
        evidence_store=EvidenceStore(),
    )


def test_run_probes_returns_list_of_probe_results(monkeypatch):
    monkeypatch.setattr(orchestrator, "get_enabled_probes", lambda config=None: [GoodProbe()])
    ctx = _make_ctx()
    results = _run(orchestrator.run_probes(ctx, ctx.scan_config))
    assert isinstance(results, list)
    assert all(isinstance(r, ProbeResult) for r in results)
    assert len(results) == 1
    assert results[0].title == "ok"


def test_failing_probe_does_not_abort_others(monkeypatch):
    # 실패 probe + 정상 probe 를 함께 주입 → 전체가 중단되지 않고 정상 결과는 포함되어야 함.
    monkeypatch.setattr(
        orchestrator, "get_enabled_probes",
        lambda config=None: [FailingProbe(), GoodProbe()],
    )
    ctx = _make_ctx()
    results = _run(orchestrator.run_probes(ctx, ctx.scan_config))
    titles = [r.title for r in results]
    assert "ok" in titles                       # 정상 probe 결과는 포함
    assert len(results) == 1                     # 실패 probe 는 결과 미산출
    # 예외는 격리되어 evidence_store.errors 에 기록됨
    assert ctx.evidence_store.has_errors()
    assert any(e["probe"] == "boom" for e in ctx.evidence_store.errors)


def test_disabled_probe_not_executed():
    # ScanConfig.enabled 에서 카테고리를 끄면 get_enabled_probes 결과에서 제외.
    config = ScanConfig()
    config.enabled = {"good": True, "boom": False}

    import probes.orchestrator as orch
    # load_probes 가 가짜 probe 들을 반환하도록 패치하여 enable 필터링을 검증.
    fake_probes = [GoodProbe(), FailingProbe()]
    orig_load = orch.load_probes
    try:
        orch.load_probes = lambda: fake_probes
        enabled = orch.get_enabled_probes(config)
    finally:
        orch.load_probes = orig_load

    cats = {getattr(p, "category", "") for p in enabled}
    assert "good" in cats          # enabled=True → 포함
    assert "boom" not in cats      # enabled=False → 제외


def test_rate_limiter_passed_to_every_probe(monkeypatch):
    RateLimiterRecordingProbe.seen_rate_limiter = None
    probe = RateLimiterRecordingProbe()
    monkeypatch.setattr(orchestrator, "get_enabled_probes", lambda config=None: [probe])

    ctx = _make_ctx()
    assert isinstance(ctx.rate_limiter, RateLimiter)
    assert ctx.rate_limiter is not None

    _run(orchestrator.run_probes(ctx, ctx.scan_config))
    # probe.run 에서 ctx.rate_limiter 로 접근 가능했고 동일 인스턴스가 전달됨.
    assert RateLimiterRecordingProbe.seen_rate_limiter is ctx.rate_limiter
    assert isinstance(RateLimiterRecordingProbe.seen_rate_limiter, RateLimiter)


def test_build_context_provides_rate_limiter():
    config = ScanConfig()
    ctx = _run(orchestrator.build_context(
        host="example.test", port=80, scheme="http", http_info=None,
        cookies=[], session=None, config=config,
    ))
    assert ctx.rate_limiter is not None
    assert isinstance(ctx.rate_limiter, RateLimiter)
