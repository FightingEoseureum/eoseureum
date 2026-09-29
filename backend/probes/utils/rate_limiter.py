"""probes/utils/rate_limiter.py — 비동기 요청 rate limiter.

RateLimiter: 단일 rps 상한(최소 간격 기반).
CompositeRateLimiter: 여러 limiter 를 결합 — acquire() 가 전부를 통과해야 진행.
  (전역 GLOBAL_ACTIVE_PROBE_RPS + 카테고리별 상한을 동시에 적용하기 위함)
"""
from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """초당 요청 수(rps) 상한을 최소 호출 간격으로 보장. rps<=0 이면 무제한."""

    def __init__(self, rps: float = 10.0):
        self.rps = float(rps)
        self._min_interval = (1.0 / self.rps) if self.rps > 0 else 0.0
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


class CompositeRateLimiter:
    """여러 limiter 를 결합. 모든 limiter 의 간격을 동시에 만족해야 acquire 반환.
    (예: 전역 10rps + 인증 2rps → 둘 다 통과)."""

    def __init__(self, *limiters):
        self._limiters = [l for l in limiters if l is not None]

    async def acquire(self) -> None:
        for l in self._limiters:
            try:
                await l.acquire()
            except Exception:
                pass
