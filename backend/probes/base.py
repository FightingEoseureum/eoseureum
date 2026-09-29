"""
probes/base.py — Probe 공통 인터페이스.

모든 취약점 점검(Probe)은 BaseProbe 를 상속하고 list[ProbeResult] 를 반환한다.
실제 탐지 로직은 (1차 리팩토링에서) 검증된 active_probing 의 _probe_* 함수에 위임하며,
이 구조는 향후 각 probe 파일에서 독립적으로 수정/확장하기 위한 것이다.

원칙:
  - run()/execute() 는 예외를 밖으로 던지지 않는다(전체 스캔 중단 방지). 오류는 probe_error 로 기록.
  - destructive 동작 금지. 요청 전 ctx.rate_limiter 사용.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProbeContext:
    """probe 실행에 필요한 입력 컨텍스트."""
    target_url: str = ""
    host: str = ""
    port: int = 0
    scheme: str = "http"
    discovered_urls: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    injection_points: list = field(default_factory=list)
    session: Any = None                      # aiohttp.ClientSession (또는 테스트 mock)
    cookies: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    rate_limiter: Any = None                 # 전역 RateLimiter (acquire() 제공)
    auth_rate_limiter: Any = None            # 인증/로그인용(전역+auth_rps 결합) limiter
    scan_config: Any = None                  # probes.config.ScanConfig
    technologies: list = field(default_factory=list)
    evidence_store: Any = None               # EvidenceStore
    scan_id: str = ""
    # 인증 스캔 결과(있을 때만 채워짐)
    authenticated_session: Any = None
    authenticated_urls: list = field(default_factory=list)
    authenticated_forms: list = field(default_factory=list)

    async def throttle(self):
        """요청 전 rate limit 적용 (rate_limiter 가 있으면)."""
        if self.rate_limiter is not None:
            try:
                await self.rate_limiter.acquire()
            except Exception:
                pass


@dataclass
class ProbeResult:
    """probe 단일 발견 결과 (정규화 이전의 중립 구조)."""
    title: str = ""
    category: str = ""                       # probe category (xss, sqli, ...)
    finding_type: str = "vulnerability"      # vulnerability | attack_surface | discovery | good | noise
    severity: str = "Medium"                 # High | Medium | Low | Info
    confidence: str = "MANUAL_REVIEW"        # CONFIRMED | POSSIBLE | MANUAL_REVIEW
    confidence_score: int = 0
    affected_url: str = ""
    affected_endpoint: str = ""
    evidence: list = field(default_factory=list)
    reproduction: str = ""
    recommendation: str = ""
    cwe: str = ""
    owasp: str = ""
    tags: list = field(default_factory=list)
    safe_check: bool = True
    # 호환 레이어용: 위임한 active_probing 결과의 probe_key 와 원본 데이터
    probe_key: str = ""
    raw: dict = field(default_factory=dict)


class BaseProbe:
    """모든 Probe 의 베이스. 하위 클래스는 name/category/enabled_by_default 와 run() 구현."""
    name: str = "base"
    category: str = "base"
    enabled_by_default: bool = True

    async def run(self, context: ProbeContext) -> list[ProbeResult]:
        raise NotImplementedError

    async def execute(self, context: ProbeContext) -> list[ProbeResult]:
        """예외를 격리하는 안전 실행 래퍼. orchestrator 가 이걸 호출한다."""
        try:
            results = await self.run(context)
            return results or []
        except Exception as e:  # 전체 스캔 중단 방지
            if context.evidence_store is not None:
                try:
                    context.evidence_store.add_error(self.name, str(e))
                except Exception:
                    pass
            return []
