"""adaptive_throttle.py — 요청 rate 거버너(Safe = 전역 합산 상한 / PROOF = 단계별 독립 상한).

목적(사용자 목적):
  - Safe 모드: 서버에 무리 없이 최대 커버리지. 전 단계(크롤·프로빙·퍼징·nuclei·인증) 요청이 '하나의
    거버너'를 공유해 합산 초당 상한(기본 5rps)을 절대 넘지 않는다(고정 저속, 증속 끔, 감속만).
  - PROOF 모드: '더 깊고 빠르게'. 전역 하드캡을 두지 않되, '각 단계별로 정의된 상한'을 가진다
    (단계마다 자기 리미터 → 단계 간 합산 없음, 단계별로만 제한).

per-scan 격리: contextvar 로 스캔별 Governor 를 보관(동시 스캔이 서로 영향 없음).
미설치 시(current() is None / stage(name) is None) 완전 no-op → 기존 동작·테스트 무영향.

핵심 제어(AIMD 감속): 지연이 SLO(baseline×slo_factor)를 넘거나 5xx/429/Retry-After 면 배수 감속.
증속은 기본 비활성(안전 최우선) — EOSEUREUM_SAFE_RAMP=on 이면 낮게 시작해 상한까지 완만 증속.
"""
from __future__ import annotations

import asyncio
import contextvars
import os
import threading
import time

_ctx: contextvars.ContextVar = contextvars.ContextVar("eos_governor", default=None)
# 스캔별 scan_id(일시정지 게이트용) — install_profile 에서 set, 자식 태스크(프로브)로 전파.
_scan_ctx: contextvars.ContextVar = contextvars.ContextVar("eos_scan_id", default="")

# ── 일시정지 게이트 — 모든 요청 앞(before/before_sync)에서 즉시 반영 ──────────────────
# main.py 의 /pause·/resume 이 pause()/resume() 을 호출한다. 단계 경계뿐 아니라 '요청 단위'로
# 멈추므로 긴 단계(크롤/능동점검) 중에도 네트워크 활동이 즉시 중단된다. PROOF(거버너 미설치)는
# before() 가 호출되지 않아 이 게이트가 안 걸리며, 단계 경계 대기(_wait_if_paused)로만 멈춘다.
_PAUSED: set = set()
_PAUSE_MAX_WAIT = 3600.0   # 무한 대기 방지(초). 초과 시 자동 진행.


def pause(scan_id) -> None:
    if scan_id:
        _PAUSED.add(str(scan_id))


def resume(scan_id) -> None:
    _PAUSED.discard(str(scan_id))


def is_paused(scan_id) -> bool:
    return bool(scan_id) and str(scan_id) in _PAUSED


def _current_scan_id() -> str:
    try:
        return _scan_ctx.get() or ""
    except Exception:
        return ""


# ── 프로파일(보수/균형/적극) — Safe 기본값 = 보수(가장 젠틀) ─────────────────────────
_PROFILES = {
    #                conc  rate0  rate_max  slo   md    ai_step
    "conservative": (2,    1.0,   5.0,      1.2,  0.5,  0.15),
    "balanced":     (4,    3.0,   10.0,     1.5,  0.5,  0.30),
    "aggressive":   (8,    8.0,   25.0,     2.0,  0.6,  0.60),
}

# Safe 하위호환 상수(EOSEUREUM_SAFE_MAX_RPS 로 SAFE 를 더 낮출 수 있음).
_SAFE_MAX_RPS_DEFAULT = 5.0

# ── 검증 프로파일 사다리 ── (profile: (전역 합산 rps, 동시 '요청' 수))
# 사용자 설계: SAFE 5/단독 → STANDARD 10 → ADVANCED 100 → PROOF 무제한(거버너 미설치).
# '동시'는 '한 대상 서버에 동시에 날아가는 HTTP 요청 수'이지 '동시 스캔(다른 대상)'이 아니다.
# SAFE 는 단독(1) = 한 번에 요청 1개(완전 순차) — 가장 젠틀. env EOSEUREUM_<PROFILE>_RPS/_CONC 로 조절.
_LADDER = {   # profile: (rps, concurrent_requests)
    "SAFE":     (5.0,   1),
    "STANDARD": (10.0,  3),
    "ADVANCED": (100.0, 12),
    # "PROOF": 미설치(무제한)
}
_DEFAULT_STAGE = "active_probing"




class AdaptiveThrottle:
    """단일 리미터. before()→요청→after() 로 사용.

    explicit rate_max/rate/concurrency 를 주면(PROOF 단계별) 그대로 사용(전역 5rps 하드캡 미적용).
    주지 않으면(Safe) 프로파일+env 로 구성하고 전역 하드캡(5rps)을 적용한다.
    """

    def __init__(self, profile: str = "conservative", *, rate: float | None = None,
                 rate_max: float | None = None, concurrency: int | None = None,
                 ramp: bool | None = None, hard_cap: bool = True, label: str = ""):
        conc0, rate0, rmax0, slo, md, ai = _PROFILES.get(profile, _PROFILES["conservative"])
        self.profile = profile
        self.label = label or profile
        self.conc = concurrency if concurrency is not None else _int_env(
            "SAFE_THROTTLE_CONCURRENCY", conc0, 1, 64)
        self.slo_factor = _float_env("SAFE_THROTTLE_SLO", slo, 1.05, 10.0)
        self.md_factor = _float_env("SAFE_THROTTLE_MD", md, 0.1, 0.95)
        self.ai_step = _float_env("SAFE_THROTTLE_AI_STEP", ai, 0.01, 5.0)
        self.ramp = ramp if ramp is not None else _bool_env("EOSEUREUM_SAFE_RAMP", False)

        if rate_max is not None:
            # PROOF 단계별(명시): 해당 단계 상한을 그대로 사용(전역 하드캡 없음)
            self.rate_max = max(0.05, float(rate_max))
            self.max_rps = self.rate_max
        else:
            # Safe: 프로파일+env 상한에 전역 하드캡(5rps) 적용
            _rmax = _float_env("SAFE_THROTTLE_RATE_MAX", rmax0, 0.05, 5000.0)
            self.max_rps = (_float_env("EOSEUREUM_SAFE_MAX_RPS", _SAFE_MAX_RPS_DEFAULT, 0.1, 1000.0)
                            if hard_cap else _rmax)
            self.rate_max = min(_rmax, self.max_rps)

        _start = rate if rate is not None else _float_env("SAFE_THROTTLE_RATE_START", rate0, 0.05, 1000.0)
        self.rate = min(_start, self.rate_max) if self.ramp else self.rate_max
        self.rate_min = _float_env("SAFE_THROTTLE_RATE_MIN", max(0.1, self.rate_max * 0.2),
                                   0.02, self.rate_max)

        self._sem = asyncio.Semaphore(self.conc)
        self._lock = asyncio.Lock()
        self._last = 0.0
        self._backoff_until = 0.0
        self._base = None
        self._ema = None
        self._ai_credits = 0
        self._tlock = threading.Lock()   # 동기 경로 페이싱용
        self._tlast = 0.0
        self.samples = 0
        self.decreases = 0
        self.increases = 0
        self.retry_after_hits = 0

    async def before(self) -> None:
        # 일시정지 게이트 — 요청 단위로 멈춤(재개/취소 시 빠져나옴). 취소는 asyncio.sleep 이 전파.
        _sid = _current_scan_id()
        if _sid:
            _w = 0.0
            while is_paused(_sid) and _w < _PAUSE_MAX_WAIT:
                await asyncio.sleep(0.5)
                _w += 0.5
        now = time.monotonic()
        if self._backoff_until > now:
            await asyncio.sleep(min(self._backoff_until - now, 30.0))
        async with self._lock:
            interval = 1.0 / self.rate if self.rate > 0 else 0.0
            wait = interval - (time.monotonic() - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()
        await self._sem.acquire()

    def after(self, latency: float, status: int, retry_after: str | None) -> None:
        try:
            self._sem.release()
        except (ValueError, RuntimeError):
            pass
        self._record(latency, status, retry_after)

    # ── 동기(sync) 경로용 게이트 — socket/http.client 등 async 아닌 코드(포트/서비스 스캔)에서 사용 ──
    # 별도 락/타임스탬프로 최소 간격 페이싱(같은 self.rate 사용). 동기 단계는 능동프로빙과 시간대가
    # 겹치지 않고 순차 실행되므로 별도 pacer 여도 순간 합산이 상한을 넘지 않는다.
    def before_sync(self) -> None:
        _sid = _current_scan_id()
        if _sid:
            _w = 0.0
            while is_paused(_sid) and _w < _PAUSE_MAX_WAIT:
                time.sleep(0.5)
                _w += 0.5
        now = time.monotonic()
        if self._backoff_until > now:
            time.sleep(min(self._backoff_until - now, 30.0))
        with self._tlock:
            interval = 1.0 / self.rate if self.rate > 0 else 0.0
            wait = interval - (time.monotonic() - self._tlast)
            if wait > 0:
                time.sleep(wait)
            self._tlast = time.monotonic()

    def after_sync(self, latency: float, status: int, retry_after: str | None) -> None:
        self._record(latency, status, retry_after)

    def _record(self, latency: float, status: int, retry_after: str | None) -> None:
        self.samples += 1
        if status in (429, 503) or retry_after:
            self.retry_after_hits += 1 if retry_after else 0
            self._decrease(strong=True)
            ra = _parse_retry_after(retry_after)
            if ra is not None:
                self._backoff_until = max(self._backoff_until, time.monotonic() + min(ra, 60.0))
            return
        if status == 0:
            self._decrease(strong=False)
            return
        if latency > 0:
            self._base = latency if self._base is None else min(self._base, latency)
            self._ema = latency if self._ema is None else (0.3 * latency + 0.7 * self._ema)
            base = max(self._base or 0.0, 0.01)
            if self._ema > self.slo_factor * base or status >= 500:
                self._decrease(strong=False)
            else:
                self._increase()

    def _decrease(self, strong: bool) -> None:
        factor = self.md_factor if strong else max(self.md_factor, 0.7)
        self.rate = max(self.rate_min, self.rate * factor)
        self._ai_credits = 0
        self.decreases += 1

    def _increase(self) -> None:
        if not self.ramp:      # 안전 최우선: 증속 비활성이면 상한 고정(감속만)
            return
        self._ai_credits += 1
        if self._ai_credits >= 3:
            self._ai_credits = 0
            if self.rate < self.rate_max:
                self.rate = min(self.rate_max, self.rate + self.ai_step)
                self.increases += 1

    def stats(self) -> dict:
        return {
            "label": self.label, "rate": round(self.rate, 3), "rate_max": self.rate_max,
            "max_rps": self.max_rps, "concurrency": self.conc,
            "baseline_ms": round((self._base or 0) * 1000, 1),
            "recent_ms": round((self._ema or 0) * 1000, 1),
            "samples": self.samples, "decreases": self.decreases,
            "increases": self.increases, "retry_after_hits": self.retry_after_hits,
        }


class Governor:
    """스캔 1개의 rate 거버너. mode='safe' → 전 단계 공유(합산 상한), 'proof' → 단계별 독립 상한."""

    def __init__(self, rps: float, conc: int, profile_label: str = "SAFE"):
        self.profile_label = profile_label
        # 전 단계가 공유하는 하나의 리미터(전역 합산 상한). 증속은 EOSEUREUM_SAFE_RAMP(기본 off).
        self._shared = AdaptiveThrottle(
            "conservative", rate_max=rps, concurrency=conc,
            hard_cap=False, label=f"{profile_label}-{rps:g}rps")

    @property
    def mode(self) -> str:
        return self.profile_label.lower()

    def limiter(self, stage: str = _DEFAULT_STAGE) -> AdaptiveThrottle:
        return self._shared                     # 전 단계 공유(전역 합산)

    def stage_rps(self, stage: str = _DEFAULT_STAGE) -> float:
        return self._shared.max_rps

    def stage_conc(self, stage: str = _DEFAULT_STAGE) -> int:
        return self._shared.conc

    def stats(self) -> dict:
        return {"profile": self.profile_label, "global": self._shared.stats()}


def _int_env(name: str, base: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is not None:
        try:
            return max(lo, min(hi, int(raw)))
        except (TypeError, ValueError):
            pass
    return max(lo, min(hi, int(base)))


def _float_env(name: str, base: float, lo: float, hi: float) -> float:
    raw = os.getenv(name)
    if raw is not None:
        try:
            return max(lo, min(hi, float(raw)))
        except (TypeError, ValueError):
            pass
    return max(lo, min(hi, float(base)))


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _parse_retry_after(v: str | None) -> float | None:
    if not v:
        return None
    v = v.strip()
    try:
        return max(0.0, float(int(v)))
    except (TypeError, ValueError):
        return None


# ── per-scan 설치/조회 ────────────────────────────────────────────────────────
def install_profile(profile: str | None, scan_id: str = "") -> Governor | None:
    """검증 프로파일에 맞는 전역 합산 상한 거버너를 설치.

    사다리: SAFE 5rps/단독 · STANDARD 10rps · ADVANCED 100rps · PROOF 무제한(미설치).
    env EOSEUREUM_<PROFILE>_RPS / _CONC 로 조절. PROOF 는 거버너를 설치하지 않아 완전 무제한.
    scan_id: 일시정지 게이트 대상 식별(before/before_sync 가 이 scan_id 의 pause 를 확인).
    """
    _scan_ctx.set(str(scan_id or ""))
    p = (profile or "SAFE").strip().upper()
    if p == "PROOF":
        _ctx.set(None)               # 무제한 — 어떤 경로도 페이싱하지 않음
        return None
    if p not in _LADDER:
        p = "SAFE"
    rps, conc = _LADDER[p]
    rps = _float_env(f"EOSEUREUM_{p}_RPS", rps, 0.1, 100000.0)
    if p == "SAFE":                  # 하위호환: EOSEUREUM_SAFE_MAX_RPS 로 더 낮출 수 있음
        rps = min(rps, _float_env("EOSEUREUM_SAFE_MAX_RPS", rps, 0.1, 100000.0))
    conc = _int_env(f"EOSEUREUM_{p}_CONC", conc, 1, 256)
    g = Governor(rps, conc, profile_label=p)
    _ctx.set(g)
    return g


def install_safe(profile: str | None = None) -> Governor:
    """하위호환 — SAFE 프로파일 거버너 설치(5rps/단독)."""
    return install_profile("SAFE")


def install(profile: str | None = None) -> Governor:
    """하위호환 별칭 — SAFE 거버너 설치."""
    return install_profile("SAFE")


def uninstall() -> None:
    _ctx.set(None)


def current() -> Governor | None:
    return _ctx.get()


def stage(name: str = _DEFAULT_STAGE) -> AdaptiveThrottle | None:
    """현재 스캔 거버너에서 해당 단계의 리미터를 반환(미설치/PROOF 무제한 시 None)."""
    g = _ctx.get()
    return g.limiter(name) if g is not None else None
