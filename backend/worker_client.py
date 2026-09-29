"""worker_client.py — STEP5 백엔드(Mac)에서 원격 워커(i7)로 능동 점검을 넘기는 클라이언트.

worker_enabled()(WORKER_URL+WORKER_TOKEN 설정) 일 때만 사용. 넘기지 않으면 백엔드가 기존처럼
로컬에서 능동 점검을 수행한다(기본 동작 불변 — 원격은 opt-in). 결과는 워커가 callback_url 로
되돌리므로, 이 클라이언트는 dispatch/status/stop 만 담당한다.

회로차단기(B2): 워커가 죽거나 크래시-루프이면 매 phase 마다 5초 프리플라이트 헬스체크로 낭비하던
것을, 연속 실패가 임계치에 도달하면 회로를 open 해 헬스체크·디스패치를 생략하고 즉시 로컬 폴백한다.
쿨다운 경과 후 half-open 으로 단 한 번 시험 호출을 허용해, 성공하면 close(정상 오프로드 재개),
실패하면 다시 open. 반복 스캔(100회 루프)에서 죽은 워커에 매번 5초씩 물리는 문제를 없앤다.
"""
import os
import time

import aiohttp

import worker_config as wc


class _WorkerCircuit:
    """워커 헬스/디스패치 결과로 상태(closed/open/half_open)를 관리하는 프로세스 전역 회로차단기."""

    def __init__(self):
        self.fails = 0
        self.opened_at = 0.0
        self.state = "closed"          # closed | open | half_open
        self._trial_in_flight = False

    @staticmethod
    def _enabled() -> bool:
        return (os.getenv("WORKER_CIRCUIT_ENABLED", "true") or "").strip().lower() in (
            "1", "true", "yes", "on")

    @staticmethod
    def _threshold() -> int:
        try:
            return max(1, int(os.getenv("WORKER_CIRCUIT_THRESHOLD", "3")))
        except (TypeError, ValueError):
            return 3

    @staticmethod
    def _cooldown() -> float:
        try:
            return max(1.0, float(os.getenv("WORKER_CIRCUIT_COOLDOWN", "60")))
        except (TypeError, ValueError):
            return 60.0

    def allow_request(self) -> bool:
        """지금 워커 호출을 시도해도 되는가. open 이면 쿨다운 전까지 False(즉시 로컬 폴백)."""
        if not self._enabled():
            return True
        if self.state == "closed":
            return True
        if self.state == "open":
            if time.monotonic() - self.opened_at >= self._cooldown():
                # 쿨다운 경과 → half-open 으로 단 한 번 시험 호출 허용
                self.state = "half_open"
                self._trial_in_flight = True
                return True
            return False
        # half_open: 시험 호출이 이미 나가 있으면 나머지는 폴백
        if self._trial_in_flight:
            return False
        self._trial_in_flight = True
        return True

    def record(self, ok: bool):
        """실제 워커 호출(헬스/디스패치) 결과를 반영. 미설정 조기반환은 호출하지 않는다."""
        if not self._enabled():
            return
        if ok:
            self.fails = 0
            self.state = "closed"
            self._trial_in_flight = False
            self.opened_at = 0.0
        else:
            self.fails += 1
            self._trial_in_flight = False
            # half_open 시험 실패 → 즉시 재open, 또는 closed 에서 연속 실패 임계 도달 시 open
            if self.state == "half_open" or self.fails >= self._threshold():
                self.state = "open"
                self.opened_at = time.monotonic()

    def snapshot(self) -> dict:
        return {"state": self.state, "fails": self.fails,
                "cooldown_remaining": max(0.0, self._cooldown() - (time.monotonic() - self.opened_at))
                if self.state == "open" else 0.0,
                "enabled": self._enabled()}

    def reset(self):
        self.fails = 0
        self.opened_at = 0.0
        self.state = "closed"
        self._trial_in_flight = False


_circuit = _WorkerCircuit()


def circuit_open() -> bool:
    """회로가 열려(open) 워커 호출을 건너뛰는 상태인가 — 폴백 메시지 구분용(부작용 없음)."""
    return _circuit.state == "open"


def circuit_snapshot() -> dict:
    return _circuit.snapshot()


def circuit_reset():
    _circuit.reset()


def _headers() -> dict:
    tok = wc.worker_token()
    return {"Authorization": f"Bearer {tok}"} if tok else {}


async def dispatch_scan(scan_id: str, target: str, host_results: list,
                        config: dict, callback_url: str,
                        phase: str = "active_probing",
                        timeout: float = 15.0) -> dict:
    """워커에 지정 phase 작업을 넘긴다. 반환: {"ok": bool, "status"|"error": ...}.
    phase ∈ {active_probing, external_tools, screenshots}."""
    base = wc.worker_url()
    if not base:
        return {"ok": False, "error": "WORKER_URL not configured"}
    payload = {"scan_id": scan_id, "target": target, "phase": phase,
               "host_results": host_results or [], "config": config or {},
               "callback_url": callback_url or ""}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(f"{base}/worker/scan", json=payload, headers=_headers(),
                              timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                ok = r.status < 400
                data = await r.json(content_type=None)
                _circuit.record(ok)
                return {"ok": ok, "status": r.status, "data": data}
    except Exception as e:
        _circuit.record(False)
        return {"ok": False, "error": str(e)}


async def worker_health(timeout: float = 5.0) -> bool:
    """워커(i7)가 살아있는지 가볍게 확인(/worker/health). 오프로드 대기 중 워커가 죽었는지
    빠르게 감지해 로컬 폴백하기 위한 용도. 도달 불가/에러/4xx·5xx 면 False.
    실제 호출 결과를 회로차단기에 반영한다(미설정 조기반환은 기록하지 않음)."""
    base = wc.worker_url()
    if not base:
        return False
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{base}/worker/health", headers=_headers(),
                             timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                ok = r.status < 400
                _circuit.record(ok)
                return ok
    except Exception:
        _circuit.record(False)
        return False


async def worker_available(timeout: float = 5.0) -> bool:
    """프리플라이트용: 회로차단기가 허용할 때만 실제 헬스체크한다. open 이면 네트워크 호출 없이
    즉시 False(로컬 폴백) → 죽은 워커에 매 phase 5초씩 물리지 않는다. half-open 시엔 시험 1회 허용."""
    if not _circuit.allow_request():
        return False               # 회로 open — 헬스체크 생략, 즉시 폴백
    return await worker_health(timeout=timeout)


async def get_status(scan_id: str, timeout: float = 10.0) -> dict:
    base = wc.worker_url()
    if not base:
        return {"ok": False, "error": "WORKER_URL not configured"}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{base}/worker/scan/{scan_id}", headers=_headers(),
                             timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                return {"ok": r.status < 400, "status": r.status,
                        "data": await r.json(content_type=None)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def stop_scan(scan_id: str, timeout: float = 10.0) -> dict:
    base = wc.worker_url()
    if not base:
        return {"ok": False, "error": "WORKER_URL not configured"}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(f"{base}/worker/scan/{scan_id}/stop", headers=_headers(),
                              timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                return {"ok": r.status < 400, "status": r.status,
                        "data": await r.json(content_type=None)}
    except Exception as e:
        return {"ok": False, "error": str(e)}
