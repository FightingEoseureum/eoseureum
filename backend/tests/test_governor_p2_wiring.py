"""P2: 포트/서비스/네트워크 스캔 egress 의 rate 거버너 배선(async + sync 게이트)."""
import asyncio
import time

import adaptive_throttle as at
import scanner
import service_scan
import network_discovery as nd


def _run(c):
    return asyncio.run(c)


# ── async: 포트스캔 burst 페이싱 ──────────────────────────────────────────────
def test_scan_port_paced_by_governor(monkeypatch):
    """scan_port(raw TCP)가 거버너에 물려 페이싱된다(닫힌 포트 5개 → 5rps면 ≥0.35s)."""
    async def t():
        at.install_profile("SAFE")   # 5rps/단독
        try:
            t0 = time.monotonic()
            # 127.0.0.1의 임의 닫힌 포트 5개 → connect 실패(빠름), 페이싱만 측정
            await asyncio.gather(*[scanner.scan_port("127.0.0.1", p, timeout=0.5)
                                   for p in (9,9,9,9,9)])
            return time.monotonic() - t0
        finally:
            at.uninstall()
    # 5요청 × 0.2s interval ≈ 0.8s (미배선이면 동시라 ~0)
    assert _run(t()) >= 0.6


def test_scan_port_no_governor_fast():
    async def t():
        at.uninstall()
        t0 = time.monotonic()
        await asyncio.gather(*[scanner.scan_port("127.0.0.1", 9, timeout=0.5)
                               for _ in range(5)])
        return time.monotonic() - t0
    assert _run(t()) < 0.4   # 미설치 → 동시, 빠름


def test_scan_port_releases_slot():
    async def t():
        at.install_profile("SAFE")
        lim = at.stage("port_scan")
        try:
            for _ in range(3):
                await scanner.scan_port("127.0.0.1", 9, timeout=0.3)
            return lim._sem._value
        finally:
            at.uninstall()
    assert _run(t()) == 1   # SAFE 단독 → 슬롯 원복


# ── sync 게이트: service_scan / network_discovery ────────────────────────────
def test_before_sync_paces():
    at.install_profile("SAFE")   # 5rps → interval 0.2
    try:
        lim = at.stage("service_probe")
        t0 = time.monotonic()
        for _ in range(3):
            lim.before_sync(); lim.after_sync(0.001, 0, None)
        elapsed = time.monotonic() - t0
    finally:
        at.uninstall()
    assert elapsed >= 0.35   # 3회 × 0.2 ≈ 0.4


def test_network_sweep_paced(monkeypatch):
    """discover_live_hosts 가 host별로 sync 게이트를 태운다."""
    at.install_profile("SAFE")
    try:
        # ping_fn 을 즉시반환으로 주입 → 순수 페이싱만 측정
        t0 = time.monotonic()
        nd.discover_live_hosts(["10.0.0.%d" % i for i in range(3)],
                               ping_fn=lambda ip, to: False)
        elapsed = time.monotonic() - t0
    finally:
        at.uninstall()
    assert elapsed >= 0.35   # 3 host × 0.2


def test_sync_gate_shared_rate_with_async():
    """sync 게이트와 async 게이트가 같은 리미터(=같은 rate)를 참조(SAFE 공유)."""
    at.install_profile("SAFE")
    try:
        assert at.stage("service_probe") is at.stage("port_scan")   # 공유
        assert at.stage("host_sweep").max_rps == 5.0
    finally:
        at.uninstall()
