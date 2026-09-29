"""전역 rate 거버너 — 모든 요청 소스(dir퍼징/크롤/인증)가 safe 상한에 합산되는지 검증."""
import asyncio
import time

import aiohttp
from aiohttp import web

import adaptive_throttle as at
import external_tools as et
import authenticated_scan as ascan


def _run(c):
    return asyncio.run(c)


async def _serve():
    async def h(req):
        return web.Response(text="ok")
    app = web.Application(); app.router.add_route("*", "/{tail:.*}", h)
    runner = web.AppRunner(app); await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
    return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"


def test_fuzz_get_paced_by_governor(monkeypatch):
    """dir 퍼징의 _fuzz_get 이 거버너 설치 시 초당 상한으로 페이싱된다."""
    async def t():
        runner, base = await _serve()
        try:
            monkeypatch.setenv("EOSEUREUM_SAFE_MAX_RPS", "5")   # interval 0.2s
            at.install("conservative")
            async with aiohttp.ClientSession() as s:
                t0 = time.monotonic()
                for _ in range(3):
                    await et._fuzz_get(s, base + "/x")
                return time.monotonic() - t0
        finally:
            at.uninstall()
            await runner.cleanup()
    # 3요청 × 0.2s → ≥0.35s (5rps 고정)
    assert _run(t()) >= 0.35


def test_fuzz_get_no_governor_fast():
    async def t():
        runner, base = await _serve()
        try:
            at.uninstall()
            async with aiohttp.ClientSession() as s:
                t0 = time.monotonic()
                for _ in range(5):
                    await et._fuzz_get(s, base + "/x")
                return time.monotonic() - t0
        finally:
            await runner.cleanup()
    assert _run(t()) < 0.3   # 미설치 → 페이싱 없음


def test_fuzz_get_releases_slot_on_error():
    """예외(연결 실패)에도 거버너 동시성 슬롯을 반납(누수 없음)."""
    async def t():
        at.install("conservative")
        thr = at.stage("dir_fuzz")   # _fuzz_get 이 쓰는 리미터(safe=공유)
        try:
            async with aiohttp.ClientSession() as s:
                # 존재하지 않는 포트 → 연결 실패 → after() 로 슬롯 반납되어야 함
                for _ in range(3):
                    await et._fuzz_get(s, "http://127.0.0.1:1/x", timeout=0.3)
            return thr._sem._value
        finally:
            at.uninstall()
    assert _run(t()) == 1   # SAFE 단독(conc1) → 슬롯 원복(누수 없음)


def test_auth_safe_rps_clamps_when_governed():
    at.install("conservative")   # max_rps 5
    try:
        assert ascan._safe_rps(10.0) == 5.0    # 10 → 5 클램프
        assert ascan._safe_rps(2.0) == 2.0     # 더 낮은 값은 유지
    finally:
        at.uninstall()
    # 거버너 없으면 원값
    assert ascan._safe_rps(10.0) == 10.0


def test_governor_max_rps_default_5():
    at.install("conservative")
    try:
        assert at.current().stage_rps("active_probing") == 5.0
        assert at.stage("active_probing").max_rps == 5.0
    finally:
        at.uninstall()


def test_ladder_all_stages_share_one_limiter():
    """모든 프로파일에서 전 단계가 '같은' 리미터를 공유 → 전역 합산 상한."""
    at.install_profile("SAFE")
    try:
        assert at.stage("active_probing") is at.stage("dir_fuzz") is at.stage("crawl")
    finally:
        at.uninstall()


def test_ladder_safe_5rps_solo():
    at.install_profile("SAFE")
    try:
        assert at.stage("active_probing").max_rps == 5.0
        assert at.stage("active_probing").conc == 1   # 단독(순차)
        assert at.current().profile_label == "SAFE"
    finally:
        at.uninstall()


def test_ladder_standard_10rps():
    at.install_profile("STANDARD")
    try:
        assert at.stage("active_probing").max_rps == 10.0
        assert at.stage("active_probing").conc == 3
    finally:
        at.uninstall()


def test_ladder_advanced_100rps():
    at.install_profile("ADVANCED")
    try:
        assert at.stage("active_probing").max_rps == 100.0
        assert at.stage("active_probing").conc == 12
    finally:
        at.uninstall()


def test_ladder_proof_unlimited_no_governor():
    """PROOF = 거버너 미설치(완전 무제한) → current()/stage() 는 None."""
    at.install_profile("PROOF")
    try:
        assert at.current() is None
        assert at.stage("active_probing") is None
        assert at.stage("dir_fuzz") is None
    finally:
        at.uninstall()


def test_ladder_env_override(monkeypatch):
    monkeypatch.setenv("EOSEUREUM_ADVANCED_RPS", "50")
    monkeypatch.setenv("EOSEUREUM_SAFE_CONC", "2")
    at.install_profile("ADVANCED")
    try:
        assert at.stage("active_probing").max_rps == 50.0
    finally:
        at.uninstall()
    at.install_profile("SAFE")
    try:
        assert at.stage("active_probing").conc == 2
    finally:
        at.uninstall()


def test_safe_max_rps_env_lowers_safe(monkeypatch):
    monkeypatch.setenv("EOSEUREUM_SAFE_MAX_RPS", "2")
    at.install_profile("SAFE")
    try:
        assert at.stage("active_probing").max_rps == 2.0
    finally:
        at.uninstall()
