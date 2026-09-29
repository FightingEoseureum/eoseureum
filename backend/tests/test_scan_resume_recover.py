"""스캔 재개(체크포인트/재개) + 네트워크 죽음 감지 회귀 테스트.

- 고아 'running' 스캔 정리(reconcile_orphan_running_scans) → 재개 버튼 노출 조건
- ScanInterrupted 가 gather(return_exceptions=True) 를 넘어 전파되는지
- 네트워크 헬스 카운터의 raise / 비-raise(트립 플래그) 경로
"""
import asyncio
import os
import tempfile

import pytest

import database as db
import active_probing as ap
import url_discovery as ud


@pytest.mark.asyncio
async def test_reconcile_orphan_running_scans(monkeypatch):
    """서버 시작 시 status='running' 스캔은 모두 고아 → 'interrupted' 로 정리된다."""
    tmp = tempfile.mktemp(suffix=".db")
    monkeypatch.setattr(db, "DB_PATH", tmp)
    await db.init_db()
    await db.create_scan_record("orphan-1", 1, "example.com")
    await db.create_scan_record("orphan-2", 1, "example.org")
    await db.create_scan_record("done-1", 1, "example.net")
    await db.update_scan_record("orphan-1", "running")
    await db.update_scan_record("orphan-2", "running")
    await db.update_scan_record("done-1", "complete")

    cleaned = await db.reconcile_orphan_running_scans()

    assert set(cleaned) == {"orphan-1", "orphan-2"}
    assert (await db.get_scan_record("orphan-1"))["status"] == "interrupted"
    assert (await db.get_scan_record("orphan-2"))["status"] == "interrupted"
    # 완료된 스캔은 건드리지 않는다
    assert (await db.get_scan_record("done-1"))["status"] == "complete"
    # 두 번째 호출은 정리할 게 없다(멱등)
    assert await db.reconcile_orphan_running_scans() == []
    os.remove(tmp)


@pytest.mark.asyncio
async def test_net_record_raise_path():
    """능동 점검 경로(raise_on_trip=True): 연속 실패 임계 초과 시 즉시 ScanInterrupted."""
    ap.net_reset(threshold=3)
    with pytest.raises(ap.ScanInterrupted):
        for _ in range(3):
            ap._net_record(False)
    # 성공은 카운터를 리셋해 트립을 막는다
    ap.net_reset(threshold=3)
    for _ in range(2):
        ap._net_record(False)
    ap._net_record(True)  # 리셋
    ap._net_record(False)
    ap._net_record(False)  # 아직 2회 → 미트립
    assert not ap.net_tripped()


@pytest.mark.asyncio
async def test_net_record_nonraise_trip_flag():
    """recon/url_discovery 경로(raise_on_trip=False): raise 없이 트립 플래그만 세운다."""
    ap.net_reset(threshold=5)
    for _ in range(5):
        ud._net_record(False, raise_on_trip=False)  # url_discovery 경로
    assert ap.net_tripped() is True
    # 트립 후 성공이 와도 플래그는 유지(스테이지 경계에서 감지되도록)
    ud._net_record(True)
    assert ap.net_tripped() is True


@pytest.mark.asyncio
async def test_scan_interrupted_propagates_through_gather():
    """gather(return_exceptions=True) 는 BaseException 을 캡처하므로, 프로브 경로가
    ScanInterrupted 를 재-raise 해 probe_active_for_all_hosts 밖으로 전파해야 한다."""
    orig = ap.probe_http_vulnerabilities

    async def _dead(host, port, *a, **k):
        raise ap.ScanInterrupted("net dead mid-probe")

    ap.probe_http_vulnerabilities = _dead
    try:
        hr = [{"host": "h", "services": [{"port": 80, "http_info": {"cookies": []}}]}]
        ap._net_reset(threshold=25)
        with pytest.raises(ap.ScanInterrupted):
            await ap.probe_active_for_all_hosts(hr, scan_id="s", reset_cov=False)
    finally:
        ap.probe_http_vulnerabilities = orig
