"""
test_watchlist_schedule.py — 대상 관리(watchlist) 정기 점검 예약(안 A) 로직 검증.

- compute_next_run: 주기→다음 실행 시각 계산(manual=None)
- update_watchlist_item: 스케줄 설정 시 enabled/next_run 갱신
- get_due_watchlist: next_run 도래 대상 선별
- mark_watchlist_ran: 실행 후 last_run/next_run 갱신

임시 DB 사용(실제 스캔/네트워크 없음).
실행: cd backend && venv_linux/bin/python -m pytest tests/test_watchlist_schedule.py -q
"""
import os
import sys
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database as db


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    return db


# ── compute_next_run (순수) ────────────────────────────────────────────────────
def test_compute_next_run_manual_is_none():
    assert db.compute_next_run("manual") is None
    assert db.compute_next_run("") is None
    assert db.compute_next_run(None) is None


def test_compute_next_run_weekly():
    base = datetime(2026, 6, 18, 10, 0, 0)
    nxt = db.compute_next_run("weekly", "03:00", base=base)
    assert nxt == "2026-06-25 03:00:00"   # +7일, 03:00 보정


def test_compute_next_run_quarterly():
    base = datetime(2026, 6, 18, 10, 0, 0)
    nxt = db.compute_next_run("quarterly", "02:30", base=base)
    assert nxt == "2026-09-16 02:30:00"   # +90일


# ── 스케줄 설정 / 조회 (임시 DB) ────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_set_schedule_enables_and_sets_next_run(temp_db):
    await temp_db.init_db()  # 기본 사용자(admin id=1) 생성
    item = await temp_db.add_to_watchlist("example.com", 1, "desc", "notes")
    assert item["scan_cycle"] == "manual" and item["enabled"] == 0

    updated = await temp_db.update_watchlist_item(item["id"], scan_cycle="weekly", enabled=True)
    assert updated["scan_cycle"] == "weekly"
    assert updated["enabled"] == 1
    assert updated["next_run"]   # 예약 시각이 설정됨

    # manual 로 되돌리면 비활성 + next_run 해제
    off = await temp_db.update_watchlist_item(item["id"], scan_cycle="manual", enabled=False)
    assert off["enabled"] == 0
    assert off["next_run"] is None


@pytest.mark.asyncio
async def test_get_due_watchlist_selects_only_due(temp_db):
    await temp_db.init_db()
    item = await temp_db.add_to_watchlist("due.example.com", 1, "", "")
    await temp_db.update_watchlist_item(item["id"], scan_cycle="weekly", enabled=True)

    # 현재 시각 기준: next_run 은 +7일 → 아직 도래 안 함
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    assert all(r["id"] != item["id"] for r in await temp_db.get_due_watchlist(now))

    # 충분히 미래 시각으로 조회하면 도래 대상에 포함
    future = (datetime.now() + timedelta(days=8)).strftime("%Y-%m-%d %H:%M:%S")
    due = await temp_db.get_due_watchlist(future)
    assert any(r["id"] == item["id"] for r in due)


@pytest.mark.asyncio
async def test_mark_watchlist_ran_advances_next_run(temp_db):
    await temp_db.init_db()
    item = await temp_db.add_to_watchlist("ran.example.com", 1, "", "")
    await temp_db.update_watchlist_item(item["id"], scan_cycle="weekly", enabled=True)

    await temp_db.mark_watchlist_ran(item["id"], "weekly", "03:00")
    after = await temp_db.get_watchlist_item(item["id"], 1, "admin")
    assert after["last_run"]            # 실행 시각 기록
    assert after["next_run"]            # 다음 예약 재설정
    # manual 비활성 상태에서는 자동 점검 대상이 아님
    await temp_db.update_watchlist_item(item["id"], scan_cycle="manual", enabled=False)
    future = (datetime.now() + timedelta(days=400)).strftime("%Y-%m-%d %H:%M:%S")
    assert all(r["id"] != item["id"] for r in await temp_db.get_due_watchlist(future))
