"""티어3 3-A: recover 재개 스캔 수명주기 — SCAN_TASKS 등록·동시성 집계·취소 시 정리."""
import asyncio

import main


def _run(c):
    return asyncio.run(c)


def _reset(uid, sid):
    for d in (main.SCAN_TASKS, main.SCAN_CANCEL, main.SCAN_STATE, main.SCAN_PROGRESS,
              main.SCAN_PAUSE, main.SCAN_EXCLUDE, main.SCAN_INCLUDE, main.SCAN_BUDGET,
              main.SCAN_DEADLINE):
        d.pop(sid, None)
    main.RUNNING_BY_USER.pop(uid, None)


def test_cleanup_scan_state_decrements_and_clears():
    uid, sid = 4242, "sid-clean"
    main.RUNNING_BY_USER[uid] = 2
    main.SCAN_TASKS[sid] = "task"
    main.SCAN_BUDGET[sid] = {"total_min": 5}
    main._cleanup_scan_state(sid, uid)
    assert sid not in main.SCAN_TASKS
    assert sid not in main.SCAN_BUDGET
    assert main.RUNNING_BY_USER[uid] == 1     # 감소
    _reset(uid, sid)


def test_managed_scan_cleans_up_on_normal_completion(monkeypatch):
    uid, sid = 4243, "sid-normal"
    _reset(uid, sid)
    main.RUNNING_BY_USER[uid] = 1

    async def _fake_run_scan(ws, domain, scan_id, user_id, role, **kw):
        return None
    monkeypatch.setattr(main, "run_scan", _fake_run_scan)

    async def t():
        task = asyncio.create_task(main._run_managed_scan(None, "t", sid, uid, "user"))
        main.SCAN_TASKS[sid] = task
        await task
        return sid in main.SCAN_TASKS, main.RUNNING_BY_USER.get(uid, 0)
    in_tasks, running = _run(t())
    assert in_tasks is False        # 완료 후 SCAN_TASKS 에서 제거
    assert running == 0             # 동시성 카운터 감소
    _reset(uid, sid)


def test_managed_scan_finalizes_and_cleans_on_cancel(monkeypatch):
    uid, sid = 4244, "sid-cancel"
    _reset(uid, sid)
    main.RUNNING_BY_USER[uid] = 1
    _finalized = {"called": False}

    async def _fake_run_scan(ws, domain, scan_id, user_id, role, **kw):
        await asyncio.sleep(30)   # 취소될 때까지 대기

    async def _fake_finalize(scan_id, domain, send=None):
        _finalized["called"] = True
    monkeypatch.setattr(main, "run_scan", _fake_run_scan)
    monkeypatch.setattr(main, "_finalize_partial", _fake_finalize)

    async def t():
        task = asyncio.create_task(main._run_managed_scan(None, "t", sid, uid, "user"))
        main.SCAN_TASKS[sid] = task
        await asyncio.sleep(0.1)
        task.cancel()             # /stop 이 SCAN_TASKS[sid].cancel() 하는 것과 동일
        try:
            await task
        except asyncio.CancelledError:
            pass
        return _finalized["called"], sid in main.SCAN_TASKS, main.RUNNING_BY_USER.get(uid, 0)
    finalized, in_tasks, running = _run(t())
    assert finalized is True       # 취소 시 부분보고 생성
    assert in_tasks is False       # 정리됨(고스트 스캔 아님)
    assert running == 0            # 동시성 카운터 감소
    _reset(uid, sid)
