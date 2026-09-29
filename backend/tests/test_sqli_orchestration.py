"""Blind SQLi 오케스트레이션 회귀 테스트.

버그: error→union→bool→time 단락 체인이 앞 기법(error/union)이 탐지하면 blind(bool/time)를
아예 실행하지 않아, blind SQLi 커버리지가 사라졌다. _orchestrate_sqli 로 분리 후:
  - boolean 블라인드는 error/union 성공 여부와 무관하게 '항상' 수행
  - time 블라인드는 아무 것도 확정 못했을 때만(지연 큼) 최후수단
  - 확정 기법을 모두 수집(additional_confirmations)
"""
import asyncio
import active_probing as ap


def _run(coro):
    return asyncio.run(coro)


def _patch(monkeypatch, *, error=None, union=None, boolean=None, timeb=None):
    calls = {"error": 0, "union": 0, "bool": 0, "time": 0}

    async def _err(session, points, scan_id=""):
        calls["error"] += 1; return error

    async def _uni(session, points, scan_id=""):
        calls["union"] += 1; return union

    async def _bool(session, points):
        calls["bool"] += 1; return boolean

    async def _time(session, points):
        calls["time"] += 1; return timeb

    monkeypatch.setattr(ap, "_probe_sqli_error", _err)
    monkeypatch.setattr(ap, "_probe_sqli_union", _uni)
    monkeypatch.setattr(ap, "_probe_sqli_bool", _bool)
    monkeypatch.setattr(ap, "_probe_sqli_time", _time)
    return calls


def test_boolean_blind_runs_even_when_error_hits(monkeypatch):
    """핵심: error 가 탐지해도 boolean 블라인드는 반드시 실행된다(예전엔 단락으로 skip)."""
    err = {"type": "error_based", "param": "id", "url": "u", "confirmed": True}
    calls = _patch(monkeypatch, error=err, boolean=None)
    res = _run(ap._orchestrate_sqli(None, [{"params": {"id": "1"}}], scan_id="s"))
    assert calls["error"] == 1
    assert calls["bool"] == 1                 # ← blind 가 실행됨(회귀 방지 핵심)
    assert calls["union"] == 0                # error 확정 → union 은 단락(무-지연 최적화 유지)
    assert calls["time"] == 0                 # 이미 확정 → time(지연) 미수행
    assert res["type"] == "error_based"


def test_multiple_confirmations_collected(monkeypatch):
    """error + boolean 이 모두 확정되면 대표 1건 + additional_confirmations."""
    err = {"type": "error_based", "param": "id", "url": "u", "confirmed": True}
    bl = {"type": "boolean_based", "param": "q", "url": "u2", "confirmed": True}
    _patch(monkeypatch, error=err, boolean=bl)
    res = _run(ap._orchestrate_sqli(None, [{"params": {"id": "1"}}], scan_id="s"))
    assert res["type"] == "error_based"
    assert res["additional_confirmations"][0]["type"] == "boolean_based"


def test_time_runs_only_when_nothing_confirmed(monkeypatch):
    """error/union/bool 모두 미확정일 때만 time 블라인드(지연)가 최후수단으로 수행."""
    tb = {"type": "time_based", "param": "id", "url": "u", "confirmed": True}
    calls = _patch(monkeypatch, error=None, union=None, boolean=None, timeb=tb)
    res = _run(ap._orchestrate_sqli(None, [{"params": {"id": "1"}}], scan_id="s"))
    assert calls["error"] == 1 and calls["union"] == 1 and calls["bool"] == 1
    assert calls["time"] == 1
    assert res["type"] == "time_based"


def test_time_skipped_when_boolean_hits(monkeypatch):
    """boolean 이 확정하면 time(지연)은 수행하지 않는다(비용 절감)."""
    bl = {"type": "boolean_based", "param": "q", "url": "u", "confirmed": True}
    calls = _patch(monkeypatch, error=None, union=None, boolean=bl, timeb=None)
    res = _run(ap._orchestrate_sqli(None, [{"params": {"q": "1"}}], scan_id="s"))
    assert calls["bool"] == 1
    assert calls["time"] == 0
    assert res["type"] == "boolean_based"


def test_none_when_all_clean(monkeypatch):
    _patch(monkeypatch)
    res = _run(ap._orchestrate_sqli(None, [{"params": {"id": "1"}}], scan_id="s"))
    assert res is None
