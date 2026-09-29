"""
test_cmdi_probe.py — CmdiProbe 검증.

- run() 이 list[ProbeResult] 를 반환하는지 (ap._probe_cmdi monkeypatch).
- 소스 실행 코드에 외부통신/sleep 유발 호출(time.sleep/os.system/subprocess)이 없는지.

실행: venv_linux/bin/python -m pytest tests/test_cmdi_probe.py -q
"""
import ast
import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import active_probing as ap
import probes.cmdi_probe as cmdi_mod
from probes.base import ProbeContext, ProbeResult
from probes.utils.rate_limiter import RateLimiter


def _ctx(**kw):
    base = dict(
        target_url="http://t.example/app",
        host="t.example", port=80, scheme="http",
        session=None,
        injection_points=[{"url": "http://t.example/app", "method": "GET",
                           "params": {"q": "1"}, "source": "generic"}],
        rate_limiter=RateLimiter(0),
        scan_id="scanX",
    )
    base.update(kw)
    return ProbeContext(**base)


@pytest.mark.asyncio
async def test_run_returns_list_confirmed(monkeypatch):
    async def fake_probe_cmdi(session, points, scan_id=""):
        return {"type": "output_based", "param": "q", "url": "http://t.example/app",
                "confirmed": True, "evidence": "에코 토큰 확인됨"}

    monkeypatch.setattr(ap, "_probe_cmdi", fake_probe_cmdi)
    results = await cmdi_mod.PROBE.run(_ctx())
    assert isinstance(results, list)
    assert len(results) == 1
    r = results[0]
    assert isinstance(r, ProbeResult)
    assert r.cwe == "CWE-78"
    assert r.owasp == "A03:2021 - 인젝션"
    assert r.severity == "High"
    assert r.probe_key == "cmd_injection"
    assert r.confidence == "CONFIRMED"
    assert r.raw.get("confirmed") is True


@pytest.mark.asyncio
async def test_run_possible_when_not_confirmed(monkeypatch):
    async def fake_probe_cmdi(session, points, scan_id=""):
        return {"param": "q", "url": "http://t.example/app", "confirmed": False}

    monkeypatch.setattr(ap, "_probe_cmdi", fake_probe_cmdi)
    results = await cmdi_mod.PROBE.run(_ctx())
    assert len(results) == 1
    assert results[0].confidence == "POSSIBLE"


@pytest.mark.asyncio
async def test_run_empty_when_none(monkeypatch):
    async def fake_probe_cmdi(session, points, scan_id=""):
        return None

    monkeypatch.setattr(ap, "_probe_cmdi", fake_probe_cmdi)
    results = await cmdi_mod.PROBE.run(_ctx())
    assert results == []


@pytest.mark.asyncio
async def test_run_empty_when_no_points(monkeypatch):
    called = {"v": False}

    async def fake_probe_cmdi(session, points, scan_id=""):
        called["v"] = True
        return {"confirmed": True}

    monkeypatch.setattr(ap, "_probe_cmdi", fake_probe_cmdi)
    results = await cmdi_mod.PROBE.run(_ctx(injection_points=[]))
    assert results == []
    assert called["v"] is False, "주입 포인트가 없으면 위임 함수를 호출하지 않아야 한다"


def test_source_has_no_external_comm_or_sleep():
    """probe 모듈 실행 코드에 time.sleep/os.system/subprocess 호출이 없어야 한다."""
    src = inspect.getsource(cmdi_mod)
    tree = ast.parse(src)
    forbidden = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            # time.sleep / os.system / subprocess.* 형태의 attribute 호출 검출
            if isinstance(func, ast.Attribute):
                attr = func.attr
                root = func.value
                root_name = root.id if isinstance(root, ast.Name) else None
                if (root_name, attr) in {("time", "sleep"), ("os", "system")}:
                    forbidden.append(f"{root_name}.{attr}")
                if root_name == "subprocess":
                    forbidden.append(f"subprocess.{attr}")
            elif isinstance(func, ast.Name) and func.id in {"system", "sleep"}:
                forbidden.append(func.id)
    assert not forbidden, f"금지된 호출 발견: {forbidden}"
