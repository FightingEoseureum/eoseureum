"""tests/test_sqli_payload_policy.py — SQLi payload 정책 + time-based 게이팅 + 로그인 폼 대상 검증.

- safe/balanced/aggressive 분기 정상.
- SQLI_PAYLOAD_FILE 최대 1000.
- ENABLE_TIME_BASED_SQLI=false → _probe_sqli_time 미호출(time payload []).
- =true(+aggressive+advanced)여도 delay≤3, time payload 셋 산출.
- 로그인 폼이 SQLi auth bypass 대상이 됨(monkeypatch 캡처).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import active_probing as ap
from probes import sqli_probe
from probes.base import ProbeContext
from probes.config import ScanConfig
from probes.utils import payloads
from probes.utils.rate_limiter import RateLimiter


class _DummySession:
    pass


def _ctx(points, config=None):
    return ProbeContext(
        target_url="http://target.example/",
        session=_DummySession(),
        injection_points=points,
        scan_config=config or ScanConfig(),
        rate_limiter=RateLimiter(0),
        scan_id="test-scan",
    )


def _patch_all(monkeypatch, **overrides):
    async def none_pt(session, points, scan_id=""):
        return None

    async def none_bt(session, points):
        return None

    monkeypatch.setattr(ap, "_probe_sqli_error", overrides.get("error", none_pt))
    monkeypatch.setattr(ap, "_probe_sqli_union", overrides.get("union", none_pt))
    monkeypatch.setattr(ap, "_probe_sqli_bool", overrides.get("bool", none_bt))
    monkeypatch.setattr(ap, "_probe_sqli_time", overrides.get("time", none_bt))
    monkeypatch.setattr(ap, "_probe_sqli_auth_bypass", overrides.get("auth_bypass", none_bt))


def test_login_payload_levels():
    safe = payloads.get_sqli_login_payloads(ScanConfig(payload_level="safe"))
    balanced = payloads.get_sqli_login_payloads(ScanConfig(payload_level="balanced"))
    aggressive = payloads.get_sqli_login_payloads(ScanConfig(payload_level="aggressive"))
    assert len(safe) >= 1
    assert len(balanced) > len(safe)
    assert set(safe).issubset(set(balanced))
    assert set(balanced).issubset(set(aggressive))


def test_payload_file_capped_at_1000(tmp_path):
    f = tmp_path / "sqli.txt"
    f.write_text("\n".join(f"' OR {i}={i}--" for i in range(5000)), encoding="utf-8")
    cfg = ScanConfig(payload_level="aggressive", enable_advanced_payloads=True,
                     sqli_payload_file=str(f), max_sqli_payloads=1000)
    out = payloads.get_sqli_login_payloads(cfg)
    assert len(out) <= 1000


def test_time_based_disabled_by_default():
    cfg = ScanConfig()  # enable_time_based_sqli=False, level=safe
    assert payloads.get_time_based_sqli_payloads(cfg) == []


def test_time_based_requires_all_gates():
    # 활성이어도 aggressive + advanced 가 아니면 빈 리스트
    assert payloads.get_time_based_sqli_payloads(
        ScanConfig(enable_time_based_sqli=True)) == []
    assert payloads.get_time_based_sqli_payloads(
        ScanConfig(enable_time_based_sqli=True, payload_level="aggressive")) == []
    # 모든 게이트 충족 시에만 비어있지 않음
    out = payloads.get_time_based_sqli_payloads(ScanConfig(
        enable_time_based_sqli=True, payload_level="aggressive",
        enable_advanced_payloads=True, max_time_based_sqli_delay=3))
    assert out


def test_time_based_delay_capped():
    # delay 를 99 로 줘도 3 이하로 고정.
    out = payloads.get_time_based_sqli_payloads(ScanConfig(
        enable_time_based_sqli=True, payload_level="aggressive",
        enable_advanced_payloads=True, max_time_based_sqli_delay=99))
    assert out
    # SLEEP/WAITFOR/pg_sleep payload 안의 숫자 delay 가 3 이하인지 확인
    for p in out:
        if "SLEEP(" in p:
            num = p.split("SLEEP(")[1].split(")")[0]
            assert int(num) <= 3


@pytest.mark.asyncio
async def test_time_probe_not_called_when_disabled(monkeypatch):
    called = {"v": False}

    async def fake_time(session, points):
        called["v"] = True
        return {"confirmed": True}

    _patch_all(monkeypatch, time=fake_time)
    point = {"url": "http://target.example/p", "method": "GET",
             "source": "url", "params": {"id": "1"}}
    await sqli_probe.PROBE.run(_ctx([point], ScanConfig()))  # time disabled
    assert called["v"] is False, "time payload 가 비어있으면 _probe_sqli_time 미호출"


@pytest.mark.asyncio
async def test_time_probe_called_when_enabled_downgraded(monkeypatch):
    called = {"v": False}

    async def fake_time(session, points):
        called["v"] = True
        return {"confirmed": True, "url": "http://target.example/p", "evidence": "delay"}

    _patch_all(monkeypatch, time=fake_time)
    cfg = ScanConfig(enable_time_based_sqli=True, payload_level="aggressive",
                     enable_advanced_payloads=True)
    point = {"url": "http://target.example/p", "method": "GET",
             "source": "url", "params": {"id": "1"}}
    results = await sqli_probe.PROBE.run(_ctx([point], cfg))
    assert called["v"] is True
    time_res = [r for r in results if r.probe_key == "sqli_time"]
    assert len(time_res) == 1
    # time-based 단독 확정 금지 → CONFIRMED 가 아니라 POSSIBLE/MANUAL_REVIEW
    assert time_res[0].confidence in ("POSSIBLE", "MANUAL_REVIEW")


@pytest.mark.asyncio
async def test_login_form_targeted_for_auth_bypass(monkeypatch):
    captured = {}

    async def fake_auth_bypass(session, points):
        captured["points"] = points
        return None

    _patch_all(monkeypatch, auth_bypass=fake_auth_bypass)
    login_point = {"url": "http://target.example/login", "method": "POST",
                   "source": "form", "params": {"username": "a", "password": "b"}}
    non_login = {"url": "http://target.example/p", "method": "GET",
                 "source": "url", "params": {"id": "1"}}
    await sqli_probe.PROBE.run(_ctx([non_login, login_point]))

    assert "points" in captured
    assert login_point in captured["points"]
    assert non_login not in captured["points"]
