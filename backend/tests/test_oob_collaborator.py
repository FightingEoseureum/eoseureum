"""OOB 컬래보레이터 + SSRF/blind XXE/OOB cmdi 확증(고도화 #1) 회귀 테스트.

실제 로컬 aiohttp 리스너를 띄우고, '대상이 콜백 URL 을 fetch' 하는 상황을 모사해
프로브가 콜백 히트로만 확증하는지(오탐 0) 검증. ENABLE_OOB 게이트도 확인.
"""
import asyncio

import aiohttp
import pytest

import oob_collaborator as oob
import active_probing as ap


def _run(coro):
    return asyncio.run(coro)


def test_oob_disabled_no_collaborator(monkeypatch):
    monkeypatch.delenv("ENABLE_OOB", raising=False)
    assert oob.oob_enabled() is False
    assert _run(oob.start_collaborator("x")) is None


def test_collaborator_records_hit(monkeypatch):
    monkeypatch.setenv("ENABLE_OOB", "true")

    async def t():
        c = await oob.start_collaborator("s1")
        assert c is not None and c.port
        tok = c.new_token()
        url = c.url_for(tok)
        assert not c.was_hit(tok)
        # 대상이 콜백 URL 을 fetch 하는 것을 모사
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=3)) as r:
                await r.read()
        assert c.was_hit(tok) is True
        await oob.stop_collaborator("s1")
        assert oob.get_collaborator("s1") is None
    _run(t())


def test_probe_ssrf_confirms_only_on_callback(monkeypatch):
    monkeypatch.setenv("ENABLE_OOB", "true")

    async def t():
        c = await oob.start_collaborator("s2")
        # 대상 서버가 주입된 콜백 URL 을 실제로 fetch 하도록 _get 을 가로챈다
        orig = ap._get
        import urllib.parse as up

        async def fake_get(session, url, headers=None, timeout=8.0):
            for vals in up.parse_qs(up.urlparse(url).query).values():
                for v in vals:
                    if v.startswith(f"http://127.0.0.1:{c.port}/"):
                        async with aiohttp.ClientSession() as s:
                            try:
                                async with s.get(v, timeout=aiohttp.ClientTimeout(total=3)) as r:
                                    await r.read()
                            except Exception:
                                pass
            return 200, "", {}

        ap._get = fake_get
        try:
            points = [{"method": "GET", "url": "http://tgt/f",
                       "params": {"url": "http://x"}, "source": "link"}]
            res = await ap._probe_ssrf(None, "http://tgt", points, scan_id="s2")
        finally:
            ap._get = orig
            await oob.stop_collaborator("s2")
        assert res and res["confirmed"] and res["oob_hit"]
    _run(t())


def test_probe_ssrf_no_callback_no_confirm(monkeypatch):
    """콜백이 안 오면(대상이 fetch 안 함) 절대 확증하지 않는다(오탐 0)."""
    monkeypatch.setenv("ENABLE_OOB", "true")

    async def t():
        await oob.start_collaborator("s3")
        orig = ap._get

        async def silent_get(session, url, headers=None, timeout=8.0):
            return 200, "no callback", {}   # 대상이 콜백 안 함

        ap._get = silent_get
        try:
            points = [{"method": "GET", "url": "http://tgt/f",
                       "params": {"url": "http://x"}, "source": "link"}]
            # 대기 시간을 줄이기 위해 asyncio.sleep 를 즉시 반환으로
            _osleep = asyncio.sleep
            async def fast_sleep(n): await _osleep(0)
            import active_probing
            monkeypatch.setattr(active_probing.asyncio, "sleep", fast_sleep)
            res = await ap._probe_ssrf(None, "http://tgt", points, scan_id="s3")
        finally:
            ap._get = orig
            await oob.stop_collaborator("s3")
        assert res is None
    _run(t())
