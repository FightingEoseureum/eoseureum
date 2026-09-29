"""P5: SSTI→RCE 실증(PROOF 게이트) — 엔진 네이티브 OOB 콜백으로 코드실행 도달성 확증.

안전 불변식 검증 포함: 페이로드에 셸/웹쉘/popen/curl/wget 이 절대 없어야 한다.
"""
import asyncio

import aiohttp
from aiohttp import web

import active_probing as ap
import rule_engine as re_mod


def _run(c):
    return asyncio.run(c)


_SHELL_TOKENS = ("/bin/sh", "/bin/bash", "popen", "system(", "os-shell",
                 "webshell", "curl ", "wget ", "cmd.exe", "powershell",
                 "xp_cmdshell", "subprocess")


def test_oob_payloads_are_shell_free():
    """모든 엔진 페이로드가 셸/웹쉘 없이 언어 네이티브 네트워크 프리미티브만 사용."""
    engines = ["Jinja2", "Twig", "Mako", "Smarty", "ERB (Ruby)", "Ruby/Pebble",
               "Freemarker/Spring EL", "Spring EL", "Thymeleaf", "JSP/ASP EL",
               "Razor (.NET)", "Velocity", "unknown-engine"]
    for eng in engines:
        pls = ap._ssti_oob_payloads(eng, "127.0.0.1:9/tok")
        assert pls, f"{eng} 페이로드 없음"
        for pl in pls:
            low = pl.lower()
            for bad in _SHELL_TOKENS:
                assert bad not in low, f"{eng}: 금지 토큰 '{bad}' in {pl}"
            assert "127.0.0.1:9/tok" in pl  # 콜백 호스트 삽입 확인


def test_escalate_noop_without_proof(monkeypatch):
    """PROOF 비활성이면 RCE 승격을 시도하지 않는다(None)."""
    import validation_profiles as vp
    monkeypatch.setattr(vp, "proof_active", lambda: False)
    pt = {"method": "GET", "url": "http://t/x", "params": {"id": "1"}}
    assert _run(ap._ssti_escalate_rce(None, pt, "id", "Jinja2", "s")) is None


def test_escalate_confirms_on_callback(monkeypatch):
    """PROOF 활성 + 콜백 히트 → rce_confirmed."""
    import validation_profiles as vp
    monkeypatch.setattr(vp, "proof_active", lambda: True)

    class _Collab:
        def new_token(self):
            return "toktok123"
        def host_for(self, t):
            return f"127.0.0.1:9/{t}"
        def was_hit(self, t):
            return t == "toktok123"
    import oob_collaborator as oob
    monkeypatch.setattr(oob, "get_collaborator", lambda sid: _Collab())

    async def fake_get(session, url, **kw):
        return 200, "", {}
    monkeypatch.setattr(ap, "_get", fake_get)
    pt = {"method": "GET", "url": "http://t/x", "params": {"id": "1"}}
    r = _run(ap._ssti_escalate_rce(None, pt, "id", "Jinja2", "s"))
    assert r and r["rce_confirmed"] is True and r["oob_hit"] is True
    assert r["rce_token"] == "toktok123"


def test_escalate_none_when_no_callback(monkeypatch):
    """콜백 미수신이면 승격 안 함(오탐 0)."""
    import validation_profiles as vp
    monkeypatch.setattr(vp, "proof_active", lambda: True)

    class _Collab:
        def new_token(self):
            return "t"
        def host_for(self, t):
            return f"127.0.0.1:9/{t}"
        def was_hit(self, t):
            return False
    import oob_collaborator as oob
    monkeypatch.setattr(oob, "get_collaborator", lambda sid: _Collab())

    async def fake_get(session, url, **kw):
        return 200, "", {}
    monkeypatch.setattr(ap, "_get", fake_get)
    pt = {"method": "GET", "url": "http://t/x", "params": {"id": "1"}}
    assert _run(ap._ssti_escalate_rce(None, pt, "id", "Jinja2", "s")) is None


def test_full_probe_arithmetic_then_rce(monkeypatch):
    """실서버: {{7*7}} 평가(산술 확증) → OOB 콜백으로 서버가 콜백 → rce_confirmed 실린다."""
    import validation_profiles as vp
    monkeypatch.setattr(vp, "proof_active", lambda: True)

    hits = {"n": 0}

    class _Collab:
        def new_token(self):
            return "rcetoken9"
        def host_for(self, t):
            return f"127.0.0.1:9/{t}"
        def was_hit(self, t):
            return hits["n"] > 0
    import oob_collaborator as oob
    monkeypatch.setattr(oob, "get_collaborator", lambda sid: _Collab())

    async def t():
        async def h(req):
            v = req.query.get("q", "")
            # 산술 SSTI: 마커 사이 표현식을 평가해 49 로 치환(Jinja2 흉내)
            import re as _re
            m = _re.search(r"(eosti\w+)\{\{7\*7\}\}(eosti\w+)", v)
            if m:
                return web.Response(text=f"{m.group(1)}49{m.group(2)}")
            # RCE 페이로드(urllib 네이티브)를 서버가 '실행'한 것처럼 콜백 발생
            if "urlopen('http://127.0.0.1:9/rcetoken9')" in v:
                hits["n"] += 1
                return web.Response(text="ok")
            return web.Response(text="nothing")
        app = web.Application(); app.router.add_route("*", "/", h)
        runner = web.AppRunner(app); await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
        port = site._server.sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/"
        try:
            async with aiohttp.ClientSession() as s:
                pts = [{"method": "GET", "url": url, "params": {"q": "1"}}]
                return await ap._probe_ssti(s, pts, scan_id="rce")
        finally:
            await runner.cleanup()

    r = _run(t())
    assert r and r["confirmed"] is True
    assert r.get("rce_confirmed") is True and r.get("oob_hit") is True


def test_rule_engine_upgrades_ssti_to_critical():
    """rce_confirmed 결과 → CRITICAL 승격 + 제목/CVSS 갱신."""
    probes = {"ssti": {
        "param": "q", "payload": "eostix{{7*7}}eostix", "expected_result": "49",
        "engine": "Jinja2", "url": "http://t/", "method": "GET", "confirmed": True,
        "rce_confirmed": True, "oob_hit": True, "rce_token": "rcetoken9",
        "rce_payload": "{{...urlopen('http://127.0.0.1:9/rcetoken9')}}",
        "evidence": "SSTI→RCE 실증",
    }}
    out = re_mod._build_active_probe_findings("t", 80, "http", probes, set())
    assert len(out) == 1
    f = out[0]
    assert f["severity"] == "CRITICAL"
    assert f["cvss_estimate"] == "9.9"
    assert "RCE" in f["title"]
    assert any("RCE 실증" in s for s in f["detection_steps"])


def test_rule_engine_plain_ssti_stays_high():
    """rce_confirmed 없으면 기존 HIGH 유지(회귀 방지)."""
    probes = {"ssti": {
        "param": "q", "payload": "eostix{{7*7}}eostix", "expected_result": "49",
        "engine": "Jinja2", "url": "http://t/", "method": "GET", "confirmed": True,
        "evidence": "SSTI 확인",
    }}
    out = re_mod._build_active_probe_findings("t", 80, "http", probes, set())
    assert len(out) == 1
    assert out[0]["severity"] == "HIGH"
