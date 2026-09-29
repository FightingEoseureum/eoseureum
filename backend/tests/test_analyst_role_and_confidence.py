"""dir_fuzz confidence + AI analyst 역할모델 라우팅 회귀."""
import asyncio

import external_tools as et
import ai_provider as ap


def _run(c):
    return asyncio.run(c)


# ── dir_fuzz finding 이 CONFIRMED confidence 를 갖는지 ──────────────────────────
def test_dir_fuzz_findings_confirmed(monkeypatch, tmp_path):
    from aiohttp import web

    wl = tmp_path / "wl.txt"; wl.write_text(".env\nrandomnope")
    monkeypatch.setattr(et, "_wordlist_path", lambda: str(wl))
    monkeypatch.setenv("QUICKHITS_ENABLE", "false")

    async def _serve():
        app = web.Application()

        async def env(req):
            return web.Response(text="DB_PASSWORD=secret12345\nAPI_KEY=xxxxyyyy", content_type="text/plain")

        async def nf(req):
            return web.Response(status=404, text="nope")

        app.router.add_get("/.env", env)
        app.router.add_get("/{t:.*}", nf)
        runner = web.AppRunner(app); await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
        base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        try:
            return await et.run_dir_fuzz(base, "127.0.0.1", 80)
        finally:
            await runner.cleanup()

    res = _run(_serve())
    assert res, "dir_fuzz 결과 없음"
    assert all(f.get("confidence") == "CONFIRMED" for f in res), \
        [f.get("confidence") for f in res]


# ── analyst 가 'analysis' 역할 모델을 사용하는지 ──────────────────────────────
def test_analyst_uses_analysis_role_model(monkeypatch):
    # role_model('analysis') → 특정 모델을 반환하도록 강제, _provider_with_model 이 그 모델로 생성하는지
    monkeypatch.setattr(ap, "role_model", lambda role: "qwen2.5:32b" if role == "analysis" else None)
    monkeypatch.setattr(ap, "_AI_PROVIDER", "ollama")
    prov = ap._provider_with_model(ap.role_model("analysis"))
    assert getattr(prov, "model", "") == "qwen2.5:32b"


def test_analyst_role_falls_back_when_no_routing(monkeypatch):
    # role_model 이 None → 기본 프로바이더로 폴백(예외 없이)
    monkeypatch.setattr(ap, "role_model", lambda role: None)
    prov = ap._provider_with_model(ap.role_model("analysis"))
    assert prov is not None  # get_ai_provider() 폴백
