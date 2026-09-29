"""SecLists 흡수 회귀 테스트 — 파라미터 사전(burp-parameter-names) + quickhits 민감파일 패스."""
import asyncio

from aiohttp import web

import external_tools as et
import param_miner as pm


def _run(c):
    return asyncio.run(c)


# ── 파라미터 사전(정제·병합) ─────────────────────────────────────────────────
def test_param_name_filter():
    assert pm._PARAM_NAME_RE.match("id") and pm._PARAM_NAME_RE.match("user_id")
    assert pm._PARAM_NAME_RE.match("x-api-key")
    assert not pm._PARAM_NAME_RE.match("1")       # 순수숫자 정크 배제
    assert not pm._PARAM_NAME_RE.match("12")
    assert not pm._PARAM_NAME_RE.match("%3f")


def test_load_param_wordlist_curated_first_plus_seclists(monkeypatch, tmp_path):
    wl = tmp_path / "params.txt"
    wl.write_text("1\n12\nid\ncustom_param\nfoo_bar")   # 1,12 정크 / id 중복 / 2개 신규
    monkeypatch.setenv("PARAM_WORDLIST", str(wl))
    monkeypatch.setattr(pm, "_PARAM_WL_CACHE", None)
    got = pm.load_param_wordlist()
    assert got[0] == pm.COMMON_PARAMS[0]                 # 내장 커리큘 앞쪽 배치
    assert "custom_param" in got and "foo_bar" in got    # 신규 SecLists 항목 포함
    assert "1" not in got and "12" not in got            # 정크 제외
    assert got.count("id") == 1                          # 중복 제거


# ── quickhits(정제 + prepend) ────────────────────────────────────────────────
def test_quickhits_words_cleaned(monkeypatch, tmp_path):
    q = tmp_path / "qh.txt"
    q.write_text("!.gitignore\n/.env\n# comment\n\nadmin/backup.sql")
    monkeypatch.setenv("QUICKHITS_PATH", str(q))
    got = et._quickhits_words()
    assert ".gitignore" in got and ".env" in got and "admin/backup.sql" in got
    assert not any(g.startswith("#") for g in got)       # 주석 제외
    assert not any(g.startswith("!") or g.startswith("/") for g in got)  # 특수문자 정제


async def _serve(routes):
    app = web.Application()
    for m, p, h in routes:
        app.router.add_route(m, p, h)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"


def test_quickhits_prepended_into_dir_fuzz(monkeypatch, tmp_path):
    # 워드리스트엔 없고 quickhits 에만 있는 민감경로(.env)가 탐지되는지
    wl = tmp_path / "wl.txt"
    wl.write_text("index.html\nabout")
    monkeypatch.setattr(et, "_wordlist_path", lambda: str(wl))
    q = tmp_path / "qh.txt"
    q.write_text(".env")
    monkeypatch.setenv("QUICKHITS_PATH", str(q))

    async def t():
        async def env(req):
            return web.Response(text="DB_PASSWORD=secret12345\nAPI_KEY=xxxxyyyy", content_type="text/plain")

        async def nf(req):
            return web.Response(status=404, text="nf")

        runner, base = await _serve([("GET", "/.env", env), ("GET", "/{tail:.*}", nf)])
        try:
            return await et.run_dir_fuzz(base, "127.0.0.1", 80)
        finally:
            await runner.cleanup()

    res = _run(t())
    titles = " ".join(f["title"] for f in res)
    assert "/.env" in titles      # quickhits 에서 온 민감경로 탐지
