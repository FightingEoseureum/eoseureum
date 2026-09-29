"""내부(네이티브) 디렉터리 퍼징 회귀 테스트 — ffuf 대체.

로컬 aiohttp 서버로 (1) 민감 경로 탐지 (2) 소프트404(catch-all 200) 사이트 오탐 억제를 검증한다.
"""
import asyncio

from aiohttp import web

import external_tools as et


def _run(c):
    return asyncio.run(c)


async def _serve(routes):
    app = web.Application()
    for m, p, h in routes:
        app.router.add_route(m, p, h)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"


def _wordlist(tmp_path, words):
    p = tmp_path / "wl.txt"
    p.write_text("\n".join(words))
    return str(p)


def test_dir_fuzz_finds_sensitive_paths(monkeypatch, tmp_path):
    monkeypatch.setattr(et, "_wordlist_path",
                        lambda: _wordlist(tmp_path, [".env", "backup.sql", "index.html", "randomnope"]))

    async def t():
        async def env(req):
            return web.Response(text="DB_PASSWORD=secret123\nAPI_KEY=abcdef1234567890",
                                content_type="text/plain")

        async def bak(req):
            return web.Response(text="-- MySQL dump 10.13\nCREATE TABLE users (id INT, pw VARCHAR);",
                                content_type="text/plain")

        async def idx(req):
            return web.Response(text="<html><body>Welcome to the public home page content.</body></html>",
                                content_type="text/html")

        async def nf(req):
            return web.Response(status=404, text="not found")

        runner, base = await _serve([("GET", "/.env", env), ("GET", "/backup.sql", bak),
                                     ("GET", "/index.html", idx), ("GET", "/{tail:.*}", nf)])
        try:
            return await et.run_dir_fuzz(base, "127.0.0.1", 80)
        finally:
            await runner.cleanup()

    res = _run(t())
    titles = " ".join(f["title"] for f in res)
    # 민감 경로(.env, backup.sql)는 탐지, index.html(비민감 200)·randomnope(404)는 제외
    assert "/.env" in titles and "/backup.sql" in titles
    assert "/index.html" not in titles and "/randomnope" not in titles
    # tool_source 는 내부 엔진
    assert all(f.get("tool_source") == "내부 퍼징 엔진" for f in res)
    # 내용/파일명이 민감한 200 → '민감 파일 노출(정보 노출)' 로 승급(취약점)
    assert any(f["title"].startswith("민감 파일 노출") for f in res)
    # .env 는 내용에 자격증명(DB_PASSWORD/API_KEY) → 취약점 승급 마커(content_confirmed) 부여
    _env_f = next((f for f in res if "/.env" in f["title"]), None)
    assert _env_f and "content_confirmed" in (_env_f.get("tags") or [])


def test_dir_fuzz_soft404_site_suppressed(monkeypatch, tmp_path):
    monkeypatch.setattr(et, "_wordlist_path",
                        lambda: _wordlist(tmp_path, [".env", "admin", "secret", "backup"]))

    async def t():
        async def catchall(req):
            # 모든 경로에 동일한 200 페이지 반환(soft-404 catch-all 사이트)
            return web.Response(text="<html><body>Our custom page shown for every path.</body></html>",
                                content_type="text/html")

        runner, base = await _serve([("GET", "/{tail:.*}", catchall)])
        try:
            return await et.run_dir_fuzz(base, "127.0.0.1", 80)
        finally:
            await runner.cleanup()

    res = _run(t())
    # 베이스라인 대비 모두 유사(soft-404) → 오탐 0
    assert res == []


def test_wordlist_path_env_priority(monkeypatch, tmp_path):
    p = tmp_path / "custom.txt"
    p.write_text("admin\n.env")
    monkeypatch.setenv("FFUF_WORDLIST", str(p))
    assert et._wordlist_path() == str(p)


def test_dir_fuzz_respects_max_words_cap(monkeypatch, tmp_path):
    monkeypatch.setenv("DIRFUZZ_MAX_WORDS", "2")
    monkeypatch.setattr(et, "_wordlist_path",
                        lambda: _wordlist(tmp_path, ["a", "b", "c", "d", "e", ".env"]))
    hits = []

    async def t():
        async def any_path(req):
            hits.append(req.path)
            return web.Response(status=404, text="nf")
        runner, base = await _serve([("GET", "/{tail:.*}", any_path)])
        try:
            return await et.run_dir_fuzz(base, "127.0.0.1", 80)
        finally:
            await runner.cleanup()

    _run(t())
    # 캡=2 → 워드 앞 2개(a,b)만 테스트. .env(6번째)는 잘림. (베이스라인 eoseureum-* 제외)
    non_baseline = [h for h in hits if "eoseureum" not in h]
    assert len(non_baseline) <= 2


def test_dir_fuzz_follows_redirect_to_sensitive(monkeypatch, tmp_path):
    # /admin 이 302 → /login(200, admin 로그인) 인 경우 추적해서 탐지해야 함(빈 본문 오억제 회귀)
    monkeypatch.setattr(et, "_wordlist_path", lambda: _wordlist(tmp_path, ["admin", "randomnope"]))
    monkeypatch.setenv("QUICKHITS_ENABLE", "false")

    async def t():
        async def admin(req):
            return web.Response(status=302, headers={"Location": "/login"})

        async def login(req):
            return web.Response(
                text="<title>Login</title><h1>Admin Console Login</h1> please sign in to the admin dashboard",
                content_type="text/html")

        async def nf(req):
            return web.Response(status=404, text="not found page content here")

        runner, base = await _serve([("GET", "/admin", admin), ("GET", "/login", login),
                                     ("GET", "/{tail:.*}", nf)])
        try:
            return await et.run_dir_fuzz(base, "127.0.0.1", 80)
        finally:
            await runner.cleanup()

    res = _run(t())
    titles = " ".join(f["title"] for f in res)
    assert "/admin" in titles
