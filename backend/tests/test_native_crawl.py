"""내부(네이티브) 크롤러 회귀 테스트 — 외부 katana 대체.

로컬 서버로 HTML 링크 + 인라인/외부 JS 엔드포인트를 수집하고, 외부 출처는 제외,
depth 크롤(2단계)이 동작하는지 검증한다.
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


def test_native_crawl_collects_links_and_js_endpoints():
    async def t():
        async def home(req):
            html = ('<html><body>'
                    '<a href="/page1?id=1">p1</a>'
                    '<a href="https://external.example/x">ext</a>'   # 외부 → 제외
                    '<script src="/app.js"></script>'
                    '<script>fetch("/api/data?q=1")</script>'
                    '</body></html>')
            return web.Response(text=html, content_type="text/html")

        async def page1(req):
            return web.Response(text='<a href="/page2">p2</a>', content_type="text/html")

        async def page2(req):
            return web.Response(text='<html>leaf</html>', content_type="text/html")

        async def appjs(req):
            return web.Response(text='const u = fetch("/api/users?role=admin");',
                                content_type="application/javascript")

        async def api(req):
            return web.Response(text='{"ok":true}', content_type="application/json")

        runner, base = await _serve([
            ("GET", "/", home), ("GET", "/page1", page1), ("GET", "/page2", page2),
            ("GET", "/app.js", appjs), ("GET", "/api/data", api), ("GET", "/api/users", api),
        ])
        try:
            return await et.run_native_crawl(base, "127.0.0.1", 80, depth=2)
        finally:
            await runner.cleanup()

    urls = _run(t())
    joined = " ".join(urls)
    # 파라미터 URL 수집(HTML a href + 인라인 fetch + .js 내부 fetch)
    assert "id=1" in joined and "q=1" in joined and "role=admin" in joined
    # depth 2: /page1 에서 /page2 발견
    assert any(u.endswith("/page2") for u in urls)
    # 외부 출처는 제외
    assert "external.example" not in joined


def test_native_crawl_unreachable_returns_empty():
    urls = _run(et.run_native_crawl("http://127.0.0.1:59999", "127.0.0.1", 59999, depth=1))
    assert urls == []
