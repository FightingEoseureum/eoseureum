"""내부(네이티브) 기술 핑거프린팅 회귀 테스트 — 외부 httpx 대체.

로컬 서버가 주는 헤더/HTML 마커로 technology_fingerprint 엔진이 기술스택을 뽑는지,
그리고 hr['technologies'] 병합이 dict/문자열 혼재를 dedup·정규화하는지 검증한다.
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


def test_native_fingerprint_detects_wordpress_react_php():
    async def t():
        async def home(req):
            html = ('<html><head>'
                    '<meta name="generator" content="WordPress 6.1.1">'
                    '</head><body>'
                    '<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
                    '<div data-reactroot></div>'
                    '<script src="/wp-includes/js/jquery-3.6.0.min.js"></script>'
                    '</body></html>')
            return web.Response(text=html, content_type="text/html",
                                headers={"X-Powered-By": "PHP/7.4.3"})

        runner, base = await _serve([("GET", "/", home)])
        try:
            return await et.run_native_fingerprint(base, "127.0.0.1", 80)
        finally:
            await runner.cleanup()

    fp = _run(t())
    names = [n.lower() for n in fp.get("technologies", [])]
    assert fp.get("wordpress") is True
    assert any("wordpress" in n for n in names)
    assert any("php" in n for n in names)          # X-Powered-By: PHP
    assert any("react" in n for n in names)        # data-reactroot
    # 반환 tech_entries 는 dict 포맷
    assert all(isinstance(e, dict) and e.get("name") for e in fp.get("tech_entries", []))


def test_merge_tech_dedup_and_normalize():
    hr = {"technologies": [{"name": "Nginx", "confidence": 50}]}
    et._merge_tech_into(hr, ["React", "nginx", {"name": "PHP", "confidence": 80}])
    names = [t["name"] for t in hr["technologies"]]
    assert names == ["Nginx", "React", "PHP"]              # nginx 중복 제거, React 정규화, PHP 추가
    assert all(isinstance(t, dict) for t in hr["technologies"])  # 전부 dict 포맷 유지


def test_native_fingerprint_unreachable_returns_empty():
    # 연결 불가 → 빈 dict(우아한 실패)
    fp = _run(et.run_native_fingerprint("http://127.0.0.1:59999", "127.0.0.1", 59999))
    assert fp == {}
