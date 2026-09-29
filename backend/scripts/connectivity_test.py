import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import asyncio, aiohttp, ssl, socket

async def test():
    # 1. 직접 HTTP 요청
    print("=== 직접 HTTP 요청 테스트 ===")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    targets = [
        ("http://testphp.vulnweb.com/", False),
        ("https://testphp.vulnweb.com/", True),
        ("http://httpbin.org/get", False),
        ("http://example.com/", False),
    ]

    connector = aiohttp.TCPConnector(ssl=ctx)
    async with aiohttp.ClientSession(connector=connector,
                                     timeout=aiohttp.ClientTimeout(total=10)) as s:
        for url, is_ssl in targets:
            try:
                async with s.get(url, allow_redirects=True) as r:
                    print(f"  {url}: HTTP {r.status}")
            except Exception as e:
                print(f"  {url}: ERROR - {type(e).__name__}: {e}")

asyncio.run(test())
