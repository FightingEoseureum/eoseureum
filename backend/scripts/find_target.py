import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import asyncio, aiohttp, ssl

TARGETS = [
    "http://testphp.vulnweb.com/",
    "http://testhtml5.vulnweb.com/",
    "http://testasp.vulnweb.com/",
    "http://demo.testfire.net/",
    "http://juice-shop.herokuapp.com/",
    "http://dvwa.co.uk/",
    "http://neverssl.com/",
    "http://httpbin.org/",
    "http://scanme.nmap.org/",
    "http://zero.webappsecurity.com/",
]

async def test():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ctx)
    timeout = aiohttp.ClientTimeout(total=8)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as s:
        for url in TARGETS:
            try:
                async with s.get(url, allow_redirects=True) as r:
                    server = r.headers.get("Server", "")
                    print(f"  [OK  {r.status}] {url}  server={server}")
            except Exception as e:
                print(f"  [FAIL] {url}  {type(e).__name__}")

asyncio.run(test())
