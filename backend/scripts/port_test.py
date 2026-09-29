import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import asyncio, socket
from scanner import scan_port, detect_http_service

async def test():
    host = "testphp.vulnweb.com"
    try:
        ip = socket.gethostbyname(host)
        print(f"IP: {ip}")
    except Exception as e:
        print(f"DNS 오류: {e}")
        return

    for port in [80, 443, 8080]:
        open_ = await scan_port(ip, port, timeout=5.0)
        status = "OPEN" if open_ else "closed"
        print(f"  port {port}: {status}")

    print("\nHTTP 직접 요청 테스트:")
    info = await detect_http_service(host, 80, use_ssl=False)
    print(f"  status: {info.get('status')}")
    print(f"  server: {info.get('server')}")
    print(f"  title: {info.get('title')}")
    print(f"  error: {info.get('error', 'none')}")

asyncio.run(test())
