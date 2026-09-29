import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import asyncio
from scanner import scan_port

TARGETS = [
    ("demo.testfire.net",      [80, 443]),
    ("testasp.vulnweb.com",    [80, 443]),
    ("zero.webappsecurity.com",[80, 443]),
    ("scanme.nmap.org",        [80, 443, 22]),
]

async def main():
    for host, ports in TARGETS:
        print(f"\n{host}:")
        for port in ports:
            ok = await scan_port(host, port, timeout=6.0)
            print(f"  :{port} -> {'OPEN' if ok else 'closed'}")

asyncio.run(main())
