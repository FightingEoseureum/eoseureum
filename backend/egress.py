"""
egress.py — 스캔 트래픽 단일 출구(i7) 관리.

목표: 어스름이 대상으로 내보내는 모든 스캔 패킷이 맥이 아니라 **i7 을 통해서만** 나가게 한다
      (사용자 지침: "패킷은 i7에서만 나간다" / 단일 출구).

기전: 맥에서 `ssh -D <port> i7` 로 동적 SOCKS5 터널을 띄운다. i7 무설치·암호화 터널이며
      실제 대상 연결은 SSH 서버(i7)에서 이뤄지므로 출발지가 i7 이 된다. DNS 는 socks5h 로
      원격(i7) 해석해 DNS 누출도 막는다.

안전 원칙(fail-closed): EGRESS_ENABLED=true 인데 터널이 없으면 **직접 송신으로 폴백하지 않는다**.
      (직접 폴백하면 맥 IP 로 패킷이 새어 단일출구 원칙이 깨진다.) 터널이 죽으면 스캔 요청은
      실패하고, ensure_tunnel() 이 재기동을 시도한다.

기본값 OFF: EGRESS_ENABLED 미설정/false 면 이 모듈은 no-op(기존과 100% 동일한 직접 연결).

제어 평면은 우회: AI(Ollama localhost)·워커 콜백·자기 자신 접속은 각자 별도 세션을 쓰며 이
      모듈을 거치지 않는다. 이 모듈은 '스캔 대상' 트래픽 커넥터에만 주입된다.
"""
from __future__ import annotations

import os
import socket
import subprocess
import time

import aiohttp


def enabled() -> bool:
    return os.getenv("EGRESS_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")


def _port() -> int:
    try:
        return int(os.getenv("EGRESS_SOCKS_PORT", "11080"))
    except (TypeError, ValueError):
        return 11080


def _ssh_host() -> str:
    # ~/.ssh/config 의 Host 별칭(기본 'i7') 또는 user@host.
    return os.getenv("EGRESS_SSH_HOST", "i7").strip()


def proxy_url() -> str | None:
    """스캔 커넥터용 SOCKS5 프록시 URL. 비활성 시 None.

    원격 DNS(DNS 누출 방지)는 aiohttp_socks 의 rdns=True 로 지정하므로 스킴은 socks5:// 를
    쓴다(python_socks 는 curl 식 socks5h:// 스킴을 파싱하지 못한다)."""
    if not enabled():
        return None
    return f"socks5://127.0.0.1:{_port()}"


def playwright_proxy() -> dict | None:
    """Playwright launch(proxy=) 용. 비활성 시 None. Playwright 는 SOCKS 원격 DNS 를 기본 처리."""
    if not enabled():
        return None
    return {"server": f"socks5://127.0.0.1:{_port()}"}


def _port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def tunnel_alive() -> bool:
    """SOCKS 로컬 엔드포인트가 살아 있는지(포트 응답)."""
    return _port_open("127.0.0.1", _port())


def ensure_tunnel(wait_sec: float = 6.0) -> bool:
    """SOCKS5 터널을 보장한다(idempotent). 이미 살아 있으면 True.

    없으면 `ssh -f -N -D 127.0.0.1:<port> <host>` 로 백그라운드 기동 후 포트가 열릴 때까지 대기.
    성공하면 True, 실패하면 False(호출부는 fail-closed 로 스캔 egress 를 막아야 한다)."""
    if not enabled():
        return False
    if tunnel_alive():
        return True
    port = _port()
    host = _ssh_host()
    # -f 백그라운드, -N 명령없음, -D 동적 SOCKS. 자동 재연결/헬스는 ServerAlive 로 최소 보강.
    cmd = [
        "ssh", "-f", "-N",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        "-o", "ConnectTimeout=8",
        "-D", f"127.0.0.1:{port}",
        host,
    ]
    try:
        subprocess.run(cmd, check=False, timeout=15,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return False
    # 포트가 열릴 때까지 대기
    deadline = time.monotonic() + wait_sec
    while time.monotonic() < deadline:
        if tunnel_alive():
            return True
        time.sleep(0.3)
    return False


def stop_tunnel() -> None:
    """기동한 SOCKS 터널을 정리(best-effort)."""
    port = _port()
    try:
        subprocess.run(["pkill", "-f", f"ssh -f -N.*-D 127.0.0.1:{port}"],
                       check=False, timeout=8,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def scan_connector(ssl_ctx=None, **kwargs) -> aiohttp.BaseConnector:
    """스캔 대상 트래픽용 aiohttp 커넥터.

    - EGRESS_ENABLED=true: i7 SOCKS5 를 경유하는 ProxyConnector(원격 DNS). 터널이 없으면
      기동 시도하고, 그래도 안 되면 **연결 불가 커넥터**를 반환하지 않고 예외 대신 여기서
      ProxyConnector 를 그대로 반환한다(요청 시점에 연결 실패 → fail-closed, 직접 누출 없음).
    - 비활성: 기존과 동일한 TCPConnector(직접 연결).

    ssl_ctx: SSL 컨텍스트(기존 _ssl_connector 의 verify 비활성 컨텍스트 등).
    kwargs: TCPConnector/ProxyConnector 공통 인자(limit 등) 전달용.
    """
    if enabled():
        ensure_tunnel()  # 없으면 기동 시도(실패해도 아래 ProxyConnector 는 연결 시점 실패 = fail-closed)
        from aiohttp_socks import ProxyConnector
        # rdns=True: 대상 도메인을 i7(SOCKS 서버)에서 원격 해석 → 맥에서 DNS 조회가 안 나감(누출 방지).
        return ProxyConnector.from_url(proxy_url(), rdns=True, ssl=ssl_ctx, **kwargs)
    return aiohttp.TCPConnector(ssl=ssl_ctx, **kwargs)
