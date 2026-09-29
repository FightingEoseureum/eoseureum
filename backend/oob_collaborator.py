"""
oob_collaborator.py — Out-of-Band(OOB) 콜백 컬래보레이터.

블라인드 취약점(SSRF·blind XXE·OOB 커맨드 인젝션)은 응답 본문만으로 확증할 수 없다.
유니크 토큰이 박힌 콜백 URL 을 페이로드에 심고, 대상 서버가 그 URL 로 요청을 보내오면
(= 서버측에서 우리 리스너에 도달) 100% 실증된다(오탐 0). 이 모듈은 스캔별 공유 HTTP
리스너를 띄우고 토큰 히트를 기록한다.

기본 비활성(ENABLE_OOB=false). 활성 시:
  - EOSEUREUM_OOB_HOST: 대상이 스캐너에 도달할 수 있는 주소(광고용). 기본 127.0.0.1
    (대상이 같은 호스트/네트워크에 있을 때). 원격 대상은 스캐너의 라우팅 가능 IP 를 지정.
  - 리스너는 0.0.0.0:임의포트 로 바인딩(대상 네트워크에서 도달 가능하도록).

주의(권한): OOB 콜백은 대상이 외부(스캐너)로 요청을 보내게 한다. 반드시 고객 승인 범위
안에서만 사용하고, 광고 호스트/포트가 스코프 밖 제3자를 향하지 않도록 관리한다.
"""
from __future__ import annotations

import asyncio
import os
import secrets

try:
    from aiohttp import web
except Exception:  # pragma: no cover
    web = None


def oob_enabled() -> bool:
    if os.getenv("ENABLE_OOB", "false").strip().lower() in ("1", "true", "yes", "on"):
        return True
    # PROOF 모드는 OOB 확증을 자동 활성(깊고 정확한 blind 실증). 실패 시 안전 폴백.
    try:
        import validation_profiles as _vp
        return _vp.proof_active()
    except Exception:
        return False


def _advertise_host() -> str:
    return (os.getenv("EOSEUREUM_OOB_HOST", "").strip() or "127.0.0.1")


class OOBCollaborator:
    """스캔 1개에 대응하는 공유 콜백 리스너 + 토큰 히트 기록."""

    def __init__(self, advertise_host: str):
        self.advertise_host = advertise_host
        self._hits: dict[str, dict] = {}   # token -> {"method","path","ua"}
        self._runner = None
        self.port: int | None = None
        # 토큰별 raw-TCP 캐처(JNDI/LDAP·역직렬화 등 비-HTTP 콜백 확증용)
        self._raw_servers: dict[str, asyncio.AbstractServer] = {}
        self._raw_hits: dict[str, dict] = {}   # token -> {"peer","preview"}

    async def start(self) -> bool:
        if web is None:
            return False

        async def _handle(request):
            # 경로 첫 세그먼트를 토큰으로 사용: /<token>[/...]
            seg = request.path.strip("/").split("/", 1)[0]
            if seg:
                self._hits.setdefault(seg, {
                    "method": request.method,
                    "path": request.path,
                    "ua": request.headers.get("User-Agent", ""),
                })
            return web.Response(text="ok")

        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", _handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        # 대상 네트워크에서 도달 가능하도록 0.0.0.0 바인딩, 임의 포트.
        site = web.TCPSite(self._runner, "0.0.0.0", 0)
        await site.start()
        try:
            self.port = site._server.sockets[0].getsockname()[1]
        except Exception:
            self.port = None
        return self.port is not None

    def new_token(self) -> str:
        return secrets.token_hex(8)

    async def new_raw_endpoint(self) -> tuple[str, str] | None:
        """토큰별 raw-TCP 리스너를 띄운다. 반환 (token, "host:port").

        해당 포트로 JNDI/LDAP 등 '프로토콜 데이터를 실제 전송'하는 연결이 오면 히트로 기록한다.
        포트=토큰 정체성으로 정확 상관. 오탐 억제: '바이트를 보내지 않는 단순 TCP connect'
        (포트스캐너·로드밸런서 헬스체크 등)는 히트로 세지 않는다 — 실 JNDI 클라이언트는 LDAP
        bind PDU 를 즉시 전송하므로 데이터가 있다. 실패 시 None.
        """
        token = secrets.token_hex(8)

        async def _raw_handle(reader, writer):
            try:
                peer = writer.get_extra_info("peername")
                data = b""
                try:
                    data = await asyncio.wait_for(reader.read(512), timeout=2.0)
                except Exception:
                    pass
                # 데이터를 실제로 전송한 연결만 히트(바이트 0 = 단순 connect → 무시, 오탐 방지)
                if data:
                    self._raw_hits.setdefault(token, {
                        "peer": str(peer), "preview": data[:64].hex(),
                    })
                    self._hits.setdefault(token, {"method": "RAW", "path": "/raw", "ua": ""})
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        try:
            server = await asyncio.start_server(_raw_handle, "0.0.0.0", 0)
            port = server.sockets[0].getsockname()[1]
        except Exception:
            return None
        self._raw_servers[token] = server
        return token, f"{self.advertise_host}:{port}"

    def url_for(self, token: str) -> str:
        return f"http://{self.advertise_host}:{self.port}/{token}"

    def host_for(self, token: str) -> str:
        """DNS/HTTP 페이로드에 넣을 host:port 형태(스킴 없이)."""
        return f"{self.advertise_host}:{self.port}/{token}"

    def was_hit(self, token: str) -> bool:
        return token in self._hits

    def hit_detail(self, token: str) -> dict | None:
        return self._hits.get(token)

    async def stop(self) -> None:
        if self._runner is not None:
            try:
                await self._runner.cleanup()
            except Exception:
                pass
            self._runner = None
        for _srv in list(self._raw_servers.values()):
            try:
                _srv.close()
                await _srv.wait_closed()
            except Exception:
                pass
        self._raw_servers.clear()


# ── 스캔별 컬래보레이터 레지스트리 ────────────────────────────────────────────────
_COLLABORATORS: dict[str, OOBCollaborator] = {}


async def start_collaborator(scan_id: str) -> OOBCollaborator | None:
    """스캔용 컬래보레이터를 시작(ENABLE_OOB 시). 이미 있으면 재사용. 실패 시 None."""
    if not oob_enabled():
        return None
    key = str(scan_id)
    if key in _COLLABORATORS:
        return _COLLABORATORS[key]
    c = OOBCollaborator(_advertise_host())
    ok = await c.start()
    if not ok:
        return None
    _COLLABORATORS[key] = c
    return c


def get_collaborator(scan_id: str) -> OOBCollaborator | None:
    return _COLLABORATORS.get(str(scan_id))


async def stop_collaborator(scan_id: str) -> None:
    c = _COLLABORATORS.pop(str(scan_id), None)
    if c is not None:
        await c.stop()
