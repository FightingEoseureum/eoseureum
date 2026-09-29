"""P6: JNDI/Log4Shell OOB 실증 — raw-TCP 캐처 콜백 시 확증, 콜백 없으면 미보고(오탐 0)."""
import asyncio

import active_probing as ap
import rule_engine as re_mod
import oob_collaborator as oob


def _run(c):
    return asyncio.run(c)


def test_jndi_registered_in_contract():
    assert "jndi" in re_mod._ACTIVE_PROBE_TEMPLATES
    assert re_mod._OWASP_MAPPING.get("jndi") == "A03:2021 - 인젝션"


def test_jndi_payloads_shell_free():
    for pl in ap._jndi_payloads("127.0.0.1:9"):
        low = pl.lower()
        for bad in ("/bin/sh", "popen", "curl ", "wget ", "cmd.exe", "powershell"):
            assert bad not in low
        # host 는 항상 삽입되고, ndi 룩업 흔적이 있어야 함(난독화 변형은 'jndi:' 리터럴을 깨뜨림)
        assert "127.0.0.1:9" in pl and "ndi" in low


def test_raw_catcher_records_tcp_connection():
    """raw 엔드포인트로 TCP 연결하면 was_hit 이 True 가 된다(포트=토큰 상관)."""
    async def t():
        c = oob.OOBCollaborator("127.0.0.1")
        ep = await c.new_raw_endpoint()
        assert ep
        token, hostport = ep
        host, port = hostport.split(":")
        assert c.was_hit(token) is False
        # TCP 연결만 열었다 닫는다(LDAP JVM 흉내)
        reader, writer = await asyncio.open_connection(host, int(port))
        writer.write(b"\x30\x0c\x02\x01\x01")  # 임의 LDAP 유사 바이트
        await writer.drain()
        writer.close()
        await asyncio.sleep(0.3)
        hit = c.was_hit(token)
        await c.stop()
        return hit
    assert _run(t()) is True


def test_jndi_noop_without_collaborator(monkeypatch):
    monkeypatch.setattr(oob, "get_collaborator", lambda sid: None)
    pts = [{"method": "GET", "url": "http://t/x", "params": {"id": "1"}}]
    assert _run(ap._probe_jndi(None, "http://t/", pts, scan_id="s")) is None


def test_jndi_confirms_on_real_callback(monkeypatch):
    """실 콜라보레이터 raw 캐처 + 대상 서버가 JNDI 페이로드를 보고 raw 포트로 연결 → 확증."""
    async def t():
        collab = oob.OOBCollaborator("127.0.0.1")
        # HTTP 리스너도 시작(base_url GET 을 받기 위해 실제 필요치 않음 — _get 은 실패해도 무방)
        monkeypatch.setattr(oob, "get_collaborator", lambda sid: collab)

        # 대상 서버 흉내: _get/_post 를 가로채, 페이로드에서 raw host:port 를 추출해 그 포트로 연결
        import re as _re

        async def _connect_back(payload_blob: str):
            m = _re.search(r"ldap://([\d.]+):(\d+)/", payload_blob) or \
                _re.search(r"rmi://([\d.]+):(\d+)/", payload_blob)
            if not m:
                return
            try:
                r, w = await asyncio.open_connection(m.group(1), int(m.group(2)))
                w.write(b"\x30\x0c")
                await w.drain(); w.close()
            except Exception:
                pass

        async def fake_get(session, url, headers=None, **kw):
            blob = " ".join((headers or {}).values()) + " " + url
            await _connect_back(blob)
            return 200, "", {}

        async def fake_post(session, url, data=None, **kw):
            blob = " ".join(str(v) for v in (data or {}).values())
            await _connect_back(blob)
            return 200, "", {}

        monkeypatch.setattr(ap, "_get", fake_get)
        monkeypatch.setattr(ap, "_post", fake_post)
        pts = [{"method": "GET", "url": "http://t/x", "params": {"id": "1"}}]
        try:
            return await ap._probe_jndi(None, "http://t/", pts, scan_id="s")
        finally:
            await collab.stop()

    r = _run(t())
    assert r and r["confirmed"] is True and r["oob_hit"] is True
    assert r["type"] == "jndi_injection"


def test_rule_engine_jndi_finding_critical():
    probes = {"jndi": {
        "type": "jndi_injection", "confirmed": True, "oob_hit": True,
        "vector": "header", "url": "http://t/", "affected_endpoints": ["http://t/"],
        "evidence": "JNDI 실증",
    }}
    out = re_mod._build_active_probe_findings("t", 80, "http", probes, set())
    assert len(out) == 1
    assert out[0]["severity"] == "CRITICAL"
    assert "CVE-2021-44228" in out[0]["cve_references"]


def test_rule_engine_jndi_without_oob_dropped():
    """oob_hit 없으면 concrete evidence 아님 → finding 미생성(오탐 0)."""
    probes = {"jndi": {"type": "jndi_injection", "confirmed": True, "url": "http://t/"}}
    out = re_mod._build_active_probe_findings("t", 80, "http", probes, set())
    assert out == []
