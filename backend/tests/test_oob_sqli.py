"""P3: OOB blind SQLi 프로브 — 콜백 히트 시 확증, 콜라보레이터 없으면 no-op."""
import asyncio

import active_probing as ap
import rule_engine as re_mod


def _run(c):
    return asyncio.run(c)


def test_sqli_oob_registered_in_contract():
    assert "sqli_oob" in re_mod._ACTIVE_PROBE_TEMPLATES
    assert re_mod._OWASP_MAPPING.get("sqli_oob") == "A03:2021 - 인젝션"


def test_sqli_oob_noop_without_collaborator(monkeypatch):
    import oob_collaborator as oob
    monkeypatch.setattr(oob, "get_collaborator", lambda sid: None)
    pts = [{"method": "GET", "url": "http://t/x", "params": {"id": "1"}}]
    assert _run(ap._probe_sqli_oob(None, pts, scan_id="s")) is None


def test_sqli_oob_confirms_on_callback(monkeypatch):
    # 가짜 콜라보레이터: 첫 토큰이 히트했다고 응답 → 확증
    class _Collab:
        def __init__(self):
            self._t = []
        def new_token(self):
            t = f"tok{len(self._t)}"; self._t.append(t); return t
        def host_for(self, t):
            return f"127.0.0.1:9/{t}"
        def was_hit(self, t):
            return t == "tok0"   # 첫 주입점 콜백 성공
    import oob_collaborator as oob
    monkeypatch.setattr(oob, "get_collaborator", lambda sid: _Collab())

    async def fake_get(session, url, **kw):
        return 200, "", {}
    monkeypatch.setattr(ap, "_get", fake_get)
    pts = [{"method": "GET", "url": "http://t/x", "params": {"id": "1"}}]
    r = _run(ap._probe_sqli_oob(None, pts, scan_id="s"))
    assert r and r["confirmed"] is True and r["oob_hit"] is True
    assert r["type"] == "sql_injection" and "out-of-band" in r["injection_types"]
