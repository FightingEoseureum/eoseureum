"""test_param_miner.py — 파라미터 마이닝(숨은 파라미터 발굴) 검증.
반사 기반 고정밀 탐지 · SAFE(GET). 새 판정 생성 없음."""
import os, sys, asyncio
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import param_miner as pm


def test_build_chunk_url_assigns_unique_canaries():
    url, canaries = pm.build_chunk_url("http://t/search", ["q", "id", "page"])
    assert set(canaries) == {"q", "id", "page"}
    # 각 파라미터가 서로 다른 카나리
    assert len(set(canaries.values())) == 3
    for name, c in canaries.items():
        assert f"{name}={c}" in url


def test_build_chunk_url_skips_existing_param():
    url, canaries = pm.build_chunk_url("http://t/p?q=hello", ["q", "id"])
    assert "q" not in canaries and "id" in canaries   # 기존 q 는 발굴 대상 아님


def test_reflected_params_detects_echo():
    canaries = {"q": "eoszx0", "id": "eoszx1", "page": "eoszx2"}
    body = "<html>results for eoszx0 ... user eoszx1 not found</html>"
    got = set(pm.reflected_params(body, canaries))
    assert got == {"q", "id"}          # page 는 반사 안 됨


def _run(coro):
    return asyncio.run(coro)


def test_mine_finds_reflected_params_only():
    # 가짜 fetch: 'q'와 'id' 카나리만 반사하는 서버
    async def fake_fetch(u):
        body = ""
        import urllib.parse as up
        qs = up.parse_qs(up.urlparse(u).query)
        for name in ("q", "id"):
            for c in qs.get(name, []):
                if c.startswith(pm._CANARY):
                    body += f" echo:{c} "
        return 200, body

    res = _run(pm.mine(fake_fetch, "http://t/search", chunk_size=10, max_params=40))
    assert "q" in res["discovered"] and "id" in res["discovered"]
    assert "page" not in res["discovered"]        # 반사 안 되면 미채택(고정밀)
    assert res["requests"] >= 2                    # 베이스라인 + 최소 1청크


def test_to_input_point_format():
    ip = pm.to_input_point("http://t/search?a=1", ["q", "id"])
    assert ip["method"] == "GET" and ip["source"] == "param_mining"
    assert "q" in ip["params"] and "id" in ip["params"] and ip["params"]["a"] == "1"
    assert pm.to_input_point("http://t/x", []) is None
