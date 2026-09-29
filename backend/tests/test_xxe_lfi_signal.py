"""XXE discovery-driven + LFI POST 지원(P3-#8) 회귀 테스트."""
import asyncio
import active_probing as ap


def _run(coro):
    return asyncio.run(coro)


def test_xxe_targets_include_discovered_points(monkeypatch):
    """_probe_xxe 가 고정 경로뿐 아니라 발견된 입력점 URL 도 대상에 포함하는지."""
    posted = []

    async def _fake_post(session, url, data=None, json=None, headers=None, timeout=8.0):
        posted.append(url)
        return 200, "", {}

    monkeypatch.setattr(ap, "_post", _fake_post)
    points = [{"method": "POST", "url": "http://t/deep/xmlapi", "params": {"x": "1"},
               "source": "discovered_form"}]
    _run(ap._probe_xxe(None, "http://t", points))
    assert any("/deep/xmlapi" in u for u in posted), "발견 엔드포인트가 XXE 대상에 포함돼야 함"
    assert any("/soap" in u for u in posted)  # 기존 고정 경로도 유지


def test_lfi_uses_post_for_post_points(monkeypatch):
    """POST 입력점이면 LFI 가 _post 로 요청하는지(예전 GET 전용 → POST 미검사 보정)."""
    calls = {"get": [], "post": []}

    async def _fake_get(session, url, headers=None, timeout=8.0):
        calls["get"].append(url); return 200, "", {}

    async def _fake_post(session, url, data=None, json=None, headers=None, timeout=8.0):
        calls["post"].append(url); return 200, "", {}

    monkeypatch.setattr(ap, "_get", _fake_get)
    monkeypatch.setattr(ap, "_post", _fake_post)
    points = [{"method": "POST", "url": "http://t/upload",
               "params": {"file": "x"}, "source": "form"}]
    _run(ap._probe_lfi(None, points, scan_id=""))
    assert calls["post"], "POST 입력점은 _post 로 LFI 점검돼야 함"
    assert all("/upload" in u for u in calls["post"])
