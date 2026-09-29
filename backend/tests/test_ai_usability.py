"""AI 사용성 확장(Phase 2~4) 회귀 테스트 — 안전 가드레일 중심(네트워크/LLM 불필요).

- PoC AI 생성 안전 검증기(파괴적 코드 거부)
- 크롤 AI 제안 경로 sanitize(외부 URL/쿼리/비경로 차단)
- 동기 ai_fn 브리지 예산/미가용 계약
"""
import os
import poc_generator as pg
import ai_crawl_assist as aca
import ai_provider as ap


# ── PoC AI 생성 안전 검증기 ─────────────────────────────────────────────────────
def test_poc_safety_validator():
    assert pg._is_safe_poc("import requests\nrequests.get(URL)") is True
    # 파괴적/셸/파일쓰기/코드실행 거부
    for bad in ("import os\nos.system('rm -rf /')",
                "import requests\ncur.execute('DROP TABLE users')",
                "import requests\ncur.execute('DELETE FROM users')",
                "import subprocess\nsubprocess.run(['x'])",
                "import requests\nopen('/etc/x','w')",
                "eval('1')"):
        assert pg._is_safe_poc(bad) is False, bad
    # requests 없으면 거부(임의 시스템 조작 방지)
    assert pg._is_safe_poc("print(1)") is False


def test_generate_ai_poc_safe_vs_destructive():
    f = {"type": "xss_reflected", "url": "http://t/s", "param": "q", "payload": "<x>",
         "evidence": "reflected", "judgment": "취약", "confidence": "CONFIRMED"}
    safe = pg.generate_ai_poc(f, lambda p: "```python\nimport requests\nr=requests.get('http://t/s', params={'q':'<x>'})\nprint(r.status_code)\n```")
    assert safe and "requests" in safe and "AI(qwen) 생성" in safe
    # 파괴적 코드 → None (결정적 PoC 만 유지)
    assert pg.generate_ai_poc(f, lambda p: "import os\nos.system('rm -rf /')") is None
    # ai_fn 없으면 None
    assert pg.generate_ai_poc(f, None) is None


def test_attach_pocs_keeps_deterministic_and_adds_ai():
    analysis = {"findings": [
        {"type": "xss_reflected", "url": "http://t/s", "param": "q", "payload": "<x>",
         "evidence": "reflected", "judgment": "취약", "confidence": "CONFIRMED"},
    ]}
    n = pg.attach_pocs(analysis, ai_fn=lambda p: "```python\nimport requests\nrequests.get('http://t/s')\n```")
    f = analysis["findings"][0]
    assert n == 1
    assert f.get("poc")          # 결정적(간결) PoC 부착됨
    assert f.get("poc_ai") and "AI(qwen) 생성" in f["poc_ai"]  # AI PoC 추가


# ── 크롤 AI 제안 경로 sanitize ──────────────────────────────────────────────────
def test_crawl_path_sanitize():
    raw = ["/admin", "http://evil.com/x", "//cdn/x", "/api/v1/users?x=1",
           "/admin", "not-a-path", "/a b", "/valid_path-1.json"]
    out = aca._sanitize_paths(raw, known={"/known"}, cap=20)
    assert "/admin" in out and "/api/v1/users" in out and "/valid_path-1.json" in out
    assert all(p.startswith("/") and "://" not in p and "?" not in p for p in out)
    assert "not-a-path" not in out and "/a b" not in out and "/known" not in out


def test_crawl_exclude_blocks_link_following():
    """링크추적/큐 등록이 사용자 제외(부분일치)를 건드리지 않는지 — url_discovery 하드가드."""
    import types
    import url_discovery as ud
    eng = ud.URLDiscoveryEngine(max_urls=100, max_depth=2)
    eng._exclude_patterns = ["/admin", "/logout"]
    eng._base_url = "http://t"
    # _is_excluded: 제외 범위 True, 그 외 False, base 는 항상 False
    assert eng._is_excluded("http://t/admin/del") is True
    assert eng._is_excluded("http://t/logout") is True
    assert eng._is_excluded("http://t/api/users") is False
    assert eng._is_excluded("http://t") is False
    # _add_url: 제외 URL 은 큐/결과에 안 들어감(→ 크롤 안 됨)
    eng._queued = set()
    eng._result = types.SimpleNamespace(urls=[])
    eng._base_host = "t"
    eng.same_origin_only = False
    assert eng._add_url("http://t/admin/del", "html_link", 1) is False
    assert eng._add_url("http://t/ok", "html_link", 1) is True


def test_crawl_assist_disabled_returns_empty(monkeypatch):
    monkeypatch.delenv("ENABLE_AI_CRAWL_ASSIST", raising=False)
    assert aca.crawl_assist_enabled() is False
    import asyncio
    assert asyncio.run(aca.suggest_crawl_paths("http://t/", known_paths=["/a"])) == []


# ── 동기 ai_fn 브리지 ───────────────────────────────────────────────────────────
def test_sync_ai_fn_none_when_provider_none(monkeypatch):
    monkeypatch.setattr(ap, "get_ai_provider", lambda: ap.NoneProvider())
    assert ap.make_sync_ai_fn() is None


def test_sync_ai_fn_budget(monkeypatch):
    calls = {"n": 0}

    class _FakeProvider:            # NoneProvider 상속 금지(그러면 미가용으로 판정됨)
        @property
        def name(self):
            return "fake"

        async def complete(self, prompt):
            calls["n"] += 1
            return "ok"

    monkeypatch.setattr(ap, "get_ai_provider", lambda: _FakeProvider())
    fn = ap.make_sync_ai_fn(max_calls=2)
    assert fn is not None
    assert fn("a") == "ok" and fn("b") == "ok"   # 예산 내
    assert fn("c") == ""                           # 예산 소진 → 백스톱
    assert calls["n"] == 2                          # 초과분은 실제 호출 안 함
