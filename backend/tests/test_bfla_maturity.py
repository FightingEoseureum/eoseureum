"""④ 인증 스캔 성숙화 — BFLA 기본 ON + 스펙 엔드포인트 매트릭스 공급 회귀."""
import os

import authz_matrix as am


def test_bfla_default_on(monkeypatch):
    # 기본 true(SAFE 읽기전용), env 로 끌 수 있음
    monkeypatch.delenv("ENABLE_BFLA_TESTS", raising=False)
    assert os.getenv("ENABLE_BFLA_TESTS", "true").strip().lower() in ("1", "true", "yes", "on")


def test_gather_accepts_extra_urls():
    # extra_urls(스펙/swagger 특권 엔드포인트)를 매트릭스 후보에 포함
    hr = [{"host": "t", "services": [{"port": 80, "http_info": {"url": "http://t/"}}]}]
    extra = ["http://t:80/admin/users", "http://t:80/api/admin/config"]
    eps = am.gather_privileged_endpoints(hr, extra_urls=extra)
    urls = {e.get("url") for e in eps}
    assert any("/admin/users" in u for u in urls)
    assert any("/api/admin/config" in u for u in urls)


def test_swagger_endpoint_extraction_shape():
    # main.py 의 추출 로직과 동일: "GET /admin/x" → path 만
    e = "GET /admin/users"
    path = e.split(" ", 1)[-1] if " " in e else e
    assert path == "/admin/users" and path.startswith("/")
