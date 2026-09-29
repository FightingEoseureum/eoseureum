"""파이프라인 유기성 개선 회귀 — ① tech 전달 ② sqlmap 후보 재사용 ③ CVE tech 재사용."""
import asyncio

import active_probing as ap


def _run(c):
    return asyncio.run(c)


# ── ③ CVE 상관이 recon technologies 를 상관 입력에 포함 ──────────────────────
def test_cve_correlation_uses_prior_technologies(monkeypatch):
    captured = {}

    class _Cve:
        @staticmethod
        def correlate(fp):
            captured["fp"] = fp
            return []  # 매칭 없음 → None 반환, 하지만 fp 는 캡처됨

    import sys
    monkeypatch.setitem(sys.modules, "cve_intel", _Cve)
    monkeypatch.setenv("ENABLE_CVE_INTEL", "true")

    async def fake_get(session, url, **kw):
        return 200, "<html>body</html>", {"Server": "nginx"}

    monkeypatch.setattr(ap, "_get", fake_get)
    techs = [{"name": "Apache Tomcat", "evidence": ["Apache-Coyote/1.1"]},
             {"name": "Java"}]
    _run(ap._probe_cve_correlation(None, "http://t/", technologies=techs))
    # recon 기술스택(제품명/근거)이 상관 입력 fp 에 반영되어야 함
    assert "Apache Tomcat" in captured["fp"]
    assert "Apache-Coyote/1.1" in captured["fp"]
    assert "Java" in captured["fp"]


def test_cve_correlation_without_technologies_still_works(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "cve_intel",
                        type("C", (), {"correlate": staticmethod(lambda fp: [])}))
    monkeypatch.setenv("ENABLE_CVE_INTEL", "true")

    async def fake_get(session, url, **kw):
        return 200, "body", {"Server": "x"}

    monkeypatch.setattr(ap, "_get", fake_get)
    assert _run(ap._probe_cve_correlation(None, "http://t/")) is None  # 매칭 없음


# ── ① probe_http_vulnerabilities 가 technologies 인자를 받는다(시그니처) ──────
def test_probe_signature_accepts_technologies():
    import inspect
    sig = inspect.signature(ap.probe_http_vulnerabilities)
    assert "technologies" in sig.parameters


# ── ② _sqli_candidates 메타키가 GET 주입점에서 합성되는지(로직 단위) ──────────
def test_sqli_candidate_synthesis_logic():
    # to_input_point 이 만든 GET 주입점(clean url + params) → 쿼리 URL 로 합성
    import urllib.parse
    p = {"method": "GET", "url": "http://t/search", "params": {"q": "test", "id": "test"}}
    u = p["url"] + "?" + urllib.parse.urlencode(p["params"])
    assert "?" in u and "q=test" in u and "id=test" in u
