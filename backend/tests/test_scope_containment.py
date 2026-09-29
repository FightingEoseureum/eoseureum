"""스코프 봉쇄 회귀 — 명시 포트 지정 시 그 포트만 스캔(같은 호스트의 다른 서비스 미점검)."""
import asyncio

import scanner


def _run(c):
    return asyncio.run(c)


def _patch_scan_port(monkeypatch, open_ports):
    checked = []

    async def fake_scan_port(ip, port):
        checked.append(port)
        return port in open_ports

    monkeypatch.setattr(scanner, "scan_port", fake_scan_port)
    # 서비스 상세/HTTP 탐지는 스코프 검증과 무관 → 무해화
    async def fake_detail(ip, port, **kw):
        return {"port": port, "service": "HTTP"}
    if hasattr(scanner, "_probe_service"):
        monkeypatch.setattr(scanner, "_probe_service", fake_detail, raising=False)
    return checked


def test_explicit_port_scans_only_that_port(monkeypatch):
    # 3000 지정 + 호스트에 8080 도 열려있음 → 8080 은 절대 점검되면 안 됨
    checked = _patch_scan_port(monkeypatch, open_ports={3000, 8080, 80, 443})
    _run(scanner.scan_host("127.0.0.1", "127.0.0.1",
                           extra_ports=[3000], force_http_ports=[3000],
                           only_ports=[3000]))
    assert 3000 in checked
    assert 8080 not in checked, f"스코프 유출! 점검된 포트: {sorted(checked)}"
    assert 80 not in checked and 443 not in checked
    assert set(checked) == {3000}


def test_no_explicit_port_scans_default_set(monkeypatch):
    # 명시 포트 없음(바레 호스트) → 기본 HIGH_RISK 포트 탐색은 유지
    checked = _patch_scan_port(monkeypatch, open_ports={80})
    _run(scanner.scan_host("example.com", "1.2.3.4"))
    assert 80 in checked and 8080 in checked   # 기본 포트목록 스캔
    assert len(checked) > 5
