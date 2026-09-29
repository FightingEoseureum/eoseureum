"""test_sqlmap_integration.py — SQLMap 최종 검증 통합 검증(네트워크/서브프로세스 없음)."""
import os, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import external_tools as et


@pytest.mark.asyncio
async def test_sqlmap_disabled_no_failure(monkeypatch):
    # ENABLE_SQLMAP 미설정 → 실행 안 함, 예외 없이 구조화 dict 반환(전체 스캔 실패 금지)
    monkeypatch.delenv("ENABLE_SQLMAP", raising=False)
    r = await et.run_sqlmap("http://t/p?id=1", "t", 80)
    assert r["tool"] == "sqlmap"
    assert r["enabled"] is False and r["executed"] is False
    assert r["error"] is None


@pytest.mark.asyncio
async def test_sqlmap_not_found_no_failure(monkeypatch):
    # 설치 안 됨 → SQLMAP_NOT_FOUND, 예외 없이 반환
    monkeypatch.setenv("ENABLE_SQLMAP", "true")
    monkeypatch.setattr(et, "_which", lambda n: None)
    r = await et.run_sqlmap("http://t/p?id=1", "t", 80)
    assert r["executed"] is False
    assert r["error"] == "SQLMAP_NOT_FOUND"
    assert r["injectable"] is False


def test_sqlmap_injectable_promotes_to_confirmed():
    sqlmap_res = {"executed": True, "injectable": True, "parameter": "uid",
                  "injection_types": ["boolean-based blind"], "dbms": "MySQL",
                  "payloads": ["uid=1 AND 1=1"], "databases": [], "command": "...", "error": None}
    f = et.build_sqli_finding("http://t/p?uid=1", "t", 80, None, sqlmap_res)
    assert f["sqli_grade"] == "CONFIRMED"
    assert f["confidence"] == "CONFIRMED"


def test_sqlmap_no_dbs_no_extraction_phrase():
    sqlmap_res = {"executed": True, "injectable": True, "parameter": "uid",
                  "injection_types": ["error-based"], "dbms": "MySQL",
                  "payloads": [], "databases": [], "command": "...", "error": None}
    f = et.build_sqli_finding("http://t/p?uid=1", "t", 80, None, sqlmap_res)
    assert "DB 목록 추출 성공" not in f["title"]
    assert "DB 목록 추출 성공" not in f["evidence_detail"]


def test_sqlmap_command_masks_secrets():
    # 마스킹: cookie/password 값이 명령 문자열에 평문 노출 금지
    masked = et._mask_command(["sqlmap", "-u", "http://t/login?password=secret123&id=1",
                               "--cookie=SESSION=abc123", "--batch"])
    assert "secret123" not in masked
    assert "abc123" not in masked
    assert "***" in masked
