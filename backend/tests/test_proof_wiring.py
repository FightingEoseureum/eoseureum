"""P1: PROOF 프로파일이 실제 스캐너 깊이 게이트를 자동 활성하는지 회귀."""
import importlib

import validation_profiles as vp


def _reset_env(mp):
    for k in ("VALIDATION_PROFILE", "ALLOW_PROOF_MODE", "ENABLE_OOB",
              "ENABLE_TIME_BASED_SQLI", "SQLMAP_ENUM_DBS", "ALLOW_ADVANCED_VALIDATION",
              "SQLMAP_LEVEL", "SQLMAP_RISK"):
        mp.delenv(k, raising=False)


def test_proof_active_gate(monkeypatch):
    _reset_env(monkeypatch)
    assert vp.proof_active() is False                       # 기본 SAFE
    monkeypatch.setenv("ALLOW_PROOF_MODE", "true")
    assert vp.proof_active() is True                        # 명시 승인
    monkeypatch.delenv("ALLOW_PROOF_MODE")
    monkeypatch.setenv("VALIDATION_PROFILE", "PROOF")
    monkeypatch.setenv("ALLOW_PROOF_MODE", "true")
    assert vp.proof_active() is True                        # PROOF + 승인


def test_proof_requires_approval(monkeypatch):
    _reset_env(monkeypatch)
    monkeypatch.setenv("VALIDATION_PROFILE", "PROOF")       # 승인 없으면 ADVANCED 로 강등
    assert vp.proof_active() is False


def test_oob_auto_enabled_in_proof(monkeypatch):
    _reset_env(monkeypatch)
    import oob_collaborator as oob
    assert oob.oob_enabled() is False                       # 기본 off
    monkeypatch.setenv("ALLOW_PROOF_MODE", "true")
    assert oob.oob_enabled() is True                        # PROOF → OOB 자동 활성


def test_time_based_auto_enabled_in_proof(monkeypatch):
    _reset_env(monkeypatch)
    import payload_validator as pv
    assert pv._time_based_enabled() is False
    monkeypatch.setenv("ALLOW_PROOF_MODE", "true")
    assert pv._time_based_enabled() is True


def test_sqlmap_level_boosted_in_proof(monkeypatch):
    _reset_env(monkeypatch)
    import external_tools as et
    cfg = et._sqlmap_env()
    assert cfg["level"] == 2 and cfg["risk"] == 1           # 기본
    monkeypatch.setenv("ALLOW_PROOF_MODE", "true")
    cfg2 = et._sqlmap_env()
    assert cfg2["level"] == 3 and cfg2["risk"] == 2         # PROOF 심화
    assert cfg2["timeout"] == 300
