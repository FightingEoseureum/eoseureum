"""sqlmap '확인하면 멈춤' 게이팅 회귀 테스트.

DB 목록 열거(--dbs)는 PROOF 실증 모드에서만. 기본은 injectable 확정 후 종료.
"""
import external_tools as et

_KEYS = ("SQLMAP_ENUM_DBS", "VALIDATION_PROFILE", "ALLOW_PROOF_MODE", "RCE_PROOF_MODE")


def _clear(mp):
    for k in _KEYS:
        mp.delenv(k, raising=False)


def test_enum_dbs_off_by_default(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("SQLMAP_ENUM_DBS", "true")   # 플래그는 켰지만 PROOF 아님
    assert et._sqlmap_env()["enum_dbs"] is False


def test_enum_dbs_on_with_proof_profile(monkeypatch):
    # PROOF 는 2키 게이트(VALIDATION_PROFILE=PROOF + ALLOW_PROOF_MODE) — 다른 게이트와 일관.
    _clear(monkeypatch)
    monkeypatch.setenv("SQLMAP_ENUM_DBS", "true")
    monkeypatch.setenv("VALIDATION_PROFILE", "PROOF")
    monkeypatch.setenv("ALLOW_PROOF_MODE", "true")
    assert et._sqlmap_env()["enum_dbs"] is True


def test_enum_dbs_off_when_proof_requested_but_not_allowed(monkeypatch):
    # VALIDATION_PROFILE=PROOF 만이면 ADVANCED 로 강등 → sqlmap 도 다른 게이트와 동일하게 --dbs 안 함.
    # (그동안 sqlmap 만 raw env 를 봐서 PROOF 로 오작동하던 불일치 해소)
    _clear(monkeypatch)
    monkeypatch.setenv("SQLMAP_ENUM_DBS", "true")
    monkeypatch.setenv("VALIDATION_PROFILE", "PROOF")   # ALLOW_PROOF_MODE 없음 → 강등
    assert et._sqlmap_env()["enum_dbs"] is False


def test_enum_dbs_on_with_allow_proof(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("SQLMAP_ENUM_DBS", "true")
    monkeypatch.setenv("ALLOW_PROOF_MODE", "true")
    assert et._sqlmap_env()["enum_dbs"] is True


def test_enum_dbs_off_when_flag_off_even_in_proof(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("VALIDATION_PROFILE", "PROOF")   # PROOF 지만 SQLMAP_ENUM_DBS 미설정
    assert et._sqlmap_env()["enum_dbs"] is False


def test_build_cmd_dbs_gated_by_cfg():
    cfg = {"path": "sqlmap", "level": 2, "risk": 1, "timeout": 180, "technique": "",
           "random_agent": False, "tamper": "", "enum_dbs": False, "retry_on_no_injectable": False}
    cmd = et._build_sqlmap_cmd("sqlmap", "http://t/?id=1", cfg, "/tmp",
                               level=2, risk=1, technique="", random_agent=False, tamper="")
    assert "--dbs" not in cmd
    cmd2 = et._build_sqlmap_cmd("sqlmap", "http://t/?id=1", {**cfg, "enum_dbs": True}, "/tmp",
                                level=2, risk=1, technique="", random_agent=False, tamper="")
    assert "--dbs" in cmd2
