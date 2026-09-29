"""test_policies_templates.py — 정책 및 템플릿(스캔 정책/보고서 템플릿) 검증."""
import os, sys, importlib
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import database as db
import report


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "pt.db"))
    return db


@pytest.mark.asyncio
async def test_seed_policies_and_templates(temp_db):
    await temp_db.init_db()
    pols = await temp_db.list_policies()
    assert len(pols) == 4
    names = {p["name"] for p in pols}
    assert names == {"Safe", "Balance", "Critical", "Proof (승인)"}
    active = [p for p in pols if p["is_active"] == 1]
    assert len(active) == 1 and active[0]["name"] == "Balance"
    # Proof (승인): 병합 프로파일 — BEU(time-based 제외) + RCE 무해 실증, level 은 전역 env 상속(미지정)
    deep = next(p for p in pols if p["name"] == "Proof (승인)")
    assert deep["config"]["SQLMAP_TECHNIQUE"] == "BEU"
    assert deep["config"]["ENABLE_TIME_BASED_SQLI"] == "false"
    assert deep["config"]["RCE_PROOF_MODE"] == "true"
    assert "SQLMAP_LEVEL" not in deep["config"]
    tpls = await temp_db.list_templates()
    assert len(tpls) == 3
    default = [t for t in tpls if t["is_default"] == 1]
    assert len(default) == 1


@pytest.mark.asyncio
async def test_activate_policy_switches_active(temp_db):
    await temp_db.init_db()
    pols = await temp_db.list_policies()
    deep = next(p for p in pols if p["name"] == "Critical")
    await temp_db.set_active_policy(deep["id"])
    act = await temp_db.get_active_policy()
    assert act["name"] == "Critical"
    assert act["config"]["SQLMAP_ENUM_DBS"] == "true"
    # 활성은 1개만
    assert sum(p["is_active"] for p in await temp_db.list_policies()) == 1


@pytest.mark.asyncio
async def test_policy_config_only_allowed_keys(temp_db):
    await temp_db.init_db()
    p = await temp_db.create_policy("커스텀", "테스트", {
        "PROBE_PAYLOAD_LEVEL": "safe", "ENABLE_SQLMAP": "true",
        "EVIL_KEY": "rm -rf",  # 허용 목록 외 → 제거되어야
    })
    assert "EVIL_KEY" not in p["config"]
    assert p["config"]["PROBE_PAYLOAD_LEVEL"] == "safe"


@pytest.mark.asyncio
async def test_template_set_default_and_options(temp_db):
    await temp_db.init_db()
    tpls = await temp_db.list_templates()
    execu = next(t for t in tpls if t["name"] == "경영진 요약형")
    await temp_db.set_default_template(execu["id"])
    d = await temp_db.get_default_template()
    assert d["name"] == "경영진 요약형"
    assert d["options"]["show_coverage"] is False
    assert d["options"]["show_service_scan"] is False


def test_apply_policy_env_and_template_env(monkeypatch):
    import main
    monkeypatch.delenv("ENABLE_SQLMAP", raising=False)
    main._apply_policy_env({"ENABLE_SQLMAP": "true", "PROBE_PAYLOAD_LEVEL": "aggressive",
                            "EVIL": "x"})
    assert os.environ["ENABLE_SQLMAP"] == "true"
    assert os.environ["PROBE_PAYLOAD_LEVEL"] == "aggressive"
    assert "EVIL" not in os.environ  # 허용 키만 적용
    env = main._template_env({"org_name": "테스트팀", "show_coverage": False, "show_ai": True})
    assert env["REPORT_ORG_NAME"] == "테스트팀"
    assert env["REPORT_SHOW_COVERAGE"] == "false"
    assert env["REPORT_SHOW_AI"] == "true"


def test_report_gates_honor_env(monkeypatch):
    monkeypatch.setenv("REPORT_SHOW_COVERAGE", "false")
    assert report._report_show("COVERAGE") is False
    monkeypatch.setenv("REPORT_SHOW_SERVICE_SCAN", "true")
    assert report._report_show("SERVICE_SCAN") is True
    monkeypatch.setenv("REPORT_ORG_NAME", "정보보호팀X")
    assert report._report_org_name() == "정보보호팀X"
    monkeypatch.delenv("REPORT_ORG_NAME", raising=False)
    assert report._report_org_name() == "Eoseureum Security"
