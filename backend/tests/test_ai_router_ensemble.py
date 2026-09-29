"""역할→모델 라우터 + 오탐 앙상블 판정(advisory) — 설정 기반 다중 AI.

모델 호출(네트워크) 없이 순수 로직·설정·라우팅·게이팅을 검증한다.
"""
import json
import os

import ai_provider as ap


def _write_roles(tmp_path, data):
    p = tmp_path / "ai_roles.json"
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return str(p)


def _reset_cache():
    ap._ROLES_CACHE.update(mtime=0.0, data=None)


# ── 설정 로드 + 역할 라우팅 ──────────────────────────────────────────────────
def test_role_model_routing(monkeypatch, tmp_path):
    cfg = {"enabled": True, "fallback_model": "qwen2.5:7b",
           "roles": {"poc": {"model": "qwen2.5-coder:14b"},
                     "analysis": {"model": "qwen2.5:32b"}}}
    monkeypatch.setenv("AI_ROLES_CONFIG", _write_roles(tmp_path, cfg))
    monkeypatch.setattr(ap, "_ROLES_PATH", os.environ["AI_ROLES_CONFIG"])
    _reset_cache()
    assert ap.role_model("poc") == "qwen2.5-coder:14b"
    assert ap.role_model("analysis") == "qwen2.5:32b"
    assert ap.role_model("unknown_role") is None
    assert ap.role_model(None) is None


def test_role_routing_disabled_returns_none(monkeypatch, tmp_path):
    cfg = {"enabled": False, "roles": {"poc": {"model": "x"}}}
    monkeypatch.setattr(ap, "_ROLES_PATH", _write_roles(tmp_path, cfg))
    _reset_cache()
    assert ap.role_model("poc") is None      # 라우팅 off → 기본 모델 사용


def test_roles_config_reload_on_mtime(monkeypatch, tmp_path):
    path = _write_roles(tmp_path, {"enabled": True, "roles": {"poc": {"model": "a"}}})
    monkeypatch.setattr(ap, "_ROLES_PATH", path)
    _reset_cache()
    assert ap.role_model("poc") == "a"
    # 파일을 고치면(계속 업데이트) 다음 호출에 자동 반영
    import time
    time.sleep(0.01)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"enabled": True, "roles": {"poc": {"model": "b"}}}, f)
    os.utime(path, (os.path.getmtime(path) + 1, os.path.getmtime(path) + 1))
    assert ap.role_model("poc") == "b"


# ── 투표 파싱 + 집계(순수) ───────────────────────────────────────────────────
def test_parse_vote():
    assert ap._parse_vote("FP\n검증 오류로 오탐") == "fp"
    assert ap._parse_vote("REAL\n실제 SQL 에러 노출") == "real"
    assert ap._parse_vote("오탐입니다") == "fp"
    assert ap._parse_vote("잘 모르겠습니다") == "uncertain"
    assert ap._parse_vote("") == "uncertain"


def test_aggregate_votes_advisory():
    # 2/3 이상 FP → downgrade(삭제 아님)
    r = ap._aggregate_votes(["fp", "fp", "real"], 2, "downgrade_and_flag")
    assert r["verdict"] == "fp" and r["action"] == "downgrade_and_flag" and r["fp_votes"] == 2
    # 과반 real → 조치 없음
    r = ap._aggregate_votes(["real", "real", "fp"], 2, "downgrade_and_flag")
    assert r["verdict"] == "real" and r["action"] == "none"
    # 유효표 2 미만 → 판단 보류(미탐 방지 — 절대 삭제/강등 안 함)
    r = ap._aggregate_votes(["real"], 2, "downgrade_and_flag")
    assert r["verdict"] == "uncertain" and r["action"] == "none"
    r = ap._aggregate_votes(["uncertain", "uncertain"], 2, "downgrade_and_flag")
    assert r["verdict"] == "uncertain" and r["action"] == "none"


# ── 앙상블 게이팅: 비활성/비-ollama 면 None(아무 조치 안 함) ──────────────────
def test_ensemble_disabled_returns_none(monkeypatch, tmp_path):
    import asyncio
    cfg = {"enabled": True, "fp_judge_ensemble": {"enabled": False, "panel": ["x"]}}
    monkeypatch.setattr(ap, "_ROLES_PATH", _write_roles(tmp_path, cfg))
    monkeypatch.setattr(ap, "_AI_PROVIDER", "ollama")
    _reset_cache()
    res = asyncio.run(ap.ensemble_fp_judge({"title": "t", "evidence": "e"}))
    assert res is None
