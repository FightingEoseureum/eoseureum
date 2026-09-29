"""
test_adaptive_recon.py — adaptive_recon.is_enabled / suggest_checks 검증.

모듈: backend/adaptive_recon.py
  is_enabled() -> bool
  suggest_checks(technologies, findings, attack_surface_items) -> dict

핵심 불변식:
  - ENABLE_ADAPTIVE_RECON 미설정 시 is_enabled()==False, 모든 후보 auto_run_allowed==False.
  - ENABLE_ADAPTIVE_RECON="true" 시 is_enabled()==True, 안전(low) 후보의 auto_run_allowed==True.
  - Tomcat 입력 시 "/manager/html" 포함 후보 생성.
  - 빈 입력 → {"suggested_checks": []}.
  - paths 에 파괴적/인증우회 경로 미포함(GET/HEAD 안전 경로만).

실행:
  cd backend && venv_linux/bin/python -m pytest tests/test_adaptive_recon.py -q
"""
import os
import sys

import pytest

# backend 디렉터리를 import 경로에 추가 (tests/ 의 부모)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import adaptive_recon as ar


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """각 테스트는 기본적으로 ENABLE_ADAPTIVE_RECON 미설정 상태에서 시작."""
    monkeypatch.delenv("ENABLE_ADAPTIVE_RECON", raising=False)


def _all_paths(result):
    paths = []
    for c in result["suggested_checks"]:
        paths.extend(c["paths"])
    return paths


def test_default_disabled_and_no_auto_run():
    assert ar.is_enabled() is False
    result = ar.suggest_checks(
        technologies=[{"name": "Apache-Coyote/Tomcat"}]
    )
    assert result["suggested_checks"], "후보가 생성되어야 한다"
    assert all(
        c["auto_run_allowed"] is False for c in result["suggested_checks"]
    )


def test_enabled_via_env_allows_auto_run(monkeypatch):
    monkeypatch.setenv("ENABLE_ADAPTIVE_RECON", "true")
    assert ar.is_enabled() is True
    result = ar.suggest_checks(technologies=[{"name": "Tomcat"}])
    low_risk = [c for c in result["suggested_checks"] if c["risk"] == "low"]
    assert low_risk, "low 위험 후보가 있어야 한다"
    assert all(c["auto_run_allowed"] is True for c in low_risk)


@pytest.mark.parametrize("val", ["true", "TRUE", "True", "1", "yes", "YES"])
def test_truthy_values_enable(monkeypatch, val):
    monkeypatch.setenv("ENABLE_ADAPTIVE_RECON", val)
    assert ar.is_enabled() is True


@pytest.mark.parametrize("val", ["false", "0", "no", "", "off", "maybe"])
def test_falsy_values_disable(monkeypatch, val):
    monkeypatch.setenv("ENABLE_ADAPTIVE_RECON", val)
    assert ar.is_enabled() is False


def test_tomcat_generates_manager_html():
    result = ar.suggest_checks(
        technologies=[{"name": "Apache-Coyote/Tomcat"}]
    )
    assert "/manager/html" in _all_paths(result)


def test_empty_input_returns_empty_list():
    assert ar.suggest_checks() == {"suggested_checks": []}
    assert ar.suggest_checks(technologies=[], findings=[]) == {
        "suggested_checks": []
    }


def test_no_destructive_or_bypass_paths(monkeypatch):
    monkeypatch.setenv("ENABLE_ADAPTIVE_RECON", "true")
    # 위험/파괴적 경로를 recommended_probes 로 주입해도 걸러져야 한다.
    techs = [
        {
            "name": "Tomcat",
            "recommended_probes": [
                "/admin/delete-all",
                "/users/remove",
                "/auth/bypass",
                "/api/brute-force",
                "/../../etc/passwd",
                "/account/logout",
                "/safe/info",  # 이것만 안전
            ],
        }
    ]
    result = ar.suggest_checks(technologies=techs)
    paths = _all_paths(result)
    forbidden = ("delete", "remove", "bypass", "brute", "..", "logout")
    for p in paths:
        low = p.lower()
        assert all(tok not in low for tok in forbidden), p
        assert p.startswith("/")
    assert "/safe/info" in paths


def test_dict_recommended_probe_and_merge():
    techs = [
        {
            "name": "Tomcat",
            "recommended_probes": [
                {"reason": "Apache-Coyote 헤더로 Tomcat 가능성",
                 "paths": ["/manager/status"], "risk": "low"},
            ],
        }
    ]
    result = ar.suggest_checks(technologies=techs)
    # 동일 reason 은 병합되어 paths 가 합쳐진다.
    coyote = [
        c for c in result["suggested_checks"]
        if c["reason"] == "Apache-Coyote 헤더로 Tomcat 가능성"
    ]
    assert len(coyote) == 1
    assert "/manager/html" in coyote[0]["paths"]
    assert "/manager/status" in coyote[0]["paths"]


def test_return_shape():
    result = ar.suggest_checks(technologies=[{"name": "nginx"}])
    assert set(result.keys()) == {"suggested_checks"}
    for c in result["suggested_checks"]:
        assert set(c.keys()) == {"reason", "paths", "risk", "auto_run_allowed"}
        assert isinstance(c["reason"], str)
        assert isinstance(c["paths"], list)
        assert c["risk"] in ("low", "medium")
        assert isinstance(c["auto_run_allowed"], bool)
