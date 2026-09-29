"""SPA 자동 브라우저 발견(고도화 #5) 회귀 테스트."""
import discovery_worker.discovery_policy as dp


def test_auto_enable_for_spa_frameworks(monkeypatch):
    monkeypatch.delenv("BROWSER_DISCOVERY_AUTO", raising=False)
    assert dp.auto_enable_for_tech([{"name": "React"}]) is True
    assert dp.auto_enable_for_tech([{"name": "Vue.js"}]) is True
    assert dp.auto_enable_for_tech([{"name": "Next.js"}]) is True
    assert dp.auto_enable_for_tech([{"name": "Angular"}]) is True


def test_no_auto_for_non_spa(monkeypatch):
    monkeypatch.delenv("BROWSER_DISCOVERY_AUTO", raising=False)
    assert dp.auto_enable_for_tech([{"name": "Apache"}, {"name": "PHP"}]) is False
    assert dp.auto_enable_for_tech([]) is False
    assert dp.auto_enable_for_tech(None) is False


def test_auto_can_be_disabled(monkeypatch):
    monkeypatch.setenv("BROWSER_DISCOVERY_AUTO", "false")
    assert dp.auto_enable_for_tech([{"name": "React"}]) is False


def test_accepts_plain_strings(monkeypatch):
    monkeypatch.delenv("BROWSER_DISCOVERY_AUTO", raising=False)
    assert dp.auto_enable_for_tech(["svelte"]) is True
