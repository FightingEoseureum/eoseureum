"""P2: 시간 예산 × PROOF → 깊이 에스컬레이션 회귀."""
import scan_depth as sd


def setup_function():
    sd.reset_depth()


def test_budget_scale_tiers():
    assert sd._budget_scale(0) == 1.0
    assert sd._budget_scale(30) == 1.0
    assert sd._budget_scale(120) == 1.5
    assert sd._budget_scale(480) == 2.0
    assert sd._budget_scale(1440) == 3.0
    assert sd._budget_scale(2880) == 5.0     # 48h


def test_set_depth_and_scale():
    sd.set_depth(budget_min=1440, proof=False)
    assert sd.scale() == 3.0
    sd.set_depth(budget_min=1440, proof=True)
    assert sd.scale() == 4.5                  # ×1.5 PROOF


def test_scaled_caps_grow_with_budget(monkeypatch):
    for k in ("MAX_DISCOVERED_FOR_INJECTION", "MAX_INJECTION_POINTS", "PARAM_MINING_MAX"):
        monkeypatch.delenv(k, raising=False)
    sd.reset_depth()
    base_inj = sd.injection_candidate_cap()   # scale 1.0 → 500
    base_pts = sd.injection_points_cap()       # 40
    base_pm = sd.param_mining_max()            # 512
    assert base_inj == 500 and base_pts == 40 and base_pm == 512
    sd.set_depth(budget_min=2880, proof=True)  # ×7.5
    assert sd.injection_candidate_cap() == int(500 * 7.5)
    assert sd.injection_points_cap() == int(40 * 7.5)
    assert sd.param_mining_max() == int(512 * 7.5)
    assert sd.blind_samples() == 6             # 상한 6


def test_env_override_wins(monkeypatch):
    monkeypatch.setenv("MAX_DISCOVERED_FOR_INJECTION", "123")
    sd.set_depth(budget_min=2880, proof=True)
    assert sd.injection_candidate_cap() == 123   # 사용자 명시값 우선


def test_default_no_scale_when_unset():
    sd.reset_depth()
    assert sd.scale() == 1.0 and sd.blind_samples() == 2


# ── A안: 시간-박스(time-box) throttle ──────────────────────────────────────────
def test_throttle_full_at_start(monkeypatch):
    import time
    monkeypatch.delenv("MAX_INJECTION_POINTS", raising=False)
    monkeypatch.setenv("EOSEUREUM_TIME_THROTTLE", "true")
    sd.set_depth(budget_min=120, proof=False, deadline_ts=time.time() + 120 * 60)  # 방금 시작 frac≈1.0
    assert sd.time_throttle() == 1.0
    assert sd.injection_points_cap() == int(40 * 1.5)   # 60 — 초반은 예산대로 깊게


def test_throttle_shrinks_to_baseline_late(monkeypatch):
    import time
    for k in ("MAX_INJECTION_POINTS", "PARAM_MINING_MAX"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("EOSEUREUM_TIME_THROTTLE", "true")
    # 2h 예산인데 6분(잔여 frac≈0.05)만 남음 → 강하게 축소, 단 base 하한 유지
    sd.set_depth(budget_min=120, proof=False, deadline_ts=time.time() + 6 * 60)
    assert sd.time_throttle() < 1.0
    assert sd.injection_points_cap() == 40    # scaled 60×0.3=18 < base → base(40)로 회귀
    assert sd.param_mining_max() == 512        # baseline 아래로는 안 내려감(breadth 보존)
    assert sd.blind_samples() == 2             # baseline


def test_throttle_disabled_env(monkeypatch):
    import time
    monkeypatch.setenv("EOSEUREUM_TIME_THROTTLE", "false")
    sd.set_depth(budget_min=120, deadline_ts=time.time() + 1)   # 거의 만료지만 비활성
    assert sd.time_throttle() == 1.0


def test_throttle_noop_without_deadline():
    sd.set_depth(budget_min=120, proof=False)   # deadline 미지정 → 기존 동작
    assert sd.time_throttle() == 1.0
    assert sd.injection_points_cap() == int(40 * 1.5)
