"""scan_depth.py — 시간 예산 × PROOF 를 '깊이'로 변환하는 중앙 컨트롤러.

원칙(사용자 목적): 일반 단계 스캔은 안전·저부하(패킷 최소). 시간 예산(최대 48h)을 크게 잡을수록,
그리고 PROOF 모드일수록 '더 깊고 집요하게' 취약점을 찾는다 — 주입점 상한·파라미터 마이닝·
blind 샘플수·재크롤 라운드 등을 예산에 비례해 스케일한다.

per-scan 격리: contextvar 로 스캔별 깊이를 보관한다(동시 스캔이 서로의 깊이에 영향 없음).
값이 미설정이면 모든 knob 이 기존 env 기본값으로 폴백(무영향).
"""
from __future__ import annotations

import contextvars
import os
import time as _time

# {"scale": float, "proof": bool, "budget_min": int, "deadline_ts": float|None,
#  "total_sec": int} 또는 None
_depth_ctx: contextvars.ContextVar = contextvars.ContextVar("eos_depth", default=None)


def _budget_scale(budget_min: int) -> float:
    """시간 예산(분) → 깊이 배수. 30분 이하=1.0(기본), 48h=5.0."""
    b = max(0, int(budget_min or 0))
    if b <= 30:
        return 1.0
    if b <= 120:      # ~2h
        return 1.5
    if b <= 480:      # ~8h
        return 2.0
    if b <= 1440:     # ~24h
        return 3.0
    return 5.0        # ~48h


def set_depth(budget_min: int = 0, proof: bool = False,
              deadline_ts: float | None = None) -> None:
    """스캔 시작 시 1회 호출 — 예산·PROOF 로 깊이 스케일을 설정(해당 스캔 태스크 컨텍스트에만 적용).

    deadline_ts(자동중지 시각)를 주면 '시간-박스(time-box)' 모드: 시간이 갈수록 깊이를
    baseline 까지 낮춰(time_throttle) 전체 단계가 예산 안에 완주하도록 페이싱한다."""
    scale = _budget_scale(budget_min)
    if proof:
        scale *= 1.5   # PROOF 는 깊이를 한 단계 더(집요한 실증)
    _depth_ctx.set({"scale": round(scale, 2), "proof": bool(proof),
                    "budget_min": max(0, int(budget_min or 0)),
                    "deadline_ts": (float(deadline_ts) if deadline_ts else None),
                    "total_sec": max(0, int(budget_min or 0)) * 60})


def reset_depth() -> None:
    _depth_ctx.set(None)


def _throttle_enabled() -> bool:
    return os.getenv("EOSEUREUM_TIME_THROTTLE", "true").strip().lower() in ("1", "true", "yes", "on")


def time_throttle() -> float:
    """남은 예산에 따른 '깊이 축소 계수'(0.3~1.0). 시간 전반(잔여≥50%)은 1.0(예산대로 깊게),
    후반부로 갈수록 baseline(0.3)까지 선형 축소 → 뒷단계가 예산을 넘겨 잘리지 않게 한다.
    데드라인 미설정/스로틀 비활성 시 1.0(무영향 — 기존 동작 유지)."""
    if not _throttle_enabled():
        return 1.0
    d = _depth_ctx.get()
    if not d:
        return 1.0
    dl = d.get("deadline_ts")
    total = d.get("total_sec") or 0
    if not dl or total <= 0:
        return 1.0
    frac = (float(dl) - _time.time()) / total   # 1.0(시작) → 0.0(데드라인)
    if frac >= 0.5:
        return 1.0
    if frac <= 0.0:
        return 0.3
    return max(0.3, frac / 0.5)                  # 잔여 50%→0% 을 1.0→0.3 으로 축소


def current() -> dict | None:
    return _depth_ctx.get()


def scale() -> float:
    d = _depth_ctx.get()
    return d["scale"] if d else 1.0


def _scaled_env(env_name: str, base_default: int, hard_max: int) -> int:
    """env 명시값이 있으면 그대로(사용자 우선, 스로틀 미적용), 없으면 base_default × scale.
    시간-박스 모드에선 time_throttle 로 후반부 깊이를 축소하되 base_default 아래로는 내리지
    않는다(=breadth/최소 점검량 보존). 상한 clamp."""
    raw = os.getenv(env_name)
    if raw is not None:
        try:
            return max(1, min(hard_max, int(raw)))
        except (TypeError, ValueError):
            pass
    scaled = base_default * scale()
    eff = max(base_default, scaled * time_throttle())   # 시간 압박 시 baseline 까지만 축소
    return max(1, min(hard_max, int(eff)))


def injection_candidate_cap() -> int:
    """URL 발견 → 주입점 후보 처리 상한(기본 500 × scale)."""
    return _scaled_env("MAX_DISCOVERED_FOR_INJECTION", 500, 300000)


def injection_points_cap() -> int:
    """최종 주입점 상한(기본 40 × scale)."""
    return _scaled_env("MAX_INJECTION_POINTS", 40, 4000)


def param_mining_max() -> int:
    """파라미터 마이닝 단어 상한(기본 512 × scale)."""
    return _scaled_env("PARAM_MINING_MAX", 512, 20000)


def blind_samples() -> int:
    """blind(boolean/time) 확증 반복 샘플수 — 예산 클수록 더 엄밀(기본 2, 최대 6).
    시간-박스 후반부엔 baseline(2)까지 축소."""
    return max(2, min(6, int(max(2, 2 * scale() * time_throttle()))))


def crawl_depth() -> int:
    """내부 크롤(BFS) 깊이. 깊이는 비용이 지수적이라 완만히 스케일: 기본 2, PROOF 3, 대형 예산 4~5.
    env CRAWL_DEPTH 명시 시 그대로(사용자 우선)."""
    raw = os.getenv("CRAWL_DEPTH")
    if raw is not None:
        try:
            return max(1, min(6, int(raw)))
        except (TypeError, ValueError):
            pass
    d = _depth_ctx.get()
    base = 3 if (d and d.get("proof")) else 2
    if scale() * time_throttle() >= 2.5:   # 대형 예산(≈8h+ PROOF)일 때 한 단계 더
        base += 1
    return max(1, min(5, base))


def crawl_max_pages() -> int:
    """내부 크롤 최대 페이지 수(기본 60 × scale). PROOF/예산 클수록 넓게."""
    return _scaled_env("CRAWL_MAX_PAGES", 60, 3000)


def dirfuzz_maxtime() -> int:
    """디렉터리 퍼징 시간 예산(초, 기본 45 × scale). PROOF/예산 클수록 더 오래 탐색."""
    return _scaled_env("DIRFUZZ_MAXTIME", 45, 1800)


def dirfuzz_word_cap() -> int:
    """디렉터리 퍼징 테스트 단어 상한(기본 5000 × scale). PROOF/예산 클수록 더 많은 경로."""
    return _scaled_env("DIRFUZZ_MAX_WORDS", 5000, 300000)
