"""
probe_policy.py — 점검 정책 헬퍼 (순수 함수, 네트워크 없음).

- 로그인 폼 SQLi / 인증 우회 payload + 판정 정책 (time-based 금지, 브루트포스 금지)
- XSS 판정 정책 (reflected/DOM: alert 실증 시에만 CONFIRMED)
- XSS/인증 크롤 env 게이트 + Stored XSS 마커
- 인증 후 크롤 설정/coverage 헬퍼
"""
from __future__ import annotations

import os

# ── env 게이트 ──────────────────────────────────────────────────────────────────
def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def dom_xss_enabled() -> bool:
    return _bool("ENABLE_DOM_XSS", True)


def stored_xss_enabled() -> bool:
    # 명시 활성(env) 또는 PROOF(실증) 모드에서 점검. 저장형은 마커가 대상에 남으므로 비파괴
    # 계약(인증세션 확인·btnClear/빈값 재제출 정리·잔여물 정직 residue 보고)을 갖춘 상태에서만 켠다.
    if _bool("ENABLE_STORED_XSS", False):
        return True
    try:
        import validation_profiles as _vp
        return bool(_vp.proof_active())
    except Exception:
        return False


def csp_bypass_enabled() -> bool:
    """CSP 정책 우회(base-uri 하이재킹 등) 점검. 기본 on. 브라우저 실증은 SAFE(로컬 전용)."""
    return _bool("ENABLE_CSP_BYPASS", True)


def auth_crawl_enabled() -> bool:
    return _bool("ENABLE_AUTH_CRAWL", False)


def stored_xss_marker(scan_id: str = "") -> str:
    prefix = os.getenv("STORED_XSS_MARKER_PREFIX", "EOSEUREUM_STORED_XSS_PROBE")
    sid = (scan_id or "").replace("-", "")[:12] or "X"
    return f"{prefix}_{sid}"


def auth_crawl_config() -> dict:
    """AUTH_* 환경변수로 인증 후 크롤 설정을 구성한다(자격증명은 호출부에서만 사용)."""
    try:
        max_pages = int(os.getenv("AUTH_MAX_PAGES", "50"))
    except (TypeError, ValueError):
        max_pages = 50
    return {
        "enabled": auth_crawl_enabled(),
        "login_url": os.getenv("AUTH_LOGIN_URL", ""),
        "username": os.getenv("AUTH_USERNAME", ""),
        "password": os.getenv("AUTH_PASSWORD", ""),
        "success_pattern": os.getenv("AUTH_SUCCESS_PATTERN", ""),
        "failure_pattern": os.getenv("AUTH_FAILURE_PATTERN", ""),
        "max_pages": max_pages,
        # 로그인용 셀렉터(선택) — 미지정 시 폼 필드 자동 탐지. submit_selector 는
        # 셀렉터 기반 로그인 경로에서 사용(HTTP POST 자동 제출 경로에서는 자동 탐지).
        "username_selector": os.getenv("AUTH_USERNAME_SELECTOR", ""),
        "password_selector": os.getenv("AUTH_PASSWORD_SELECTOR", ""),
        "submit_selector": os.getenv("AUTH_SUBMIT_SELECTOR", ""),
    }


def auth_crawl_skip_reason(cfg: dict) -> str | None:
    """인증 크롤을 건너뛰는 사유. 진행 가능하면 None."""
    if not cfg.get("enabled"):
        return "ENABLE_AUTH_CRAWL=false"
    if not cfg.get("login_url"):
        return "AUTH_LOGIN_URL 미설정"
    if not cfg.get("username") or not cfg.get("password"):
        return "AUTH_USERNAME/PASSWORD 미설정"
    return None


# ── 로그인 폼 SQLi / 인증 우회 payload (time-based 절대 금지) ──────────────────────
_LOGIN_SQLI_SAFE = [
    "' OR '1'='1",
    "admin'--",
    "' OR 1=1--",
]
_LOGIN_SQLI_BALANCED = _LOGIN_SQLI_SAFE + [
    '" OR "1"="1',
    "') OR ('1'='1",
    "admin' #",
]
# 시간지연/blind 토큰(금지 목록) — payload 에 포함되면 안 됨(검증용)
_FORBIDDEN_TOKENS = ("sleep", "benchmark", "waitfor", "pg_sleep", "dbms_lock")


def login_sqli_payloads(level: str = "balanced") -> list[str]:
    """로그인 폼 SQLi/인증 우회 후보(safe/balanced). time-based 미포함, 개수 제한."""
    lvl = (level or "balanced").lower()
    payloads = _LOGIN_SQLI_SAFE if lvl == "safe" else _LOGIN_SQLI_BALANCED
    # 안전 가드: 금지 토큰 제거 + 최대 8개로 제한(브루트포스 아님)
    out = [p for p in payloads if not any(t in p.lower() for t in _FORBIDDEN_TOKENS)]
    return out[:8]


def judge_login_sqli(*, url_changed=False, logout_seen=False, dashboard_seen=False,
                     session_changed=False, failure_absent=False,
                     db_error=False, response_diff=False) -> str | None:
    """로그인 폼 SQLi/인증 우회 판정 등급.
    CONFIRMED: 로그인 성공 지표(로그아웃/대시보드 등) 다수 또는 명확
    LIKELY   : 성공 지표 1개 + URL 변화
    POSSIBLE : DB 에러 메시지만
    MANUAL_REVIEW: 응답 차이만
    None     : 신호 없음
    """
    success_signals = sum([logout_seen, dashboard_seen, session_changed,
                           (url_changed and failure_absent)])
    if logout_seen or dashboard_seen or success_signals >= 2:
        return "CONFIRMED"
    if success_signals == 1:
        return "LIKELY"
    if db_error:
        return "POSSIBLE"
    if response_diff:
        return "MANUAL_REVIEW"
    return None


# ── XSS 판정 (alert 실증 시에만 CONFIRMED) ────────────────────────────────────────
def judge_reflected_xss(alert_fired: bool, reflected: bool = False) -> str | None:
    if alert_fired:
        return "CONFIRMED"
    if reflected:
        return "POSSIBLE"
    return None


def judge_dom_xss(alert_fired: bool, sink_found: bool = False) -> str | None:
    """DOM XSS: 실제 alert/dialog 발생 시에만 CONFIRMED. sink 존재만이면 POSSIBLE."""
    if alert_fired:
        return "CONFIRMED"
    if sink_found:
        return "POSSIBLE"
    return None


def judge_csp_bypass(*, hijack_executed: bool = False, hijack_requested: bool = False,
                     bypassable_static: bool = False, injection_point: bool = False) -> str | None:
    """CSP 우회 판정.
    CONFIRMED: <base> 하이재킹된 스크립트가 브라우저에서 실제 실행됨(nonce/strict-dynamic 통과).
    LIKELY   : 하이재킹된 스크립트 로드 요청까지 관측(실행 확인 전).
    POSSIBLE : 정적 분석상 우회 가능 + 같은 페이지에 HTML 주입점 존재.
    None     : 우회 불가(정책이 실효적으로 XSS 차단).
    """
    if hijack_executed:
        return "CONFIRMED"
    if hijack_requested:
        return "LIKELY"
    if bypassable_static and injection_point:
        return "POSSIBLE"
    return None


def build_auth_coverage(*, enabled: bool, login_success: bool | None,
                        login_forms: int = 0, authenticated_pages: int = 0,
                        reason: str | None = None) -> dict:
    """coverage 에 병합할 인증 크롤 수치."""
    return {
        "auth_crawl_enabled": bool(enabled),
        "auth_login_success": bool(login_success) if login_success is not None else None,
        "login_forms": int(login_forms),
        "authenticated_pages": int(authenticated_pages),
        "auth_scan_reason": reason or "",
    }
