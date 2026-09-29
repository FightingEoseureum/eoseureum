"""
probes/config.py — Probe 설정/환경변수 로딩.

안전 기본값: credential/service probe·인증 스캔·공격성 payload·time-based SQLi 모두 기본 비활성.
전체 Active Probe 합산 rate 는 GLOBAL_ACTIVE_PROBE_RPS(기본 10) 이하로 제한.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

# payload 강도 레벨
PAYLOAD_LEVELS = ("safe", "balanced", "aggressive")


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("true", "1", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_str(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or "").strip()


# probe 카테고리별 enable 환경변수 + 기본값 (credential/service 만 기본 disabled)
PROBE_ENABLE_ENV = {
    "xss":             ("ENABLE_XSS_PROBE", True),
    "sqli":            ("ENABLE_SQLI_PROBE", True),
    "source_sqli":     ("ENABLE_SOURCE_SQLI_PROBE", True),
    "cmdi":            ("ENABLE_CMDI_PROBE", True),
    "auth":            ("ENABLE_AUTH_PROBE", True),
    "credential":      ("ENABLE_CREDENTIAL_PROBE", False),
    "cors":            ("ENABLE_CORS_PROBE", True),
    "clickjacking":    ("ENABLE_CLICKJACKING_PROBE", True),
    "http_method":     ("ENABLE_HTTP_METHOD_PROBE", True),
    "info_disclosure": ("ENABLE_INFO_DISCLOSURE_PROBE", True),
    "admin_exposure":  ("ENABLE_ADMIN_EXPOSURE_PROBE", True),
}


def is_probe_enabled(category: str) -> bool:
    env_name, default = PROBE_ENABLE_ENV.get(category, (None, True))
    if env_name is None:
        return True
    return _env_bool(env_name, default)


def payload_level() -> str:
    lvl = _env_str("PROBE_PAYLOAD_LEVEL", "safe").lower()
    return lvl if lvl in PAYLOAD_LEVELS else "safe"


@dataclass
class ScanConfig:
    """probe 실행 전역 설정 (환경변수 기반)."""
    # 실행 경로
    use_orchestrator: bool = False

    # payload 정책
    payload_level: str = "safe"
    enable_advanced_payloads: bool = False
    enable_extended_xss: bool = False
    # time-based SQLi (서버 부하 가능 → 기본 비활성, 엄격 제한)
    enable_time_based_sqli: bool = False
    max_time_based_sqli_delay: int = 3
    max_time_based_sqli_tests_per_param: int = 1
    # payload 파일 + 상한
    xss_payload_file: str = ""
    max_xss_payloads: int = 1000
    sqli_payload_file: str = ""
    max_sqli_payloads: int = 1000
    cmdi_payload_file: str = ""
    max_cmdi_payloads: int = 200

    # rate limit (전체 합산 ≤ global_rps)
    global_rps: float = 10.0
    auth_rps: float = 2.0
    xss_rps: float = 10.0
    sqli_rps: float = 10.0
    cmdi_rps: float = 10.0

    # 인증 스캔
    enable_auth_scan: bool = False
    auth_login_url: str = ""
    auth_username: str = ""
    auth_password: str = ""
    auth_username_b: str = ""        # IDOR 교차검증용 2번째 테스트 계정
    auth_password_b: str = ""
    auth_role_a: str = ""            # 계정 A 권한 등급(예: admin) — BFLA 판정용(선택)
    auth_role_b: str = ""            # 계정 B 권한 등급(예: user)  — BFLA 판정용(선택)
    auth_username_field: str = "auto"
    auth_password_field: str = "auto"
    auth_success_pattern: str = "auto"
    auth_max_pages: int = 50
    auth_scan_timeout: int = 10
    idor_verify_max: int = 20        # IDOR 교차검증 최대 대상 수

    # known credential 검증 / safe bruteforce
    enable_known_credential_check: bool = False
    enable_safe_bruteforce: bool = False
    auth_credential_file: str = ""
    max_auth_credentials: int = 1000
    max_auth_attempts_per_form: int = 1000
    stop_on_account_lock_hint: bool = True

    # 크롤
    max_crawl_depth: int = 3
    max_crawl_pages: int = 200
    same_origin_only: bool = True

    # 화이트박스(소스코드) SQLi 분석 — 승인된 grey-box 점검에서 소스가 제공될 때만 사용.
    # 블랙박스 페이로드로는 트리거 불가한 '필터↔싱크 변환 불일치' SQLi 등을 정적 발견.
    source_root: str = ""            # 분석할 소스 루트(파일/디렉터리). 비면 비활성.
    enable_source_sqli: bool = True  # source_root 가 지정된 경우에만 실질 동작.

    # 공통
    request_timeout: float = 8.0
    safe_mode: bool = True
    enabled: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "ScanConfig":
        cfg = cls(
            use_orchestrator=_env_bool("USE_PROBE_ORCHESTRATOR", False),
            payload_level=payload_level(),
            enable_advanced_payloads=_env_bool("ENABLE_ADVANCED_PAYLOADS", False),
            enable_extended_xss=_env_bool("ENABLE_EXTENDED_XSS_PAYLOADS", False),
            enable_time_based_sqli=_env_bool("ENABLE_TIME_BASED_SQLI", False),
            max_time_based_sqli_delay=_env_int("MAX_TIME_BASED_SQLI_DELAY", 3),
            max_time_based_sqli_tests_per_param=_env_int("MAX_TIME_BASED_SQLI_TESTS_PER_PARAM", 1),
            xss_payload_file=_env_str("XSS_PAYLOAD_FILE"),
            max_xss_payloads=_env_int("MAX_XSS_PAYLOADS", 1000),
            sqli_payload_file=_env_str("SQLI_PAYLOAD_FILE"),
            max_sqli_payloads=_env_int("MAX_SQLI_PAYLOADS", 1000),
            cmdi_payload_file=_env_str("CMDI_PAYLOAD_FILE"),
            max_cmdi_payloads=_env_int("MAX_CMDI_PAYLOADS", 200),
            global_rps=_env_float("GLOBAL_ACTIVE_PROBE_RPS", 10.0),
            auth_rps=_env_float("AUTH_PROBE_RPS", 2.0),
            xss_rps=_env_float("XSS_PROBE_RPS", 10.0),
            sqli_rps=_env_float("SQLI_PROBE_RPS", 10.0),
            cmdi_rps=_env_float("CMDI_PROBE_RPS", 10.0),
            enable_auth_scan=_env_bool("ENABLE_AUTH_SCAN", False),
            auth_login_url=_env_str("AUTH_LOGIN_URL"),
            auth_username=_env_str("AUTH_USERNAME"),
            auth_password=_env_str("AUTH_PASSWORD"),
            auth_username_b=_env_str("AUTH_USERNAME_B"),
            auth_password_b=_env_str("AUTH_PASSWORD_B"),
            auth_role_a=_env_str("AUTH_A_ROLE"),
            auth_role_b=_env_str("AUTH_B_ROLE"),
            idor_verify_max=_env_int("IDOR_VERIFY_MAX", 20),
            auth_username_field=_env_str("AUTH_USERNAME_FIELD", "auto") or "auto",
            auth_password_field=_env_str("AUTH_PASSWORD_FIELD", "auto") or "auto",
            auth_success_pattern=_env_str("AUTH_SUCCESS_PATTERN", "auto") or "auto",
            auth_max_pages=_env_int("AUTH_MAX_PAGES", 50),
            auth_scan_timeout=_env_int("AUTH_SCAN_TIMEOUT", 10),
            enable_known_credential_check=_env_bool("ENABLE_KNOWN_CREDENTIAL_CHECK", False),
            enable_safe_bruteforce=_env_bool("ENABLE_SAFE_BRUTEFORCE", False),
            auth_credential_file=_env_str("AUTH_CREDENTIAL_FILE"),
            max_auth_credentials=_env_int("MAX_AUTH_CREDENTIALS", 1000),
            max_auth_attempts_per_form=_env_int("MAX_AUTH_ATTEMPTS_PER_FORM", 1000),
            stop_on_account_lock_hint=_env_bool("STOP_ON_ACCOUNT_LOCK_HINT", True),
            max_crawl_depth=_env_int("MAX_CRAWL_DEPTH", 3),
            max_crawl_pages=_env_int("MAX_CRAWL_PAGES", 200),
            same_origin_only=_env_bool("SAME_ORIGIN_ONLY", True),
            request_timeout=_env_float("PROBE_REQUEST_TIMEOUT", 8.0),
            safe_mode=_env_bool("PROBE_SAFE_MODE", True),
            source_root=_env_str("EOSEUREUM_SOURCE_ROOT"),
            enable_source_sqli=_env_bool("ENABLE_SOURCE_SQLI", True),
        )
        # 안전장치: 상한 클램프
        cfg.max_xss_payloads = max(1, min(cfg.max_xss_payloads, 1000))
        cfg.max_sqli_payloads = max(1, min(cfg.max_sqli_payloads, 1000))
        cfg.max_cmdi_payloads = max(1, min(cfg.max_cmdi_payloads, 200))
        cfg.max_auth_credentials = max(0, min(cfg.max_auth_credentials, 1000))
        cfg.max_time_based_sqli_delay = max(1, min(cfg.max_time_based_sqli_delay, 3))
        cfg.max_time_based_sqli_tests_per_param = max(1, min(cfg.max_time_based_sqli_tests_per_param, 1))
        cfg.global_rps = max(0.1, min(cfg.global_rps, 1000.0))   # 전체 합산 rps 상한(정책 설정 허용 범위)
        cfg.auth_rps = min(cfg.auth_rps, cfg.global_rps)
        cfg.enabled = {cat: is_probe_enabled(cat) for cat in PROBE_ENABLE_ENV}
        return cfg
