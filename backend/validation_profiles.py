"""
validation_profiles.py — Proof-Oriented Validation Framework v1: 검증 프로파일.

Eoseureum은 공격 도구가 아니라 승인된 범위 내에서 '증거'를 확보하는 진단 플랫폼이다.
프로파일은 "어느 깊이의 (안전한) 재검증을 허용하는가"만 결정한다.
- 기본값은 반드시 SAFE.
- 강한 검증(ADVANCED/PROOF)은 명시 승인 환경변수가 있을 때만 유효(없으면 자동 강등).
- 프로파일은 '무엇이 허용되는가'를 정의할 뿐, 최종 판정/Level 은 Rule Engine 전담.

프로파일:
  SAFE      — 현재 수준 유지(후보 탐지 + 안전 검증)
  STANDARD  — 안전한 재검증 강화(브라우저 실행 확인, 응답 기반 증거)
  ADVANCED  — 더 깊은 read-only 증거(union/error, DOM/Stored 재확인, controlled callback)
  PROOF     — 명시 승인 필요. 실증 우선(단, read-only 증거로만 제한)
"""
from __future__ import annotations

import os

SAFE = "SAFE"
STANDARD = "STANDARD"
ADVANCED = "ADVANCED"
PROOF = "PROOF"

ORDER = [SAFE, STANDARD, ADVANCED, PROOF]
DEFAULT = SAFE
_RANK = {name: i for i, name in enumerate(ORDER)}


def rank(profile: str) -> int:
    return _RANK.get((profile or "").upper(), 0)


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def allow_advanced() -> bool:
    """ADVANCED 이상 검증 허용 여부 — 기본 False."""
    return _env_bool("ALLOW_ADVANCED_VALIDATION", False)


def allow_proof() -> bool:
    """PROOF 모드 허용 여부 — 기본 False(명시 승인 필요)."""
    return _env_bool("ALLOW_PROOF_MODE", False)


def requested_profile() -> str:
    """환경변수 VALIDATION_PROFILE(요청값). 미설정/오타는 SAFE."""
    p = (os.getenv("VALIDATION_PROFILE", DEFAULT) or DEFAULT).strip().upper()
    return p if p in _RANK else DEFAULT


def resolve_profile(requested: str | None = None) -> str:
    """요청 프로파일을 승인 정책에 따라 '실효 프로파일'로 강등하여 반환.

    - PROOF 는 ALLOW_PROOF_MODE=true 일 때만 유지, 아니면 ADVANCED 로 강등(가장 위험한 모드만 2단계 승인).
    - STANDARD / ADVANCED 는 별도 승인 불필요(프로파일 설정만으로 사용). (사용자 결정: PROOF 게이트만 유지)
    - 어떤 경우에도 기본값은 SAFE.
    """
    req = (requested or requested_profile() or DEFAULT).strip().upper()
    if req not in _RANK:
        req = DEFAULT
    eff = req
    if rank(eff) >= rank(PROOF) and not allow_proof():
        eff = ADVANCED   # PROOF 미허용 → ADVANCED 로 강등(ADVANCED 는 자유 선택)
    # (ADVANCED 게이트 제거) STANDARD·ADVANCED 는 프로파일만으로 사용. 최소값 SAFE.
    return eff


def current_profile() -> str:
    """지금 유효한(실효) 검증 프로파일."""
    return resolve_profile(requested_profile())


def proof_active() -> bool:
    """PROOF 모드가 '실효'로 활성인지 — 실제 스캐너의 깊이 게이트가 참조하는 단일 진실.

    실효 프로파일이 PROOF 이거나(=요청 PROOF + ALLOW_PROOF_MODE 승인), 명시적
    ALLOW_PROOF_MODE=true 일 때 True. PROOF 모드에서 스캐너는 더 깊고 집요한 실증
    기법(OOB·time-based·심화 sqlmap 등)을 자동 활성한다.

    ※ 안전 불변: 데이터 덤프/쉘/파일읽기 등 파괴적 행위는 proof_policy 가 여전히 하드 차단.
    PROOF 는 '무해 마커·OOB 콜백·읽기전용 메타데이터' 범위 내에서만 깊이를 늘린다.
    """
    return current_profile() == PROOF or allow_proof()


def was_downgraded() -> bool:
    return current_profile() != requested_profile()


# ── 프로파일별 검증 예산(안전 상한) ──────────────────────────────────────────────
def _env_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def budget() -> dict:
    """Proof 검증 예산 — 과도한 요청/행위를 구조적으로 제한."""
    return {
        "max_actions": _env_int("PROOF_MAX_ACTIONS", 20),
        "max_requests_per_finding": _env_int("PROOF_MAX_REQUESTS_PER_FINDING", 5),
        "timeout": _env_int("PROOF_TIMEOUT", 180),
        "sqlmap_allow_time_based": _env_bool("SQLMAP_ALLOW_TIME_BASED", False),
    }


# ── 프로파일 × 검증 기법 능력 매트릭스 ───────────────────────────────────────────
# 각 기법: 최소 프로파일(min) + read-only 여부. 모든 기법은 '안전(무해)'만 포함한다.
# 위험 행위(dump/shell/exfil/write/state-change/brute)는 여기 존재하지 않으며,
# proof_policy 에서 항상 차단된다.
CAPABILITIES: dict[str, dict[str, str]] = {
    "sqli": {
        "boolean_diff": STANDARD,        # 응답 차이(참/거짓) 관찰
        "error_evidence": STANDARD,      # 에러 기반 증거
        "dbms_fingerprint": ADVANCED,    # DBMS 종류/버전 fingerprint
        "union_minimal": ADVANCED,       # 최소 union 증거(데이터 추출 없음)
        "sqlmap_injectable": PROOF,      # SQLMap injectable 여부(메타데이터 read-only)
        "readonly_metadata": PROOF,      # 현재 DB 이름 수준 read-only metadata
    },
    "xss": {
        "reflection_context": STANDARD,
        "browser_alert": STANDARD,       # Playwright alert 실행 확인
        "screenshot": STANDARD,
        "dom_context": ADVANCED,
        "stored_revisit": ADVANCED,      # 저장형 후보 재방문 검증
    },
    "idor": {
        "response_compare": STANDARD,    # 응답 코드/길이/해시 비교(read-only)
        "cross_account_read": STANDARD,  # A/B 교차 계정 '조회' (상태 변경 없음)
    },
    "path_traversal": {
        "response_diff": ADVANCED,
        "known_safe_file_read": ADVANCED,  # 안전한 known 파일 후보 read-only
    },
    "ssrf": {
        "param_reaction": STANDARD,      # 파라미터 반응만(Level 1)
        "dns_callback": ADVANCED,        # Eoseureum controlled DNS callback
        "controlled_callback": ADVANCED,  # 단일 HTTP controlled callback
    },
    "file_upload": {
        "content_type_check": STANDARD,
        "benign_marker_upload": ADVANCED,  # 무해 marker 파일 업로드 가능 여부
        "stored_url_access": ADVANCED,     # 저장 URL 접근 가능 여부(실행 확인 안 함)
    },
    "open_redirect": {
        "param_reflection": STANDARD,
        "location_header_check": STANDARD,
        "controlled_safe_redirect": STANDARD,  # example.com 등 안전 도메인 redirect 확인
    },
    "service": {
        "banner_observe": SAFE,
        "auth_required_check": STANDARD,
        "tls_check": STANDARD,
        "redis_auth_check": ADVANCED,
        "ftp_anon_check": ADVANCED,
        "smtp_open_relay_response": ADVANCED,  # 실제 메일 발송 없이 응답 기반
        "smb_guest_policy": ADVANCED,          # listing 없이 협상/정책 수준
        "service_readonly_proof": PROOF,
    },
}

_ALIAS = {
    "sql_injection": "sqli", "sql": "sqli",
    "reflected_xss": "xss", "stored_xss": "xss", "dom_xss": "xss",
    "access_control": "idor",
    "lfi": "path_traversal", "path": "path_traversal", "traversal": "path_traversal",
    "upload": "file_upload",
    "redirect": "open_redirect", "openredirect": "open_redirect",
}


def norm_family(family: str) -> str:
    f = (family or "").strip().lower()
    return _ALIAS.get(f, f)


def allowed_techniques(family: str, profile: str | None = None) -> list[str]:
    """해당 프로파일에서 허용되는(안전) 기법 목록."""
    prof = (profile or current_profile()).upper()
    fam = norm_family(family)
    caps = CAPABILITIES.get(fam, {})
    return [t for t, minp in caps.items() if rank(prof) >= rank(minp)]


def technique_min_profile(family: str, technique: str) -> str | None:
    return CAPABILITIES.get(norm_family(family), {}).get(technique)


def config_snapshot() -> dict:
    """UI/보고서 노출용 프로파일 설정 스냅샷."""
    return {
        "requested_profile": requested_profile(),
        "profile": current_profile(),
        "downgraded": was_downgraded(),
        "allow_advanced": allow_advanced(),
        "allow_proof": allow_proof(),
        "budget": budget(),
        "profiles": ORDER,
        "default": DEFAULT,
    }
