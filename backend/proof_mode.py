"""
proof_mode.py — Safe Proof Mode: 무해한 증거로만 취약 여부를 '판정'한다.

원칙:
  - 최종 판정은 Rule Engine 만 가능. AI 가 만든 판정은 거부한다(assert_rule_engine_verdict).
  - 운영 영향 없는 증거만 인정: 쉘 획득/덤프/파일쓰기/권한상승/정보탈취 금지.
  - RCE/Command Injection 은 기본 자동 실행 금지. RCE_PROOF_MODE=true 승인 시에만
    '고정 echo marker 반사' 수준의 무해 증거만 CONFIRMED_RESPONSE.

판정 상태:
  CONFIRMED_BROWSER / CONFIRMED_RESPONSE / POSSIBLE / MANUAL_REVIEW /
  BLOCKED_BY_POLICY / SKIPPED_UNSAFE
"""
from __future__ import annotations

import os

import candidate_verification as cv

CONFIRMED_BROWSER = "CONFIRMED_BROWSER"
CONFIRMED_RESPONSE = "CONFIRMED_RESPONSE"
POSSIBLE = "POSSIBLE"
MANUAL_REVIEW = "MANUAL_REVIEW"
BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
SKIPPED_UNSAFE = "SKIPPED_UNSAFE"

_VALID_VERDICTS = {CONFIRMED_BROWSER, CONFIRMED_RESPONSE, POSSIBLE,
                   MANUAL_REVIEW, BLOCKED_BY_POLICY, SKIPPED_UNSAFE}
# AI 가 직접 부여할 수 없는(=Rule Engine 전용) 판정
_RULE_ENGINE_ONLY = {CONFIRMED_BROWSER, CONFIRMED_RESPONSE}

RCE_ECHO_MARKER = "EOSEUREUM_RCE_PROOF_7F3A"


def rce_proof_mode_enabled() -> bool:
    """OS 명령 증거 모드 — 기본 OFF(미설정 시 False)."""
    return os.getenv("RCE_PROOF_MODE", "false").strip().lower() in ("1", "true", "yes", "on")


def assert_rule_engine_verdict(verdict: str, source: str) -> str:
    """Rule Engine 외 출처(AI 등)가 CONFIRMED 류 판정을 주면 강등시킨다.
    AI 가 '취약하다'고 확정하지 못하도록 강제하는 게이트."""
    if source != "rule_engine" and verdict in _RULE_ENGINE_ONLY:
        return MANUAL_REVIEW   # AI/외부의 확정 판정은 인정하지 않음
    if verdict not in _VALID_VERDICTS:
        return MANUAL_REVIEW
    return verdict


# ── 유형별 무해 증거 판정(Rule Engine 컨텍스트에서 호출) ─────────────────────────
def grade_xss(*, alert_fired: bool, reflected: bool = False) -> str:
    if alert_fired:
        return CONFIRMED_BROWSER
    if reflected:
        return POSSIBLE
    return MANUAL_REVIEW


def grade_sqli(*, sqlmap_injectable: bool, error_reflected: bool = False) -> str:
    # 덤프/파일읽기/os-shell/sql-shell 은 수행하지 않으며 증거로 쓰지 않는다.
    if sqlmap_injectable:
        return CONFIRMED_RESPONSE
    if error_reflected:
        return POSSIBLE
    return MANUAL_REVIEW


def grade_idor(owner: dict, cross: dict, *, owner_identity=None, cross_identity=None) -> str:
    """교차 계정 읽기 검증 위임(상태 변경 없음)."""
    r = cv.compare_idor(owner, cross, owner_identity=owner_identity, cross_identity=cross_identity)
    g = r.get("grade")
    return g if g in _VALID_VERDICTS else MANUAL_REVIEW


def grade_csrf(candidate: dict) -> dict:
    """CSRF 는 자동 확정 금지 — 위험도 평가 + MANUAL_REVIEW 유지."""
    risk = cv.score_csrf_risk(candidate)
    return {"verdict": MANUAL_REVIEW, "risk": risk["risk"], "reasons": risk["reasons"]}


def grade_file_upload(*, approved: bool = False, benign_upload_ok: bool | None = None) -> str:
    """파일 업로드: 기본은 후보 분석(MANUAL_REVIEW). 승인 시 무해 파일 업로드 가능 여부만.
    실행 가능 여부는 자동 확인하지 않는다."""
    if not approved:
        return MANUAL_REVIEW
    if benign_upload_ok:
        return POSSIBLE          # 무해 파일 업로드가 허용됨(실행 여부는 수동 확인)
    return MANUAL_REVIEW


def grade_rce(*, echo_reflected: bool, marker: str = RCE_ECHO_MARKER,
              observed: str = "", proof_mode: bool | None = None) -> str:
    """Command Injection/RCE — 기본 금지. proof mode 에서 고정 echo marker 반사만 인정.

    네트워크 연결/리버스셸/파일쓰기/권한상승/정보탈취 증거는 인정하지 않는다.
    """
    if proof_mode is None:
        proof_mode = rce_proof_mode_enabled()
    if not proof_mode:
        return SKIPPED_UNSAFE          # 승인 없으면 OS 명령 증거 수집 자체를 생략
    # proof mode 라도 '고정 marker 반사'만 증거로 인정
    if echo_reflected and marker and marker in (observed or ""):
        return CONFIRMED_RESPONSE
    if echo_reflected:
        return POSSIBLE
    return MANUAL_REVIEW


def finalize_verdict(*, vuln_type: str, signals: dict, source: str = "rule_engine") -> dict:
    """Rule Engine 단일 판정 진입점. source != 'rule_engine' 이면 CONFIRMED 류를 강등한다.

    signals: 유형별 무해 증거 신호 dict.
    반환: {verdict, vuln_type, evidence_basis}.
    """
    vt = (vuln_type or "").lower()
    s = signals or {}
    if s.get("blocked_by_policy"):
        v = BLOCKED_BY_POLICY
    elif s.get("skipped_unsafe"):
        v = SKIPPED_UNSAFE
    elif vt == "xss":
        v = grade_xss(alert_fired=bool(s.get("alert_fired")), reflected=bool(s.get("reflected")))
    elif vt in ("sqli", "sql_injection"):
        v = grade_sqli(sqlmap_injectable=bool(s.get("sqlmap_injectable")),
                       error_reflected=bool(s.get("error_reflected")))
    elif vt == "idor":
        v = grade_idor(s.get("owner") or {}, s.get("cross") or {},
                       owner_identity=s.get("owner_identity"),
                       cross_identity=s.get("cross_identity"))
    elif vt == "csrf":
        v = MANUAL_REVIEW
    elif vt in ("command_injection", "cmdi", "rce"):
        v = grade_rce(echo_reflected=bool(s.get("echo_reflected")),
                      observed=s.get("observed", ""),
                      proof_mode=s.get("proof_mode"))
    elif vt == "file_upload":
        v = grade_file_upload(approved=bool(s.get("approved")),
                              benign_upload_ok=s.get("benign_upload_ok"))
    else:
        v = POSSIBLE if s.get("signal") else MANUAL_REVIEW

    v = assert_rule_engine_verdict(v, source)
    return {"verdict": v, "vuln_type": vt,
            "evidence_basis": "운영 영향 없는 무해 증거(쉘/덤프/파일쓰기 없음)"}
