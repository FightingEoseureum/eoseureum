"""
authz_write.py — 쓰기 권한(Broken Access Control on WRITE) 검증 '순수 로직' + CSRF 탐지.

목적:
  "인증 우회/권한 오류로 '다른 사용자의 데이터'를 수정·삭제할 수 있는가"를 안전하게 검증하기
  위한 후보 선별·판정·안전가드·마커 로직을 담는다. 네트워크 실행은 authenticated_scan.py
  (verify_write_authz_dual_account)가 담당한다.

안전 원칙(코드로 강제):
  - 오직 '도구가 소유·통제하는 테스트 계정 A/B'의 데이터만 대상으로 한다. 제3자(실사용자)
    데이터는 절대 건드리지 않는다.
  - 기본은 '수정-후-원복(modify-and-revert)'만: A 소유 객체의 필드 원본을 캡처 → B가 수정
    시도 → 원본으로 되돌린다. 삭제(DELETE)는 되돌리기 불가라 기본 비활성
    (ENABLE_WRITE_AUTHZ_DELETE, 별도 옵트인, v1 미수행).
  - 비밀번호/결제/금융 등 민감 필드는 기본 제외(오탐·부작용 방지).
  - 이 모듈 함수는 네트워크를 하지 않으며 예외를 던지지 않는다(방어적).
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

# 상태 변경(쓰기) 메서드
STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# action/url 에 나타나면 '쓰기'로 보는 키워드
_WRITE_ACTION_RE = re.compile(
    r"(edit|update|modify|save|delete|remove|drop|write|create|add|insert|"
    r"수정|삭제|저장|편집|등록|작성)", re.IGNORECASE)

# 되돌리기 불가/고위험이라 기본 제외하는 액션(삭제 계열)
_DESTRUCTIVE_ACTION_RE = re.compile(
    r"(delete|remove|drop|destroy|purge|삭제|제거)", re.IGNORECASE)

# 수정 대상으로 부적절한(민감) 필드명 — 기본 제외
_SENSITIVE_FIELD_RE = re.compile(
    r"(pass|pwd|secret|token|csrf|email|mail|phone|tel|card|account|"
    r"amount|price|money|balance|role|admin|is_admin|권한|비밀|결제|금액)",
    re.IGNORECASE)

# CSRF 토큰으로 인정하는 필드명
_CSRF_FIELD_RE = re.compile(
    r"(csrf|xsrf|_token|authenticity_token|__requestverificationtoken|nonce)",
    re.IGNORECASE)

WRITE_MARKER_PREFIX = "EOSEUREUM_AUTHZ_WRITE"


def write_marker(seed: str = "") -> str:
    """수정 검증용 고유 마커(원복 대상 식별에도 사용)."""
    h = hashlib.md5((seed or "x").encode("utf-8", "ignore")).hexdigest()[:8]
    return f"{WRITE_MARKER_PREFIX}_{h}"


def is_state_changing(method: str, action: str = "") -> bool:
    m = (method or "GET").upper()
    if m in STATE_METHODS and m != "POST":
        return True
    if m == "POST":
        return True  # POST 는 기본 쓰기로 간주
    # GET 이라도 action 이 명백히 쓰기면 위험 신호(권장X 설계지만 탐지)
    return bool(action and _WRITE_ACTION_RE.search(action))


def is_destructive(method: str, action: str = "") -> bool:
    if (method or "").upper() == "DELETE":
        return True
    return bool(action and _DESTRUCTIVE_ACTION_RE.search(action))


def pick_mutable_field(params: dict) -> str | None:
    """수정에 쓸 '안전한 텍스트 필드'를 고른다. 민감/CSRF/식별자 필드는 제외."""
    if not isinstance(params, dict):
        return None
    for name in params:
        n = str(name)
        if _SENSITIVE_FIELD_RE.search(n) or _CSRF_FIELD_RE.search(n):
            continue
        if n.lower() in ("id", "uid", "no", "seq", "idx", "pk"):
            continue
        return n
    return None


def gather_write_candidates(host_results: list, auth_forms: list | None = None,
                            *, allow_destructive: bool = False,
                            max_candidates: int = 30) -> list:
    """discovery/인증크롤 결과에서 '쓰기 권한 검증 후보'를 모은다.

    후보 dict: {url, method, params, csrf_fields, source, view_url, mutable_field}
    - 상태 변경(POST/PUT/PATCH, 또는 쓰기 action)만 포함.
    - 기본은 삭제 계열 제외(allow_destructive=True 여야 포함).
    - 수정 가능한 안전 텍스트 필드가 있는 후보만(없으면 제외).
    """
    forms: list = list(auth_forms or [])
    # host_results 의 서비스에 저장된 폼(있으면)도 수집
    for hr in host_results or []:
        for svc in (hr.get("services") or []):
            for f in (svc.get("auth_forms") or svc.get("forms") or []):
                if isinstance(f, dict):
                    forms.append(f)

    out, seen = [], set()
    for f in forms:
        if not isinstance(f, dict):
            continue
        url = f.get("url") or ""
        method = (f.get("method") or "GET").upper()
        params = f.get("params") or {}
        action = url
        if not is_state_changing(method, action):
            continue
        if is_destructive(method, action) and not allow_destructive:
            continue
        field = pick_mutable_field(params)
        if not field:
            continue  # 안전하게 수정/원복할 텍스트 필드가 없으면 제외
        key = (method, urlparse(url).path, field)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "url": url, "method": method, "params": dict(params),
            "csrf_fields": list(f.get("csrf_fields") or []),
            "source": f.get("source") or "form",
            "view_url": f.get("view_url") or url,
            "mutable_field": field,
        })
        if len(out) >= max_candidates:
            break
    return out


def judge_write_authz(b_status: int | None, readback_has_marker: bool | None,
                      a_owns: bool) -> str | None:
    """쓰기 권한 취약 판정.

    CONFIRMED_WRITE : B(타 계정)의 수정 요청이 수락(2xx)되고 A 재조회에서 마커가 확인됨
                      → B 가 실제로 A 의 데이터를 변경(권한 통제 실패).
    POSSIBLE        : B 수정이 2xx 로 수락됐으나 재조회로 반영을 확정하지 못함.
    None            : A 가 소유 확인 안 됨 / B 가 차단(401/403/기타) → 취약 아님.
    """
    if not a_owns:
        return None
    if b_status is None:
        return None
    if b_status in (401, 403, 405, 419):
        return None
    if 200 <= b_status < 300:
        if readback_has_marker is True:
            return "CONFIRMED_WRITE"
        return "POSSIBLE"
    if b_status in (301, 302, 303, 307, 308):
        # 리다이렉트는 앱마다 성공/실패 모두 가능 → 재조회로만 판단
        return "CONFIRMED_WRITE" if readback_has_marker is True else None
    return None


def analyze_csrf(forms: list, cookies: list | None = None) -> list:
    """상태 변경 폼의 CSRF 방어(토큰/SameSite) 부재를 탐지(요청 전송 없음, 순수 분석).

    반환: finding dict 리스트(판정은 Rule Engine 계약과 동일한 최소 필드).
    """
    findings = []
    cookies = cookies or []
    # SameSite 미설정 쿠키가 하나라도 있으면 CSRF 위험 가중
    samesite_missing = False
    for c in cookies:
        try:
            attrs = (c.get("attributes") if isinstance(c, dict) else "") or ""
            raw = (c.get("raw") if isinstance(c, dict) else str(c)) or ""
            blob = f"{attrs} {raw}".lower()
            if "samesite" not in blob:
                samesite_missing = True
        except Exception:
            continue

    for f in (forms or []):
        if not isinstance(f, dict):
            continue
        method = (f.get("method") or "GET").upper()
        url = f.get("url") or ""
        if not is_state_changing(method, url):
            continue
        params = f.get("params") or {}
        csrf_fields = list(f.get("csrf_fields") or [])
        has_token = bool(csrf_fields) or any(_CSRF_FIELD_RE.search(str(k)) for k in params)
        if has_token:
            continue  # 토큰 존재 → 이 폼은 보고하지 않음
        sev = "MEDIUM"
        detail = "상태 변경 폼에 CSRF 토큰이 없습니다."
        if samesite_missing:
            sev = "HIGH"
            detail += " 또한 SameSite 미설정 쿠키가 있어 교차 출처 요청이 세션과 함께 전송될 수 있습니다."
        findings.append({
            "judgment": "참고", "severity": sev, "confidence": "POSSIBLE",
            "force_finding_type": "attack_surface",
            "owasp": "A01:2021 - 접근 제어 취약점", "cwe": "CWE-352",
            "title": f"CSRF 방어 부재 가능성 — {method} {urlparse(url).path or url}",
            "description": detail,
            "evidence_url": url, "evidence_detail": detail,
            "recommendation": ("상태 변경 요청에 CSRF 토큰(동기화 토큰 패턴)을 적용하고, "
                               "세션 쿠키에 SameSite=Lax/Strict 를 설정하십시오."),
            "discovered_by": "authz_write.analyze_csrf",
        })
    return findings


def extract_field_value(html: str, field: str) -> str | None:
    """편집 페이지 HTML 에서 특정 필드의 현재 값을 추출(원복 정확도용). 없으면 None.

    <input name="field" value="X">, <textarea name="field">X</textarea> 지원.
    """
    if not html or not field:
        return None
    fn = re.escape(str(field))
    # input value=
    m = re.search(
        r'<input\b[^>]*\bname\s*=\s*["\']' + fn + r'["\'][^>]*\bvalue\s*=\s*["\']([^"\']*)["\']',
        html, re.IGNORECASE)
    if m:
        return m.group(1)
    # value= 가 name 앞에 오는 경우
    m = re.search(
        r'<input\b[^>]*\bvalue\s*=\s*["\']([^"\']*)["\'][^>]*\bname\s*=\s*["\']' + fn + r'["\']',
        html, re.IGNORECASE)
    if m:
        return m.group(1)
    # textarea
    m = re.search(
        r'<textarea\b[^>]*\bname\s*=\s*["\']' + fn + r'["\'][^>]*>(.*?)</textarea>',
        html, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1)
    return None


def safety_guard(candidate: dict, *, allow_destructive: bool = False) -> tuple[bool, str]:
    """실제 쓰기 시도 직전 최종 안전 점검. (진행가능?, 사유)."""
    if not isinstance(candidate, dict):
        return False, "후보 형식 오류"
    method = (candidate.get("method") or "").upper()
    url = candidate.get("url") or ""
    if is_destructive(method, url) and not allow_destructive:
        return False, "삭제 계열(되돌리기 불가) — 기본 차단"
    field = candidate.get("mutable_field")
    if not field or _SENSITIVE_FIELD_RE.search(str(field)):
        return False, "안전한 수정 필드 없음/민감 필드"
    if not candidate.get("view_url"):
        return False, "원복 확인용 조회 URL 없음"
    return True, "ok"
