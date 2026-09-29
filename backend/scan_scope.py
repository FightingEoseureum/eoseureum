"""scan_scope.py — STEP3: 스캔 거버넌스 (allow/disallow scopes + category deny list).

Xint 거버넌스 모델 대응: allow_scopes / disallow_scopes / vulnerability_category_deny_list.
- allow_scopes      : 대상과 다른 도메인이라도 명시적으로 점검을 허용할 호스트(서브도메인 포함).
- disallow_scopes   : 절대 점검하지 않을 호스트/패턴. same-domain·allow 보다 **우선**(안전 우선).
- category_deny_list: 특정 취약점 카테고리를 점검 결과에서 제외(정책상 제외 / 스코프 외 항목).

스캔별 설정은 register_scope(scan_id, ...) 로 등록하고 핫패스(스코프 가드)에서 조회한다
(active_probing 의 세션 쿠키 레지스트리와 동일한 scan_id 키 패턴). 순수 판정 함수는 레지스트리
없이도 직접 호출 가능하다(테스트·재사용 용이). active_probing 을 import 하지 않아 순환 의존 없음.
"""
import re
import urllib.parse

# scan_id -> {"allow": [...], "disallow": [...], "deny": [...]}
_SCOPE: dict = {}


def parse_list(raw) -> list[str]:
    """콤마/공백 구분 문자열 또는 리스트를 소문자 토큰 리스트로 정규화."""
    if not raw:
        return []
    items = raw if isinstance(raw, (list, tuple, set)) else re.split(r'[,\s]+', str(raw))
    return [str(s).strip().lower() for s in items if s and str(s).strip()]


def host_of(url_or_host: str) -> str:
    """URL 또는 호스트 문자열에서 호스트(포트 제외, 소문자)를 뽑는다."""
    s = (url_or_host or "").strip()
    if not s:
        return ""
    if "://" in s:
        try:
            s = urllib.parse.urlparse(s).netloc
        except Exception:
            return ""
    return s.split("@")[-1].split(":")[0].lower()


def host_matches(host: str, entry: str) -> bool:
    """host 가 scope 항목과 일치하는가 — 정확히 같거나 그 서브도메인이면 True."""
    host = (host or "").lower()
    entry = (entry or "").lower().lstrip(".")
    if not host or not entry:
        return False
    return host == entry or host.endswith("." + entry)


def host_denied(host: str, disallow: list[str] | None) -> bool:
    """host 가 disallow 목록의 어느 항목과 매칭되면 True(점검 금지)."""
    host = (host or "").lower()
    for entry in disallow or []:
        # 호스트/서브도메인 매칭 또는 부분문자열 패턴(예: 'staging.' 접두)도 허용.
        if host_matches(host, entry) or (entry and entry in host):
            return True
    return False


def host_allowed(host: str, allow: list[str] | None) -> bool:
    """host 가 allow 목록의 어느 항목과 매칭되면 True(대상 외 도메인이라도 점검 허용)."""
    for entry in allow or []:
        if host_matches(host, entry):
            return True
    return False


# 카테고리 매칭에 참고하는 finding 식별 필드(있는 것만 사용).
_CATEGORY_FIELDS = ("probe_key", "type", "check_type", "category", "kisa_category",
                    "owasp", "cwe", "title")


def is_category_denied(finding: dict, deny_list: list[str] | None) -> bool:
    """finding 의 카테고리 식별 필드 중 하나라도 deny 토큰을 포함하면 True.

    deny 토큰은 유연하게 매칭된다 — 예: 'sql', 'xss', 'csrf', '인젝션', 'a03',
    'cwe-79', 'sql_injection' 등이 모두 해당 카테고리를 걸러낸다.
    """
    if not deny_list or not isinstance(finding, dict):
        return False
    blob = " ".join(str(finding.get(k, "")) for k in _CATEGORY_FIELDS).lower()
    return any(tok and tok in blob for tok in deny_list)


# ── scan_id 레지스트리 ────────────────────────────────────────────────────────

def register_scope(scan_id: str, allow=None, disallow=None, deny=None) -> None:
    if not scan_id:
        return
    _SCOPE[str(scan_id)] = {
        "allow": parse_list(allow),
        "disallow": parse_list(disallow),
        "deny": parse_list(deny),
    }


def get_scope(scan_id: str) -> dict:
    return _SCOPE.get(str(scan_id), {"allow": [], "disallow": [], "deny": []})


def clear_scope(scan_id: str) -> None:
    _SCOPE.pop(str(scan_id), None)


def scan_host_denied(scan_id: str, host: str) -> bool:
    return host_denied(host, get_scope(scan_id)["disallow"])


def scan_host_allowed(scan_id: str, host: str) -> bool:
    return host_allowed(host, get_scope(scan_id)["allow"])


def scan_category_denied(scan_id: str, finding: dict) -> bool:
    return is_category_denied(finding, get_scope(scan_id)["deny"])
