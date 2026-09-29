"""
discovery_policy.py — Browser Discovery 안전 정책 + 예산(Budget).

원칙: 기본 비활성화, GET/Navigation 중심의 '안전한 탐색'만. 상태 변경 유발 요소는 클릭하지
않고 기록만 한다. 모든 한계값은 env 로 조정 가능하며 초과 시 정상 종료(partial result).
"""
from __future__ import annotations

import os
from urllib.parse import urlparse


def _b(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _i(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


# ── 활성화 플래그(기본 OFF — 기존 동작 보존) ────────────────────────────────────
def enabled() -> bool:
    return _b("ENABLE_BROWSER_DISCOVERY", False)


# 클라이언트 렌더(SPA) 프레임워크 — 이 경우 서버 HTML 만으론 표면이 거의 안 보여
# 브라우저 발견이 사실상 필수. 감지되면 자동 활성(BROWSER_DISCOVERY_AUTO 로 끌 수 있음).
_SPA_FRAMEWORKS = {"next.js", "nuxt", "react", "vue.js", "vue", "angular", "svelte", "sveltekit"}


def auto_enable_for_tech(technologies: list | None) -> bool:
    """recon 기술스택에 SPA 프레임워크가 감지되면 브라우저 발견을 자동 활성한다.
    BROWSER_DISCOVERY_AUTO=false 로 비활성 가능(기본 활성)."""
    if not _b("BROWSER_DISCOVERY_AUTO", True):
        return False
    for t in (technologies or []):
        name = (t.get("name") if isinstance(t, dict) else str(t)) or ""
        if name.strip().lower() in _SPA_FRAMEWORKS:
            return True
    return False


def auth_crawl_enabled() -> bool:
    return _b("ENABLE_AUTH_BROWSER_CRAWL", False)


def graphql_enabled() -> bool:
    return _b("ENABLE_GRAPHQL_DISCOVERY", True)


def websocket_enabled() -> bool:
    return _b("ENABLE_WEBSOCKET_DISCOVERY", True)


def websocket_message_capture_enabled() -> bool:
    return _b("ENABLE_WEBSOCKET_MESSAGE_CAPTURE", False)


def budget() -> dict:
    return {
        "max_pages": _i("BROWSER_DISCOVERY_MAX_PAGES", 100),
        "max_requests": _i("BROWSER_DISCOVERY_MAX_REQUESTS", 1000),
        "timeout": _i("BROWSER_DISCOVERY_TIMEOUT", 1800),
        "max_depth": _i("BROWSER_DISCOVERY_MAX_DEPTH", 3),
        "max_browser": _i("BROWSER_DISCOVERY_MAX_BROWSER", 1),
        "max_contexts": _i("BROWSER_DISCOVERY_MAX_CONTEXTS", 2),
        "rate_limit": _i("BROWSER_DISCOVERY_RATE_LIMIT", 5),
        "same_origin_only": _b("BROWSER_DISCOVERY_SAME_ORIGIN_ONLY", True),
    }


# ── Safe Click Exploration: 상태 변경 유발 키워드 차단 ───────────────────────────
BLOCKED_CLICK_KEYWORDS = [
    "delete", "remove", "logout", "sign out", "signout", "submit", "save", "update",
    "create", "approve", "pay", "payment", "checkout", "transfer", "withdraw", "upload",
    "change", "modify", "cancel", "confirm", "purchase", "order", "subscribe", "unsubscribe",
    "reset", "deactivate", "disable", "enable", "grant", "revoke",
    "탈퇴", "삭제", "수정", "저장", "등록", "승인", "결제", "송금", "업로드", "취소",
    "제출", "변경", "확인", "구매", "주문", "발송", "전송", "로그아웃",
]

# 상태 변경 메서드(자동 제출 금지)
STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def same_origin(url: str, base_url: str) -> bool:
    a, b = _host(url), _host(base_url)
    return bool(a) and a == b


def in_scope(url: str, base_url: str, scope: list | None = None) -> bool:
    """same-origin 우선. scope 목록이 있으면 해당 host 도 허용."""
    h = _host(url)
    if not h:
        return False
    if same_origin(url, base_url):
        return True
    if not budget()["same_origin_only"] and scope:
        norm = [str(s).strip().lower() for s in scope if s]
        return any(h == s or h.endswith("." + s) for s in norm)
    return False


def is_safe_click(*, text: str = "", href: str = "", role: str = "",
                  onclick: str = "", element_type: str = "") -> dict:
    """클릭 요소가 상태 변경을 유발하지 않는 '안전한' 요소인지 판정.

    반환: {"safe": bool, "reason": str}. 위험 키워드/제출/상태변경 신호가 있으면 unsafe.
    """
    blob = " ".join([text or "", href or "", role or "", onclick or "", element_type or ""]).lower()
    for kw in BLOCKED_CLICK_KEYWORDS:
        if kw in blob:
            return {"safe": False, "reason": f"상태 변경 유발 키워드 감지: '{kw}'"}
    et = (element_type or "").lower()
    if et in ("submit", "button[type=submit]"):
        return {"safe": False, "reason": "form submit 요소는 자동 클릭 금지"}
    if (onclick or "") and any(m in onclick.lower() for m in ("post(", "delete(", "put(", "patch(")):
        return {"safe": False, "reason": "상태 변경 요청을 유발하는 onclick"}
    # javascript: 스킴/외부 링크는 네비게이션만 허용(별도 same-origin 검사에서 처리)
    return {"safe": True, "reason": "안전한 네비게이션 요소"}


def is_safe_navigation(method: str) -> bool:
    """GET/HEAD 등 조회성 네비게이션만 안전."""
    return (method or "GET").upper() not in STATE_METHODS
