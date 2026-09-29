"""
authz_matrix.py — BFLA(Broken Function-Level Authorization) 인가 매트릭스 '순수 로직'.

목적:
  "관리/특권 기능 엔드포인트에 낮은 권한(익명·일반계정 B)이 접근 가능한가"를 검증하기 위한
  후보 수집·응답 분류·판정 로직. 네트워크 실행은 authenticated_scan.verify_bfla_matrix 가 담당.

안전 원칙:
  - BFLA 접근 검증은 '읽기 전용(GET)'으로 접근 통제 상태만 관측한다(상태 변경 없음 → SAFE).
  - 판정은 익명/계정B/계정A 의 접근 결과 매트릭스와 (알려진 경우) 권한 등급으로만 내린다.
  - 이 모듈은 네트워크를 하지 않으며 예외를 던지지 않는다.

매트릭스(행=특권 엔드포인트, 열=접근 주체[anon/B/A], 셀=접근 결과[allowed/denied/notfound/error]).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# 특권(관리/내부/기능) 경로 패턴 — 이 경로들이 낮은 권한에 열리면 BFLA 신호.
PRIVILEGED_RE = re.compile(
    r"(^|/)(admin|administrator|manage|manager|backend|console|superadmin|sysadmin|"
    r"webadmin|cms|panel|dashboard)(/|$)"
    r"|/api/(admin|users?|accounts?|config|configuration|settings?|system|internal|"
    r"private|management|manage)"
    r"|/api/v\d+/(admin|users?|config)",
    re.IGNORECASE)

# 응답이 '로그인/거부 페이지'임을 시사하는 표지(2xx 인데 실제로는 접근 거부)
_DENY_BODY_RE = re.compile(
    r"(type\s*=\s*[\"']password|sign\s*in|로그인|아이디.*비밀번호|"
    r"unauthorized|forbidden|access\s*denied|권한이?\s*없|접근\s*권한|"
    r"please\s*log\s*in|session\s*expired|세션\s*만료|로그인이?\s*필요)",
    re.IGNORECASE)

# 접근 결과 상수
ALLOWED = "allowed"
DENIED = "denied"
NOTFOUND = "notfound"
ERROR = "error"


# 정적 에셋 확장자 — 이런 파일은 '특권 엔드포인트'가 아니다(공개 서빙이 정상).
# 예: /_nuxt/pages/admin/api.<hash>.js 같은 SPA 빌드 번들이 경로에 'admin' 을 포함한다고
# 무인증 관리기능 접근으로 오판되던 오탐 방지.
_STATIC_EXT = (".js", ".mjs", ".css", ".map", ".json", ".woff", ".woff2", ".ttf", ".otf",
               ".eot", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
               ".avif", ".mp4", ".mp3", ".webm", ".pdf", ".zip")
_STATIC_DIR_RE = re.compile(r'/(?:_nuxt|_next|static|assets|dist|build|chunks?)/', re.IGNORECASE)


def _is_static_path(path: str) -> bool:
    p = (path or "").split("?", 1)[0].split("#", 1)[0].lower().rstrip("/")
    return p.endswith(_STATIC_EXT) or bool(_STATIC_DIR_RE.search(p))


def is_privileged(url: str) -> bool:
    """URL 경로가 관리/특권 기능으로 보이는지. 단, 정적 에셋(JS/CSS/빌드 번들)은 제외."""
    try:
        path = urlparse(url or "").path or ""
    except Exception:
        return False
    if _is_static_path(path):
        return False   # 정적 파일은 공개가 정상 — 특권 엔드포인트 아님(오탐 방지)
    return bool(PRIVILEGED_RE.search(path))


def _norm_url(url: str) -> str:
    try:
        p = urlparse((url or "").strip())
        if p.scheme not in ("http", "https"):
            return ""
        return f"{p.scheme}://{p.netloc}{(p.path or '/').rstrip('/') or '/'}"
    except Exception:
        return ""


def gather_privileged_endpoints(host_results: list, extra_urls: list | None = None,
                                max_n: int = 60) -> list:
    """discovery 결과에서 특권 엔드포인트 후보를 모은다.

    후보 dict: {url, kind}  (kind: admin_page|admin_api|function)
    - discovery_result.admin_hits → admin_page, api_hits → admin_api
    - discovered_urls / extra_urls 중 is_privileged 인 것 → function
    경로 기준 중복 제거.
    """
    out, seen = [], set()

    def _add(url, kind):
        n = _norm_url(url)
        if not n or n in seen or not is_privileged(n):
            return
        seen.add(n)
        out.append({"url": url, "kind": kind})

    for hr in host_results or []:
        for svc in (hr.get("services") or []):
            dr = svc.get("discovery_result") or {}
            for a in (dr.get("admin_hits") or []):
                if isinstance(a, dict) and a.get("url"):
                    _add(a["url"], "admin_page")
            for a in (dr.get("api_hits") or []):
                if isinstance(a, dict) and a.get("url"):
                    _add(a["url"], "admin_api")
            for u in (svc.get("discovered_urls") or []):
                _add(u, "function")
    for u in (extra_urls or []):
        _add(u, "function")
    return out[:max_n]


def classify_access(status: int | None, body: str | None) -> str:
    """단일 응답을 접근 결과로 분류. (redirect 는 allow_redirects=False 전제로 거부로 간주)."""
    if status is None:
        return ERROR
    if status == 0 or status >= 500:
        return ERROR
    if status in (404, 410):
        return NOTFOUND
    if status in (401, 403):
        return DENIED
    if 300 <= status < 400:
        return DENIED  # 로그인 등으로의 리다이렉트 = 접근 통제됨
    if 200 <= status < 300:
        # 2xx 라도 본문이 로그인/거부 페이지면 실제로는 거부
        if body and _DENY_BODY_RE.search(body[:4000]):
            return DENIED
        return ALLOWED
    return DENIED


def role_rank(role: str) -> int:
    """권한 등급 랭크(높을수록 상위). 미지정/미상=0."""
    r = (role or "").strip().lower()
    if not r:
        return 0
    if any(k in r for k in ("admin", "superuser", "root", "manager", "관리", "super", "staff")):
        return 3
    if any(k in r for k in ("user", "member", "guest", "일반", "회원", "customer", "basic")):
        return 1
    return 2  # 알려졌으나 분류 애매 → 중간


def judge_bfla(anon: str | None, b: str | None, a: str | None,
               role_a: str = "", role_b: str = "") -> tuple[str | None, str, str]:
    """BFLA 판정. 반환 (grade, category, reason).

    grade: CONFIRMED | POSSIBLE | None
    - anon 이 특권 기능에 ALLOWED → CONFIRMED(missing_auth, 인증 없이 접근)
    - B(인증 계정)가 ALLOWED:
        · 역할 등급이 알려졌고 B<A → CONFIRMED(bfla, 저권한이 고권한 기능 접근)
        · B>=A(동급/상위) → None(정상)
        · 역할 미상 → POSSIBLE(권한 등급 확인 필요)
    - 그 외(B DENIED 등) → None
    """
    if anon == ALLOWED:
        return ("CONFIRMED", "missing_auth", "인증 없이 관리/특권 기능에 접근 가능")
    if b == ALLOWED:
        ra, rb = role_rank(role_a), role_rank(role_b)
        if ra and rb:
            if rb < ra:
                return ("CONFIRMED", "bfla", "저권한 계정(B)이 상위 권한 전용 기능에 접근")
            return (None, "", "B 가 동급/상위 권한 — 접근 정상")
        return ("POSSIBLE", "bfla",
                "인증 계정(B)이 관리/특권 기능에 접근 — 계정 권한 등급 확인 필요")
    return (None, "", "B 차단 — 정상 통제")


def build_matrix(results: list) -> dict:
    """결과 리스트를 리포트용 매트릭스로 정리."""
    rows = []
    for r in results or []:
        ep = r.get("endpoint") or {}
        rows.append({
            "url": ep.get("url", ""), "kind": ep.get("kind", ""),
            "anon": r.get("anon"), "B": r.get("b"), "A": r.get("a"),
            "grade": r.get("grade"), "category": r.get("category", ""),
        })
    return {"columns": ["anon", "B", "A"], "rows": rows}


def summarize(results: list) -> dict:
    confirmed = sum(1 for r in (results or []) if r.get("grade") == "CONFIRMED")
    possible = sum(1 for r in (results or []) if r.get("grade") == "POSSIBLE")
    return {"tested": len(results or []), "confirmed": confirmed, "possible": possible}
