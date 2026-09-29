"""csrf_dynamic.py — 동적 CSRF 검증 (강제 여부 실측, 인증정보 독립, 비파괴).

정적 탐지(토큰/SameSite 부재)를 넘어, 상태 변경 요청을 '토큰 제거 + 교차출처 Origin/Referer'
로 재전송해 서버가 수락하는지 관측한다. 수락되면 CSRF 방어가 실제로 강제되지 않는 것.

원칙:
  - 인증정보 독립: 세션쿠키 있으면 사용, 없어도 엔드포인트의 강제 여부는 확인 가능.
  - 비파괴: POST 상태변경 폼만, 비가역/민감 키워드(delete/transfer/password/admin 등) 제외,
    무해 마커 데이터, 폼당 1회.
  - 심각도 = '영향 기반'(익명이라고 무조건 LOW 아님). 공유상태/게시·피드백·구독 등 가용성·무결성
    영향이면 MEDIUM+, 진짜 무영향만 LOW. 로그인 CSRF 는 클래스가 약해 LOW.
  - 판정 불변: 최종 verdict/Severity 는 Rule Engine 전담. 본 모듈은 증거/후보만 산출.

HTTP I/O 는 주입 가능한 콜러블(post_fn)로 받아 테스트에서 monkeypatch 한다.
"""
from __future__ import annotations

import urllib.parse

FORGED_ORIGIN = "https://eoseureum-csrf-probe.example"

# 상태값
CSRF_ENFORCEMENT_MISSING = "CSRF_ENFORCEMENT_MISSING"   # 교차출처+토큰없이 수락 → 방어 미강제
CSRF_ENFORCED = "CSRF_ENFORCED"                          # 거부됨 → 방어 동작
SKIPPED_NOT_STATE_CHANGING = "SKIPPED_NOT_STATE_CHANGING"
SKIPPED_DESTRUCTIVE = "SKIPPED_DESTRUCTIVE"
ERROR = "ERROR"

# 비가역/민감 액션 → 동적 검증 제외(정적 참고로만)
_DESTRUCTIVE_HINT = ("delete", "remove", "destroy", "drop", "transfer", "withdraw", "pay",
                     "payment", "purchase", "order", "checkout", "password", "passwd", "admin",
                     "grant", "revoke", "deactivate", "unregister", "withdrawal",
                     "송금", "결제", "삭제", "탈퇴")
_TOKEN_NAME_HINT = ("csrf", "xsrf", "authenticity", "_token", "token", "nonce")
# 공유상태/가용성 영향(→ MEDIUM+) 힌트
_SHARED_STATE_HINT = ("post", "comment", "board", "feedback", "subscribe", "review", "message",
                      "write", "reply", "guestbook", "vote", "rating",
                      "글", "댓글", "게시", "구독", "방명록")
_CSRF_REJECT_HINT = ("csrf", "invalid token", "forbidden", "not allowed", "access denied",
                     "잘못된 요청", "유효하지 않", "권한이 없")


def group_post_forms(points: list[dict]) -> list[dict]:
    """input_points.parse_forms 결과를 (url) 기준 POST 폼으로 그룹화(action/fields)."""
    forms: dict = {}
    for p in (points or []):
        if str(p.get("method", "GET")).upper() != "POST":
            continue
        key = p.get("url") or ""
        if not key:
            continue
        f = forms.setdefault(key, {"action": key, "method": "POST", "fields": []})
        nm = p.get("param")
        if nm and nm not in f["fields"]:
            f["fields"].append(nm)
    return list(forms.values())


def is_destructive(form: dict) -> bool:
    blob = (str(form.get("action", "")) + " "
            + " ".join(str(x) for x in (form.get("fields") or []))).lower()
    return any(h in blob for h in _DESTRUCTIVE_HINT)


def _strip_tokens(data: dict) -> dict:
    return {k: v for k, v in data.items()
            if not any(h in str(k).lower() for h in _TOKEN_NAME_HINT)}


def _curl_repro(url: str, data: dict, headers: dict) -> str:
    """재현용 curl 명령(텍스트 PoC). 교차출처 헤더 + 토큰 제거 body 그대로."""
    body = urllib.parse.urlencode(data)
    hs = " ".join(f"-H '{k}: {v}'" for k, v in (headers or {}).items())
    return f"curl -i -X POST {hs} --data '{body}' '{url}'"


def _accepted(resp: dict) -> bool:
    """수락 판정: 2xx/3xx 이고 CSRF/토큰 거부 신호가 본문에 없음."""
    st = int(resp.get("status", 0) or 0)
    body = (resp.get("body", "") or "").lower()
    if any(k in body for k in _CSRF_REJECT_HINT):
        return False
    return 200 <= st < 400


def impact_severity(form: dict, *, has_session: bool) -> str:
    """영향 기반 심각도(익명=무조건 LOW 아님)."""
    blob = (str(form.get("action", "")) + " "
            + " ".join(str(x) for x in (form.get("fields") or []))).lower()
    if "login" in blob or "dologin" in blob:
        return "LOW"                        # 로그인 CSRF 는 클래스 약함
    shared = any(h in blob for h in _SHARED_STATE_HINT)
    if has_session and shared:
        return "HIGH"                       # 세션 신원 + 공유상태
    if has_session or shared:
        return "MEDIUM"                     # 세션 결부 or 공유상태·가용성 영향
    return "LOW"                            # 완전 익명·자기범위·무영향


async def verify_csrf(form: dict, post_fn, *, has_session: bool = False,
                      benign_data: dict | None = None) -> dict:
    """단일 폼 동적 CSRF 검증. post_fn(url, data, headers) -> {status, body, final_url}."""
    action = form.get("action")
    if not action or str(form.get("method", "GET")).upper() != "POST":
        return {"status": SKIPPED_NOT_STATE_CHANGING, "action": action}
    if is_destructive(form):
        return {"status": SKIPPED_DESTRUCTIVE, "action": action}
    data = dict(benign_data or {})
    for fn in (form.get("fields") or []):
        data.setdefault(str(fn), "EOSEUREUM_CSRF_PROBE")
    data = _strip_tokens(data)
    headers = {"Origin": FORGED_ORIGIN, "Referer": FORGED_ORIGIN + "/attacker"}
    try:
        resp = await post_fn(action, data, headers) or {}
    except Exception:
        return {"status": ERROR, "action": action}
    if _accepted(resp):
        st = resp.get("status")
        body_str = urllib.parse.urlencode(data)
        curl = _curl_repro(action, data, headers)
        # 텍스트 PoC — 요청 원문 + 응답 + 재현 명령(스크린샷 대신 재현 가능한 증거).
        poc = (
            "[CSRF 동적 실증 — 교차출처 상태변경 요청 수락]\n"
            f"요청: POST {action}\n"
            f"헤더: Origin: {headers.get('Origin')} / Referer: {headers.get('Referer')} (공격자 출처)\n"
            f"본문: {body_str}  (CSRF 토큰 필드 제거함)\n"
            f"응답: HTTP {st} → 수락(요청 처리됨)\n"
            f"재현: {curl}\n"
            "판정 근거: 정상 폼과 다른 출처에서, CSRF 토큰 없이 보낸 상태변경 요청을 서버가 "
            "그대로 수락 → 토큰/Origin 미강제 = CSRF 방어 부재."
            + ("" if has_session else "\n비고: 익명 세션 — 악용 영향은 액션 영향도에 따름."))
        return {
            "status": CSRF_ENFORCEMENT_MISSING, "action": action,
            "severity": impact_severity(form, has_session=has_session),
            "response_status": st, "has_session": has_session,
            "request": {"method": "POST", "url": action, "headers": dict(headers), "body": body_str},
            "curl": curl, "poc": poc,
            "evidence": poc,
        }
    return {"status": CSRF_ENFORCED, "action": action, "response_status": resp.get("status")}
