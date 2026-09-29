"""
candidate_verification.py — 후보(candidate) → 검증(verification) 발전 로직.

오탐 방지·비파괴가 절대 원칙:
  - 브루트포스 금지, Time-based SQLi 비활성 유지(이 모듈은 SQLi 미수행).
  - 실제 데이터 변경/상태 변경 금지 — IDOR/API 검증은 GET(읽기)만, Stored XSS 는
    무해 마커만, 파일 업로드는 '분석'만(실제 업로드 금지).
  - 자동 확정 기준 유지: 명백한 증거가 있을 때만 승격, 부족하면 MANUAL_REVIEW.

네트워크 I/O 는 호출부에서 주입(get_fn 등)하여 테스트 가능하게 한다.

승격 등급:
  IDOR        : CONFIRMED_RESPONSE / POSSIBLE / MANUAL_REVIEW
  Stored XSS  : CONFIRMED_BROWSER / MANUAL_REVIEW
  CSRF        : 위험도(LOW/MEDIUM/HIGH) 평가만 — 자동 확정 없음(MANUAL_REVIEW 유지)
"""
from __future__ import annotations

import hashlib
import re

# ── 공통 헬퍼 ────────────────────────────────────────────────────────────────
def _body_hash(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8", "ignore")).hexdigest()


def _len(body: str) -> int:
    return len(body or "")


def _len_ratio(a: str, b: str) -> float:
    """두 본문 길이의 상대 차이(0=동일, 1=완전히 다름)."""
    la, lb = _len(a), _len(b)
    if la == 0 and lb == 0:
        return 0.0
    return abs(la - lb) / max(la, lb, 1)


def _is_login_redirect(status: int, headers: dict) -> bool:
    if status not in (301, 302, 303, 307, 308):
        return False
    loc = ""
    for k, v in (headers or {}).items():
        if k.lower() == "location":
            loc = str(v).lower()
    return any(t in loc for t in ("login", "signin", "auth", "logon"))


# ── 1. IDOR 교차 계정 검증 ────────────────────────────────────────────────────
# 계정 A 가 소유/조회 가능한 객체를, 계정 B 세션으로 접근해 응답을 비교한다(읽기 전용).
def compare_idor(owner: dict, cross: dict, *,
                 owner_identity: list[str] | None = None,
                 cross_identity: list[str] | None = None) -> dict:
    """IDOR 교차 접근 응답 비교 → 등급 산정.

    owner : 계정 A 가 자기 객체 접근 응답 {status, body, headers}
    cross : 계정 B 가 '동일 A 객체' 접근 응답 {status, body, headers}
    owner_identity : A 의 식별 토큰(아이디/이메일/이름 등) — B 응답에 나타나면 A 데이터 노출 증거
    cross_identity : B 의 식별 토큰 — B 응답에 B 자신의 정보만 있으면 우회 아님

    반환: {grade, reasons[], signals{}}
    grade ∈ {CONFIRMED_RESPONSE, POSSIBLE, MANUAL_REVIEW}
    """
    owner_identity = [t for t in (owner_identity or []) if t]
    cross_identity = [t for t in (cross_identity or []) if t]
    o_status = owner.get("status", 0)
    c_status = cross.get("status", 0)
    o_body = owner.get("body", "") or ""
    c_body = cross.get("body", "") or ""
    c_headers = cross.get("headers", {}) or {}

    signals = {
        "owner_status": o_status, "cross_status": c_status,
        "owner_len": _len(o_body), "cross_len": _len(c_body),
        "len_ratio": round(_len_ratio(o_body, c_body), 4),
        "hash_equal": bool(o_body) and _body_hash(o_body) == _body_hash(c_body),
        "owner_identity_in_cross": False,
        "cross_identity_in_cross": False,
        "cross_blocked": False,
    }
    reasons: list[str] = []

    # 1) B 접근이 차단됨 → 권한 통제가 동작 → 우회 증거 없음(MANUAL_REVIEW 유지)
    if c_status in (401, 403) or _is_login_redirect(c_status, c_headers):
        signals["cross_blocked"] = True
        reasons.append(f"계정 B 접근이 차단됨(status={c_status}) — 접근 통제 동작, 우회 증거 없음")
        return {"grade": "MANUAL_REVIEW", "reasons": reasons, "signals": signals}

    # 2) B 가 정상 응답(200) 을 받지 못함 → 증거 부족
    if c_status != 200 or not c_body:
        reasons.append(f"계정 B 응답이 200/본문이 아님(status={c_status}) — 증거 부족")
        return {"grade": "MANUAL_REVIEW", "reasons": reasons, "signals": signals}

    # 3) A 의 식별 토큰이 B 응답에 나타남 → B 가 A 의 데이터를 봄(강한 증거)
    low_c = c_body.lower()
    owner_hit = [t for t in owner_identity if t.lower() in low_c]
    cross_hit = [t for t in cross_identity if t.lower() in low_c]
    signals["owner_identity_in_cross"] = bool(owner_hit)
    signals["cross_identity_in_cross"] = bool(cross_hit)

    body_similar = signals["hash_equal"] or signals["len_ratio"] <= 0.05

    if owner_hit and (body_similar or signals["len_ratio"] <= 0.15):
        # B 응답에 A 의 식별정보가 노출 + 응답이 A 것과 유사 → 권한 우회 실증(응답 기반)
        reasons.append(
            f"계정 B 응답에 계정 A 식별정보({', '.join(owner_hit)[:60]}) 노출 + "
            f"응답 유사(len_ratio={signals['len_ratio']}, hash_equal={signals['hash_equal']})"
        )
        return {"grade": "CONFIRMED_RESPONSE", "reasons": reasons, "signals": signals}

    # 4) A 와 응답이 매우 유사하지만 A 식별정보가 명확치 않음 → 가능성
    if body_similar and not cross_hit:
        reasons.append(
            f"계정 B 응답이 계정 A 응답과 매우 유사(len_ratio={signals['len_ratio']}, "
            f"hash_equal={signals['hash_equal']})하나 A 식별정보 미검출 — 가능성"
        )
        return {"grade": "POSSIBLE", "reasons": reasons, "signals": signals}

    # 5) 그 외(B 자신의 데이터/다른 내용) → 증거 부족
    if cross_hit:
        reasons.append("계정 B 응답에 B 자신의 식별정보만 존재 — 우회 아님(증거 없음)")
    else:
        reasons.append(f"응답이 충분히 유사하지 않음(len_ratio={signals['len_ratio']}) — 증거 부족")
    return {"grade": "MANUAL_REVIEW", "reasons": reasons, "signals": signals}


async def verify_idor_candidates(candidates, get_a, get_b, *,
                                 owner_identity=None, cross_identity=None,
                                 max_targets: int = 20) -> list[dict]:
    """IDOR 후보를 두 계정으로 교차 검증한다(읽기 전용 GET 만, 비파괴).

    candidates : [{url, method, param, ...}] — GET 후보만 검증(상태변경 메서드 제외).
    get_a(url) / get_b(url) : 각 계정 세션의 GET → {status, body, headers} (주입).
    반환: [{candidate, grade, reasons, signals}] (grade 승격 기준은 compare_idor).
    """
    results: list[dict] = []
    seen: set = set()
    n = 0
    for cand in candidates or []:
        if n >= max_targets:
            break
        method = (cand.get("method") or "GET").upper()
        url = cand.get("url", "")
        if method != "GET" or not url:
            continue  # 상태 변경 가능 메서드는 검증하지 않음(비파괴)
        if url in seen:
            continue
        seen.add(url)
        n += 1
        try:
            owner = await get_a(url)
            cross = await get_b(url)
        except Exception:
            continue
        verdict = compare_idor(owner or {}, cross or {},
                               owner_identity=owner_identity,
                               cross_identity=cross_identity)
        results.append({"candidate": cand, **verdict})
    return results


# ── 2. CSRF 위험도 평가 ──────────────────────────────────────────────────────
_SENSITIVE_FUNC_RE = re.compile(
    r"(change.?password|reset.?password|passwd|account.?delete|delete.?account|"
    r"deactivate|remove.?user|role|grant|permission|privilege|admin|transfer|"
    r"withdraw|payment|order|approve|approval|비밀번호|계정\s*삭제|권한|이체|결제|승인)",
    re.IGNORECASE,
)


def score_csrf_risk(candidate: dict) -> dict:
    """CSRF 후보의 추천 위험도(LOW/MEDIUM/HIGH) 산정. 자동 확정은 하지 않는다.

    candidate 기대 키:
      url, method, params(list), authenticated(bool), token_present(bool),
      samesite(str|None), state_changing(bool)
    """
    url = candidate.get("url", "") or ""
    params = candidate.get("params") or []
    method = (candidate.get("method") or "GET").upper()
    authenticated = bool(candidate.get("authenticated"))
    token_present = bool(candidate.get("token_present"))
    samesite = (candidate.get("samesite") or "").lower()
    state_changing = candidate.get("state_changing")
    if state_changing is None:
        state_changing = method in ("POST", "PUT", "DELETE", "PATCH")

    text = url + " " + " ".join(str(p) for p in params)
    sensitive = bool(_SENSITIVE_FUNC_RE.search(text))
    samesite_weak = samesite in ("", "none")

    reasons: list[str] = []
    if sensitive:
        reasons.append("민감 기능(비밀번호/계정/권한/결제 등) 관련")
    if not token_present:
        reasons.append("anti-CSRF 토큰 부재")
    else:
        reasons.append("CSRF 토큰 존재(검증 여부는 수동 확인)")
    if samesite_weak:
        reasons.append(f"세션 쿠키 SameSite 미흡({samesite or '미설정'})")
    if authenticated:
        reasons.append("인증 필요 기능")
    if state_changing:
        reasons.append(f"상태 변경 요청({method})")

    # 위험도 규칙 — 자동 확정 아님(추천값)
    #  HIGH   : 토큰 부재 + 상태 변경 + 민감 기능 (+ SameSite 미흡이면 더 확실)
    #  MEDIUM : 토큰 부재 + 상태 변경 (민감 기능 아님)
    #  LOW    : 그 외(토큰 존재 또는 비상태변경 등)
    risk = "LOW"
    if state_changing and not token_present:
        risk = "HIGH" if sensitive else "MEDIUM"
    # SameSite 가 적절히 설정되어 있고 토큰도 있으면 위험을 낮춤
    if token_present and not samesite_weak:
        risk = "LOW"

    return {"risk": risk, "sensitive": sensitive,
            "samesite_weak": samesite_weak, "token_present": token_present,
            "state_changing": state_changing, "reasons": reasons}


# ── 3. 인증 후 Stored XSS 판정 ────────────────────────────────────────────────
def judge_stored_xss(*, marker_reflected: bool, alert_fired: bool) -> str | None:
    """저장형 XSS 판정.
    alert_fired(실제 브라우저 alert) → CONFIRMED_BROWSER
    marker 재출현만 → MANUAL_REVIEW(실행 미확인)
    그 외 → None
    """
    if alert_fired:
        return "CONFIRMED_BROWSER"
    if marker_reflected:
        return "MANUAL_REVIEW"
    return None


# ── 4. 파일 업로드 분석(실제 업로드 금지, 폼 분석만) ─────────────────────────────
def analyze_file_upload_forms(forms: list[dict]) -> list[dict]:
    """multipart/form-data + file input 폼을 찾아 업로드 통제 정보를 수집한다.

    forms 각 항목 기대 키(있으면 사용): url, enctype, method, file_inputs[{name, accept}],
    action_url. 실제 파일 업로드/웹쉘 업로드는 수행하지 않는다.
    """
    out: list[dict] = []
    for fm in forms or []:
        file_inputs = fm.get("file_inputs") or []
        enctype = (fm.get("enctype") or "").lower()
        is_multipart = "multipart/form-data" in enctype
        if not file_inputs and not is_multipart:
            continue
        accepts = [fi.get("accept", "") for fi in file_inputs]
        has_accept = any(a for a in accepts)
        out.append({
            "url": fm.get("url") or fm.get("action_url", ""),
            "method": (fm.get("method") or "POST").upper(),
            "multipart": is_multipart,
            "file_input_names": [fi.get("name", "") for fi in file_inputs],
            "accept_attr": [a for a in accepts if a],
            "extension_restriction": "client-accept" if has_accept else "unknown",
            "note": "실제 업로드 미수행 — 서버측 확장자/콘텐츠 검증은 수동 확인 필요",
        })
    return out


# ── 5. Business Logic 후보 분류 ───────────────────────────────────────────────
_BUSINESS_LOGIC_PARAMS = {
    "role", "admin", "isadmin", "is_admin", "price", "amount", "discount",
    "point", "points", "balance", "approval", "approve", "permission",
    "permissions", "grade", "level", "qty", "quantity", "cost", "total",
}


def classify_business_logic_params(points: list[dict]) -> list[dict]:
    """입력점에서 비즈니스 로직 민감 파라미터를 후보로 수집(가격/권한/포인트 등)."""
    cands: list[dict] = []
    seen: set = set()
    for pt in points or []:
        params = pt.get("params") or {}
        method = (pt.get("method") or "GET").upper()
        for k in params:
            base = str(k).lower().replace("-", "").replace("_", "")
            if base not in {n.replace("_", "") for n in _BUSINESS_LOGIC_PARAMS}:
                continue
            url = pt.get("url", "")
            key = (method, url, base)
            if key in seen:
                continue
            seen.add(key)
            cands.append({
                "url": url, "method": method, "param": k,
                "sample_value": str(params.get(k, ""))[:40],
            })
    return cands


# ── 검증 요약(보고서용): 후보 → 검증 → 승격/미승격 카운트 ─────────────────────
_PROMOTED_GRADES = {"CONFIRMED_RESPONSE", "CONFIRMED_BROWSER", "POSSIBLE"}


def summarize_verification(candidates: int, verified: int, results: list[str]) -> dict:
    """후보/검증/승격/미승격 카운트 요약.
    results: 검증 결과 등급 문자열 목록(예: ["CONFIRMED_RESPONSE","MANUAL_REVIEW",...]).
    """
    promoted = sum(1 for g in results if g in _PROMOTED_GRADES)
    manual = sum(1 for g in results if g == "MANUAL_REVIEW")
    return {
        "candidates": int(candidates),
        "verified": int(verified),
        "promoted": promoted,
        "manual_review": manual,
    }
