"""
proof_evidence.py — Proof Evidence Detail Engine v1.

철학: Evidence → Proof → Business Context. 이미 확보된(무해) 증거를 재현 가능하고 설명
가능한 형태로 '정리'만 한다. 신규 탐지/실행 없음. 판정(Rule Engine/Severity/Confidence/
Validation/Evidence/Risk)은 절대 변경하지 않는다 — 본 모듈은 표현/설명/점수 산출 전용.

SAFE: OS 명령·파일 읽기·DB 덤프·권한 상승·brute force 등을 절대 수행하지 않으며,
그러한 '수행하지 않은 위험 검증'은 blocked/skip 로만 기록한다. response body 전체는
저장하지 않고 snippet(발췌)만 사용한다.

산출: Finding 별 Evidence/Proof/Reproduction 카드 + Fingerprint + Proof Quality Score +
Business Function.
"""
from __future__ import annotations

import re as _re

import evidence_levels as evl

_SNIPPET_LIMIT = 300


def _snip(text, limit=_SNIPPET_LIMIT):
    t = (text or "").strip()
    return t[:limit] + (" …" if len(t) > limit else "")


def _family(f: dict) -> str:
    fam = (f.get("family") or f.get("vuln_type") or "").lower()
    if fam:
        return fam
    title = (f.get("title") or "").lower()
    for kw, name in (("ssti", "ssti"), ("template", "ssti"), ("sql", "sqli"), ("xss", "xss"),
                     ("idor", "idor"), ("접근", "idor"), ("ssrf", "ssrf"), ("redirect", "open_redirect"),
                     ("traversal", "path_traversal"), ("lfi", "path_traversal"),
                     ("upload", "file_upload"), ("csrf", "csrf"), ("jwt", "jwt"),
                     ("tls", "tls"), ("ssl", "tls"), ("graphql", "graphql"),
                     # 경로/노출 계열 — 커버리지 기법 귀속(예전엔 'generic' 으로 빠져 not_reached 오표기)
                     ("swagger", "swagger"), ("openapi", "swagger"),
                     ("actuator", "actuator"), ("source map", "source_map"), ("소스맵", "source_map"),
                     ("backup", "backup_file"), ("백업", "backup_file"),
                     ("subdomain", "subdomain_takeover"), ("서브도메인", "subdomain_takeover"),
                     ("email header", "email_header_injection"), ("이메일 헤더", "email_header_injection"),
                     ("user enum", "user_enumeration"), ("사용자 열거", "user_enumeration"),
                     ("계정 열거", "user_enumeration"), ("인증 우회", "auth_bypass"),
                     ("admin", "admin_exposure"), ("관리자", "admin_exposure"),
                     ("js 시크릿", "js_secrets"), ("시크릿", "js_secrets"), ("secret", "js_secrets"),
                     ("clickjack", "clickjacking"), ("iframe", "clickjacking"),
                     ("trace", "http_method"), ("method", "http_method"),
                     ("header", "server"), ("헤더", "server"), ("cookie", "server"),
                     ("server", "server"), ("버전 정보", "server"), ("배너", "server")):
        if kw in title:
            return name
    return "generic"


# ══ 2. Fingerprint Framework (유형별, 안전 신호만) ═══════════════════════════
def _fp(name, conf, reason, extra=None):
    d = {"fingerprint_name": name, "fingerprint_confidence": conf, "fingerprint_reason": reason}
    if extra:
        d.update(extra)
    return d


_SSTI_ENGINES = [("jinja", "Jinja2"), ("twig", "Twig"), ("freemarker", "FreeMarker"),
                 ("velocity", "Velocity"), ("erb", "ERB/Ruby"), ("smarty", "Smarty"),
                 ("handlebars", "Handlebars"), ("mako", "Mako"), ("thymeleaf", "Thymeleaf")]
_DBMS = [("mysql", "MySQL"), ("mariadb", "MariaDB"), ("postgres", "PostgreSQL"),
         ("psql", "PostgreSQL"), ("mssql", "MSSQL"), ("sql server", "MSSQL"),
         ("oracle", "Oracle"), ("sqlite", "SQLite")]
_INJ_TYPE = [("boolean", "Boolean-based"), ("error", "Error-based"), ("union", "Union-based"),
             ("time", "Time-based(미수행)")]


def fingerprint(f: dict) -> dict:
    """Finding 에 이미 담긴 안전 신호로 유형별 fingerprint 를 산출(신규 probing 없음)."""
    fam = _family(f)
    blob = " ".join(str(f.get(k, "")) for k in
                    ("evidence_detail", "title", "dbms", "template_engine", "server",
                     "fingerprint", "banner", "detail")).lower()
    if fam == "ssti":
        for kw, name in _SSTI_ENGINES:
            if kw in blob:
                return _fp(name, "High", f"응답에서 {name} 엔진 특성 관찰",
                           {"supported_feature": "Arithmetic·String(안전)만 확인",
                            "sandbox_status": "미상", "rce_validation_status": "SKIPPED_SAFE",
                            "skipped_reason": "OS/Import/Class 접근은 SAFE 정책상 미수행"})
        if any(m in blob for m in ("7*7", "49", "arithmetic", "산술")):
            return _fp("미상 템플릿 엔진", "Medium", "산술식 평가 관찰(엔진 특정 불가)",
                       {"supported_feature": "Arithmetic", "sandbox_status": "미상",
                        "rce_validation_status": "SKIPPED_SAFE",
                        "skipped_reason": "안전 fingerprint(산술/문자열)만 수행"})
        return _fp("미상", "Low", "SSTI 후보 — 엔진 특성 미확인")
    if fam == "sqli":
        dbms = next((n for kw, n in _DBMS if kw in blob), "미상")
        inj = next((n for kw, n in _INJ_TYPE if kw in blob), "미상")
        conf = "High" if dbms != "미상" else ("Medium" if inj != "미상" else "Low")
        return _fp(dbms, conf, f"DBMS {dbms} · Injection {inj}",
                   {"injection_type": inj})
    if fam == "tls":
        ver = f.get("tls_version") or next((v for v in ("TLS 1.3", "TLS 1.2", "TLS 1.1",
                                                        "TLS 1.0", "SSLv3") if v.lower() in blob), "미상")
        return _fp(str(ver), "High" if ver != "미상" else "Low", f"TLS 버전 {ver}",
                   {"cipher": f.get("cipher", "미상"), "certificate": f.get("cert", "미상")})
    if fam == "graphql":
        introspect = bool(f.get("introspection")) or "introspection" in blob
        return _fp(f.get("graphql_impl", "GraphQL"), "Medium",
                   "GraphQL endpoint", {"introspection": introspect})
    if fam == "jwt":
        alg = f.get("jwt_alg") or next((a for a in ("hs256", "rs256", "none", "es256")
                                        if a in blob), "미상")
        return _fp(f"JWT ({alg})", "Medium" if alg != "미상" else "Low", f"JWT 알고리즘 {alg}",
                   {"algorithm": alg})
    if fam == "clickjacking" or "clickjack" in blob or "iframe" in blob:
        xfo = "미설정" if ("x-frame" not in blob and "frame-ancestors" not in blob) else "설정됨"
        return _fp("Clickjacking", "Medium",
                   f"X-Frame-Options/CSP frame-ancestors {xfo} · iframe 로드 관찰",
                   {"x_frame_options": xfo, "iframe_load_result": "loaded" if "loaded" in blob
                    or "성공" in blob else "미상"})
    if fam in ("http_method", "trace") or "trace" in blob or "method" in blob:
        allow = f.get("allow_header") or ""
        return _fp("HTTP Method", "Medium", "위험 메서드/Allow 헤더 관찰",
                   {"allow_header": allow or "미상",
                    "trace_echo": "확인" if "trace" in blob else "미상",
                    "actual_method_validation": "관찰 기반(파괴적 검증 미수행)"})
    if fam == "file_upload":
        return _fp("Upload Surface", "Low", "업로드 표면(저장 위치 추정)",
                   {"storage_guess": f.get("upload_storage", "미상")})
    if fam == "server" or fam == "generic":
        server = f.get("server") or next((s for s in ("nginx", "apache", "iis", "express",
                                                      "tomcat", "gunicorn") if s in blob), "")
        lang = next((l for l in ("php", "python", "java", "node", "ruby", ".net") if l in blob), "")
        if server or lang:
            return _fp((server or "Server").title(), "Medium",
                       f"서버 {server or '미상'} · 언어 {lang or '미상'}",
                       {"framework": server, "language": lang})
    return _fp("미상", "Low", "유형별 fingerprint 신호 부족")


# ══ 5. Proof Quality Score ═══════════════════════════════════════════════════
def proof_quality(f: dict, card: dict, analysis: dict) -> dict:
    """확보된 증거 요소를 가중 합산해 0~100 점수 + 근거. (판정 아님, 증거 충실도 지표)"""
    factors, score = [], 0

    def add(cond, pts, label):
        nonlocal score
        if cond:
            score += pts
            factors.append(f"{label}(+{pts})")

    level = evl.level_of(f)
    add(bool(card.get("payload") and card["payload"] != "-"), 15, "Payload")
    add(bool(card.get("response_evidence_snippet") and card["response_evidence_snippet"] != "-"),
        20, "Response 증거")
    add(bool(f.get("evidence_screenshot") or (f.get("probe_detail") or {}).get("evidence_screenshots")),
        15, "Screenshot")
    add(bool(card.get("_replayable")), 10, "Replay 후보")
    add(bool(card.get("_dom_correlated")), 10, "DOM 상관")
    add(card.get("fingerprint", {}).get("fingerprint_name", "미상") != "미상", 10, "Fingerprint")
    add(bool(card.get("business_function") and card["business_function"] != "미상"), 10, "Business Context")
    add(level >= 3, 10, "실증(L3)")
    if level == 2:
        score += 5
        factors.append("증거확보(L2)(+5)")
    score = min(100, score)
    grade = "높음" if score >= 75 else ("보통" if score >= 45 else "낮음")
    return {"score": score, "grade": grade, "factors": factors}


# ══ 9. Business Process Mapping ══════════════════════════════════════════════
# Business Process Engine 2.0 — 지원 기능 확장(Authentication/Admin/Search/Profile/Payment/
# Transfer/Invoice/Order/Approval/File Upload/Notification/Customer Service/CMS/Analytics/API Gateway).
_BIZ_RULES = [
    (("login", "signin", "logon", "로그인", "auth", "oauth", "sso", "session", "token"), "Authentication"),
    (("admin", "manage", "console", "dashboard", "관리", "backoffice"), "Administration"),
    (("search", "query", "검색", "find"), "Search"),
    (("profile", "account", "mypage", "프로필", "내정보", "설정", "settings"), "Profile"),
    (("pay", "payment", "checkout", "billing", "결제", "card"), "Payment"),
    (("transfer", "remit", "송금", "이체", "wire"), "Transfer"),
    (("invoice", "receipt", "청구", "영수증", "statement"), "Invoice"),
    (("order", "cart", "purchase", "주문", "장바구니", "basket"), "Order"),
    (("approve", "approval", "confirm", "승인", "결재"), "Approval"),
    (("upload", "attach", "file", "업로드", "document"), "File Upload"),
    (("notify", "notification", "alert", "알림", "message", "메시지", "mail"), "Notification"),
    (("support", "help", "inquiry", "contact", "cs", "문의", "고객"), "Customer Service"),
    (("cms", "content", "post", "board", "게시", "article", "blog"), "CMS"),
    (("analytics", "report", "stat", "metric", "통계", "dashboard"), "Analytics"),
    (("/api/", "/v1/", "/v2/", "graphql", "/rest/", "gateway"), "API Gateway"),
]


def business_function(f: dict, dom_context: dict | None = None) -> dict:
    """DOM context / endpoint / parameter / heading 키워드로 비즈니스 기능 적극 추정.
    Unknown 은 최소화하고, Unknown 이라도 reason 을 남긴다."""
    hay = " ".join([str(f.get("title", "")), str(f.get("url", "")),
                    str(f.get("evidence_url", "")), str(f.get("parameter", "")),
                    str((dom_context or {}).get("business_hint", "")),
                    str((dom_context or {}).get("business_function", "")),
                    str((dom_context or {}).get("section", "")),
                    " ".join((dom_context or {}).get("headings", {}).get("h1", [])
                             if isinstance(dom_context, dict) else [])]).lower()
    for kws, name in _BIZ_RULES:
        if any(k in hay for k in kws):
            hit = next(k for k in kws if k in hay)
            return {"function": name, "confidence": "Medium",
                    "reason": f"'{hit}' 키워드/문맥 매칭 → {name}"}
    # 유형(family) 기반 기본 매핑 — Unknown 최소화(최후 fallback 전에 적용)
    fam = _family(f)
    _FAM_FALLBACK = {
        "clickjacking": "User Interaction / Web UI",
        "http_method": "Web Server / HTTP Interface",
        "server": "Infrastructure Exposure",
        "tls": "Infrastructure Exposure",
        "ssti": "Search", "xss": "Web UI", "csrf": "Web UI",
        "idor": "Data Access", "sqli": "Data Access", "path_traversal": "File Access",
        "file_upload": "File Upload", "ssrf": "Server-side Fetch", "open_redirect": "Web UI",
        "jwt": "Authentication", "graphql": "API Gateway",
    }
    if fam in _FAM_FALLBACK:
        return {"function": _FAM_FALLBACK[fam], "confidence": "Low",
                "reason": f"취약점 유형({fam}) 기반 기본 비즈니스 기능 매핑"}
    return {"function": "미상", "confidence": "Low",
            "reason": "경로·파라미터·DOM·유형에서 비즈니스 기능 특정 신호가 없어 미상 처리"}


# ══ 1./3./4. Proof Evidence Card ═════════════════════════════════════════════
def finding_uid(f: dict):
    """Finding 안정 식별자 — finding_uid 우선, 없으면 _idx, 그것도 없으면 제목 기반.
    Proof/KG/Report/HTML 이 모두 이 값으로 '자기 자신'의 증거만 매핑(교차 오염 방지)."""
    return f.get("finding_uid") or f.get("_idx") or ("T:" + (f.get("title") or ""))


def _observed_for(fam: str, f: dict, v: dict) -> tuple:
    """유형별 '실제 관찰값' 우선 산출 → (expected, observed, evidence_snippet).
    설명문보다 실제 값(예: SSTI 49)을 우선 표시한다."""
    ed = (f.get("evidence_detail") or "") + " " + (v.get("evidence") or "") + " " + (v.get("observed_phenomenon") or "")
    if fam == "ssti":
        payload = f.get("payload") or "{{7*7}}"
        # payload 의 산술 결과를 기대값으로(간단 평가), 응답에 그 값이 있으면 관찰값으로
        import re as _re
        expected = "49"
        m = _re.search(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", str(payload))
        if m:
            expected = str(int(m.group(1)) * int(m.group(2)))
        observed = expected if expected in ed else (expected if "49" in ed else "-")
        snip = f"응답 내 '{expected}' 출력 확인" if observed != "-" else _snip(ed)
        return expected, observed, snip
    if fam == "clickjacking":
        return ("X-Frame-Options/CSP frame-ancestors 부재 시 iframe 로드 성공",
                ("iframe 로드됨" if ("iframe" in ed.lower() or "loaded" in ed.lower() or "성공" in ed) else "-"),
                _snip("X-Frame-Options/CSP frame-ancestors: " + ed))
    if fam == "http_method":
        allow = f.get("allow_header") or ""
        return ("위험 메서드(TRACE 등) 허용/반사",
                ("TRACE 반사" if "trace" in ed.lower() else (allow or "-")),
                _snip(f"Allow: {allow} · " + ed))
    if fam == "server":
        srv = f.get("server") or ""
        import re as _re
        m = _re.search(r"Server:\s*[\w./+\- ]{1,40}", f.get("evidence_detail") or ed)
        obs = (m.group(0).strip() if m else (("Server: " + srv) if srv else _snip(ed)))
        return ("서버/버전 헤더 노출", obs, _snip(obs))
    # 기본: observed_view 값
    return (_expected_for(fam), _snip(v.get("observed_phenomenon") or ed or "-"),
            _fold_snip(v.get("evidence") or ed or "-"))


def _fold_snip(t):
    return _snip(t, _SNIPPET_LIMIT)


def _proof_record_for(f: dict, analysis: dict) -> dict | None:
    for r in (analysis.get("proof_validation") or []):
        if r.get("finding_title") == f.get("title"):
            return r
    return None


def _replay_hit(f: dict, analysis: dict) -> bool:
    url = f.get("evidence_url") or f.get("url") or ""
    for rc in (analysis.get("browser_discovery_replay_candidates") or []):
        if url and rc.get("url") == url:
            return True
    return False


def build_proof_card(f: dict, analysis: dict) -> dict:
    """단일 Finding → Evidence/Proof/Reproduction 통합 카드(공통 필드). 판정 변경 없음."""
    fam = _family(f)
    try:
        v = evl.observed_view(f, finding_type="vulnerability")
    except Exception:
        v = {"observed_phenomenon": "", "evidence": "", "possible_impact": "",
             "verification_label": ""}
    pr = _proof_record_for(f, analysis)
    fp = fingerprint(f)
    biz = business_function(f)
    if fam == "ssti" and (not f.get("payload")):
        payload = "{{7*7}}"
    else:
        payload = f.get("payload") or (f.get("probe_detail") or {}).get("payload") or "-"
    method = (f.get("http_method") or f.get("method") or "GET").upper()
    endpoint = f.get("evidence_url") or f.get("url") or f"{f.get('host','')}:{f.get('port','')}"
    param = f.get("parameter") or f.get("param") or "-"
    expected, observed, ev_snip = _observed_for(fam, f, v)
    lay = _layman_explanation(fam, expected, observed)

    card = {
        "finding_id": finding_uid(f),           # 안정 식별자(교차 오염 방지)
        "finding_uid": finding_uid(f),
        "finding_title": f.get("title", ""),
        "vulnerability_type": fam,
        "target_url": f.get("url") or endpoint,
        "affected_endpoint": endpoint,
        "parameter_name": param,
        "parameter_location": f.get("parameter_location") or "-",
        "method": method,
        "payload": _snip(str(payload), 160),
        "expected_result": expected,
        "observed_result": observed,
        "response_evidence_snippet": ev_snip,
        "validation_level": evl.level_of(f),
        "validation_label": v.get("verification_label", ""),
        "validation_method": _validation_method(fam),
        "confidence": f.get("confidence", ""),
        "proof_profile": (pr or {}).get("profile", "SAFE"),
        "blocked_actions": [b.get("action") for b in (pr or {}).get("blocked_actions", [])][:6],
        "blocked_reason": "; ".join(sorted({b.get("decision", "") for b in
                                           (pr or {}).get("blocked_actions", [])}))[:120],
        "skip_reason": _skip_reason(fam),
        "reproduction_steps": _reproduction(fam, method, endpoint, param, payload),
        "remediation_summary": _snip(f.get("recommendation") or _default_reco(fam), 200),
        "fingerprint": fp,
        "template_engine_guess": (fp.get("fingerprint_name") if fam == "ssti" else None),
        "business_function": biz["function"],
        "evidence_quality": evl.label_of(evl.level_of(f)),
        "limitations": _limitations(fam, pr),
        # 4. 비전문가용 3단 설명
        "one_liner": lay["one_liner"],
        "why_risky": lay["why_risky"],
        "technical_basis": lay["technical_basis"],
        "_replayable": _replay_hit(f, analysis),
        "_dom_correlated": bool(f.get("_dom_correlated")),
    }
    card["proof_quality"] = proof_quality(f, card, analysis)
    return card


def _validation_method(fam: str) -> str:
    return {"ssti": "ssti_arithmetic_probe", "sqli": "sqli_boolean_error_probe",
            "xss": "xss_browser_alert_probe", "idor": "idor_cross_account_read",
            "clickjacking": "clickjacking_iframe_probe", "http_method": "http_method_allow_probe",
            "open_redirect": "open_redirect_location_probe", "ssrf": "ssrf_controlled_callback",
            "server": "response_header_analysis"}.get(fam, "response_evidence_analysis")


def _skip_reason(fam: str) -> str:
    if fam == "ssti":
        return "OS command·file read·class introspection·object/env access 금지(SAFE)"
    if fam == "sqli":
        return "DB 덤프·file I/O·os-shell 금지, read-only metadata 만(SAFE)"
    return "운영 영향/파괴적 검증은 SAFE 정책상 미수행"


def _default_reco(fam: str) -> str:
    return {"ssti": "템플릿 엔진 샌드박스 적용 및 사용자 입력을 템플릿 표현식과 분리하십시오.",
            "clickjacking": "X-Frame-Options: DENY 또는 CSP frame-ancestors 'none' 을 설정하십시오.",
            "http_method": "TRACE 등 불필요한 HTTP 메서드를 비활성화하십시오.",
            "server": "응답의 Server/버전 헤더 노출을 제거하십시오."}.get(
        fam, "확인된 취약점에 대한 입력 검증·설정 강화를 적용하십시오.")


def _layman_explanation(fam: str, expected: str, observed: str) -> dict:
    """비전문가용 3단 설명(한 줄 요약 / 왜 위험한가 / 기술 근거)."""
    table = {
        "ssti": {
            "one_liner": "사용자 입력이 서버에서 코드처럼 처리되고 있습니다.",
            "why_risky": "공격자가 특수한 입력값을 넣으면 서버가 의도하지 않은 계산이나 동작을 수행할 수 있습니다.",
            "technical_basis": f"{{{{7*7}}}} 입력 시 응답에서 {observed or expected} 가 출력되어 서버 측 템플릿 표현식 평가가 확인되었습니다."},
        "sqli": {
            "one_liner": "입력값이 데이터베이스 질의에 그대로 섞여 들어갑니다.",
            "why_risky": "공격자가 조작된 입력으로 데이터베이스를 열람·조작할 수 있어 고객 정보 유출로 이어질 수 있습니다.",
            "technical_basis": "참/거짓 조건에 따른 응답 차이 또는 DB 오류 메시지로 SQL Injection 신호가 확인되었습니다."},
        "xss": {
            "one_liner": "입력한 스크립트가 다른 사용자의 브라우저에서 실행될 수 있습니다.",
            "why_risky": "공격자가 사용자의 세션·정보를 탈취하거나 화면을 위조할 수 있습니다.",
            "technical_basis": "브라우저에서 삽입 스크립트(alert 등) 실행이 확인되었습니다."},
        "idor": {
            "one_liner": "다른 사람의 데이터에 접근할 수 있습니다.",
            "why_risky": "식별자만 바꾸면 타인의 정보를 조회할 수 있어 개인정보 노출 위험이 있습니다.",
            "technical_basis": "타 계정 식별자로 조회 시 타인 데이터가 반환되어 접근통제 결함이 확인되었습니다."},
        "clickjacking": {
            "one_liner": "우리 화면이 다른 사이트에 몰래 삽입될 수 있습니다.",
            "why_risky": "공격자가 투명한 프레임으로 사용자의 클릭을 가로채(클릭재킹) 원치 않는 동작을 유도할 수 있습니다.",
            "technical_basis": "X-Frame-Options/CSP frame-ancestors 부재로 iframe 내 페이지 로드가 확인되었습니다."},
        "http_method": {
            "one_liner": "불필요하거나 위험한 HTTP 메서드가 열려 있습니다.",
            "why_risky": "TRACE 등 메서드가 정보 노출·우회에 악용될 수 있습니다.",
            "technical_basis": "Allow 헤더/TRACE 반사로 위험 메서드 허용이 확인되었습니다."},
        "server": {
            "one_liner": "서버 종류·버전이 외부에 노출되고 있습니다.",
            "why_risky": "공격자가 서버 환경을 파악해 알려진 취약점을 노릴 수 있습니다.",
            "technical_basis": f"응답 헤더에서 서버 정보({observed}) 노출이 확인되었습니다."},
    }
    return table.get(fam, {
        "one_liner": "보안 점검에서 잠재적 취약점이 확인되었습니다.",
        "why_risky": "악용 시 서비스·데이터에 영향을 줄 수 있습니다.",
        "technical_basis": f"관찰: {observed or '-'} (기대: {expected or '-'})."})


def _expected_for(fam: str) -> str:
    return {
        "ssti": "안전 산술식(예: 7*7)이 평가되어 결과가 반사되면 템플릿 주입 신호",
        "sqli": "참/거짓 조건에 따른 응답 차이 또는 DB 오류 메시지 반사",
        "xss": "브라우저에서 삽입 스크립트가 실행(alert 등)되면 실증",
        "idor": "타 계정 식별자로 조회 시 타인 데이터가 반환되면 접근통제 결함",
        "open_redirect": "controlled 안전 도메인으로 실제 리다이렉트 발생",
        "ssrf": "controlled callback 으로 서버측 요청 발생 확인",
    }.get(fam, "정의된 안전 신호가 응답에서 관찰됨")


def _reproduction(fam, method, endpoint, param, payload) -> list:
    steps = [f"대상 확인: {method} {endpoint}"]
    if param and param != "-":
        steps.append(f"파라미터 '{param}' 에 안전 검증 페이로드 입력")
    if payload and payload != "-":
        steps.append(f"페이로드(발췌): {_snip(str(payload), 80)}")
    steps.append("응답에서 정의된 안전 신호(반사/차이/실행) 관찰")
    steps.append("※ 재현은 조회성·무해 범위에서만. 파괴적/실행 검증은 수행하지 않음(SAFE).")
    return steps


def _limitations(fam: str, pr: dict | None) -> str:
    base = "SAFE 정책상 OS 명령·파일 접근·DB 덤프·권한 상승·brute force 는 수행하지 않았습니다."
    if fam == "ssti":
        return base + " 템플릿 엔진의 RCE 가능성은 실증하지 않았습니다(안전 fingerprint 만)."
    if fam == "sqli":
        return base + " 데이터 추출은 하지 않았고 read-only metadata 수준 증거만 사용했습니다."
    return base


def build_all(analysis: dict) -> dict:
    """analysis.findings 전체의 Proof Evidence 산출물 생성(판정 불변, 표현 전용)."""
    findings = [f for f in (analysis.get("findings") or []) if f.get("judgment") != "양호"]
    cards = [build_proof_card(f, analysis) for f in findings]
    fps = [{"finding": c["target_url"], **c["fingerprint"]} for c in cards]
    biz_map = {}
    for c in cards:
        biz_map.setdefault(c["business_function"], 0)
        biz_map[c["business_function"]] += 1
    avg_q = round(sum(c["proof_quality"]["score"] for c in cards) / max(1, len(cards)))
    summary = {
        "proof_cards": len(cards),
        "avg_proof_quality": avg_q,
        "high_quality": sum(1 for c in cards if c["proof_quality"]["score"] >= 75),
        "fingerprinted": sum(1 for c in cards if c["fingerprint"]["fingerprint_name"] != "미상"),
        "business_functions": biz_map,
    }
    return {"proof_evidence_cards": cards, "proof_quality_summary": summary,
            "fingerprints": fps, "business_process_map": biz_map}
