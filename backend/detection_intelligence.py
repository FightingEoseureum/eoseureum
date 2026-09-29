"""
detection_intelligence.py — Detection Intelligence v1 (탐지 전략 결정 계층).

Input→Technique 단순 매핑을 넘어, Business Function + Endpoint Type + Parameter Role +
Auth State + Technology Fingerprint + DOM Context + API Relationship 를 종합해
Detection Strategy(어떤 기법을·왜) → SAFE Payload Set → Evidence Goal 을 '결정'한다.

절대 원칙: 신규 공격 실행 없음. 여기서 만드는 것은 '계획/추천 카탈로그'이며 판정/실행은
기존 계층(payload_validator/proof_mode/Rule Engine)이 담당한다. SAFE — payload 는
arithmetic/string/reflection/marker 등 무해 후보만. OS command/file read/dump/shell 금지.
"""
from __future__ import annotations

# ── 4. Attack Pack System (Business Function 별 기법 팩) ─────────────────────────
ATTACK_PACKS = {
    "Authentication": ["login_bypass_candidate", "username_enumeration", "password_reset_weakness",
                       "session_fixation", "open_redirect_after_login", "csrf_login_logout",
                       "rate_limit_check", "lockout_policy_observation"],
    "Search": ["xss", "sqli", "ssti", "nosql_injection", "lucene_query_injection",
               "regex_dos_candidate", "reflected_parameter_analysis"],
    "Administration": ["admin_exposure", "missing_auth", "idor_authz", "csrf",
                       "dangerous_action_discovery", "default_admin_path"],
    "File Upload": ["extension_validation", "mime_mismatch", "double_extension",
                    "stored_xss_candidate", "path_traversal_filename", "webshell_marker_blocked"],
    "API Gateway": ["idor", "mass_assignment", "bola", "broken_function_level_authz",
                    "excessive_data_exposure", "cors", "jwt_header_cookie_auth_analysis"],
    "Infrastructure Exposure": ["server_header", "dangerous_http_method", "directory_listing",
                                "default_files", "error_disclosure", "security_headers",
                                "tls_if_materially_risky"],
    "Data Access": ["sqli", "idor", "excessive_data_exposure"],
    "Payment": ["idor", "business_logic", "csrf", "excessive_data_exposure"],
    "Transfer": ["idor", "business_logic", "csrf"],
    "Web UI": ["xss", "clickjacking", "csrf", "open_redirect"],
}

# 유형 별칭 → Attack Pack 키 후보(business function 이 없을 때 fallback)
_FAMILY_PACK = {"ssti": "Search", "sqli": "Data Access", "xss": "Web UI", "idor": "API Gateway",
                "clickjacking": "Web UI", "http_method": "Infrastructure Exposure",
                "server": "Infrastructure Exposure", "file_upload": "File Upload",
                "open_redirect": "Web UI", "ssrf": "API Gateway", "csrf": "Web UI"}


def attack_pack(business_function: str, family: str = "") -> dict:
    """Business Function(또는 family)에 맞는 Attack Pack 반환."""
    key = business_function if business_function in ATTACK_PACKS else _FAMILY_PACK.get(family, "")
    techniques = ATTACK_PACKS.get(key, [])
    return {"pack": key or "Generic", "techniques": techniques,
            "reason": (f"Business Function '{business_function}' 기반" if key == business_function
                       else f"유형 '{family}' 기반 기본 팩")}


# ── 5. Adaptive Payload Selection (SAFE 카탈로그, tech/context 기반) ─────────────
_SSTI_SAFE = {  # 엔진별 안전(arithmetic/string) 후보 — OS/file/class 금지
    "Jinja2": ["{{7*7}}", "{{'ab'+'cd'}}"], "Twig": ["{{7*7}}", "{{'a'~'b'}}"],
    "Handlebars": ["{{7*7}}"], "Thymeleaf": ["[[${7*7}]]"],
    "FreeMarker": ["${7*7}"], "Velocity": ["#set($x=7*7)$x"],
    "미상": ["{{7*7}}", "${7*7}"]}
_XSS_CONTEXT = {
    "html_body": ["<svg onload=alert('EOSEUREUM')>", "<img src=x onerror=alert('EOSEUREUM')>"],
    "attribute": ["\" onmouseover=alert('EOSEUREUM') x=\""], "script": ["';alert('EOSEUREUM');//"],
    "url": ["javascript:alert('EOSEUREUM')"], "dom_sink": ["#<img src=x onerror=alert('EOSEUREUM')>"]}
_IDOR_PARAMS = ["userid", "userId", "accountid", "accountId", "orderid", "orderId",
                "fileid", "fileId", "invoiceid", "invoiceId", "id", "uid", "no", "seq"]


def adaptive_payloads(family: str, *, fingerprint: str = "", context: str = "",
                      time_based_allowed: bool = False) -> dict:
    """기술스택/컨텍스트에 맞는 SAFE payload set 선택. 위험 payload 는 포함하지 않는다."""
    fam = (family or "").lower()
    if fam == "ssti":
        eng = fingerprint if fingerprint in _SSTI_SAFE else "미상"
        return {"family": "ssti", "engine": eng, "payloads": _SSTI_SAFE[eng],
                "mode": "arithmetic/string only",
                "forbidden": ["os command", "file read", "class introspection", "env access"]}
    if fam == "sqli":
        types = ["boolean", "error", "union_minimal", "dbms_fingerprint"]
        if time_based_allowed:
            types.append("time_based(limited)")
        return {"family": "sqli", "dbms": fingerprint or "미상", "injection_types": types,
                "payloads": ["' AND 1=1-- -", "' AND 1=2-- -", "'\"", "' UNION SELECT NULL-- -"],
                "forbidden": ["dump", "file I/O", "os-shell", "sql-shell", "stacked query"]}
    if fam == "xss":
        ctx = context if context in _XSS_CONTEXT else "html_body"
        return {"family": "xss", "context": ctx, "payloads": _XSS_CONTEXT[ctx],
                "evidence": "Playwright alert 또는 DOM mutation",
                "forbidden": ["session theft", "external exfil", "keylogger"]}
    if fam == "idor":
        return {"family": "idor", "object_params": _IDOR_PARAMS,
                "mode": "read-only cross-account (A/B 계정 있을 때만)",
                "single_account": "Manual Review", "forbidden": ["state change", "write"]}
    return {"family": fam, "payloads": [], "mode": "n/a"}


_SEARCH_PARAMS = {"q", "query", "search", "keyword", "kw", "term", "s", "find"}
_REDIRECT_PARAMS = {"url", "next", "return", "returnurl", "redirect", "goto", "dest", "target"}
_FILE_PARAMS = {"file", "path", "filename", "doc", "page", "include", "template", "tpl"}


def point_signal(point: dict) -> dict:
    """입력점(param/url/method) 컨텍스트 → 우선 적용할 기법 + 우선순위 boost.
    실제 점검 우선순위·기법 선택에 반영(계획 계층). 신규 payload/실행 아님, 순수 판단.

    반환: {techniques:[정렬된 기법], boost:int, param_role:str, reason:str}
    """
    name = str(point.get("param") or point.get("parameter_name") or "").lower()
    url = str(point.get("url") or point.get("endpoint") or "").lower()
    techs, boost, role, reasons = [], 0, "generic", []

    if name and any(k.lower() in name for k in _IDOR_PARAMS):
        techs += ["idor"]; boost += 8; role = "object_ref"; reasons.append("객체 참조 파라미터(IDOR)")
    if name in _SEARCH_PARAMS:
        techs += ["sqli", "xss", "ssti"]; boost += 6; role = "search"; reasons.append("검색 파라미터(주입)")
    if name in _REDIRECT_PARAMS or any(k in name for k in _REDIRECT_PARAMS):
        techs += ["open_redirect", "ssrf"]; boost += 5; role = "redirect/url"; reasons.append("리다이렉트/URL 파라미터")
    if name in _FILE_PARAMS or any(k in name for k in _FILE_PARAMS):
        techs += ["path_traversal", "ssti"]; boost += 5; role = "file/template"; reasons.append("파일/템플릿 파라미터")
    if "/api/" in url or "graphql" in url:
        techs += ["idor", "bola"]; boost += 4; reasons.append("API 엔드포인트(권한/BOLA)")
    if any(k in url for k in ("login", "signin", "auth")):
        techs += ["sqli"]; boost += 4; reasons.append("인증 엔드포인트")
    if "admin" in url:
        techs += ["missing_auth", "idor"]; boost += 6; reasons.append("관리자 경로")
    # 중복 제거(순서 보존)
    seen, ordered = set(), []
    for t in techs:
        if t not in seen:
            seen.add(t); ordered.append(t)
    return {"techniques": ordered, "boost": min(boost, 20), "param_role": role,
            "reason": " · ".join(reasons) or "일반 입력점"}


def object_param_candidates(params) -> list:
    """IDOR 대상 object parameter 후보 추출(userId/accountId/orderId/fileId/invoiceId 등)."""
    out = []
    for p in (params or []):
        pn = str(p).lower()
        if any(k.lower() in pn for k in _IDOR_PARAMS):
            out.append(p)
    return out


# ── 6. Evidence Goal (기법별 무엇을 증거로 확보할지) ──────────────────────────────
EVIDENCE_GOALS = {
    "ssti": ["payload", "expected", "observed_actual_value", "engine_guess", "safe_skipped_reason"],
    "sqli": ["response_diff", "dbms_fingerprint", "injection_type", "sqlmap_summary",
             "blocked_dump_reason"],
    "xss": ["alert_text", "screenshot", "dom_sink", "payload", "csp_context"],
    "idor": ["object_id", "auth_context", "cross_account_result", "access_control_conclusion"],
    "clickjacking": ["x_frame_options", "csp_frame_ancestors", "iframe_load_result"],
    "http_method": ["allow_header", "trace_echo", "method_validation"],
    "server": ["server_header", "framework_guess", "version_exposure"],
}


def evidence_goal(family: str) -> list:
    return EVIDENCE_GOALS.get((family or "").lower(), ["payload", "observed", "evidence_snippet"])


# ── 3. Detection Strategy (컨텍스트 종합 → 전략) ─────────────────────────────────
def detection_strategy(*, business_function: str = "", family: str = "", endpoint: str = "",
                       parameter: str = "", auth_state: str = "anonymous",
                       fingerprint: str = "", dom_context: dict | None = None,
                       api_relationship: bool = False) -> dict:
    """컨텍스트를 종합해 탐지 전략을 결정(계획). 실행/판정 아님."""
    pack = attack_pack(business_function, family)
    ep = (endpoint or "").lower()
    endpoint_type = ("api" if ("/api/" in ep or "graphql" in ep) else
                     "auth" if any(k in ep for k in ("login", "signin", "auth")) else
                     "admin" if "admin" in ep else "web")
    param_role = ("object_ref" if parameter and any(k.lower() in parameter.lower()
                                                     for k in _IDOR_PARAMS) else
                  "search" if parameter.lower() in ("q", "query", "search", "keyword") else
                  "generic")
    payloads = adaptive_payloads(family, fingerprint=fingerprint,
                                 context=(dom_context or {}).get("xss_context", ""))
    return {
        "business_function": business_function or "미상",
        "endpoint_type": endpoint_type,
        "parameter_role": param_role,
        "auth_state": auth_state,
        "technology_fingerprint": fingerprint or "미상",
        "api_relationship": bool(api_relationship),
        "attack_pack": pack,
        "payload_set": payloads,
        "evidence_goal": evidence_goal(family),
        "note": "SAFE 계획 — 실행/판정은 Rule Engine 전담, 위험 행위 미포함",
    }


def build_strategies(analysis: dict) -> dict:
    """analysis.findings 각각에 대해 Detection Strategy 산출(보고서 참고용)."""
    import proof_evidence as pe
    out = []
    for f in [x for x in (analysis.get("findings") or []) if x.get("judgment") != "양호"]:
        fam = pe._family(f)
        biz = f.get("business_function") or pe.business_function(f)["function"]
        st = detection_strategy(
            business_function=biz, family=fam,
            endpoint=f.get("evidence_url") or f.get("url") or "",
            parameter=f.get("parameter") or f.get("param") or "",
            auth_state=("authenticated" if f.get("authenticated") else "anonymous"),
            fingerprint=str((f.get("dbms") or f.get("template_engine") or "")),
            api_relationship=bool("/api/" in (f.get("url") or "").lower()))
        st["finding_uid"] = f.get("finding_uid") or f.get("_idx")
        out.append(st)
    packs = sorted({s["attack_pack"]["pack"] for s in out})
    return {"detection_strategies": out,
            "summary": {"strategies": len(out), "attack_packs_used": packs}}
