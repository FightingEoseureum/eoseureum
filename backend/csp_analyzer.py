"""CSP 정책 정적 분석기 — Content-Security-Policy 우회 클래스 탐지.

목적: XSS 실행 게이트(alert 발생)만으로는 CSP 로 보호된 페이지의 '우회 가능한' 취약점을
      위음성(false negative) 으로 놓친다. 이 모듈은 CSP 헤더 자체를 파싱해
      "정책이 XSS 를 실제로 막는가, 아니면 우회 가능한가"를 판정한다.

핵심 우회 클래스:
  - base_uri_script_hijack : script-src 가 nonce/hash/'strict-dynamic' 에 의존하는데
      base-uri 지시자가 없음(또는 제한적이지 않음). 이때 HTML 주입점으로
      `<base href="//attacker/">` 를 삽입하면, 경로-절대(/static/..) nonce 스크립트의
      로드 출처가 공격자로 바뀌고 nonce 는 그대로 유지되어 strict-dynamic 이 허용한다.
      → 공격자 스크립트가 페이지 nonce 로 실행됨. (Dreamhack DOM-XSS 유형)
  - script_unsafe_inline   : script-src 에 'unsafe-inline' 이 있고 이를 무력화하는
      nonce/hash 가 없음 → 인라인 XSS 가 그대로 동작.
  - no_script_restriction  : script-src 도 default-src 도 없음 → 스크립트 제한 없음.
  - script_scheme_wildcard : script-src 에 '*' 또는 http:/https:/data: 스킴 → 광범위 허용.
  - unsafe_eval            : 'unsafe-eval' 존재 → eval 계열 가젯 위험.
  - object_src_open        : object-src 없음(+default-src 가 'none' 아님) → <object>/<embed> 우회.

판정 권위 원칙 준수: 이 모듈은 evidence(사실)만 산출한다. verdict/Severity 확정은 Rule Engine 몫.
"""
from __future__ import annotations

# script 실행 소스로서 nonce/hash/strict-dynamic 을 나타내는 토큰
_NONCE_PREFIX = "'nonce-"
_HASH_PREFIXES = ("'sha256-", "'sha384-", "'sha512-")
_STRICT_DYNAMIC = "'strict-dynamic'"
_UNSAFE_INLINE = "'unsafe-inline'"
_UNSAFE_EVAL = "'unsafe-eval'"
_SELF = "'self'"
_NONE = "'none'"

# script-src 값으로서 광범위(사실상 우회 가능) 출처
_SCHEME_WILDCARDS = ("*", "http:", "https:", "data:", "blob:")


def parse_csp(header: str) -> dict[str, list[str]]:
    """CSP 헤더 문자열을 {directive: [values...]} 로 파싱한다(지시자명은 소문자).

    여러 CSP 헤더가 콤마로 합쳐진 경우도 첫 정책만 취한다(가장 제한적/대표 정책 가정).
    """
    if not header:
        return {}
    # 다중 정책(콤마 구분)은 첫 정책만 — 브라우저는 모든 정책을 AND 로 적용하나
    # 정적 분석에서는 대표 정책 1개로 충분(대부분 앱은 단일 정책).
    policy = header.split(",")[0] if "," in header else header
    directives: dict[str, list[str]] = {}
    for chunk in policy.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split()
        name = parts[0].lower()
        directives[name] = parts[1:]
    return directives


def _effective_script_src(d: dict[str, list[str]]) -> list[str] | None:
    """script-src 유효값(없으면 default-src 폴백). 둘 다 없으면 None."""
    if "script-src" in d:
        return d["script-src"]
    if "script-src-elem" in d:
        return d["script-src-elem"]
    if "default-src" in d:
        return d["default-src"]
    return None


def _has_nonce_or_hash(values: list[str]) -> bool:
    for v in values:
        lv = v.lower()
        if lv.startswith(_NONCE_PREFIX) or lv.startswith(_HASH_PREFIXES):
            return True
    return False


def analyze_csp(header: str, *, has_injection_point: bool = False) -> list[dict]:
    """CSP 헤더를 분석해 우회/약점 목록을 반환한다.

    각 항목: {id, title, severity, directive, detail, recommendation, enables_xss}
      - enables_xss=True : 이 약점만으로(또는 주입점과 결합해) XSS 실행이 가능함을 의미.
    has_injection_point : 같은 페이지에 HTML 주입점(raw 반사/ URL→innerHTML DOM 싱크)이 있는지.
      base-uri 하이재킹은 주입점이 있어야 실제 익스플로잇이 성립하므로 severity 상향에 사용.
    """
    d = parse_csp(header)
    if not d:
        return []

    findings: list[dict] = []
    script_src = _effective_script_src(d)
    from_default = "script-src" not in d and "script-src-elem" not in d

    # 1) 스크립트 제한 자체가 없음
    if script_src is None:
        findings.append({
            "id": "no_script_restriction",
            "title": "script-src/default-src 미설정 — 스크립트 출처 제한 없음",
            "severity": "high",
            "directive": "script-src",
            "detail": "script-src 도 default-src 도 없어 CSP 가 스크립트 실행을 전혀 제한하지 않음.",
            "recommendation": "script-src 'self' 또는 nonce 기반 정책을 명시하세요.",
            "enables_xss": True,
        })
        return findings

    lower = [v.lower() for v in script_src]
    has_nonce_hash = _has_nonce_or_hash(script_src)
    has_strict_dynamic = _STRICT_DYNAMIC in lower
    has_unsafe_inline = _UNSAFE_INLINE in lower
    relies_on_nonce = has_nonce_hash or has_strict_dynamic

    # 2) base-uri 미설정 + nonce/strict-dynamic 의존 → <base> 스크립트 하이재킹
    #    base-uri 는 default-src 로 폴백되지 않으므로, 없으면 사실상 무제한.
    base_uri = d.get("base-uri")
    base_uri_restrictive = bool(base_uri) and any(
        t.lower() in (_SELF, _NONE) or not t.startswith("'")  # 'self'/'none'/구체적 호스트
        for t in base_uri
    ) and "*" not in base_uri
    if relies_on_nonce and not base_uri_restrictive:
        sev = "critical" if has_injection_point else "high"
        findings.append({
            "id": "base_uri_script_hijack",
            "title": "base-uri 미설정 — nonce 스크립트 로드 출처 하이재킹 가능 (CSP 우회)",
            "severity": sev,
            "directive": "base-uri",
            "detail": (
                "script-src 가 nonce/hash/'strict-dynamic' 에 의존하지만 base-uri 지시자가 "
                "없어(또는 제한적이지 않아) HTML 주입점에 `<base href=\"//공격자/\">` 를 삽입하면 "
                "경로-절대(/static/..) nonce 스크립트가 공격자 서버에서 로드된다. 스크립트는 "
                "유효 nonce 를 그대로 달고 있어 strict-dynamic 이 허용 → 공격자 JS 가 페이지 "
                "권한으로 실행된다."
                + ("" if has_injection_point else
                   " (현재 페이지에서 HTML 주입점이 함께 확인되면 즉시 익스플로잇 가능.)")
            ),
            "recommendation": "base-uri 'none' (또는 'self') 을 CSP 에 추가해 <base> 주입을 차단하세요.",
            "enables_xss": bool(has_injection_point),
        })

    # 3) unsafe-inline 이 nonce/hash 로 무력화되지 않음 → 인라인 XSS 그대로
    if has_unsafe_inline and not has_nonce_hash:
        findings.append({
            "id": "script_unsafe_inline",
            "title": "script-src 'unsafe-inline' — 인라인 스크립트/이벤트핸들러 XSS 허용",
            "severity": "high",
            "directive": "default-src" if from_default else "script-src",
            "detail": (
                "script-src 에 'unsafe-inline' 이 있고 이를 무력화할 nonce/hash 가 없어 "
                "인라인 <script> 와 on*= 이벤트 핸들러 XSS 가 그대로 실행된다."
            ),
            "recommendation": "'unsafe-inline' 을 제거하고 nonce/hash 기반으로 전환하세요.",
            "enables_xss": True,
        })

    # 4) 스킴 와일드카드/전역 허용
    wild = [v for v in lower if v in _SCHEME_WILDCARDS]
    if wild:
        findings.append({
            "id": "script_scheme_wildcard",
            "title": f"script-src 광범위 허용 ({', '.join(wild)})",
            "severity": "high" if "*" in wild else "medium",
            "directive": "default-src" if from_default else "script-src",
            "detail": (
                f"script-src 에 {', '.join(wild)} 가 포함돼 임의(또는 광범위) 출처의 스크립트 "
                "로드가 허용된다. 공격자가 자신 호스트에 스크립트를 올려 로드시킬 수 있다."
            ),
            "recommendation": "구체적 호스트 화이트리스트 또는 nonce 기반 정책으로 축소하세요.",
            "enables_xss": True,
        })

    # 5) unsafe-eval
    if _UNSAFE_EVAL in lower:
        findings.append({
            "id": "unsafe_eval",
            "title": "script-src 'unsafe-eval' — eval 계열 가젯 위험",
            "severity": "medium",
            "directive": "default-src" if from_default else "script-src",
            "detail": "eval/new Function/setTimeout(string) 등이 허용돼 DOM XSS 가젯 악용 여지가 커진다.",
            "recommendation": "'unsafe-eval' 제거를 검토하세요.",
            "enables_xss": False,
        })

    # 6) object-src 개방 (플러그인/embed 우회)
    object_src = d.get("object-src")
    default_none = d.get("default-src") == [_NONE]
    if object_src is None and not default_none:
        findings.append({
            "id": "object_src_open",
            "title": "object-src 미설정 — <object>/<embed> 플러그인 우회 여지",
            "severity": "low",
            "directive": "object-src",
            "detail": "object-src 가 없고 default-src 도 'none' 이 아니라 플러그인 콘텐츠 삽입이 가능하다.",
            "recommendation": "object-src 'none' 을 추가하세요.",
            "enables_xss": False,
        })

    return findings


def is_xss_bypassable(header: str, *, has_injection_point: bool = False) -> bool:
    """CSP 가 있어도 XSS 실행이 우회 가능한지(=alert 미발생이어도 취약) 판정."""
    for f in analyze_csp(header, has_injection_point=has_injection_point):
        if f.get("enables_xss"):
            return True
    return False


def base_uri_hijackable(header: str) -> bool:
    """base-uri 스크립트 하이재킹 전제(주입점 무관)를 만족하는지."""
    return any(
        f["id"] == "base_uri_script_hijack"
        for f in analyze_csp(header, has_injection_point=False)
    )
