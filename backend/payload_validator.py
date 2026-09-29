"""
payload_validator.py — AI/플래너가 제안한 payload 를 '실행 전' 강제 검증하는 안전 게이트.

절대 원칙:
  - AI 가 만든 payload 는 절대 그대로 실행하지 않는다. 반드시 이 Validator 를 통과해야 한다.
  - destructive / shell / reverse·bind shell / credential dump / 파괴적 SQL(DML·stacked) /
    Time-based SQLi(기본) / 웹쉘 업로드 / OS 명령 실행 은 기본 차단한다.
  - 최종 '취약 판정'은 이 모듈이 하지 않는다(Rule Engine 전담). 여기서는 '실행 허용 여부'만.

검사 결과(verdict):
  ALLOWED_SAFE / BLOCKED_DESTRUCTIVE / BLOCKED_SHELL / BLOCKED_TIME_BASED /
  BLOCKED_STATE_CHANGE / MANUAL_APPROVAL_REQUIRED
"""
from __future__ import annotations

import os
import re

# ── verdict 상수 ─────────────────────────────────────────────────────────────
ALLOWED_SAFE = "ALLOWED_SAFE"
BLOCKED_DESTRUCTIVE = "BLOCKED_DESTRUCTIVE"
BLOCKED_SHELL = "BLOCKED_SHELL"
BLOCKED_TIME_BASED = "BLOCKED_TIME_BASED"
BLOCKED_STATE_CHANGE = "BLOCKED_STATE_CHANGE"
MANUAL_APPROVAL_REQUIRED = "MANUAL_APPROVAL_REQUIRED"

_BLOCKED = {BLOCKED_DESTRUCTIVE, BLOCKED_SHELL, BLOCKED_TIME_BASED,
            BLOCKED_STATE_CHANGE, MANUAL_APPROVAL_REQUIRED}


def is_allowed(verdict: str) -> bool:
    return verdict == ALLOWED_SAFE


# ── 차단 패턴 ────────────────────────────────────────────────────────────────
# 1) 셸/리버스셸/바인드셸/다운로드 실행 — BLOCKED_SHELL
_SHELL_PATTERNS = [
    r"reverse\s*shell", r"bind\s*shell", r"\bnc\b", r"\bncat\b", r"netcat",
    r"bash\s+-i", r"sh\s+-i", r"/dev/tcp/", r"/dev/udp/",
    r"powershell.*(downloadstring|downloadfile|iwr|invoke-webrequest|webclient)",
    r"curl[^\n|]*\|\s*(sh|bash)", r"wget[^\n|]*\|\s*(sh|bash)",
    r"\|\s*(sh|bash)\b", r"\bbash\b.*\bhttp", r"socat\b",
    r"mkfifo", r"telnet\s+\d", r"\bmsfvenom\b", r"meterpreter",
    r"\bwebshell\b", r"c99|r57|b374k|wso\.php",
    # 코드 실행 함수(웹쉘류)
    r"eval\s*\(\s*\$_", r"system\s*\(\s*\$_", r"shell_exec\s*\(\s*\$_",
    r"exec\s*\(\s*\$_", r"passthru\s*\(\s*\$_", r"assert\s*\(\s*\$_",
    r"popen\s*\(", r"proc_open\s*\(", r"`\s*\$_",
    r"Runtime\.getRuntime", r"ProcessBuilder", r"Process\.Start",
    r"os\.system", r"subprocess\.", r"__import__\s*\(\s*['\"]os",
    r"<\?php.*(system|exec|passthru|shell_exec|eval)",
    r"<%.*Runtime", r"<%.*ProcessBuilder",   # JSP
]

# 2) 파괴적/시스템 변경 — BLOCKED_DESTRUCTIVE
_DESTRUCTIVE_PATTERNS = [
    r"rm\s+-rf", r"\bmkfs\b", r"dd\s+if=", r"chmod\s+777", r"chown\s+",
    r"\buseradd\b", r"\buserdel\b", r"\bpasswd\b", r"\bsudo\b", r"\bsu\s+-?",
    r":\(\)\{.*\};:",                      # fork bomb
    r"/etc/shadow", r"/etc/passwd", r"id_rsa", r"ssh\s+key", r"authorized_keys",
    r"credential\s*dump", r"mimikatz", r"lsass", r"\bhashdump\b",
    r">\s*/etc/", r">>\s*/etc/", r"\bshutdown\b", r"\breboot\b", r"\binit\s+0",
]

# 3) 파괴적 SQL(DML/DDL/stacked) — BLOCKED_DESTRUCTIVE
_SQL_DESTRUCTIVE = re.compile(
    r"\b(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|CREATE|GRANT|REVOKE|MERGE|REPLACE)\b",
    re.IGNORECASE)
_SQL_OS_CMD = re.compile(r"(xp_cmdshell|sp_oacreate|into\s+outfile|into\s+dumpfile|load_file)",
                         re.IGNORECASE)
# stacked query: 세미콜론으로 추가 구문 (끝/공백 세미콜론 제외)
_SQL_STACKED = re.compile(r";\s*(select|drop|delete|update|insert|alter|truncate|exec|create)",
                          re.IGNORECASE)

# 4) Time-based SQLi (기본 차단; ENABLE_TIME_BASED_SQLI=true 일 때만 허용)
_SQL_TIME_BASED = re.compile(
    r"(sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep\s*\(|dbms_lock|dbms_pipe|"
    r"generate_series\s*\(.*\)|rlike\s+sleep)",
    re.IGNORECASE)

# 5) 파일 업로드 — 웹쉘/실행파일/폴리글랏/매크로 차단
_UPLOAD_SHELL = re.compile(
    r"(\.php\d?\b|\.phtml|\.jsp\b|\.jspx|\.asp\b|\.aspx|\.cer|\.cshtml|\.war|"
    r"\.exe\b|\.dll\b|\.sh\b|\.bat\b|\.cmd\b|\.elf|\.bin\b|\.jar\b|"
    r"<\?php|<%|<script\s+runat|x-php|application/x-httpd-php)",
    re.IGNORECASE)
_UPLOAD_MACRO = re.compile(r"(vbaproject|auto_open|autoopen|workbook_open|macroenabled|\.docm|\.xlsm|\.pptm)",
                           re.IGNORECASE)
# 무해 hello-world 웹쉘 예외(정책 허용): hello world 출력만 포함하는 txt/php/jsp
_BENIGN_HELLO = re.compile(r"hello[\s_-]*world", re.IGNORECASE)
_DANGEROUS_CODE = re.compile(
    r"(system|exec|shell_exec|passthru|eval|assert|popen|proc_open|Runtime|ProcessBuilder|"
    r"\$_(GET|POST|REQUEST|COOKIE|SERVER)|cmd|whoami|/bin/|powershell)",
    re.IGNORECASE)

# 상태 변경 가능 메서드
_STATE_CHANGE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


def _any(patterns, text: str) -> str | None:
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return p
    return None


def _time_based_enabled() -> bool:
    if os.getenv("ENABLE_TIME_BASED_SQLI", "false").strip().lower() in ("1", "true", "yes", "on"):
        return True
    # PROOF 모드는 time-based SQLi 를 자동 허용(느리지만 blind 실증에 필요).
    try:
        import validation_profiles as _vp
        return _vp.proof_active()
    except Exception:
        return False


def _rce_proof_mode() -> bool:
    """OS 명령 증거 모드. 기본 OFF(미설정 시 False)."""
    return os.getenv("RCE_PROOF_MODE", "false").strip().lower() in ("1", "true", "yes", "on")


# RCE proof mode 에서 '유일하게' 허용되는 무해 echo marker 형태.
# 고정 marker 를 echo 하고 그 반사만 증거로 삼는다(네트워크/파일/권한 없음).
_ALLOWED_ECHO_MARKER = re.compile(
    r"^[;|&\s'\"()`]*\b(echo|print)\b\s+['\"]?EOSEUREUM_RCE_[A-Z0-9_]+['\"]?[;|&\s'\"()`]*$",
    re.IGNORECASE)


def validate_payload(payload: str, *, vuln_type: str = "", method: str = "GET",
                     is_upload: bool = False,
                     time_based_enabled: bool | None = None,
                     rce_proof_mode: bool | None = None,
                     allow_state_change: bool = False) -> dict:
    """payload 실행 허용 여부 검증. 반환: {verdict, reason, category}.

    vuln_type : 후보 취약점 유형(소문자 권장: xss/sqli/cmdi/upload/...).
    method    : 요청 메서드. 상태변경 메서드 + DML 류는 BLOCKED_STATE_CHANGE.
    is_upload : 파일 업로드 컨텍스트면 업로드 규칙 적용.
    time_based_enabled / rce_proof_mode : None 이면 env 에서 읽음.
    """
    if time_based_enabled is None:
        time_based_enabled = _time_based_enabled()
    if rce_proof_mode is None:
        rce_proof_mode = _rce_proof_mode()
    p = payload if isinstance(payload, str) else str(payload or "")
    low = p.lower()
    vt = (vuln_type or "").lower()
    m = (method or "GET").upper()

    def res(verdict, reason, category=""):
        return {"verdict": verdict, "reason": reason, "category": category or vt}

    # 0) 파일 업로드 컨텍스트
    if is_upload or vt in ("file_upload", "upload"):
        if _UPLOAD_MACRO.search(p):
            return res(BLOCKED_SHELL, "악성 매크로 문서 업로드 차단", "upload")
        if _UPLOAD_SHELL.search(p):
            # 무해 hello-world 예외: 위험 코드가 전혀 없고 hello world 만 포함
            if _BENIGN_HELLO.search(p) and not _DANGEROUS_CODE.search(p):
                return res(MANUAL_APPROVAL_REQUIRED,
                           "무해 hello-world 업로드 후보 — 별도 승인 시에만 업로드 가능성 확인", "upload")
            return res(BLOCKED_SHELL, "웹쉘/실행파일/폴리글랏 업로드 차단", "upload")
        return res(ALLOWED_SAFE, "업로드 통제 분석 대상(실행 파일 아님)", "upload")

    # 1) 셸/리버스셸/코드실행 함수
    hit = _any(_SHELL_PATTERNS, p)
    if hit:
        return res(BLOCKED_SHELL, f"셸/리버스셸/코드실행 패턴 차단: {hit}", "shell")

    # 2) 파괴적/시스템 변경
    hit = _any(_DESTRUCTIVE_PATTERNS, p)
    if hit:
        return res(BLOCKED_DESTRUCTIVE, f"파괴적/시스템 변경 패턴 차단: {hit}", "destructive")

    # 3) OS 명령 인젝션 — 기본 금지. RCE proof mode 에서 '고정 echo marker' 만 허용.
    if vt in ("cmdi", "command_injection", "command injection", "rce"):
        if _ALLOWED_ECHO_MARKER.match(p.strip()):
            if rce_proof_mode:
                return res(ALLOWED_SAFE, "RCE Proof Mode: 무해 고정 echo marker 만 허용", "rce")
            return res(MANUAL_APPROVAL_REQUIRED,
                       "OS 명령 증거는 RCE_PROOF_MODE=true 승인 시에만 수행(무해 echo marker)", "rce")
        return res(BLOCKED_SHELL, "OS 명령 인젝션 payload 차단(echo marker 외 불가)", "rce")

    # 4) SQL 안전성
    if _SQL_OS_CMD.search(p):
        return res(BLOCKED_DESTRUCTIVE, "SQL OS명령/파일 I/O(xp_cmdshell/outfile/load_file) 차단", "sqli")
    if _SQL_TIME_BASED.search(p):
        if not time_based_enabled:
            return res(BLOCKED_TIME_BASED, "Time-based SQLi 기본 차단(ENABLE_TIME_BASED_SQLI=false)", "sqli")
        # 명시 허용이어도 stacked/DML 동반은 별도 차단
    if _SQL_STACKED.search(p):
        return res(BLOCKED_STATE_CHANGE, "Stacked query(세미콜론 다중 구문) 차단", "sqli")
    if _SQL_DESTRUCTIVE.search(p):
        return res(BLOCKED_DESTRUCTIVE, "파괴적 SQL(DROP/DELETE/UPDATE/INSERT/ALTER/TRUNCATE 등) 차단", "sqli")

    # 5) 상태 변경 메서드 + 변경 키워드(허용되지 않은 경우)
    if m in _STATE_CHANGE_METHODS and not allow_state_change:
        if re.search(r"\b(delete|remove|drop|update|set|disable|deactivate|reset)\b", low):
            return res(BLOCKED_STATE_CHANGE, f"상태 변경({m}) + 변경 키워드 차단", "state")

    return res(ALLOWED_SAFE, "안전 payload — 실행 허용(비파괴)", vt or "generic")


def validate_payloads(payloads, **kw) -> list[dict]:
    """여러 payload 일괄 검증. 각 항목에 payload(마스킹용 원문) 보존."""
    out = []
    for pl in payloads or []:
        v = validate_payload(pl, **kw)
        v = {**v, "payload": pl}
        out.append(v)
    return out


def summarize(results: list[dict]) -> dict:
    """검증 결과 집계: 통과/차단 수 + 차단 사유별 카운트."""
    allowed = sum(1 for r in results if r.get("verdict") == ALLOWED_SAFE)
    blocked = [r for r in results if r.get("verdict") in _BLOCKED]
    by_reason: dict = {}
    for r in blocked:
        by_reason[r["verdict"]] = by_reason.get(r["verdict"], 0) + 1
    return {
        "total": len(results), "allowed": allowed, "blocked": len(blocked),
        "blocked_by_verdict": by_reason,
    }
