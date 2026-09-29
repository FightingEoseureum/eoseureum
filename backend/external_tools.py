"""
external_tools.py

공개 오픈소스 보안 도구 통합 모듈
  - testssl.sh  : SSL/TLS 취약점 (Heartbleed, POODLE, 약한 암호 스위트 등)
  - nuclei      : CVE·설정 오류 템플릿 기반 취약점 스캔
  - katana      : 웹 크롤링 — 숨겨진 엔드포인트·파라미터 수집
  - ffuf        : 디렉터리·파일 퍼징 — 노출된 민감 경로 발견
  - ghauri      : SQL 인젝션 심화 — 실제 DB 목록 추출로 실증

각 도구가 설치되지 않은 경우 해당 단계를 건너뛰고 진행합니다.
"""

import asyncio
import hashlib
import json
import os
import pathlib
import re
import shutil
import tempfile
import time as _time
import urllib.parse

import aiohttp

import adaptive_throttle as _gov   # safe 모드 전역 rate 거버너(미설치 시 no-op)

_BASE_DIR = pathlib.Path(__file__).parent
_WORDLIST_PATH = _BASE_DIR / "wordlists" / "common.txt"
_TEMP_DIR = pathlib.Path(tempfile.gettempdir()) / "eoseureum_scanner"
_TEMP_DIR.mkdir(exist_ok=True)


# ── 도구 가용성 확인 ──────────────────────────────────────────────────────────

def _which(name: str) -> str | None:
    return shutil.which(name)


def _testssl_cmd() -> list[str] | None:
    """testssl 실행 가능한 커맨드 반환. 없으면 None."""
    for name in ("testssl.sh", "testssl"):
        p = _which(name)
        if p:
            return [p]
    # bash/wsl 경유 시도
    for shell in ("bash", "wsl"):
        sp = _which(shell)
        if sp:
            for ts_name in ("testssl.sh", "/usr/local/bin/testssl.sh", "/opt/testssl/testssl.sh"):
                if pathlib.Path(ts_name).exists():
                    return [sp, ts_name]
    return None


def available_tools() -> dict[str, bool]:
    return {
        "testssl": _testssl_cmd() is not None,
        "nuclei":  _which("nuclei") is not None,
        # E1: run_sqlmap 과 동일하게 SQLMAP_PATH(절대경로 포함)도 인식 — PATH 밖 sqlmap 이 조용히 비활성되던 문제
        "sqlmap":  _sqlmap_binary_available(),
        "wpscan":  _which("wpscan") is not None,
        # 내부화 완료로 제외(벤치마크 검증 후): ffuf→run_dir_fuzz, httpx→run_native_fingerprint,
        # katana→run_native_crawl. ghauri→sqlmap. 도구 목록/경고에 노출하지 않음.
    }


def _sqlmap_binary_available() -> bool:
    p = os.getenv("SQLMAP_PATH", "sqlmap")
    return bool(_which(p) or (os.path.sep in p and os.path.exists(p)))


# ── 서브프로세스 실행 ─────────────────────────────────────────────────────────

async def _run(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    """커맨드를 실행하고 (returncode, stdout, stderr) 반환.

    타임아웃 시 '프로세스 그룹 전체'를 종료한다 — testssl/sqlmap 등은 bash 래퍼로 자식을 스폰하므로
    직접 자식(proc)만 kill 하면 실제 도구가 대상 상대로 계속 실행되던 문제를 막는다(start_new_session
    으로 새 세션/프로세스 그룹을 만들고 killpg 로 트리 전체 종료 후 reap).
    """
    # 단일출구(egress): 활성 시 외부도구 서브프로세스에도 SOCKS5 프록시 env 를 주입한다.
    # Go 계열(nuclei·katana·ffuf·httpx)은 ALL_PROXY(socks5) 를 존중해 i7 경유로 나간다. 프록시 env 를
    # 모르는 도구는 무시(직접) — 외부 대상 완전 무누출은 B2(외부도구 i7 이전)에서 마무리한다.
    _sub_env = None
    try:
        import egress as _eg
        if _eg.enabled():
            _pxy = f"socks5://127.0.0.1:{_eg._port()}"
            _sub_env = {**os.environ,
                        "ALL_PROXY": _pxy, "all_proxy": _pxy,
                        "HTTP_PROXY": _pxy, "http_proxy": _pxy,
                        "HTTPS_PROXY": _pxy, "https_proxy": _pxy}
    except Exception:
        _sub_env = None
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,          # 새 프로세스 그룹(=proc.pid) → killpg 대상
            env=_sub_env,                    # None 이면 부모 env 상속(egress OFF 시 기존과 동일)
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode or 0, out.decode("utf-8", errors="ignore"), err.decode("utf-8", errors="ignore")
        except asyncio.TimeoutError:
            _kill_process_tree(proc)
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)   # reap(좀비 방지)
            except Exception:
                pass
            return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", "not_found"
    except Exception as e:
        if proc is not None:
            _kill_process_tree(proc)
        return -1, "", str(e)


def _kill_process_tree(proc) -> None:
    """proc 의 프로세스 그룹 전체를 SIGKILL. 실패 시 직접 kill 폴백."""
    import os as _os
    import signal as _signal
    try:
        pgid = _os.getpgid(proc.pid)
        _os.killpg(pgid, _signal.SIGKILL)
        return
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        pass


# ── Finding 빌더 ──────────────────────────────────────────────────────────────

def _make_finding(
    host: str, port: int, service: str,
    title: str, severity: str,
    description: str, evidence_detail: str,
    detection_steps: list[str],
    recommendation: str = "",
    attack_vector: str = "",
    cve_references: list | None = None,
    tool_source: str = "",
    url: str = "",
    confidence: str | None = None,
) -> dict:
    # severity 대소문자 혼재(HIGH vs "Low")로 잘못된 CVSS 기본값이 붙던 문제 → 대문자로 정규화 후 조회
    cvss = {"HIGH": "7.5", "MEDIUM": "5.3", "LOW": "3.1"}.get((severity or "").upper(), "5.3")
    scheme = "https" if port in (443, 8443) else "http"
    # 실제 발견 URL(경로·파라미터 포함)이 주어지면 그대로 사용한다. 경로가 있어야
    # 서로 다른 엔드포인트의 finding 이 (host, path) 기준으로 구분되어 병합 시 뭉개지지 않는다.
    evidence_url = url or f"{scheme}://{host}:{port}"
    return {
        "host": host,
        "port": port,
        "service": service,
        "judgment": "취약",
        "confidence": confidence,
        "severity": severity,
        "cvss_estimate": cvss,
        "exploitation_difficulty": "Medium",
        "is_new": True,
        "is_persistent": False,
        "is_resolved": False,
        "title": title,
        "description": description,
        "attack_vector": attack_vector,
        "attack_scenario": "",
        "tools": [tool_source] if tool_source else [],
        "cve_references": cve_references or [],
        "lab_guide": "",
        "recommendation": recommendation,
        "evidence_url": evidence_url,
        "detection_steps": detection_steps,
        "evidence_detail": evidence_detail,
        "evidence_screenshot": "",
        "probe_confirmed": True,
        "tool_source": tool_source,
    }


# ── testssl.sh ────────────────────────────────────────────────────────────────

# 보고할 심각도 (OK / INFO / DEBUG 는 제외)
_TESTSSL_REPORT = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

# 취약하지 않은 결과를 나타내는 패턴 (스킵)
_TESTSSL_OK_RE = re.compile(
    r"not (offered|vulnerable|supported|affected|present|detected)"
    r"|^OK$|\(OK\)|not affected|No weak",
    re.IGNORECASE,
)

# 단순 정보성 ID (취약점이 아닌 것)
_TESTSSL_SKIP_IDS = {
    "service", "cert_signatureAlgorithm", "cert_keySize",
    "cert_expirationStatus", "cipher_order", "PFS",
    "cipher-tls1_2_offered", "cipher-tls1_3_offered",
    "protocol_negotiated", "certificate_transparency",
    "DNS_CAArecord", "OCSP_stapling",
}

_TESTSSL_CVE = {
    "heartbleed":     "CVE-2014-0160",
    "CCS":            "CVE-2014-0224",
    "ROBOT":          "CVE-2017-13099",
    "POODLE_SSL":     "CVE-2014-3566",
    "DROWN":          "CVE-2016-0800",
    "LOGJAM":         "CVE-2015-4000",
    "FREAK":          "CVE-2015-0204",
    "BEAST_CBC_TLS1": "CVE-2011-3389",
    "LUCKY13":        "CVE-2013-0169",
    "ticketbleed":    "CVE-2016-9244",
}

_TESTSSL_REC = {
    "SSLv2":    "SSLv2를 즉시 비활성화하세요. TLS 1.2 이상만 허용하세요.",
    "SSLv3":    "SSLv3를 비활성화하세요. TLS 1.2 이상만 허용하세요.",
    "TLS1":     "TLS 1.0을 비활성화하고 TLS 1.2/1.3만 허용하세요.",
    "TLS1_1":   "TLS 1.1을 비활성화하고 TLS 1.2/1.3만 허용하세요.",
    "RC4":      "RC4 암호 스위트를 비활성화하세요. AES-GCM을 사용하세요.",
    "SWEET32":  "3DES(SWEET32) 암호 스위트를 비활성화하세요.",
    "heartbleed": "OpenSSL을 최신 버전으로 업그레이드하세요 (1.0.1g 이상).",
    "POODLE_SSL": "SSLv3를 비활성화하여 POODLE 공격을 방지하세요.",
    "DROWN":    "SSLv2를 완전히 비활성화하세요.",
    "cert_expired": "SSL 인증서를 즉시 갱신하세요.",
    "cert_notYetValid": "인증서 유효기간을 확인하고 올바른 인증서로 교체하세요.",
    "cert_hostnameMatchDontMatch": "도메인과 일치하는 SSL 인증서를 발급받아 적용하세요.",
}


async def run_testssl(host: str, port: int, progress_cb=None) -> list[dict]:
    """testssl.sh로 SSL/TLS 취약점을 점검하고 findings를 반환합니다."""
    cmd_prefix = _testssl_cmd()
    if not cmd_prefix:
        return []

    out_file = _TEMP_DIR / f"testssl_{host}_{port}.json"
    out_file.unlink(missing_ok=True)

    cmd = cmd_prefix + [
        "--quiet", "--color", "0",
        "--jsonfile", str(out_file),
        "--severity", "LOW",
        "--nodns", "min",
        "--fast",
        f"{host}:{port}",
    ]

    if progress_cb:
        await progress_cb(f"testssl.sh: {host}:{port} SSL/TLS 점검 시작...")

    # testssl 은 느려서 120초로 자주 잘렸음 → 300초. 반환값을 캡처해 timeout 을 투명하게 보고.
    rc, _so, _se = await _run(cmd, timeout=300)
    _timed_out = (rc == -1 and _se == "timeout")

    if not out_file.exists():
        if progress_cb:
            await progress_cb(f"testssl.sh: {host}:{port} — "
                              + ("시간 초과(SSL/TLS 결과 미확보)" if _timed_out else "결과 없음"))
        return []

    try:
        raw = out_file.read_text("utf-8", errors="ignore")
        data = json.loads(raw)
    except Exception:
        return []

    # testssl JSON 은 list 또는 {"scanResult": [...]} 형태
    items: list = data if isinstance(data, list) else data.get("scanResult", [])
    if isinstance(items, dict):
        items = [items]

    findings = []
    for item in items:
        if not isinstance(item, dict):
            continue
        item_id   = item.get("id", "")
        item_sev  = item.get("severity", "")
        finding   = item.get("finding", "")
        cve_field = item.get("cve", "")

        if item_id in _TESTSSL_SKIP_IDS:
            continue
        if item_sev not in _TESTSSL_REPORT:
            continue
        if _TESTSSL_OK_RE.search(finding):
            continue

        # 심각도: testssl 등급을 충실히 매핑(CRITICAL 을 HIGH 로 강등하지 않음 → finding·근거 심각도 일치).
        severity = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
                    "LOW": "LOW"}.get(item_sev, item_sev.capitalize())
        # CWE 부여(누락 방지): 인증서류=CWE-295, 그 외 TLS 약점=CWE-326.
        cwe = "CWE-295" if "cert" in item_id.lower() else "CWE-326"
        cves = [c.strip() for c in cve_field.split() if c.strip().startswith("CVE")]
        if item_id in _TESTSSL_CVE and _TESTSSL_CVE[item_id] not in cves:
            cves.insert(0, _TESTSSL_CVE[item_id])

        rec = _TESTSSL_REC.get(item_id, "TLS 설정을 검토하고 최신 보안 권고 사항을 적용하세요.")

        _ssl_f = _make_finding(
            host=host, port=port, service="HTTPS",
            title=f"SSL/TLS 취약점 [{item_id}]",
            severity=severity,
            description=f"testssl.sh 점검 항목 '{item_id}': {finding}",
            evidence_detail=(
                f"[testssl.sh 점검 결과]\n"
                f"항목 ID : {item_id}\n"
                f"심각도  : {item_sev}\n"
                f"결과    : {finding}\n"
                + (f"CVE     : {', '.join(cves)}" if cves else "")
            ),
            detection_steps=[
                f"[1단계] testssl.sh {host}:{port} 실행",
                f"[2단계] SSL/TLS 항목 '{item_id}' 점검",
                f"[3단계] 결과: {finding}",
                f"[결론] 심각도 {item_sev} 취약점 확인 — 암호화 통신 공격에 악용 가능",
            ],
            recommendation=rec,
            attack_vector=f"{item_id} 취약점을 이용한 암호화 통신 복호화 또는 세션 탈취",
            cve_references=cves,
            tool_source="testssl.sh",
            confidence="CONFIRMED",   # testssl 이 TLS 설정을 결정적으로 관측 → confidence 미설정(None) 방지
        )
        _ssl_f["cwe"] = cwe
        findings.append(_ssl_f)

    if progress_cb:
        await progress_cb(f"testssl.sh: {host}:{port} 완료 — {len(findings)}건 발견"
                          + (" (시간 초과로 일부만)" if _timed_out else ""))
    return findings


# ── 워드리스트 / soft-404 오탐 필터 (내부 퍼징·크롤 공용) ─────────────────────────

_WORDLIST_10K = _BASE_DIR / "wordlists" / "ffuf-10k.txt"


def _wordlist_path() -> str | None:
    # 1) 명시적 env 지정 우선
    env_wl = (os.getenv("FFUF_WORDLIST") or "").strip()
    if env_wl and pathlib.Path(env_wl).exists():
        return env_wl
    # 2) SecLists raft-medium(빈도순, 권장 기본) — 설치돼 있으면 번들보다 우선.
    #    빈도순이라 캡/시간예산 내 앞쪽 테스트만으로도 알짜 경로 커버리지 확보.
    for seclists in (
        "/opt/SecLists/Discovery/Web-Content/raft-medium-words.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
        str(pathlib.Path.home() / "SecLists/Discovery/Web-Content/raft-medium-words.txt"),
    ):
        if pathlib.Path(seclists).exists():
            return seclists
    # 3) 동봉된 10k 리스트(오프라인 폴백)
    if _WORDLIST_10K.exists():
        return str(_WORDLIST_10K)
    # 4) 소형 기본 리스트
    if _WORDLIST_PATH.exists():
        return str(_WORDLIST_PATH)
    for candidate in (
        "/opt/SecLists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        str(pathlib.Path.home() / "SecLists/Discovery/Web-Content/common.txt"),
    ):
        if pathlib.Path(candidate).exists():
            return candidate
    return None


def _quickhits_words() -> list[str]:
    """SecLists quickhits(고신호 민감파일·설정·백업 큐레이션) 로드·정제. 없으면 빈 리스트.
    일부 항목이 '!'·'/' 로 시작 → 정제. QUICKHITS_ENABLE=false 로 비활성 가능."""
    if os.getenv("QUICKHITS_ENABLE", "true").strip().lower() in ("0", "false", "no", "off"):
        return []
    _env = (os.getenv("QUICKHITS_PATH") or "").strip()
    for c in (([_env] if _env else []) + [
        "/opt/SecLists/Discovery/Web-Content/quickhits.txt",
        "/usr/share/seclists/Discovery/Web-Content/quickhits.txt",
        str(pathlib.Path.home() / "SecLists/Discovery/Web-Content/quickhits.txt"),
    ]):
        p = pathlib.Path(c)
        if p.exists():
            try:
                out = []
                for ln in p.read_text("utf-8", errors="ignore").splitlines():
                    w = ln.strip().lstrip("!").lstrip("/")
                    if w and not w.startswith("#"):
                        out.append(w)
                return out
            except Exception:
                return []
    return []


_SENSITIVE_PATH_RE = re.compile(
    r"(admin|backup|config|env|\.git|console|dashboard|phpmyadmin|"
    r"actuator|swagger|api.?doc|upload|secret|credential|passwd|shadow|"
    r"database|dump|\.sql|log|debug|test|dev|staging|wp-config|"
    r"\.htaccess|\.htpasswd|web\.config|graphql|prometheus|grafana|jenkins)",
    re.IGNORECASE,
)

# 노출된 파일 '내용'에 실제 중요정보가 있는지 판별 — 있으면 '취약점(정보 노출)'으로 승격,
# 없으면 '경로 존재(참고)'로만 둔다(불필요 파일 삭제 권고). 사용자 지침: 내용 기반으로 취약/양호 판정.
_SENSITIVE_CONTENT_RE = re.compile(
    r"(?i)(<\?php|#!/(bin|usr)|password\s*[=:>]|passwd\s*[=:]|db_?password|"
    r"database.{0,24}password|pass(word)?['\"]?\s*=>|secret\s*[=:]|api[_-]?key|"
    r"access[_-]?key|client[_-]?secret|private[_-]?key|-----BEGIN [A-Z ]*PRIVATE KEY|"
    r"AKIA[0-9A-Z]{16}|mysqli?_connect|new\s+PDO|\$_DVWA|DB_(HOST|USER|PASS|PASSWORD|NAME)|"
    r"connectionstring|jdbc:|mongodb(\+srv)?://|postgres(ql)?://|redis://|"
    r"\[core\]\s*\n|ref:\s*refs/|filemode\s*=|BEGIN RSA|ssh-rsa|"
    r"aws_secret|authorization:\s*bearer|X-Api-Key)")
# 노출 시 그 자체로 민감(경로/파일명만으로도 중요) — 내용 미확보여도 취약 승격 대상.
_ALWAYS_SENSITIVE_FILE_RE = re.compile(
    r"(?i)(\.env\b|\.git/|/\.git\b|\.gitattributes|\.gitignore|id_rsa|id_dsa|\.pem\b|\.key\b|"
    r"wp-config|config\.inc\.php|settings\.py|\.htpasswd|credentials|\.aws/|\.ssh/|"
    r"\.sql\b|dump\.sql|database\.yml|\.pfx\b|\.p12\b|web\.config)")

# 정상적으로 공개되는 페이지 — '민감 경로 노출' 오탐 방지(예: login.php 는 'log' 에 매칭돼 오탐).
# 이들은 공개가 정상이므로 민감 경로로 승격하지 않는다.
_BENIGN_PUBLIC_PATHS = re.compile(
    r"(^|/)(login|logout|signin|signout|sign-in|sign-out|register|signup|sign-up|"
    r"index|home|main|default|welcome|about|contact|help|faq|search|"
    r"favicon\.ico|robots\.txt|sitemap\.xml)(\.[a-z0-9]{2,5})?/?$",
    re.IGNORECASE,
)

_CONFIG_BODY_RE = re.compile(
    r"([A-Z_]{3,}=.{2,}|\[core\]|DB_NAME|DB_PASS|define\s*\(|"
    r"RewriteEngine|-----BEGIN|password\s*=|api.?key\s*=)",
    re.IGNORECASE,
)


# ── Admin/민감 경로 soft-404 오탐 필터 (순수 함수 — 테스트 가능) ────────────────
_ADMIN_PATH_RE = re.compile(r"(admin|administrator|manage|management|dashboard|console)", re.IGNORECASE)
_ADMIN_KEYWORDS = ("admin", "administrator", "dashboard", "management", "console",
                   "관리자", "로그인", "sign in", "log in", "login")


def _body_hash(body: str) -> str:
    return hashlib.md5((body or "").strip().encode("utf-8", "ignore")).hexdigest()


def _html_title(body: str) -> str:
    m = re.search(r"<title>(.*?)</title>", body or "", re.IGNORECASE | re.DOTALL)
    return m.group(1).strip().lower() if m else ""


def _resp_len(r: dict) -> int:
    if isinstance(r.get("length"), int):
        return r["length"]
    return len(r.get("body", "") or "")


def is_soft404(candidate: dict, randoms: list[dict]) -> bool:
    """후보 응답이 랜덤(존재하지 않는) 경로 응답과 동일/유사하면 soft-404 로 판정.

    판정: 어떤 랜덤 경로와 'status 동일' 이면서 아래 내용 신호 중 1개 이상 일치.
      length 유사 / body hash 동일 / title 동일 / 후보 body 비어있음
    (즉 status 일치 + 내용 유사 = 신호 2개 이상 → catch-all soft-404)
    """
    randoms = [r for r in (randoms or []) if isinstance(r, dict)]
    if not randoms:
        return False
    c_len = _resp_len(candidate)
    c_hash = _body_hash(candidate.get("body", ""))
    c_title = candidate.get("title") or _html_title(candidate.get("body", ""))
    c_empty = not (candidate.get("body", "") or "").strip()
    for r in randoms:
        if candidate.get("status") != r.get("status"):
            continue
        content_signals = 0
        r_len = _resp_len(r)
        if abs(c_len - r_len) <= max(24, int(0.1 * max(r_len, 1))):
            content_signals += 1
        if c_hash == _body_hash(r.get("body", "")):
            content_signals += 1
        r_title = r.get("title") or _html_title(r.get("body", ""))
        if c_title and c_title == r_title:
            content_signals += 1
        if c_empty:
            content_signals += 1
        if content_signals >= 1:
            return True
    return False


def admin_surface_eligible(status: int, body: str = "", title: str = "",
                           has_fingerprint: bool = False) -> bool:
    """Admin/민감 경로를 공격 표면으로 '등록'할 자격이 있는지 판정.

    등록: 401/403 보호 경로 / password input / login form / 관리자 키워드 / 제품 fingerprint
    제외: 200 + 빈 본문(length 0) / 키워드·폼 없음
    """
    if status in (401, 403):
        return True
    if has_fingerprint:
        return True
    b = (body or "")
    if status == 200 and not b.strip():
        return False
    bl = b.lower()
    tl = (title or "").lower()
    if 'type="password"' in bl or "type='password'" in bl or "type=password" in bl:
        return True
    if "<form" in bl and any(k in bl for k in ("login", "sign in", "log in", "password", "관리자")):
        return True
    if any(k in bl or k in tl for k in _ADMIN_KEYWORDS):
        return True
    return False


async def _fetch_resp(url: str) -> dict | None:
    """단일 GET 으로 {status, length, body, title} 반환(soft-404 비교용)."""
    try:
        ssl_ctx = __import__("ssl").create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = __import__("ssl").CERT_NONE
        conn = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(connector=conn,
                                         timeout=aiohttp.ClientTimeout(total=8)) as s:
            async with s.get(url, allow_redirects=True) as r:
                body = await r.text(errors="replace")
                return {"status": r.status, "length": len(body),
                        "body": body[:8000], "title": _html_title(body)}
    except Exception:
        return None


# ── 내부(네이티브) 크롤러 — 외부 katana 대체 ──────────────────────────────────
async def run_native_crawl(base_url: str, host: str, port: int, depth: int | None = None,
                           progress_cb=None) -> list[str]:
    """내부(네이티브) 크롤러 — 외부 katana 대체.

    동일 출처를 depth 제한 BFS로 크롤하며 HTML 링크 + JS 엔드포인트(정적 파싱)를 수집한다.
    url_discovery 의 검증된 추출 패턴(HTML_LINK_PATTERNS / JS_ENDPOINT_PATTERNS)을 재사용 —
    katana 의 `-jc`(JS 정적 파싱)와 동등한 커버리지를 외부 의존 없이 확보.
    반환: 동일 출처 URL 목록(파라미터 URL 포함).
    """
    try:
        from url_discovery import HTML_LINK_PATTERNS, JS_ENDPOINT_PATTERNS
    except Exception:
        return []
    import ssl as _ssl
    import time as _t
    base = base_url.rstrip("/")
    base_netloc = urllib.parse.urlparse(base_url).netloc
    # 깊이·페이지수를 PROOF/예산에 맞춰 스케일(scan_depth). 인자 depth 명시 시 그대로.
    try:
        import scan_depth as _sd
        if depth is None:
            depth = _sd.crawl_depth()
        maxpages = max(10, min(3000, _sd.crawl_max_pages()))
    except Exception:
        if depth is None:
            depth = 2
        try:
            maxpages = max(10, min(300, int(os.getenv("CRAWL_MAX_PAGES", "60"))))
        except (TypeError, ValueError):
            maxpages = 60
    try:
        maxtime = max(15, min(300, int(os.getenv("CRAWL_MAXTIME", "60"))))
    except (TypeError, ValueError):
        maxtime = 60

    def _norm(u: str, page: str):
        try:
            u = (u or "").strip()
            if not u or u.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                return None
            full = urllib.parse.urljoin(page, u)
            p = urllib.parse.urlparse(full)
            if p.scheme not in ("http", "https") or p.netloc != base_netloc:
                return None
            return full.split("#")[0]
        except Exception:
            return None

    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    seen: set = {base_url}
    out: set = set()
    queue: list = [(base_url, 0)]
    deadline = _t.time() + maxtime
    if progress_cb:
        await progress_cb(f"내부 크롤: {base} 시작(depth≤{depth}, ≤{maxpages}p/{maxtime}s)...")
    try:
        conn = aiohttp.TCPConnector(ssl=ctx, limit=8)
        async with aiohttp.ClientSession(
                connector=conn,
                headers={"User-Agent": "Mozilla/5.0 (Eoseureum Scanner)"}) as s:
            pages = 0
            while queue and pages < maxpages and _t.time() < deadline:
                url, d = queue.pop(0)
                final_url = url
                body = ""
                ct = ""
                _g = _gov.stage("native_crawl")
                if _g is not None:
                    await _g.before()
                _t0 = _time.monotonic()
                try:
                    async with s.get(url, allow_redirects=True,
                                     timeout=aiohttp.ClientTimeout(total=8)) as r:
                        ct = (r.headers.get("Content-Type") or "").lower()
                        final_url = str(r.url).split("#")[0]
                        _ncst, _ncra = r.status, r.headers.get("Retry-After")
                        if not ("html" in ct or "javascript" in ct or ct == ""
                                or url.endswith(".js")):
                            if _g is not None:
                                _g.after(_time.monotonic() - _t0, _ncst, _ncra)
                            continue
                        body = await r.text(errors="ignore")
                    if _g is not None:
                        _g.after(_time.monotonic() - _t0, _ncst, _ncra)
                except Exception:
                    if _g is not None:
                        _g.after(_time.monotonic() - _t0, 0, None)
                    continue
                pages += 1
                out.add(final_url)
                links: list = []
                is_js = ("javascript" in ct) or url.endswith(".js")
                if not is_js:
                    for pat in HTML_LINK_PATTERNS:
                        for m in pat.finditer(body):
                            nu = _norm(m.group(1), final_url)
                            if nu:
                                links.append(nu)
                    for js in re.findall(r'<script[^>]*>(.*?)</script>', body,
                                         re.DOTALL | re.IGNORECASE):
                        for pat in JS_ENDPOINT_PATTERNS:
                            for m in pat.finditer(js):
                                nu = _norm(m.group(1), final_url)
                                if nu:
                                    links.append(nu)
                else:
                    for pat in JS_ENDPOINT_PATTERNS:
                        for m in pat.finditer(body):
                            nu = _norm(m.group(1), final_url)
                            if nu:
                                links.append(nu)
                for nu in links:
                    out.add(nu)
                    if nu not in seen and d < depth:
                        seen.add(nu)
                        queue.append((nu, d + 1))
    except Exception:
        pass
    urls = sorted(out)
    if progress_cb:
        await progress_cb(f"내부 크롤: {base} — {len(urls)}개 URL 수집")
    return urls


# ── 내부(네이티브) 디렉터리 퍼징 — 외부 ffuf 대체 ──────────────────────────────
async def _fuzz_get(session, url: str, follow: bool = False, timeout: float = 6.0) -> dict | None:
    """공유 세션 단일 GET → {status, length, body, title}. 실패 시 None.
    rate 거버너를 통과(Safe: 전역 합산 / PROOF: dir_fuzz 단계 상한)."""
    _g = _gov.stage("dir_fuzz")
    if _g is not None:
        await _g.before()
    _t0 = _time.monotonic()
    try:
        async with session.get(url, allow_redirects=follow,
                               timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            body = await r.text(errors="replace")
            _ra = r.headers.get("Retry-After")
            _res = {"status": r.status, "length": len(body),
                    "body": body[:8000], "title": _html_title(body),
                    "location": r.headers.get("Location", "")}
        if _g is not None:
            _g.after(_time.monotonic() - _t0, _res["status"], _ra)
        return _res
    except Exception:
        if _g is not None:
            _g.after(_time.monotonic() - _t0, 0, None)
        return None


async def run_dir_fuzz(target_url: str, host: str, port: int, progress_cb=None) -> list[dict]:
    """내부(네이티브) 디렉터리 퍼징 — 외부 ffuf 대체.

    워드리스트 경로를 동시 요청하고, '소프트404 베이스라인' 대비로 실제 리소스만 선별한다.
    오탐 제어(soft-404·민감/관리 경로 자격·리다이렉트 최종상태)는 기존 순수함수 헬퍼를 재사용하며,
    catch-all(모든 경로 200) 사이트를 베이스라인으로 인식해 ffuf 의 상태코드 필터보다 견고하다.
    """
    wordlist = _wordlist_path()
    if not wordlist:
        return []
    base = target_url.rstrip("/")
    # 퍼징 시간 예산을 PROOF/예산에 맞춰 스케일(scan_depth). env(DIRFUZZ_MAXTIME/FFUF_MAXTIME) 명시 시 그대로.
    try:
        if os.getenv("DIRFUZZ_MAXTIME") or os.getenv("FFUF_MAXTIME"):
            maxtime = max(15, min(1800, int(os.getenv("DIRFUZZ_MAXTIME", os.getenv("FFUF_MAXTIME", "45")))))
        else:
            import scan_depth as _sd
            maxtime = max(15, min(1800, _sd.dirfuzz_maxtime()))
    except (TypeError, ValueError, ImportError):
        maxtime = 45
    try:
        concurrency = max(4, min(64, int(os.getenv("DIRFUZZ_CONCURRENCY", "20"))))
    except (TypeError, ValueError):
        concurrency = 20
    # safe 모드(전역 거버너 설치): 동시성을 소수로 낮춘다. 초당 상한은 거버너가 강제하지만
    # 커넥션 다발(20 in-flight) 자체도 부하 → 거버너의 dir_fuzz 단계 동시성 상한으로 제한
    # (Safe: 2, PROOF: 20 등 단계 상한). 미설치 시 기존값 유지.
    _dfl = _gov.stage("dir_fuzz")
    if _dfl is not None:
        concurrency = min(concurrency, _dfl.conc)
    # 캡 예산연동: 퍼징 시간(maxtime)·동시성에 비례해 테스트 단어 상한을 조정.
    # deadline 이 실제 종료를 지배하므로, 캡은 리스트가 조기 절단되지 않을 만큼만 넉넉히(메모리 상한 유지).
    try:
        _cap = int(os.getenv("DIRFUZZ_MAX_WORDS", "0") or 0)
    except (TypeError, ValueError):
        _cap = 0
    if _cap <= 0:
        # PROOF/예산 스케일 단어 상한과 '시간×동시성' 기반 상한 중 큰 값(둘 다 시간이 실제 종료 지배).
        try:
            import scan_depth as _sd
            _cap = max(_sd.dirfuzz_word_cap(), maxtime * concurrency * 6)
        except Exception:
            _cap = maxtime * concurrency * 6
        _cap = min(300000, max(12000, _cap))
    try:
        raw = [w.strip().lstrip("/") for w in
               pathlib.Path(wordlist).read_text("utf-8", errors="ignore").splitlines()]
        raw = [w for w in raw if w and not w.startswith("#")]
    except Exception:
        return []
    # quickhits(고신호 민감파일)를 앞에 배치 — 시간예산 내 최우선 탐색 보장 + dedup 후 캡 적용
    seen = set()
    words = []
    for w in (_quickhits_words() + raw):
        wl = w.lower()
        if wl and wl not in seen:
            seen.add(wl)
            words.append(w)
    words = words[:_cap]
    if not words:
        return []

    if progress_cb:
        await progress_cb(f"내부 퍼징: {base} 디렉터리 탐색 시작(워드 {len(words)}개, ≤{maxtime}s)...")

    import ssl as _ssl
    import time as _t
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    conn = aiohttp.TCPConnector(ssl=ctx, limit=concurrency)
    MATCH = {200, 201, 204, 301, 302, 401}
    findings: list[dict] = []
    seen_paths: set[str] = set()
    redir_seen: set = set()
    soft_site = False

    async with aiohttp.ClientSession(
            connector=conn,
            headers={"User-Agent": "Mozilla/5.0 (Eoseureum Scanner)"}) as session:
        # 1) 소프트404 베이스라인 — 랜덤 비존재 경로(모든 경로 200 반환 사이트 감지용)
        baseline: list[dict] = []
        for rp in ("eoseureum-nonexist-zzq9x7a2", "eoseureum-random-4o4-7x9q2k8w",
                   "eoseureum-not-here-b3n8w1"):
            r = await _fuzz_get(session, f"{base}/{rp}", follow=False)
            if r:
                baseline.append(r)
        soft_site = any(b["status"] in MATCH for b in baseline)

        deadline = _t.time() + maxtime

        async def probe(word: str):
            if _t.time() > deadline:
                return
            url = f"{base}/{word}"
            r = await _fuzz_get(session, url, follow=False)
            if not r:
                return
            status = r["status"]
            length = r["length"]
            if status not in MATCH:
                return
            if length < 20 and status not in (301, 302):
                return
            # soft-404: 후보가 베이스라인(비존재)과 유사하면 제외(catch-all 오탐 방지)
            if baseline and is_soft404(r, baseline):
                return
            # 301/302 → 리다이렉트 최종 '응답(본문 포함)'을 가져와 상태·본문을 보정한다.
            # (status 만 보정하고 302 의 빈 본문을 유지하면 이후 민감/admin 판정이 오억제됨)
            if status in (301, 302):
                loc = r.get("location") or ""
                # catch-all 억제: 여러 경로가 같은 곳(예: /login)으로 몰리면 첫 1건만 보고
                if loc and loc in redir_seen:
                    return
                if loc:
                    redir_seen.add(loc)
                fr = await _fetch_resp(url)
                if not fr or fr["status"] in (403, 404):
                    return
                if baseline and is_soft404(fr, baseline):
                    return
                r = fr
                status = fr["status"]
                length = fr["length"]
            is_sensitive = bool(_SENSITIVE_PATH_RE.search(word)) and not _BENIGN_PUBLIC_PATHS.search("/" + word.lstrip("/"))
            if not is_sensitive and status == 200:
                return  # 민감하지 않은 200(로그인 등 정상 공개 페이지 포함) 은 노이즈 → 제외
            # 관리 경로 등록 자격(빈 본문/키워드 없음 제외)
            if _ADMIN_PATH_RE.search(word):
                if not admin_surface_eligible(status, r.get("body", ""), r.get("title", "")):
                    return
            key = word.strip("/").lower()
            if key in seen_paths:
                return
            seen_paths.add(key)
            # ── 내용 기반 판정(사용자 지침): 노출 파일에 '실제 중요정보'가 있으면 취약점(정보 노출)으로,
            #    없으면 '경로 존재(참고)'로만 둔다(불필요 파일 삭제 권고). ──
            _body = (r.get("body", "") or "")
            _content_sensitive = bool(status == 200 and _body and _SENSITIVE_CONTENT_RE.search(_body))
            _name_sensitive = bool(_ALWAYS_SENSITIVE_FILE_RE.search("/" + word.lstrip("/")))
            _is_vuln = (is_sensitive and status == 200 and (_content_sensitive or _name_sensitive))

            if _is_vuln:
                # 노출된 '중요정보 종류' 요약(무엇 때문에 취약한지 명시).
                _leaks = []
                _bl = _body.lower()
                if re.search(r"password|passwd|pass'?\s*=>|db_?pass", _bl): _leaks.append("자격증명/비밀번호")
                if re.search(r"\$_dvwa|db_(host|user|name)|new\s+pdo|mysqli?_connect|connectionstring|jdbc:", _bl):
                    _leaks.append("DB 접속 설정")
                if "<?php" in _bl or re.search(r"#!/(bin|usr)", _bl): _leaks.append("서버측 소스코드")
                if re.search(r"api[_-]?key|secret|private[_-]?key|ssh-rsa|akia[0-9a-z]{16}", _bl):
                    _leaks.append("API 키/시크릿")
                if _name_sensitive and not _leaks: _leaks.append("민감 설정/버전관리 파일")
                _leak_txt = ", ".join(_leaks) or "중요 시스템/설정 정보"
                # 내용에 실제 시크릿 확인 = HIGH, 파일명만 민감(내용 미확인, 예: .gitattributes→git 노출 정황) = MEDIUM
                _sev = "HIGH" if _content_sensitive else "MEDIUM"
                _f = _make_finding(
                    host=host, port=port, service="HTTP",
                    title=f"민감 파일 노출(정보 노출): /{word} (HTTP 200)",
                    severity=_sev,
                    description=(f"웹 루트에서 민감 파일 /{word} 이 인증 없이 열람됩니다. 내용에 실제 중요정보"
                                 f"({_leak_txt})가 포함돼 있어, 공격자가 자격증명·설정·소스 등을 획득해 후속 "
                                 "침투에 활용할 수 있습니다(CWE-538 민감정보 파일 노출)."),
                    evidence_detail=(f"[민감 파일 노출 — 내용 확인됨]\nURL    : {url}\nStatus : 200\n"
                                     f"Length : {length} bytes\n노출 정보: {_leak_txt}\n"
                                     f"발췌   : {_body.strip()[:200]}\n재현   : curl -s \"{url}\"\n"
                                     "content_confirmed"),
                    detection_steps=[
                        f"[1단계] 내부 퍼징으로 /{word} 발견(HTTP 200)",
                        f"[2단계] 파일 내용 조회 → 중요정보 확인: {_leak_txt}",
                        f"[결론] curl -s \"{url}\" 으로 직접 재현 가능(비파괴 읽기)",
                    ],
                    recommendation=("해당 파일을 웹 루트 밖으로 이동하거나 접근을 차단(인증/거부)하세요. "
                                    "노출된 자격증명·키는 즉시 폐기·교체하고, .git/설정/백업 파일이 배포에 "
                                    "포함되지 않도록 파이프라인을 점검하세요."),
                    tool_source="내부 퍼징 엔진",
                    url=url,
                    confidence="CONFIRMED",
                )
                _f["tags"] = list(_f.get("tags") or []) + ["content_confirmed"]  # → normalizer 취약점 승격
                findings.append(_f)
                return

            # 중요정보 없는 경로 존재(참고) — 불필요 파일이면 삭제 권고.
            severity = "MEDIUM" if status == 401 else "LOW"
            label = "민감 경로 존재(내용 미확인)" if is_sensitive else "숨겨진 경로 발견"
            findings.append(_make_finding(
                host=host, port=port, service="HTTP",
                title=f"{label}: /{word} (HTTP {status})",
                severity=severity,
                description=(f"내부 퍼징 엔진으로 발견된 경로 — HTTP {status}. "
                             "파일 내용에서 중요정보는 확인되지 않았습니다(참고)."),
                evidence_detail=(f"[디렉터리 퍼징 결과]\nURL    : {url}\nStatus : {status}\n"
                                 f"Length : {length} bytes\n재현   : curl -v \"{url}\""),
                detection_steps=[
                    f"[1단계] 내부 퍼징 엔진으로 {base} 대상 {'민감 경로' if is_sensitive else '디렉터리'} 탐색",
                    f"[2단계] /{word} 경로에서 HTTP {status} 응답 수신",
                    f"[3단계] 응답 크기 {length} bytes · 소프트404 베이스라인과 상이 — 실제 리소스",
                    f"[결론] curl -v \"{url}\" 으로 직접 재현 가능",
                ],
                recommendation=("서비스에 불필요한 파일/경로라면 삭제하고, 필요한 경우 인증·접근제어를 "
                                "적용하세요. 민감 파일(.env/.git/백업/설정)은 웹 루트 외부로 이동하세요."),
                tool_source="내부 퍼징 엔진",
                url=url,
                confidence="CONFIRMED",
            ))

        # 워커풀: 동시성 만큼의 워커가 단어를 인덱스로 소진(대용량 리스트도 코루틴 폭증 없이 처리)
        _idx = 0

        async def _worker():
            nonlocal _idx
            while _t.time() <= deadline:
                i = _idx
                _idx += 1
                if i >= len(words):
                    return
                try:
                    await probe(words[i])
                except Exception:
                    pass

        await asyncio.gather(*[asyncio.create_task(_worker()) for _ in range(concurrency)],
                             return_exceptions=True)

    if progress_cb:
        await progress_cb(f"내부 퍼징: {base} 완료 — {len(findings)}건 발견"
                          + (" (soft-404 사이트 감지)" if soft_site else ""))
    return findings


# ── nuclei ────────────────────────────────────────────────────────────────────

_NUCLEI_SEV_MAP = {"critical": "HIGH", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
_NUCLEI_SKIP_TAGS = {"tech", "dns", "whois", "network", "waf", "favicon"}


async def run_nuclei(target_url: str, host: str, port: int, progress_cb=None) -> list[dict]:
    """nuclei로 CVE·설정 오류 취약점 스캔을 수행합니다."""
    nuclei = _which("nuclei")
    if not nuclei:
        return []

    out_file = _TEMP_DIR / f"nuclei_{host}_{port}.jsonl"
    out_file.unlink(missing_ok=True)

    # nuclei 는 서브프로세스라 in-process 거버너를 공유 못 하므로 rate-limit/동시성 플래그로
    # 해당 단계 상한(Safe: 전역 5rps / PROOF: nuclei 단계 상한)에 맞춘다. 외부도구는 순차 실행.
    _g = _gov.stage("nuclei")
    if _g is not None:
        _nuc_rate = str(max(1, int(round(_g.max_rps))))          # Safe 5 / PROOF 50
        _nuc_conc = str(max(1, min(50, _g.conc)))                # Safe 2 / PROOF 10
    else:
        _nuc_rate, _nuc_conc = "25", "5"
    cmd = [
        nuclei,
        "-u", target_url,
        "-severity", "critical,high,medium",
        "-jsonl-export", str(out_file),
        "-silent",
        "-no-interactsh",   # OOB 없이 실행 (외부 콜백 불필요)
        "-timeout", "8",
        "-rate-limit", _nuc_rate,
        "-c", _nuc_conc,
        "-max-host-error", "30",   # 3 → 30: 느린/불안정 호스트에서 조기 중단 방지
    ]

    if progress_cb:
        await progress_cb(f"nuclei: {target_url} CVE·설정 오류 스캔 시작...")

    rc, _so, _se = await _run(cmd, timeout=180)
    _timed_out = (rc == -1 and _se == "timeout")

    if not out_file.exists():
        if progress_cb:
            await progress_cb(f"nuclei: {target_url} — "
                              + ("시간 초과" if _timed_out else "매칭 없음(medium+ 기준)"))
        return []

    findings = []
    seen: set[str] = set()

    for line in out_file.read_text("utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue

        tmpl_id   = obj.get("template-id", "")
        info      = obj.get("info") or {}
        sev_raw   = (info.get("severity") or "info").lower()
        severity  = _NUCLEI_SEV_MAP.get(sev_raw, "LOW")

        if sev_raw == "info":
            continue

        tags = set(info.get("tags") or [])
        if tags & _NUCLEI_SKIP_TAGS and sev_raw in ("info", "low"):
            continue

        # 같은 템플릿이 여러 URL에서 매칭되어도 한 번만 보고
        if tmpl_id in seen:
            continue
        seen.add(tmpl_id)

        name        = info.get("name", tmpl_id)
        description = info.get("description", "")
        matched_at  = obj.get("matched-at", target_url)
        extracted   = obj.get("extracted-results") or []
        classif     = info.get("classification") or {}
        cve_ids     = [c for c in (classif.get("cve-id") or []) if c]
        references  = info.get("reference") or []
        remediation = info.get("remediation", "")

        evidence_lines = [
            f"[nuclei 탐지 결과]",
            f"템플릿 ID  : {tmpl_id}",
            f"심각도     : {sev_raw.upper()}",
            f"매칭 URL   : {matched_at}",
        ]
        if extracted:
            evidence_lines.append(f"추출 데이터: {', '.join(str(e) for e in extracted[:5])}")
        if cve_ids:
            evidence_lines.append(f"CVE        : {', '.join(cve_ids)}")
        if references:
            evidence_lines.append(f"참조       : {references[0]}")

        findings.append(_make_finding(
            host=host, port=port, service="HTTP",
            title=f"{name}",
            severity=severity,
            description=description or f"nuclei 템플릿 '{tmpl_id}' 취약점 탐지",
            evidence_detail="\n".join(evidence_lines),
            detection_steps=[
                f"[1단계] nuclei 스캐너로 {target_url} 점검 실행",
                f"[2단계] 템플릿 '{tmpl_id}' ({sev_raw.upper()}) 매칭",
                f"[3단계] 대상 URL: {matched_at}",
                f"[결론] {name} 취약점 확인됨" + (f" (추출: {extracted[0]})" if extracted else ""),
            ],
            recommendation=remediation or f"{name} 취약점 패치 또는 설정 변경 필요",
            attack_vector=(description or "")[:150],
            cve_references=cve_ids,
            tool_source="nuclei",
        ))

    if progress_cb:
        await progress_cb(f"nuclei: {target_url} 완료 — {len(findings)}건 발견(medium+)"
                          + (" (시간 초과로 일부만)" if _timed_out else ""))
    return findings


# ── 내부(네이티브) 기술 핑거프린팅 — 외부 httpx 대체 ──────────────────────────
def _merge_tech_into(hr: dict, items) -> None:
    """핑거프린팅 결과(dict 또는 이름 문자열)를 hr['technologies']에 이름 기준 dedup 병합한다.
    recon 단계가 채운 dict 포맷과 일관되게 유지(문자열은 최소 dict 로 정규화)."""
    cur = hr.setdefault("technologies", [])

    def _nm(x):
        return (x.get("name") if isinstance(x, dict) else str(x)).strip()

    existing = {_nm(t).lower() for t in cur if _nm(t)}
    for it in (items or []):
        nm = _nm(it)
        if not nm or nm.lower() in existing:
            continue
        entry = it if isinstance(it, dict) else {
            "name": nm, "confidence": 50, "evidence": "기술 핑거프린팅", "recommended_probes": []}
        cur.append(entry)
        existing.add(nm.lower())


async def run_native_fingerprint(base_url: str, host: str, port: int, progress_cb=None) -> dict:
    """내부(네이티브) 기술 핑거프린팅 — 외부 httpx 대체.

    대상 페이지의 전체 HTML·헤더·쿠키를 직접 수집해 technology_fingerprint 엔진
    (헤더/쿠키/HTML/JS 프레임워크 마커)으로 기술스택을 추정한다. recon 단계는 title/일부만
    넘겨 클라이언트 마커를 놓칠 수 있어, 여기서 전체 HTML 을 먹여 보강한다.
    반환: {"tech_entries":[{name,confidence,...}], "technologies":[names], "webserver","title","status","wordpress"}
    """
    import technology_fingerprint as _tf
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    body = ""
    headers_l: dict = {}
    cookies: list = []
    status = 0
    try:
        conn = aiohttp.TCPConnector(ssl=ctx)
        async with aiohttp.ClientSession(
                connector=conn,
                headers={"User-Agent": "Mozilla/5.0 (Eoseureum Scanner)"}) as s:
            async with s.get(base_url, allow_redirects=True,
                             timeout=aiohttp.ClientTimeout(total=12)) as r:
                status = r.status
                body = await r.text(errors="ignore")
                headers_l = {str(k).lower(): str(v) for k, v in r.headers.items()}
                try:
                    cookies = [str(k) for k in r.cookies.keys()]
                except Exception:
                    cookies = []
    except Exception:
        return {}
    signals = {
        "server": headers_l.get("server", ""),
        "x_powered_by": headers_l.get("x-powered-by", ""),
        "headers": headers_l,
        "html": body[:300000],
        "cookies": cookies,
        "known_paths": {},
    }
    try:
        fp = _tf.fingerprint(signals)
        entries = fp.get("technologies") or []
    except Exception:
        entries = []
    names = [e.get("name", "") for e in entries if e.get("name")]
    wp = any("wordpress" in n.lower() for n in names)
    if progress_cb:
        await progress_cb(f"내부 핑거프린팅: {base_url} — 기술 {len(names)}종 식별"
                          + (" · WordPress 감지" if wp else ""))
    return {"tech_entries": entries, "technologies": names,
            "webserver": headers_l.get("server", ""), "title": _html_title(body),
            "status": status, "wordpress": wp}


# ── wpscan (WordPress 취약점) ──────────────────────────────────────────────────
def _wpscan_findings_from_json(data: dict, host: str, port: int) -> list[dict]:
    """wpscan JSON(--format json) 결과를 findings 로 변환한다(파싱 단위 분리 — 테스트 용이).

    API 토큰이 없으면 코어/플러그인 '취약점' 매칭은 비지만, 버전 노출·XML-RPC·
    디렉터리 리스팅·백업/디버그 로그 노출 등 설정 이슈는 토큰 없이도 보고된다.
    """
    def _norm_cves(refs):
        out = []
        for c in ((refs or {}).get("cve") or []):
            c = str(c)
            out.append(c if c.upper().startswith("CVE") else f"CVE-{c}")
        return out

    findings: list[dict] = []
    ver = data.get("version") or {}
    ver_num = ver.get("number")
    for v in (ver.get("vulnerabilities") or []):
        findings.append(_make_finding(
            host=host, port=port, service="HTTP",
            title=f"WordPress 코어 취약점: {v.get('title', '')}", severity="HIGH",
            description=v.get("title", ""),
            evidence_detail=f"[wpscan] WordPress {ver_num} — {v.get('title', '')}",
            detection_steps=[f"wpscan 으로 WordPress {ver_num} 식별", "코어 알려진 취약점 매칭"],
            recommendation="WordPress 코어를 최신 버전으로 업데이트",
            cve_references=_norm_cves(v.get("references")),
            tool_source="wpscan", confidence="LIKELY"))
    for section, label in (("plugins", "플러그인"), ("themes", "테마")):
        for name, info in (data.get(section) or {}).items():
            for v in ((info or {}).get("vulnerabilities") or []):
                findings.append(_make_finding(
                    host=host, port=port, service="HTTP",
                    title=f"취약한 WordPress {label}: {name} — {v.get('title', '')}",
                    severity="HIGH", description=v.get("title", ""),
                    evidence_detail=f"[wpscan] {label} '{name}' — {v.get('title', '')}",
                    detection_steps=[f"wpscan {label} 열거", f"'{name}' 알려진 취약점 매칭"],
                    recommendation=f"{label} '{name}' 업데이트 또는 제거",
                    cve_references=_norm_cves(v.get("references")),
                    tool_source="wpscan", confidence="LIKELY"))
    _EXPOSE = {
        "xmlrpc": "WordPress XML-RPC 활성화(무차별·증폭 공격 표면)",
        "readme": "WordPress readme.html 노출(버전 정보 유출)",
        "directory_listing": "디렉터리 리스팅 노출",
        "backup": "백업 파일 노출",
        "db_export": "데이터베이스 export 노출",
        "debug_log": "debug.log 노출",
        "full_path_disclosure": "전체 경로 노출(Full Path Disclosure)",
    }
    for itf in (data.get("interesting_findings") or []):
        typ = (itf.get("type") or "").lower()
        nice = next((v for k, v in _EXPOSE.items() if k in typ), None)
        if not nice:
            continue
        where = itf.get("to_s") or itf.get("url") or ""
        findings.append(_make_finding(
            host=host, port=port, service="HTTP", title=nice, severity="LOW",
            description=where or nice, evidence_detail=f"[wpscan] {where}",
            detection_steps=["wpscan 열거", f"노출 항목 확인: {where}"],
            recommendation="불필요한 노출/기능 비활성화 및 접근 제한",
            tool_source="wpscan", confidence="LIKELY"))
    return findings


async def run_wpscan(base_url: str, host: str, port: int, progress_cb=None) -> list[dict]:
    """WordPress 대상에 wpscan 을 실행해 취약 요소를 findings 로 반환한다.
    (API 토큰 없이도 버전·플러그인 열거 + 노출/설정 이슈 탐지)
    """
    wpscan = _which("wpscan")
    if not wpscan:
        return []
    cmd = [wpscan, "--url", base_url, "--format", "json", "--no-banner",
           "--random-user-agent", "--disable-tls-checks", "--force",
           "--plugins-detection", "passive", "--enumerate", "vp,vt,cb,dbe,u"]
    if progress_cb:
        await progress_cb(f"wpscan: {base_url} WordPress 취약점 점검...")
    _rc, so, _se = await _run(cmd, timeout=300)
    try:
        data = json.loads(so or "{}")
    except Exception:
        if progress_cb:
            await progress_cb(f"wpscan: {base_url} — 결과 파싱 실패(무시)")
        return []
    findings = _wpscan_findings_from_json(data if isinstance(data, dict) else {}, host, port)
    if progress_cb:
        await progress_cb(f"wpscan: {base_url} 완료 — {len(findings)}건")
    return findings


# ── ghauri ────────────────────────────────────────────────────────────────────

_GHAURI_VULNERABLE_RE = re.compile(
    r"parameter\s+'?(\w+)'?\s+(?:is|appears\s+to\s+be)\s+(?:vulnerable|injectable)",
    re.IGNORECASE,
)
_GHAURI_BACKEND_RE = re.compile(
    r"back.?end\s+DBMS\s*[:\-]\s*(.+)",
    re.IGNORECASE,
)
_GHAURI_TYPE_RE    = re.compile(r"Type\s*:\s*(.+)", re.IGNORECASE)
_GHAURI_TITLE_RE   = re.compile(r"Title\s*:\s*(.+)", re.IGNORECASE)
_GHAURI_PAYLOAD_RE = re.compile(r"Payload\s*:\s*(.+)", re.IGNORECASE)
_GHAURI_DBS_START  = re.compile(r"available\s+databases\s*\[(\d+)\]", re.IGNORECASE)


def _parse_ghauri_output(output: str) -> dict | None:
    """ghauri 텍스트 출력을 파싱하여 핵심 정보를 추출합니다."""
    if "vulnerable" not in output.lower() and "injectable" not in output.lower():
        return None

    param_m   = _GHAURI_VULNERABLE_RE.search(output)
    backend_m = _GHAURI_BACKEND_RE.search(output)
    type_m    = _GHAURI_TYPE_RE.search(output)
    title_m   = _GHAURI_TITLE_RE.search(output)
    payload_m = _GHAURI_PAYLOAD_RE.search(output)

    param   = param_m.group(1).strip() if param_m else "unknown"
    backend = backend_m.group(1).strip() if backend_m else "알 수 없음"
    inj_type = type_m.group(1).strip() if type_m else "알 수 없음"
    title    = title_m.group(1).strip() if title_m else ""
    payload  = payload_m.group(1).strip()[:150] if payload_m else ""

    # DB 목록 파싱
    db_list: list[str] = []
    in_dbs = False
    for line in output.splitlines():
        stripped = line.strip()
        if _GHAURI_DBS_START.search(stripped):
            in_dbs = True
            continue
        if in_dbs:
            if stripped.startswith("[*]") or (stripped and not stripped.startswith("[")):
                db_name = stripped.lstrip("[*] ").strip()
                if db_name:
                    db_list.append(db_name)
            elif stripped and stripped.startswith("["):
                in_dbs = False

    return {
        "param": param,
        "backend": backend,
        "inj_type": inj_type,
        "title": title,
        "payload": payload,
        "databases": db_list[:15],
    }


# ── SQLi 판정 등급 정책 ────────────────────────────────────────────────────────
#   Probe 탐지 → POSSIBLE / Ghauri 성공 → LIKELY / SQLMap 성공 → CONFIRMED
#   CONFIRMED 는 injectable parameter·injection type·DBMS·payload·enumeration 중
#   하나 이상이 SQLMap 으로 검증된 경우에만 부여한다.
_SQLI_GRADE_SCORE = {"INFO": 35, "MANUAL_REVIEW": 40, "POSSIBLE": 55, "LIKELY": 72, "CONFIRMED": 92}


# ── SQLi 검증 후보 우선순위 (입력점 컨텍스트 기반) ───────────────────────────────
#   login > search > account > 일반 GET > navigation/content(정적 include) 순.
_SQLI_CTX_PRIORITY = {"login": 0, "search": 1, "account": 2, "api": 3, "generic": 4}
_NAV_PARAM_RE = re.compile(r"^(content|page|view|include|file|tpl|template|nav|menu)$", re.IGNORECASE)
_ACCOUNT_PARAM_RE = re.compile(r"(uid|user|userid|account|id|member|profile|email|login)", re.IGNORECASE)


_LOGIN_PARAM_NAMES = {"password", "passwd", "pwd", "username", "userid", "login", "userpw", "passwrd"}
_LOGIN_PATH_RE = re.compile(r"(login|signin|sign-in|logon|auth)", re.IGNORECASE)


def _candidate_priority(url: str) -> int:
    """SQLMap 후보 URL 의 우선순위 점수(낮을수록 우선). 입력점 컨텍스트 기반."""
    try:
        import input_points as _ip
        import urllib.parse as _u
        p = _u.urlparse(url)
        params = list(_u.parse_qs(p.query).keys())
    except Exception:
        return 5
    if not params:
        return 6
    # 로그인: 경로(login/signin) 또는 로그인 계열 파라미터 → 최우선
    if _LOGIN_PATH_RE.search(p.path) or any(k.lower() in _LOGIN_PARAM_NAMES for k in params):
        return _SQLI_CTX_PRIORITY["login"]
    # 정적 include/navigation(content=... 등)만 있으면 최하위
    if all(_NAV_PARAM_RE.match(k) for k in params):
        return 9
    best = 8
    for k in params:
        ctx = _ip.classify_context(name=k, url=url)
        if ctx == "generic" and _ACCOUNT_PARAM_RE.search(k):
            ctx = "account"
        best = min(best, _SQLI_CTX_PRIORITY.get(ctx, 4))
    return best


def prioritize_sqli_candidates(candidates: list) -> list:
    """SQLMap 대상 후보를 입력점 컨텍스트 우선순위로 정렬한다(안정 정렬).

    candidates: [(url, host, port), ...]  또는  [url, ...]
    """
    def _url_of(c):
        return c[0] if isinstance(c, (tuple, list)) else c
    return sorted(candidates or [], key=lambda c: _candidate_priority(_url_of(c)))


async def run_ghauri(target_url: str, host: str, port: int, progress_cb=None) -> dict | None:
    """ghauri 로 SQL 인젝션 신호를 탐지한다. 성공 시 LIKELY 등급의 '신호 dict'를 반환.

    (최종 취약점 finding 은 build_sqli_finding 에서 SQLMap 검증과 함께 생성한다.)
    """
    ghauri = _which("ghauri")
    if not ghauri:
        return None
    parsed = urllib.parse.urlparse(target_url)
    if not parsed.query:
        return None

    if progress_cb:
        await progress_cb(f"ghauri: {target_url} SQL 인젝션 신호 점검 시작...")

    cmd = [
        # 확인-후-정지: DB 열거(--dbs) 생략 — injectable '신호'만 빠르게 확보(느린 열거 제거)
        ghauri, "-u", target_url,
        "--batch", "--threads", "3", "--timeout", "10", "--retries", "1",
    ]
    _grc, stdout, stderr = await _run(cmd, timeout=180)
    # 다른 도구(testssl/katana/ffuf/nuclei/sqlmap)와 일관되게 타임아웃을 표면화(커버리지 정직성)
    if _grc == -1 and stderr == "timeout" and progress_cb:
        await progress_cb(f"ghauri: {target_url} — 시간 초과(180s), SQL 인젝션 신호 미확보(일부만 가능)")
    result = _parse_ghauri_output(stdout + "\n" + stderr)
    if not result:
        return None

    result["grade"] = "LIKELY"
    result["tool"] = "ghauri"
    result["target_url"] = target_url
    if progress_cb:
        await progress_cb(
            f"ghauri: SQL 인젝션 가능성 확인(LIKELY) — 파라미터 '{result['param']}' "
            f"(SQLMap 최종 검증 진행)"
        )
    return result


# ── SQLMap (최종 검증 엔진) ─────────────────────────────────────────────────────

_SQLMAP_PARAM_RE   = re.compile(r"Parameter:\s*([^\(\n]+)", re.IGNORECASE)
_SQLMAP_TYPE_RE    = re.compile(r"Type:\s*(.+)", re.IGNORECASE)
_SQLMAP_TITLE_RE   = re.compile(r"Title:\s*(.+)", re.IGNORECASE)
_SQLMAP_PAYLOAD_RE = re.compile(r"Payload:\s*(.+)", re.IGNORECASE)
_SQLMAP_DBMS_RE    = re.compile(r"back-?end DBMS:\s*(.+)", re.IGNORECASE)
_SQLMAP_DBS_RE     = re.compile(r"available databases\s*\[(\d+)\]", re.IGNORECASE)
_SQLMAP_INJECTABLE_RE = re.compile(
    r"(?:is vulnerable|appears to be injectable|sqlmap identified the following injection)",
    re.IGNORECASE,
)


# 명령에서 마스킹할 민감 쿼리 파라미터/플래그
_MASK_KEYS = {"password", "passwd", "pwd", "token", "secret", "session", "sessionid",
              "jsessionid", "auth", "apikey", "api_key", "access_token"}
_MASK_FLAGS = ("--cookie", "--auth-cred", "--header", "-H", "--headers")


def _mask_command(parts: list[str]) -> str:
    """sqlmap 명령 문자열에서 cookie/password/token 등 민감값을 마스킹한다."""
    out = []
    for p in parts:
        s = str(p)
        # --cookie=... / --auth-cred=... 등 플래그 값 마스킹
        if any(s.lower().startswith(f + "=") for f in _MASK_FLAGS):
            out.append(s.split("=", 1)[0] + "=***")
            continue
        # URL 쿼리 내 민감 파라미터 값 마스킹
        if "://" in s and "?" in s:
            try:
                u = urllib.parse.urlparse(s)
                q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
                q2 = [(k, ("***" if k.lower() in _MASK_KEYS else v)) for k, v in q]
                s = urllib.parse.urlunparse((u.scheme, u.netloc, u.path, u.params,
                                             urllib.parse.urlencode(q2), u.fragment))
            except Exception:
                pass
        out.append(s)
    return " ".join(out)


def _parse_sqlmap_output(output: str) -> dict:
    """SQLMap 텍스트 출력을 파싱한다.

    반환: {injectable, parameter, injection_types[], dbms, payloads[], databases[]}
    (주입 신호가 전혀 없으면 injectable=False 로 반환)
    """
    injectable = bool(_SQLMAP_INJECTABLE_RE.search(output)) or ("Parameter:" in output)
    param_m = _SQLMAP_PARAM_RE.search(output)
    dbms_m  = _SQLMAP_DBMS_RE.search(output)
    types = [t.strip() for t in _SQLMAP_TYPE_RE.findall(output) if t.strip()]
    payloads = [p.strip()[:200] for p in _SQLMAP_PAYLOAD_RE.findall(output) if p.strip()]

    dbs: list[str] = []
    in_dbs = False
    for line in output.splitlines():
        s = line.strip()
        if _SQLMAP_DBS_RE.search(s):
            in_dbs = True
            continue
        if in_dbs:
            if s.startswith("[*]"):
                name = s.lstrip("[*] ").strip()
                if name:
                    dbs.append(name)
            elif s and not s.startswith("[*]"):
                in_dbs = False

    return {
        "injectable": injectable,
        "parameter": param_m.group(1).strip() if param_m else None,
        "injection_types": types[:5],
        "dbms": dbms_m.group(1).strip() if dbms_m else None,
        "payloads": payloads[:5],
        "databases": dbs[:15],
    }


def _sqlmap_enabled() -> bool:
    return os.getenv("ENABLE_SQLMAP", "false").lower() in ("1", "true", "yes", "on")


def _sqlmap_proof_ok() -> bool:
    """DB 목록 열거(--dbs)를 허용할지 — '실증(PROOF)' 모드에서만 True.

    기본(SAFE/STANDARD/ADVANCED/balanced/aggressive)은 '확인하면 멈춤'(injectable 확정 후 종료).
    DB 목록 추출은 추가 실증이라 느리므로 PROOF/명시 승인일 때만 수행한다(판정 등급은 이미 CONFIRMED).
    """
    def _b(n):
        return os.getenv(n, "false").strip().lower() in ("1", "true", "yes", "on")
    # 단일 진실: proof_active()(강등 정책 반영) 로 판정 — raw VALIDATION_PROFILE 직접 읽기 제거.
    # (그동안 sqlmap 만 raw env 를 봐서 다른 게이트와 어긋나던 불일치를 없앰)
    try:
        import validation_profiles as _vp
        if _vp.proof_active():
            return True
    except Exception:
        pass
    return _b("RCE_PROOF_MODE")


def _sqlmap_env() -> dict:
    def _int(name, default):
        try:
            return int(os.getenv(name, str(default)))
        except (TypeError, ValueError):
            return default
    def _b(name):
        return os.getenv(name, "false").strip().lower() in ("1", "true", "yes", "on")
    # PROOF 모드는 sqlmap 심화 — level/risk 를 자동 상향(더 많은 주입 벡터·기법 탐색).
    _proof = _sqlmap_proof_ok()
    _lvl_default = 3 if _proof else 2
    _risk_default = 2 if _proof else 1
    return {
        "path": os.getenv("SQLMAP_PATH", "sqlmap"),
        "level": max(1, min(5, _int("SQLMAP_LEVEL", _lvl_default))),
        "risk": max(1, min(3, _int("SQLMAP_RISK", _risk_default))),
        "timeout": _int("SQLMAP_TIMEOUT", 300 if _proof else 180),
        # 확인-후-정지 기본: --dbs(DB목록 열거)는 PROOF 실증 모드에서만. 그 외엔 injectable 확정 즉시 종료.
        "enum_dbs": _b("SQLMAP_ENUM_DBS") and _proof,
        # --smart: 휴리스틱상 주입 가능성 있는 파라미터만 깊게 테스트(속도↑, 미묘한 주입 스킵 가능).
        # PROOF(심화)에선 끄고 '모든 파라미터를 철저히' 테스트한다. 비PROOF는 켜서 빠르게.
        # env SQLMAP_SMART=true/false 로 강제 가능.
        "smart": (os.getenv("SQLMAP_SMART").strip().lower() in ("1", "true", "yes", "on")
                  if os.getenv("SQLMAP_SMART") is not None else (not _proof)),
        # 실행 전략 (기본: technique 미지정 / random-agent off / tamper 없음 / 재시도 off)
        "technique": os.getenv("SQLMAP_TECHNIQUE", "").strip(),
        "random_agent": _b("SQLMAP_RANDOM_AGENT"),
        "tamper": os.getenv("SQLMAP_TAMPER", "").strip(),
        "retry_on_no_injectable": _b("SQLMAP_RETRY_ON_NO_INJECTABLE"),
        "retry_level": max(1, min(5, _int("SQLMAP_RETRY_LEVEL", 3))),
        "retry_risk": max(1, min(3, _int("SQLMAP_RETRY_RISK", 1))),
    }


# SQLMap 실패 메시지 패턴
_SQLMAP_FAIL_NO_INJ = "do not appear to be injectable"
_SQLMAP_FAIL_LEVEL = "--level'/'--risk'"
_SQLMAP_FAIL_RM_TECH = "without providing the option '--technique'"


def parse_sqlmap_failure_reason(stdout: str, stderr: str) -> dict:
    """SQLMap 실패/미확인 출력에서 원인과 다음 안전 검증 권고를 구조화한다."""
    text = (stdout or "") + "\n" + (stderr or "")
    low = text.lower()
    no_inj = _SQLMAP_FAIL_NO_INJ in low
    inc_lr = (_SQLMAP_FAIL_LEVEL in low) or ("increase values for '--level'" in low) \
        or ("increase" in low and "level" in low and "risk" in low)
    rm_tech = (_SQLMAP_FAIL_RM_TECH in low) or ("rerun without providing the option" in low)
    suggest_tamper = "--tamper" in low
    suggest_ra = "--random-agent" in low or "random-agent" in low

    steps: list[str] = []
    if inc_lr:
        steps.append("--level/--risk 상향 후 재검증 (예: SQLMAP_LEVEL=3, SQLMAP_RISK=1)")
    if rm_tech:
        steps.append("--technique 옵션 제거 후 재검증 (기본값은 이미 미지정)")
    if suggest_ra:
        steps.append("--random-agent 사용 (SQLMAP_RANDOM_AGENT=true)")
    if suggest_tamper:
        steps.append("WAF/보호 의심 시 --tamper 사용 (예: SQLMAP_TAMPER=space2comment)")
    if not steps:
        steps.append("로그인/검색 등 입력점 기반 수동 검증 권고")

    # 대표 사유 한 줄
    raw = ""
    for line in text.splitlines():
        if "injectable" in line.lower() or "increase" in line.lower():
            raw = line.strip().lstrip("[").strip()[:200]
            break

    return {
        "no_injectable_parameter": no_inj,
        "suggest_increase_level_risk": bool(inc_lr),
        "suggest_remove_technique": bool(rm_tech),
        "suggest_random_agent": bool(suggest_ra),
        "suggest_tamper": bool(suggest_tamper),
        "raw_reason": raw or ("all tested parameters do not appear to be injectable" if no_inj else ""),
        "recommended_next_steps": steps,
    }


def _empty_sqlmap_result(target_url: str, **kw) -> dict:
    base = {
        "tool": "sqlmap", "enabled": _sqlmap_enabled(), "executed": False,
        "target_url": target_url, "injectable": False, "parameter": None,
        "injection_types": [], "dbms": None, "payloads": [], "databases": [],
        "confidence": None, "evidence": "", "command": "", "error": None,
        "failure_reason": None,
        "tested_parameter": None, "input_context": None, "source": None,
    }
    base.update(kw)
    return base


def _build_sqlmap_cmd(binary: str, target_url: str, cfg: dict, out_dir,
                      *, level: int, risk: int, technique: str,
                      random_agent: bool, tamper: str, post_data: str | None = None,
                      test_params: str | None = None, cookie: str | None = None) -> list[str]:
    """안전 플래그만으로 SQLMap 명령을 구성한다. 파괴/쉘/파일 옵션은 절대 추가하지 않는다.
    --technique 은 값이 있을 때만, --random-agent/--tamper 도 명시 시에만 추가한다.
    post_data 가 있으면 --data 로 POST 폼(로그인 등) 파라미터를 검증한다(sqlmap 이 POST 자동 인식)."""
    cmd = [
        binary, "-u", target_url,
        "--batch", "--threads=1",
        f"--level={level}", f"--risk={risk}",
        "--flush-session", "--disable-coloring",
        f"--output-dir={out_dir}",
    ]
    # --smart: PROOF 심화에선 끔(모든 파라미터 철저 테스트). cfg["smart"]=True 일 때만 추가.
    if cfg.get("smart"):
        cmd.insert(3, "--smart")
    if post_data:
        cmd.append(f"--data={post_data}")
    if cookie:
        # 인증 세션 쿠키 전달 — 이게 없으면 로그인 필요 대상이 로그인으로 튕겨 sqlmap 이 항상
        # "not injectable"(주입미확인)이 됐음. (마스킹 처리는 _MASK_FLAGS 에 --cookie 포함)
        cmd.append(f"--cookie={cookie}")
    if test_params:
        # 표적 파라미터만 테스트(헤더/쿠키 등 광역 테스트 배제 → level 상향에도 timeout 회피)
        cmd += ["-p", test_params]
    if technique:
        # sqlmap technique 문자만 허용(B/E/U/S/T/Q). 그 외 문자는 제거해 임의 인자 주입 방지.
        safe_tech = "".join(c for c in technique.upper() if c in "BEUSTQ")
        if safe_tech:
            cmd.append(f"--technique={safe_tech}")
    if random_agent:
        cmd.append("--random-agent")
    if tamper:
        cmd.append(f"--tamper={tamper}")
    if cfg["enum_dbs"]:
        cmd.append("--dbs")      # DB '목록' 열람만(read-only)
    return cmd


def _sqlmap_result_from_output(target_url, masked_cmd, stdout, stderr,
                               tested_parameter=None, input_context=None, source=None) -> dict:
    parsed_out = _parse_sqlmap_output((stdout or "") + "\n" + (stderr or ""))
    injectable = parsed_out["injectable"] and any([
        parsed_out["parameter"], parsed_out["injection_types"],
        parsed_out["dbms"], parsed_out["databases"],
    ])
    failure = None if injectable else parse_sqlmap_failure_reason(stdout, stderr)
    return _empty_sqlmap_result(
        target_url, executed=True, command=masked_cmd,
        injectable=injectable,
        parameter=parsed_out["parameter"],
        injection_types=parsed_out["injection_types"],
        dbms=parsed_out["dbms"],
        payloads=parsed_out["payloads"],
        databases=parsed_out["databases"],
        confidence=("CONFIRMED" if injectable else None),
        evidence=("SQLMap 주입 확인" if injectable else "SQLMap 주입 미확인(기본 검증)"),
        failure_reason=failure,
        tested_parameter=tested_parameter, input_context=input_context, source=source,
    )


def _auth_cookie_str(scan_id: str) -> str:
    """스캔의 인증 세션 쿠키를 sqlmap --cookie 형식('n=v; n=v')으로 반환. 없으면 빈 문자열.
    이게 있어야 로그인 필요 대상(DVWA 등)에 sqlmap 이 인증 상태로 접근해 실제 주입을 확증한다."""
    try:
        import active_probing as _ap
        return "; ".join(f"{c['name']}={c.get('value', '')}"
                         for c in (_ap.get_auth_cookies(scan_id) or []) if c.get("name"))
    except Exception:
        return ""


async def run_sqlmap(target_url: str, host: str, port: int, progress_cb=None,
                     input_context: str | None = None, source: str | None = None,
                     post_data: str | None = None, no_enum: bool = False,
                     timeout_override: int | None = None,
                     technique_override: str | None = None,
                     level_override: int | None = None,
                     test_params: str | None = None, cookie: str | None = None) -> dict:
    """SQLMap 으로 SQL 인젝션을 최종 검증한다(ENABLE_SQLMAP=true 일 때만 실행).

    기본 전략: --technique 미지정, random-agent/tamper 없음, 자동 재시도 없음(안전).
    no injectable 시 실패 사유(failure_reason)와 다음 안전 검증 권고를 구조화해 반환한다.
    어떤 경우에도 예외를 던지지 않으며(전체 스캔 실패 금지) 구조화 dict 를 반환한다.
    """
    if not _sqlmap_enabled():
        return _empty_sqlmap_result(target_url, error=None)

    cfg = _sqlmap_env()
    # 폼/인증 우회 확인용 오버라이드: --dbs(DB 열거) 생략·타임아웃 상향·기법 좁힘(빠른 확정).
    _build_cfg = {**cfg, "enum_dbs": False} if no_enum else cfg
    _technique = technique_override if technique_override is not None else cfg["technique"]
    _timeout = timeout_override if timeout_override else cfg["timeout"]
    _level = level_override if level_override else cfg["level"]
    binary = _which(cfg["path"]) or (cfg["path"] if os.path.sep in cfg["path"] else None)
    if not binary:
        if progress_cb:
            await progress_cb("sqlmap: 미설치(SQLMAP_NOT_FOUND) — 기본 스캔은 계속 진행됩니다.")
        return _empty_sqlmap_result(target_url, error="SQLMAP_NOT_FOUND")

    parsed = urllib.parse.urlparse(target_url)
    if not parsed.query and not post_data:
        return _empty_sqlmap_result(target_url, error="NO_QUERY_PARAM")

    # 테스트 대상 파라미터(POST 데이터 우선, 없으면 첫 쿼리 키) 기록
    if post_data:
        _tested = next(iter(urllib.parse.parse_qs(post_data).keys()), None)
    else:
        _tested = next(iter(urllib.parse.parse_qs(parsed.query).keys()), None)
    out_dir = _TEMP_DIR / f"sqlmap_{host}_{port}"

    cmd = _build_sqlmap_cmd(
        binary, target_url, _build_cfg, out_dir,
        level=_level, risk=cfg["risk"], technique=_technique,
        random_agent=cfg["random_agent"], tamper=cfg["tamper"], post_data=post_data,
        test_params=test_params, cookie=cookie,
    )
    masked_cmd = _mask_command(cmd)
    if progress_cb:
        await progress_cb(f"sqlmap: {parsed.path or target_url} 최종 검증 시작...")

    rc, stdout, stderr = await _run(cmd, timeout=_timeout)
    if rc == -1 and stderr == "timeout":
        if progress_cb:
            await progress_cb("sqlmap: 시간 초과(SQLMAP_TIMEOUT) — 기본 스캔은 계속 진행됩니다.")
        return _empty_sqlmap_result(target_url, executed=True, command=masked_cmd, error="SQLMAP_TIMEOUT",
                                    tested_parameter=_tested, input_context=input_context, source=source)
    if rc == -1 and stderr in ("not_found", ""):
        return _empty_sqlmap_result(target_url, executed=True, command=masked_cmd, error="SQLMAP_NOT_FOUND",
                                    tested_parameter=_tested, input_context=input_context, source=source)

    res = _sqlmap_result_from_output(target_url, masked_cmd, stdout, stderr,
                                     tested_parameter=_tested, input_context=input_context, source=source)

    # 자동 재시도(기본 off, 명시 활성 시에만): no injectable → level 상향 + technique 제거 + random-agent
    if (not res["injectable"]) and cfg["retry_on_no_injectable"] \
            and res.get("failure_reason", {}) and res["failure_reason"].get("no_injectable_parameter"):
        if progress_cb:
            await progress_cb("sqlmap: 재검증 시도(level 상향, technique 제거, random-agent)...")
        rcmd = _build_sqlmap_cmd(
            binary, target_url, _build_cfg, out_dir,
            level=cfg["retry_level"], risk=cfg["retry_risk"], technique="",
            random_agent=True, tamper=cfg["tamper"], post_data=post_data,
            test_params=test_params, cookie=cookie,
        )
        r2, so2, se2 = await _run(rcmd, timeout=_timeout)
        if not (r2 == -1):
            res2 = _sqlmap_result_from_output(target_url, _mask_command(rcmd), so2, se2,
                                              tested_parameter=_tested, input_context=input_context, source=source)
            res2["retried"] = True
            res = res2

    if progress_cb:
        await progress_cb(
            f"sqlmap: {'주입 확인(CONFIRMED)' if res['injectable'] else '주입 미확인'}"
            + (f" — 파라미터 {res['parameter']}" if res["parameter"] else "")
        )
    return res


def _unknownish(v) -> bool:
    """parameter/dbms/type 가 사실상 'unknown' 인지 판정."""
    if not v:
        return True
    s = str(v).strip().lower()
    return s in ("unknown", "(미상)", "(unknown)", "none", "-", "")


def grade_sqli(ghauri_sig: dict | None, sqlmap_res: dict | None,
               probe_confirmed: bool = False) -> dict:
    """ghauri/sqlmap/probe 신호를 종합해 SQLi 판정 등급과 필드를 산출한다.

    POSSIBLE : ghauri 신호뿐이고 parameter/dbms/type 모두 unknown, payload 없음
    LIKELY   : parameter 확인 + (injection type 또는 DBMS 중 하나 이상) 확인(미실증)
    CONFIRMED: sqlmap injectable / dbms / type / dbs 확보 또는 내부 probe 실증
    """
    sqlmap_res = sqlmap_res or {}
    g = ghauri_sig or {}

    # 필드 병합 (sqlmap 우선 → ghauri)
    parameter = sqlmap_res.get("parameter") or g.get("param")
    inj_types = list(sqlmap_res.get("injection_types") or [])
    if not inj_types and not _unknownish(g.get("inj_type")):
        inj_types = [g.get("inj_type")]
    dbms = sqlmap_res.get("dbms") or (None if _unknownish(g.get("backend")) else g.get("backend"))
    payloads = list(sqlmap_res.get("payloads") or [])
    if not payloads and g.get("payload"):
        payloads = [g.get("payload")]
    databases = list(sqlmap_res.get("databases") or g.get("databases") or [])

    sqlmap_confirmed = bool(
        sqlmap_res.get("injectable") or sqlmap_res.get("dbms")
        or sqlmap_res.get("injection_types") or sqlmap_res.get("databases")
    )
    sqlmap_executed = bool(sqlmap_res.get("executed"))
    # SQLMap 이 injectable 미확인 → 참고/수동검토(취약 아님). 실패 사유 or 에러(타임아웃/미설치)도 포함.
    # (B2: 타임아웃은 failure_reason=None 이라 예전엔 POSSIBLE '취약'으로 오탐됐음)
    sqlmap_no_inj = (not sqlmap_res.get("injectable")
                     and (bool(sqlmap_res.get("failure_reason")) or bool(sqlmap_res.get("error")))
                     and (sqlmap_executed or bool(sqlmap_res.get("error"))))

    if sqlmap_confirmed or probe_confirmed:
        grade = "CONFIRMED"
    elif sqlmap_no_inj:
        grade = "MANUAL_REVIEW"   # sqlmap 미확인(실패사유/에러/타임아웃) → 참고. ghauri 신호만으론 취약 아님(정책)
    elif (not _unknownish(parameter)) and (inj_types or not _unknownish(dbms)):
        grade = "LIKELY"
    else:
        grade = "POSSIBLE"

    return {
        "grade": grade,
        "parameter": parameter if not _unknownish(parameter) else None,
        "injection_types": inj_types,
        "dbms": dbms if not _unknownish(dbms) else None,
        "payloads": payloads,
        "databases": databases,
        "sqlmap_executed": sqlmap_executed,
        "sqlmap_no_injectable": sqlmap_no_inj,
        "sqlmap_error": sqlmap_res.get("error"),
        "failure_reason": sqlmap_res.get("failure_reason"),
    }


def build_sqli_finding(target_url: str, host: str, port: int,
                       ghauri_sig: dict | None, sqlmap_res: dict | None,
                       probe_confirmed: bool = False) -> dict | None:
    """SQLi 판정 정책(POSSIBLE/LIKELY/CONFIRMED)에 따라 finding 을 생성한다.

    표현 정책(불완전 증거 시 실증 표현 금지):
      - parameter unknown → '취약 파라미터 확인' 표현 금지
      - dbms unknown      → 'DBMS 확인' 표현 금지
      - payload 없음      → '검증 payload 확인' 표현 금지
      - sqlmap 미검증     → '실증 확인' 표현 금지
      - databases 비어있음 → 'DB 목록 추출 성공' 표현 금지
    """
    if not ghauri_sig and not (sqlmap_res and sqlmap_res.get("executed")) and not probe_confirmed:
        return None
    service = "HTTPS" if port in (443, 8443) else "HTTP"

    gr = grade_sqli(ghauri_sig, sqlmap_res, probe_confirmed)
    grade = gr["grade"]
    parameter = gr["parameter"]
    inj_types = gr["injection_types"]
    dbms = gr["dbms"]
    payloads = gr["payloads"]
    databases = gr["databases"]
    has_dbs = len(databases) >= 1

    inj_type_str = ", ".join(inj_types) if inj_types else "미상"
    param_str = parameter or "미상"
    dbms_str = dbms or "미상"

    if grade == "CONFIRMED":
        severity = "HIGH"
        if has_dbs:
            title = "SQL 인젝션 실증 확인 — DB 목록 추출 성공"
        else:
            title = "SQL 인젝션 실증 확인"
        description = (
            "SQLMap 최종 검증(또는 error/union 기반 실증)으로 SQL 인젝션이 확인되었습니다(CONFIRMED)."
            + (f" 취약 파라미터: {param_str}." if parameter else "")
            + (f" DBMS: {dbms_str}." if dbms else "")
            + (f" 데이터베이스 목록 열람에 성공했습니다({len(databases)}개)." if has_dbs else "")
        )
        tool_source = "sqlmap"
    elif grade == "LIKELY":
        severity = "HIGH"
        title = "SQL 인젝션 가능성 확인"
        description = (
            f"파라미터 '{param_str}' 에서 SQL 인젝션 신호가 확인되었습니다(LIKELY). "
            "SQLMap 최종 검증이 완료되지 않았으므로 실증 확인은 아니며 추가 검증을 권고합니다."
        )
        tool_source = "ghauri"
    elif grade == "MANUAL_REVIEW":
        # SQLMap 기본 검증에서 injectable 미확인 → 취약 아님, 참고/수동검토.
        severity = "Low"
        title = "[참고] SQL 인젝션 가능성 — SQLMap 기본 검증에서 미확인"
        description = (
            "SQLMap 검증을 수행했으나 현재 level/risk/technique 조건에서는 injectable parameter 가 "
            "확인되지 않았습니다. 현재 자동 판정: 취약점 아님 / 수동 검증 권고."
        )
        tool_source = "sqlmap"
    else:  # POSSIBLE
        severity = "MEDIUM"
        title = "SQL 인젝션 가능성 — 추가 검증 필요"
        description = (
            "SQL 인젝션 가능 신호가 탐지되었으나 파라미터/유형/DBMS/payload 가 확인되지 않았습니다"
            "(POSSIBLE). 수동 검증 또는 SQLMap 검증을 권고합니다."
        )
        tool_source = "ghauri"

    ev_lines = [f"[SQLi 판정 — {grade}]"]
    ev_lines.append(f"Parameter        : {param_str}")
    ev_lines.append(f"Injection Type   : {inj_type_str}")
    ev_lines.append(f"DBMS             : {dbms_str}")
    ev_lines.append(f"Payload          : {payloads[0] if payloads else '(없음)'}")
    if has_dbs:
        ev_lines.append(f"Databases        : {', '.join(databases)}")
    # MANUAL_REVIEW: SQLMap 실패 사유 + 다음 안전 검증 권고를 명시
    _fr = gr.get("failure_reason") or {}
    if grade == "MANUAL_REVIEW" and _fr:
        ev_lines.append("SQLMap 판정       : 기본 검증에서 injectable 미확인")
        if _fr.get("raw_reason"):
            ev_lines.append(f"SQLMap 사유       : {_fr['raw_reason']}")
        for _st in (_fr.get("recommended_next_steps") or [])[:4]:
            ev_lines.append(f"다음 검증 권고     : {_st}")
    if sqlmap_res and sqlmap_res.get("executed"):
        ev_lines.append(f"SQLMap           : 검증 수행" + (f" (error={sqlmap_res.get('error')})" if sqlmap_res.get("error") else ""))
        if sqlmap_res.get("command"):
            ev_lines.append(f"Command          : {sqlmap_res['command']}")
    elif sqlmap_res and sqlmap_res.get("error"):
        ev_lines.append(f"SQLMap           : 미수행 ({sqlmap_res.get('error')})")
    else:
        ev_lines.append("SQLMap           : 미수행(ENABLE_SQLMAP=false)")

    finding = _make_finding(
        host=host, port=port, service=service,
        title=title, severity=severity,
        description=description,
        evidence_detail="\n".join(ev_lines),
        detection_steps=[
            f"[1단계] ghauri/Probe SQLi 신호 탐지",
            f"[2단계] SQLMap 최종 검증 " + ("수행" if (sqlmap_res and sqlmap_res.get("executed")) else "미수행"),
            f"[결론] 판정 등급: {grade}",
        ],
        recommendation=(
            "PreparedStatement(파라미터화 쿼리)를 사용하고 ORM을 도입하세요. "
            "DB 계정에 최소 권한을 부여하고, WAF로 SQL 인젝션 패턴을 차단하세요."
        ),
        attack_vector=(f"파라미터 '{param_str}' 를 통한 SQL 인젝션" + (" (실증)" if grade == "CONFIRMED" else " 가능성")),
        tool_source=tool_source,
        url=target_url,
    )
    # OWASP/CWE 는 등급 무관 매핑(증거 불완전해도 분류는 채움)
    finding["owasp"] = "A03:2021 - 인젝션"
    finding["cwe"] = "CWE-89"
    finding["sqli_grade"] = grade
    finding["confidence"] = grade
    finding["confidence_score"] = _SQLI_GRADE_SCORE.get(grade, 55)
    finding["probe_confirmed"] = (grade == "CONFIRMED")

    # MANUAL_REVIEW(SQLMap 미확인) → 취약점 아님, 참고/수동검토로 분류.
    if grade == "MANUAL_REVIEW":
        finding["judgment"] = "참고"
        finding["finding_type"] = "discovery"
        # force_finding_type: finding_normalizer.classify 가 최우선으로 존중 → 재분류로 '취약'
        # 승격되는 것 방지(SQLi 제목의 클래스 심각도 때문에 report_severity 가 High 로 부풀던 문제 교정).
        finding["force_finding_type"] = "discovery"
        finding["vulnerability"] = False
        finding["category"] = "manual_review"
        finding["report_section"] = "참고 발견 항목"
        finding["failure_reason"] = gr.get("failure_reason")

    finding["sqlmap"] = {
        "parameter": parameter, "injection_types": inj_types, "dbms": dbms,
        "payloads": payloads, "databases": databases,
        "executed": bool(sqlmap_res and sqlmap_res.get("executed")),
        "error": sqlmap_res.get("error") if sqlmap_res else None,
        "command": sqlmap_res.get("command") if sqlmap_res else "",
        "tested_parameter": sqlmap_res.get("tested_parameter") if sqlmap_res else None,
        "input_context": sqlmap_res.get("input_context") if sqlmap_res else None,
        "source": sqlmap_res.get("source") if sqlmap_res else None,
    }
    return finding


# ── 통합 실행 ─────────────────────────────────────────────────────────────────

async def run_all_external_tools(
    host_results: list[dict],
    scan_id: str = "",
    progress_cb=None,
) -> list[dict]:
    """
    모든 외부 도구를 순서대로 실행하고 findings 목록을 반환합니다.
    progress_cb(message: str) 은 WebSocket progress 콜백입니다.
    """
    tools = available_tools()
    installed = [k for k, v in tools.items() if v]
    not_installed = [k for k, v in tools.items() if not v]

    if progress_cb:
        if installed:
            await progress_cb(f"사용 가능한 외부 도구: {', '.join(installed)}")
        if not_installed:
            await progress_cb(f"미설치 도구 (건너뜀): {', '.join(not_installed)}")

    all_findings: list[dict] = []
    # katana로 수집한 파라미터 있는 URL (ghauri 대상)
    param_urls: list[tuple[str, str, int]] = []

    async def _cb(msg: str):
        if progress_cb:
            try:
                await progress_cb(msg)
            except Exception:
                pass

    for hr in host_results:
        host = hr.get("host", "")
        for svc in hr.get("services", []):
            port     = svc.get("port", 0)
            is_ssl   = bool(svc.get("ssl_info")) or port in (443, 8443)
            scheme   = "https" if is_ssl else "http"
            base_url = f"{scheme}://{host}:{port}"

            # 1) testssl.sh — SSL 포트만
            if is_ssl and tools["testssl"]:
                try:
                    ssl_findings = await run_testssl(host, port, progress_cb=_cb)
                    all_findings.extend(ssl_findings)
                    await _cb(f"✅ testssl.sh 완료 — SSL/TLS 이슈 {len(ssl_findings)}건")
                except Exception as e:
                    await _cb(f"testssl 오류 (무시): {e}")

            if not svc.get("http_info"):
                continue

            # 2) SQLi 후보 URL 수집 — ② 이전 단계 결과 재사용 + 보조 크롤(재크롤만 의존하지 않음).
            #    stage-2 url_discovery/active_probing 이 이미 발견한 svc["discovered_urls"](숨은
            #    파라미터 마이닝 결과 포함)를 1차 소스로 쓰고, 네이티브 크롤을 보완(union·dedup)한다.
            _cand: list[str] = list(svc.get("discovered_urls") or [])
            # active_probing 이 노출한 sqlmap 후보(숨은 파라미터 마이닝 GET 주입점) 재사용
            _ap = svc.get("active_probes")
            if isinstance(_ap, dict):
                _cand += [u for u in (_ap.get("_sqli_candidates") or []) if isinstance(u, str)]
            try:
                _crawled = await run_native_crawl(base_url, host, port, progress_cb=_cb)  # depth=PROOF/예산 스케일
                _cand += _crawled
                await _cb(f"✅ 크롤(katana) 완료 — 파라미터 URL 후보 {len(_crawled)}개")
            except Exception as e:
                await _cb(f"크롤 오류 (무시): {e}")
            _seen_pu: set = set()
            for u in _cand:
                if u and "?" in u and u not in _seen_pu:
                    _seen_pu.add(u)
                    param_urls.append((u, host, port))

            # 3) 디렉터리 퍼징 — 내부(네이티브) 엔진 전담(벤치마크로 ffuf 대비 동등 확인 후 대체)
            try:
                _fuzz = await run_dir_fuzz(base_url, host, port, progress_cb=_cb)
                all_findings.extend(_fuzz)
                await _cb(f"✅ 디렉터리 퍼징(ffuf) 완료 — 노출 경로 {len(_fuzz)}건")
            except Exception as e:
                await _cb(f"디렉터리 퍼징 오류 (무시): {e}")

            # 4) nuclei — CVE·설정 오류 스캔
            if tools["nuclei"]:
                try:
                    nuc_findings = await run_nuclei(base_url, host, port, progress_cb=_cb)
                    all_findings.extend(nuc_findings)
                    await _cb(f"✅ nuclei 완료 — CVE·설정오류 {len(nuc_findings)}건")
                except Exception as e:
                    await _cb(f"nuclei 오류 (무시): {e}")

            # 4c) 기술 핑거프린팅 — 내부(네이티브) 엔진 전담(벤치마크로 httpx 대비 동등 확인 후 대체)
            _is_wp = any("wordpress" in (t.get("name") if isinstance(t, dict) else str(t)).lower()
                         for t in (hr.get("technologies") or []))
            try:
                fp = await run_native_fingerprint(base_url, host, port, progress_cb=_cb)
                _merge_tech_into(hr, fp.get("tech_entries"))
                _is_wp = _is_wp or bool(fp.get("wordpress"))
                await _cb(f"✅ 기술 핑거프린팅(httpx) 완료 — 기술 {len(fp.get('tech_entries') or [])}종 식별")
            except Exception as e:
                await _cb(f"기술 핑거프린팅 오류 (무시): {e}")

            # 4d) wpscan — WordPress 감지 시에만 실행
            if _is_wp and tools.get("wpscan"):
                try:
                    wp_findings = await run_wpscan(base_url, host, port, progress_cb=_cb)
                    all_findings.extend(wp_findings)
                    await _cb(f"✅ wpscan 완료 — WordPress 이슈 {len(wp_findings)}건")
                except Exception as e:
                    await _cb(f"wpscan 오류 (무시): {e}")

    # 5) SQLi 심화: Probe → SQLMap(CONFIRMED, 주 검증기) → Report
    #    sqlmap 이 우선순위 상위 후보(≤8)를 직접 검증한다. ghauri 는 제외(sqlmap 으로 대체)하되,
    #    설치돼 있으면 빠른 '보조 신호'로만 활용한다.
    if tools["sqlmap"] and param_urls:
        await _cb(f"🔎 SQLi 심화(sqlmap/ghauri) — 파라미터 URL {len(param_urls)}개 검증 시작 · "
                  f"sqlmap {'ON' if _sqlmap_enabled() else 'OFF(딥스캔 전용)'} · "
                  f"ghauri {'ON' if _which('ghauri') else '미설치(건너뜀)'}")
        # 입력점 컨텍스트 우선순위로 정렬: 로그인/검색/계정 > 일반 GET > navigation/content
        ordered = prioritize_sqli_candidates(param_urls)
        tested: set[str] = set()
        for url, host, port in ordered[:8]:  # 최대 8개(우선순위 높은 것부터)
            p = urllib.parse.urlparse(url)
            # E2: dedup 키에 쿼리 파라미터 이름 집합 포함 — 같은 경로의 다른 파라미터(?id= vs ?cat=)가
            # 서로 다른 취약점일 수 있어 첫 URL만 보고 나머지를 놓치던 문제 수정
            _qk = ",".join(sorted(urllib.parse.parse_qs(p.query).keys()))
            key = f"{p.netloc}{p.path}?{_qk}"
            if key in tested:
                continue
            tested.add(key)
            # 후보의 입력점 컨텍스트(보고서/결과 기록용)
            try:
                import input_points as _ip
                _pk = next(iter(urllib.parse.parse_qs(p.query).keys()), "")
                _ctx = _ip.classify_context(name=_pk, url=url)
            except Exception:
                _ctx = None
            try:
                # ghauri 는 제외 대상 — 설치돼 있을 때만 조용히 보조 신호로 사용(미설치면 None, 경고 없음)
                ghauri_sig = (
                    await run_ghauri(url, host, port, progress_cb=_cb)
                    if _which("ghauri") else None
                )
                sqlmap_res = None
                # SQLMap 은 ENABLE_SQLMAP=true 일 때만 최종 검증(미설치/timeout 은 전체 스캔 실패 없음).
                # 개선: ghauri 신호 유무와 무관하게 우선순위 상위 후보(위 ordered[:8] 로 이미 유계)에는
                # sqlmap 을 투입한다 — ghauri 는 빠른 보조 신호로만 쓰고, 그 false-negative 가
                # 실제 SQLi 를 가리지(미탐) 않도록 함. (ghauri_sig 는 여전히 판정 보강에 사용)
                if _sqlmap_enabled():
                    sqlmap_res = await run_sqlmap(url, host, port, progress_cb=_cb,
                                                  input_context=_ctx, source="katana",
                                                  cookie=_auth_cookie_str(scan_id))
                finding = build_sqli_finding(url, host, port, ghauri_sig, sqlmap_res)
                if finding:
                    all_findings.append(finding)
            except Exception as e:
                await _cb(f"SQLi 심화 점검 오류 (무시): {e}")
        await _cb(f"✅ SQLi 심화(sqlmap/ghauri) 완료 — {len(tested)}개 URL 검증")
    elif not tools.get("sqlmap"):
        await _cb("ℹ️ sqlmap 미설치 — SQLi 심화(sqlmap/ghauri) 건너뜀")
    elif not param_urls:
        await _cb("ℹ️ SQLi 심화 — 파라미터(?) 있는 URL 없음, 건너뜀")

    # 6) 로그인/POST 폼 SQLi — sqlmap --data 로 검증(GET 파라미터에 없는 인증 우회 SQLi 포착).
    #    active_probing 단계에서 이미 발견한 로그인 폼(action/필드)을 재사용한다(재크롤 없음).
    if _sqlmap_enabled():
        form_targets: list[tuple] = []
        seen_forms: set[str] = set()
        for hr in host_results:
            host = hr.get("host", "")
            for svc in hr.get("services", []):
                port = svc.get("port", 0)
                _ap = svc.get("active_probes")
                _ls = _ap.get("login_sqli") if isinstance(_ap, dict) else None
                if not isinstance(_ls, dict):
                    continue
                for _r in (_ls.get("results") or []):
                    if not isinstance(_r, dict):
                        continue
                    action = _r.get("action")
                    uf = _r.get("username_field")
                    pf = _r.get("password_field")
                    # E3: dedup 키에 필드 집합 포함 — 같은 action 에 필드가 다른 별개 폼이 버려지던 문제
                    _fkey = f"{action}|{','.join(sorted((_r.get('default_body') or {}).keys()))}"
                    if not action or not pf or _fkey in seen_forms:
                        continue
                    seen_forms.add(_fkey)
                    # 실제 브라우저 body 재현: submit 버튼·hidden 기본값 포함(default_body).
                    # user/pass 는 무해 테스트값, sqlmap 은 -p 로 그 둘만 주입(헤더 테스트 배제).
                    body = dict(_r.get("default_body") or {})
                    if uf:
                        body[uf] = "admin"
                    body[pf] = "test"
                    post_data = urllib.parse.urlencode(body)
                    tparams = ",".join([x for x in (uf, pf) if x])
                    form_targets.append((action, host, port, post_data, tparams))
        for action, host, port, post_data, tparams in form_targets[:5]:
            try:
                await _cb(f"sqlmap(로그인/POST 폼): {action} 검증...")
                # 인증 우회 확인이 목적 → DB 열거(--dbs) 생략 + 타임아웃 상향 + 불리언/에러 기법으로
                # 빠르게 확정(느린 time-based/stacked 미사용).
                sm = await run_sqlmap(action, host, port, progress_cb=_cb,
                                      post_data=post_data, input_context="authentication",
                                      source="login_form", no_enum=True,
                                      timeout_override=1000, technique_override="BE",
                                      level_override=4, test_params=tparams,
                                      cookie=_auth_cookie_str(scan_id))
                finding = build_sqli_finding(action, host, port, None, sm)
                if finding:
                    all_findings.append(finding)
            except Exception as e:
                await _cb(f"로그인 폼 SQLi(sqlmap) 오류 (무시): {e}")

    return all_findings
