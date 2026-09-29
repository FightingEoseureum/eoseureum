"""
finding_normalizer.py — 취약점 탐지 결과 중앙 정규화 모듈.

탐지 결과를 '실제 영향·근거' 기준으로 다음 버킷으로 분리한다.
  - findings             : 실제 취약점 (보고서·UI의 취약점 목록과 카운트의 단일 기준)
  - attack_surface_items : 취약점은 아니나 공격자가 추가 분석할 노출 지점(관리 인터페이스, 인증영역,
                           API 문서, 프레임워크 콘솔 등). 취약점 수·조치 우선순위에 미포함.
  - discovery_items      : 참고/발견 항목 (단순 경로 노출 후보, 저위험 TLS 등)
  - good_items           : 양호 항목 (통계용)
  - noise_items          : 노이즈/제외 항목 (404·빈 응답 등)
  - summary              : 통계

원칙 (유지)
  - 오탐보다 미탐 허용: 명확한 근거(evidence)와 신뢰도(CONFIRMED/CONFIG_CONFIRMED) 또는 실증
    (probe_confirmed)이 있을 때만 취약점으로 승격한다. 증거가 부족하면 승격하지 않는다.
  - 관리자/로그인 인터페이스가 'HTTP 200 + 로그인 폼'만 확인된 경우는 취약점이 아니라
    attack_surface(공격 표면)로 분류한다. 인증 없이 관리자 기능 접근·민감정보 노출·무인증 API 호출 등
    실제 악용 근거가 있을 때만 findings로 승격한다.
  - Informational(info)은 내부적으로 info로 두되 보고서 표시는 Low로 한다.
  - 동일 항목(제목·URL 경로)이 여러 곳에서 발견되면 affected_endpoints로 병합한다.

각 항목에 부여하는 필드: finding_type, report_severity, confidence_score(0~100).
"""
import re
import urllib.parse

_PROMOTE_CONFIDENCE = {"CONFIRMED", "CONFIG_CONFIRMED", "CONFIRMED_RESPONSE", "CONFIRMED_BROWSER"}
_WEAK_CONFIDENCE = {None, "", "POSSIBLE", "MANUAL_REVIEW"}

_STATUS_RE = re.compile(r'HTTP\s*(\d{3})')
_DISCOVERY_STATUSES = {301, 302, 304, 401, 403}

_TLS_HINT = re.compile(r'(TLS|SSL|cipher|인증서|certificate|프로토콜|testssl|HSTS|sweet32|beast)', re.I)
_INFO_DISCLOSURE_HINT = re.compile(r'(Server\s*헤더|배너|버전\s*정보\s*노출|banner)', re.I)
_HIDDEN_PATH_HINT = re.compile(r'(숨겨진\s*경로|디렉터리\s*발견|경로\s*노출|hidden\s*path)', re.I)
_SENSITIVE_FILE = re.compile(r'\.(env|git|bak|backup|sql|config|ini|pem|key|log)\b|wp-config|\.git/|\.svn|web\.xml|MANIFEST\.MF|composer\.json|package-lock|yarn\.lock|\.DS_Store|dump\.sql|db\.sql', re.I)
_ADMIN_HINT = re.compile(r'관리자\s*페이지|관리자\s*인터페이스|admin\s*panel|/admin|/manager|wp-login|wp-admin|phpmyadmin', re.I)
_TLS_HIGH_RISK = re.compile(r'(heartbleed|poodle|만료|expired|self[-\s]?signed|개인키\s*노출|private\s*key|deprecated\s*sslv[23]|sslv2|sslv3)', re.I)

# 공격 표면(취약점 아님) 후보 키워드
_LOGIN_HINT = re.compile(r'(로그인\s*폼|로그인\s*페이지|login\s*form|sign\s*in|로그인=있음|인증\s*영역|basic\s*auth)', re.I)
_CONSOLE_HINT = re.compile(
    r'(swagger|openapi|api-?docs|graphql|graphiql|actuator|jolokia|manager/html|host-manager|'
    r'phpmyadmin|jenkins|grafana|kibana|server-status|프레임워크\s*콘솔|관리\s*콘솔|api\s*문서|api\s*base)',
    re.I)
# 무인증 관리 기능 접근/민감정보 노출 = 취약점 승격 근거
_UNAUTH_FUNC_HINT = re.compile(
    r'(인증\s*없이|무인증|로그인=없음|unauthenticated|기본\s*계정|default\s*cred|약한\s*인증|'
    r'사용자\s*목록|민감\s*데이터|민감정보|설정\s*변경|관리\s*API|admin\s*api)', re.I)
# 민감정보 '실제 노출'(파일 내용/시크릿 값 등) = 취약점.
# 로그인 폼 설명('사용자/비밀번호 입력') 같은 단순 언급은 매칭하지 않도록 값-노출 형태만 인정.
_SENSITIVE_EXPOSED_HINT = re.compile(
    r'(DB_PASSWORD|password\s*[=:]\s*\S|passwd\s*[=:]\s*\S|secret\s*[=:]\s*\S|'
    r'api[_-]?key\s*[=:]\s*\S|access[_-]?key|private[_-]?key|BEGIN\s+(?:RSA|PRIVATE)|'
    r'heapdump|시크릿\s*키|비밀번호\s*[:=]\s*\S|설정\s*파일\s*내용\s*노출|소스\s*코드\s*노출)', re.I)

# '내용이 확인된 민감 경로 노출' 마커 — info_disclosure_probe 가 본문 검증 후 부여한다.
# 단순 경로 존재/401/403 은 이 마커가 없으므로 영향받지 않는다.
_CONTENT_CONFIRMED_HINT = re.compile(
    r'(content_confirmed|server-status\s*정보\s*노출|server-info\s*설정\s*정보\s*노출|'
    r'actuator\s+env\s*무인증|heapdump\s*무인증|\.env\s*파일\s*내용\s*노출|'
    r'\.git/HEAD\s*접근\s*가능|관리자\s*기능\s*무인증\s*접근)', re.I)


def _is_content_confirmed_exposure(f: dict) -> bool:
    """info_disclosure_probe 가 본문을 확인해 부여한 'content_confirmed' 마커가 있는가."""
    tags = f.get("tags") or []
    if any("content_confirmed" in str(t).lower() for t in tags):
        return True
    pd = f.get("probe_detail") or {}
    if isinstance(pd, dict) and pd.get("content_confirmed") is True:
        return True
    return bool(_CONTENT_CONFIRMED_HINT.search(_text_of(f)))

# 보고서 표시용 심각도 정규화 (Info → Low)
_SEVERITY_REPORT = {
    "CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
    "LOW": "Low", "INFO": "Low", "INFORMATIONAL": "Low",
}


def count_by_severity(findings: list[dict] | None) -> dict:
    """findings 를 report_severity(없으면 severity 매핑) 기준 등급별 집계.
    예전엔 normalize/merge_service_results/main._recompute 가 각자 계산해 드리프트 위험이 있었다."""
    by = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in (findings or []):
        if not isinstance(f, dict):
            continue
        rs = f.get("report_severity") or _SEVERITY_REPORT.get((f.get("severity") or "").upper(), "Low")
        if rs not in by:
            rs = "Low"
        by[rs] = by.get(rs, 0) + 1
    return by


def _status_of(f: dict) -> int:
    for key in ("title", "evidence_detail"):
        m = _STATUS_RE.search(f.get(key) or "")
        if m:
            return int(m.group(1))
    return int(f.get("status_code") or 0)


def _text_of(f: dict) -> str:
    return f"{f.get('title','')} {f.get('evidence_detail','') or ''} {f.get('description','') or ''}"


def _has_screenshot(f: dict) -> bool:
    pd = f.get("probe_detail") or {}
    return bool(f.get("evidence_screenshot")) or bool(pd.get("evidence_screenshots"))


def _has_repro(f: dict) -> bool:
    if f.get("reproduction_cmd"):
        return True
    return any("curl" in (s or "").lower() for s in (f.get("detection_steps") or []))


def _has_evidence(f: dict) -> bool:
    if f.get("probe_confirmed") is True:
        return True
    if _has_screenshot(f):
        return True
    ed = (f.get("evidence_detail") or "").strip()
    return len(ed) >= 30


def _has_login_form(f: dict) -> bool:
    if _LOGIN_HINT.search(_text_of(f)):
        return True
    pd = f.get("probe_detail") or {}
    for fp in (pd.get("found_pages") or []):
        if isinstance(fp, dict) and fp.get("has_login_form"):
            return True
    return False


def _is_unauth_admin_access(f: dict) -> bool:
    """인증 없이 관리자 기능 접근/민감정보 노출 등 '실제 악용 근거'가 있는가."""
    txt = _text_of(f)
    if _UNAUTH_FUNC_HINT.search(txt):
        return True
    pd = f.get("probe_detail") or {}
    # 관리자 API 무인증 노출 프로브(found_endpoints) → 실제 악용 근거
    if pd.get("found_endpoints"):
        return True
    return False


def _norm_path(url: str) -> str:
    if not url:
        return ""
    try:
        p = urllib.parse.urlparse(url).path.rstrip("/").lower()
    except Exception:
        return ""
    return p or "/"


def _finding_url(f: dict) -> str:
    m = re.search(r'URL\s*:\s*(\S+)', f.get("evidence_detail", "") or "")
    if m:
        return m.group(1)
    return f.get("evidence_url", "") or ""


_SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# 취약점 클래스별 기준 심각도 (CVSS 3.1 / OWASP 관례). family+title+cwe 텍스트 매칭, 위→아래 우선.
# 목적: probe 가 준 raw severity 편차와 무관하게 '같은 유형은 같은 등급'으로 일관 산정한다.
_CLASS_SEVERITY = [
    (re.compile(r"sql\s*injection|sqli|command\s*injection|os[_\s-]*command|cmd[_\s-]*inj|"
                r"template\s*injection|ssti|deserial|역직렬화|remote\s*code|\brce\b|"
                r"인증\s*우회|auth(entication)?[_\s-]*bypass|계정\s*탈취", re.I), "Critical"),
    (re.compile(r"xxe|xml\s*external|ssrf|서버[_\s-]*사이드[_\s-]*요청|local\s*file|\blfi\b|\brfi\b|"
                r"path\s*traversal|경로\s*탐색|디렉터리\s*트래버설|\bidor\b|접근\s*통제|broken\s*access|"
                r"권한\s*상승|privilege|secret|api[_\s-]*key|token\s*(노출|leak|exposure)|"
                r"자격\s*증명|credential|stored\s*xss|저장형\s*xss|blind\s*sql|\bjwt\b|"
                r"\bcsrf\b|cross[_\s-]*site\s*request|요청\s*위조|"
                r"cwe-(89|78|94|502|287|611|22|639|798|918|352)\b", re.I), "High"),
    (re.compile(r"\bxss\b|cross[_\s-]*site\s*script|스크립트\s*삽입|반사형|open\s*redirect|오픈\s*리다이렉트|"
                r"clickjack|클릭재킹|\btls\b|\bssl\b|인증서|\bcert|"
                r"\bcors\b|교차\s*출처|\bcsp\b|content[_\s-]*security|세션|session|쿠키|cookie", re.I), "Medium"),
    (re.compile(r"보안\s*헤더|security\s*header|http\s*method|trace\s*method|위험한?\s*메서드|jsonp|"
                r"directory\s*listing|디렉터리\s*리스팅|서버\s*정보|server\s*header|서버\s*버전|version|버전|"
                r"정보\s*노출|information\s*(disclosure|exposure)|banner|robots|sitemap", re.I), "Low"),
]


def _class_base_severity(f: dict) -> str | None:
    """취약점 유형(클래스) 기준 심각도. 매칭 없으면 None(→ probe severity 로 폴백)."""
    txt = " ".join(str(f.get(k) or "") for k in ("family", "title", "cwe", "category", "type"))
    for rx, sev in _CLASS_SEVERITY:
        if rx.search(txt):
            return sev
    return None


def _report_severity(f: dict) -> str:
    """report_severity 산정 — 취약점 클래스(영향) 기준을 authoritative 로 사용해 일관성 확보.

    설계 원칙: 심각도는 '유형이 가지는 영향'으로 결정하고(SQLi=Critical, 보안헤더/정보노출=Low),
    실증 여부는 별도(확인 상태)로 표기해 직교적으로 다룬다. probe 가 준 raw severity 는
    유형이 매칭되면 신뢰하지 않는다(오래된/부풀려진 값의 편차 제거).

    1) 유형 매칭 시 → 클래스 기준 심각도를 사용(raw 무시).
    2) 유형 미매칭 시 → probe 의 raw severity 로 폴백.
    3) 외부도구 등 권위 판정이 raw CRITICAL 이면(예: testssl 인증서 체인) 클래스보다 우선.
    4) 미확인(실증 안 됨·약한 신뢰도)의 Critical 은 과대평가 방지를 위해 High 로 하향
       (단, 위 3의 권위 CRITICAL 은 유지).
    """
    stated = _SEVERITY_REPORT.get((f.get("severity") or "").upper())
    base = _class_base_severity(f)
    raw_critical = (f.get("severity") or "").upper() == "CRITICAL"

    sev = base or stated or "Low"                      # 1) 유형 기준 우선, 없으면 raw
    if raw_critical and (base is None or _SEV_RANK[base] > 0):
        sev = "Critical"                               # 3) 권위 CRITICAL 존중

    if sev == "Critical" and not raw_critical \
            and not f.get("probe_confirmed") \
            and (f.get("confidence") or "").upper() in {"", "POSSIBLE", "MANUAL_REVIEW"}:
        sev = "High"                                   # 4) 미확인 Critical → High
    return sev


def confidence_score(f: dict, bucket: str = "") -> int:
    """판정 신뢰도 점수(0~100)를 증거 수준에 따라 산정한다.
    보호된 경로/단순 경로 발견/공격 표면은 스크린샷 유무와 무관하게 낮게 산정한다."""
    title = f.get("title", "") or ""
    ed = f.get("evidence_detail") or ""
    status = _status_of(f)
    conf = (f.get("confidence") or "").upper()
    tool = f.get("tool_source") or ""
    has_shot = _has_screenshot(f)
    has_resp = len(ed.strip()) >= 20
    has_repro = _has_repro(f)
    confirmed = f.get("probe_confirmed") is True

    # 위험 HTTP 메서드: 실제 호출 검증 vs OPTIONS Allow만 (실증 우선 판정)
    if "HTTP Method" in title or "메서드" in title:
        if confirmed or "실제 호출" in ed or "실제 동작" in ed:
            return 75
        return 50  # OPTIONS Allow 만 확인 — 승격 근거 부족
    # 401/403 보호된 경로 (공격 표면/참고) — 스크린샷이 있어도 낮게
    if status in (401, 403):
        return 45
    # 단순 경로 발견 (리다이렉트 + 도구/경로성) — 스크린샷이 있어도 낮게
    if status in (301, 302) and (tool or _HIDDEN_PATH_HINT.search(title)):
        return 45
    # 공격 표면(로그인/관리 인터페이스·콘솔·API 문서 발견): 존재는 확실하나 보안 이슈 신뢰도 중간
    if bucket == "attack_surface":
        return 60
    # Server 헤더/배너 버전 정보 노출
    if _INFO_DISCLOSURE_HINT.search(title):
        return 85
    # Playwright 등 브라우저 실증 + 스크린샷
    if has_shot and confirmed:
        return 95
    if has_shot:
        return 90
    # 응답 데이터 + 재현 명령어
    if has_resp and has_repro:
        return 88
    # 설정/헤더 명확 확인 (CONFIRMED + 응답근거)
    if conf == "CONFIRMED" and has_resp:
        return 85
    # 외부 도구 단일 탐지
    if tool:
        return 55
    # 경로/로그인 발견만
    if _HIDDEN_PATH_HINT.search(title) or _LOGIN_HINT.search(title):
        return 45
    # 근거 부족 / POSSIBLE
    if conf in _WEAK_CONFIDENCE:
        return 35
    if has_resp:
        return 70
    return 40


# '양호(good)'로 표기됐지만 제목에 취약 신호가 있으면 모순 → good 금지(참고로 강등).
_VULN_TITLE_HINT = re.compile(
    r"방어\s*부재|취약|우회|무인증|미적용|주입|인젝션|평문\s*전송|\bbypass\b", re.IGNORECASE)


def classify(f: dict) -> str:
    """단일 finding을 vulnerability / attack_surface / discovery / good / noise 로 분류."""
    # 명시적 버킷 지정(예: IDOR/CSRF 후보는 항상 참고로) 우선 적용
    forced = f.get("force_finding_type")
    if forced in _PRIORITY:
        return forced

    title = f.get("title", "") or ""
    if f.get("judgment") == "양호":
        # 모순 가드(A1): '방어 부재/취약/우회/주입' 등 취약 신호가 제목에 있으면 양호일 수 없음 → 참고.
        if _VULN_TITLE_HINT.search(title):
            return "discovery"
        return "good"

    tool = (f.get("tool_source") or "")
    status = _status_of(f)
    conf = (f.get("confidence") or "").upper() or None
    txt = _text_of(f)

    # 노이즈: 404 / 존재하지 않음
    if status == 404:
        return "noise"

    # 내용이 확인된 민감 경로 노출(본문 검증됨)은 취약점으로 승격.
    # 단순 경로 존재/401/403 은 이 마커가 없어 영향받지 않는다.
    if status != 404 and _is_content_confirmed_exposure(f):
        return "vulnerability"

    # 민감 파일/시크릿 실제 노출은 항상 취약점
    if _SENSITIVE_EXPOSED_HINT.search(txt):
        return "vulnerability"
    if status == 200 and _SENSITIVE_FILE.search(title) and tool:
        return "vulnerability"

    # 관리자/로그인 인터페이스
    if _ADMIN_HINT.search(title) or _LOGIN_HINT.search(title):
        # 인증 없이 관리 기능 접근/민감정보 노출 = 취약점 승격
        if _is_unauth_admin_access(f) and _has_evidence(f):
            return "vulnerability"
        # 401/403 보호된 관리 경로 = 공격 표면(취약점 아님)
        if status in (401, 403):
            return "attack_surface"
        # 200 + (로그인 폼 또는 인터페이스 실증 근거) = 공격 표면
        if status == 200 and (_has_login_form(f) or _has_evidence(f)):
            return "attack_surface"
        # ffuf 등 단순 경로 히트(로그인/근거 미확인 리다이렉트·디렉터리)는 참고로 유지
        if tool == "ffuf" or _HIDDEN_PATH_HINT.search(title):
            return "discovery"
        # 로그인 폼만 확인된 경우(상태코드 불명)도 공격 표면
        if _has_login_form(f):
            return "attack_surface"
        return "discovery"

    # 프레임워크 콘솔 / API 문서 (swagger/graphql/actuator/manager/phpmyadmin/jenkins 등)
    if _CONSOLE_HINT.search(txt):
        if _SENSITIVE_EXPOSED_HINT.search(txt) or (f.get("probe_confirmed") is True and _is_unauth_admin_access(f)):
            return "vulnerability"
        return "attack_surface"

    # ffuf / 단순 경로·디렉터리 발견
    if tool == "ffuf" or _HIDDEN_PATH_HINT.search(title):
        if status == 200 and _SENSITIVE_FILE.search(title):
            return "vulnerability"          # 민감 파일 노출
        return "discovery"                  # 401/403/301/302/단순 디렉터리

    # 단순 경로 상태코드 발견(외부도구/경로성)
    if status in _DISCOVERY_STATUSES and (_HIDDEN_PATH_HINT.search(title) or tool):
        return "discovery"

    # TLS/SSL 저위험 → 참고
    if _TLS_HINT.search(title) and not _TLS_HIGH_RISK.search(title + " " + (f.get("evidence_detail") or "")):
        return "discovery"

    # 서버 버전/배너 정보 노출은 정상적인(저위험) 취약점으로 인정한다(근거·신뢰도 게이트 통과 시).

    # 근거 없음 → 참고
    if not _has_evidence(f):
        return "discovery"

    # 신뢰도 게이트: 약한 신뢰도는 실증되지 않으면 승격하지 않음
    if conf in _WEAK_CONFIDENCE and not f.get("probe_confirmed"):
        return "discovery"

    return "vulnerability"


def _apply_metadata(f: dict, bucket: str) -> None:
    """버킷에 따른 표시 메타데이터 보정(공격 표면 제목/권고 등)."""
    if bucket == "attack_surface" and (_ADMIN_HINT.search(f.get("title", "")) or _LOGIN_HINT.search(f.get("title", ""))):
        # 관리자/로그인 인터페이스 '발견'은 취약점이 아님을 제목·권고에 반영
        if "인증 없이" not in f.get("title", "") and "무인증" not in f.get("title", ""):
            f["attack_surface_label"] = "관리자/인증 인터페이스 발견"
        if not f.get("recommendation"):
            f["recommendation"] = ("관리 인터페이스를 내부망/VPN/IP 제한으로 보호하고 다중 인증(MFA)을 "
                                   "적용하십시오. 외부 노출이 불필요하면 접근을 차단하십시오.")


def _dedup_key(f: dict) -> tuple:
    title = f.get("title", "") or ""
    title = re.sub(r'\s*\(HTTP\s*\d{3}\)', '', title)   # 상태코드 제거
    title = re.sub(r'^\s*\[[^\]]+\]\s*', '', title)     # [tool] 접두 제거
    title = title.strip()
    path = _norm_path(_finding_url(f))
    return (f.get("host", ""), title, path)


def _merge_into(target: dict, src: dict) -> None:
    """중복 항목을 대상에 병합 (영향 포트·엔드포인트·도구 합치기)."""
    ports = set(target.get("affected_ports") or [target.get("port", 0)])
    for p in (src.get("affected_ports") or [src.get("port", 0)]):
        if p:
            ports.add(p)
    target["affected_ports"] = sorted(x for x in ports if x)
    eps = list(target.get("affected_endpoints") or [])
    seen = {(e if isinstance(e, str) else e.get("url", "")) for e in eps}
    for e in (src.get("affected_endpoints") or []):
        key = e if isinstance(e, str) else e.get("url", "")
        if key and key not in seen:
            eps.append(e); seen.add(key)
    src_url = _finding_url(src)
    if src_url and src_url not in seen:
        eps.append(src_url)
    if eps:
        target["affected_endpoints"] = eps
    tools = list(target.get("tools") or [])
    for t in (src.get("tools") or ([src.get("tool_source")] if src.get("tool_source") else [])):
        if t and t not in tools:
            tools.append(t)
    if tools:
        target["tools"] = tools


# 버킷 우선순위 (높을수록 우선) — 같은 dedup 키 충돌 시 상위 버킷 유지
_PRIORITY = {"vulnerability": 4, "attack_surface": 3, "discovery": 2, "good": 1, "noise": 0}


def normalize(findings: list[dict]) -> dict:
    """
    findings 리스트를 정규화하여 버킷과 summary를 반환한다.
    각 항목에 finding_type, report_severity, confidence_score 를 부여한다.
    """
    findings = findings or []

    by_key: dict[tuple, dict] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        bucket = classify(f)
        f["finding_type"] = bucket
        # judgment 를 버킷과 동기화한다. _make_finding 은 기본 judgment="취약" 을 붙이므로,
        # discovery 로 분류된 항목(정상 디렉터리 302 등)이 '취약'으로 남는 오탐 표기를 교정한다.
        # attack_surface 는 민감 경로 노출(취약)~참고가 혼재하므로 기존 judgment 를 존중한다.
        if bucket == "vulnerability":
            f["judgment"] = "취약"
        elif bucket == "discovery":
            f["judgment"] = "참고"
        elif bucket == "good":
            f["judgment"] = "양호"
        f["report_severity"] = _report_severity(f)
        f["confidence_score"] = confidence_score(f, bucket)
        _apply_metadata(f, bucket)
        key = _dedup_key(f)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = f
            continue
        if _PRIORITY[bucket] > _PRIORITY[existing["finding_type"]]:
            _merge_into(f, existing)
            by_key[key] = f
        else:
            _merge_into(existing, f)

    deduped = list(by_key.values())

    findings_out  = [f for f in deduped if f["finding_type"] == "vulnerability"]
    surface_out   = [f for f in deduped if f["finding_type"] == "attack_surface"]
    discovery_out = [f for f in deduped if f["finding_type"] == "discovery"]
    good_out      = [f for f in deduped if f["finding_type"] == "good"]
    noise_out     = [f for f in deduped if f["finding_type"] == "noise"]

    # 교차버킷 중복 억제(A1): 확정 취약점과 같은 (host, cwe) 인 공격표면/참고 항목은 제거한다.
    # (동일 SQLi 등이 findings + attack_surface + discovery 에 3중 표기되던 문제 해결 — 확정이 하위 표기를 포섭)
    def _cwe_key(f):
        cwe = re.sub(r"\s+", "", (f.get("cwe") or "")).upper()
        return (f.get("host", "") or "", cwe) if cwe and cwe != "CWE-" else None
    _confirmed_cwe_keys = {k for k in (_cwe_key(f) for f in findings_out) if k}
    if _confirmed_cwe_keys:
        surface_out   = [f for f in surface_out   if _cwe_key(f) not in _confirmed_cwe_keys]
        discovery_out = [f for f in discovery_out if _cwe_key(f) not in _confirmed_cwe_keys]

    _order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings_out.sort(key=lambda f: _order.get(f.get("report_severity", "Low"), 9))

    by_sev = count_by_severity(findings_out)
    confirmed = sum(1 for f in findings_out
                    if f.get("probe_confirmed") is True
                    or (f.get("confidence") or "").upper() in _PROMOTE_CONFIDENCE)

    summary = {
        "vulnerability_count": len(findings_out),
        "by_severity": by_sev,
        "confirmed_count": confirmed,
        "attack_surface_count": len(surface_out),
        "discovery_count": len(discovery_out),
        "good_count": len(good_out),
        "noise_count": len(noise_out),
        "by_type": {
            "vulnerability": len(findings_out),
            "attack_surface": len(surface_out),
            "discovery": len(discovery_out),
            "good": len(good_out),
            "noise": len(noise_out),
        },
    }

    return {
        "findings": findings_out,
        "attack_surface_items": surface_out,
        "discovery_items": discovery_out,
        "good_items": good_out,
        "noise_items": noise_out,
        "summary": summary,
    }


def merge_service_results(analysis: dict, service_result: dict) -> dict:
    """
    service_scan.scan_services() 결과(이미 finding_type 으로 분류됨)를 기존 analysis 버킷에
    병합하고 summary 를 재계산한다. (web 점검 결과는 그대로 두고 service 항목만 추가)

    - 웹 취약점 판정/카운트 로직(normalize)은 변경하지 않는다 — 서비스 항목은 service_scan 이
      이미 분류했고 여기서는 append + report_severity 부여 + 카운트 합산만 한다.
    """
    if not service_result:
        return analysis

    sf = service_result.get("service_findings", []) or []
    sa = service_result.get("service_attack_surface", []) or []
    sd = service_result.get("service_discovery", []) or []
    sg = service_result.get("service_good", []) or []
    sn = service_result.get("service_noise", []) or []

    for it in (sf + sa + sd + sg + sn):
        if not isinstance(it, dict):
            continue
        it.setdefault("scan_category", "service")
        if not it.get("report_severity"):
            it["report_severity"] = _report_severity(it)
        it.setdefault("confidence_score", 0)

    analysis.setdefault("findings", []).extend(sf)
    analysis.setdefault("attack_surface_items", []).extend(sa)
    analysis.setdefault("discovery_items", []).extend(sd)
    analysis.setdefault("good_items", []).extend(sg)
    analysis.setdefault("noise_items", []).extend(sn)

    findings = analysis["findings"]
    s = analysis.setdefault("summary", {})
    by_sev = count_by_severity(findings)
    web_vuln = [f for f in findings if f.get("scan_category") != "service"]
    svc_vuln = [f for f in findings if f.get("scan_category") == "service"]

    s["vulnerability_count"] = len(findings)
    s["by_severity"] = by_sev
    s["web_vulnerability_count"] = len(web_vuln)
    s["service_vulnerability_count"] = len(svc_vuln)
    s["attack_surface_count"] = len(analysis.get("attack_surface_items", []))
    s["discovery_count"] = len(analysis.get("discovery_items", []))
    s["good_count"] = len(analysis.get("good_items", []))
    s["noise_count"] = len(analysis.get("noise_items", []))
    ss = service_result.get("service_summary", {}) or {}
    s["checked_ports"] = ss.get("checked_ports", s.get("checked_ports", 0))
    s["service_attack_surface_count"] = sum(
        1 for x in analysis.get("attack_surface_items", []) if x.get("scan_category") == "service"
    )
    return analysis
