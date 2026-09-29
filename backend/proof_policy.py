"""
proof_policy.py — Proof Policy Gate: 모든 Proof 검증 실행 전 반드시 통과해야 하는 안전 게이트.

원칙: Eoseureum은 승인된 범위에서 '무해한 증거'만 확보한다. 아래 게이트를 통과하지 못하는
어떤 검증도 수행되지 않는다. 최종 취약 판정은 여전히 Rule Engine 전담이며,
이 게이트는 "그 증거 수집 행위를 애초에 해도 되는가"만 결정한다.

검사 항목: Validation Profile / Scope / 승인 / Budget / 예상 영향도 / 상태 변경 /
          금지 payload / 데이터 추출 범위 / 파일 쓰기 / 외부 callback.

결과(decision):
  ALLOWED
  BLOCKED_BY_PROFILE
  BLOCKED_BY_SCOPE
  BLOCKED_DESTRUCTIVE
  BLOCKED_STATE_CHANGE
  BLOCKED_DATA_EXFILTRATION
  BLOCKED_SHELL
  BLOCKED_PRIVILEGE_ESCALATION
  MANUAL_APPROVAL_REQUIRED
"""
from __future__ import annotations

import ipaddress
import re as _re
from urllib.parse import urlparse

import validation_profiles as vp
import payload_validator as pval

ALLOWED = "ALLOWED"
BLOCKED_BY_PROFILE = "BLOCKED_BY_PROFILE"
BLOCKED_BY_SCOPE = "BLOCKED_BY_SCOPE"
BLOCKED_DESTRUCTIVE = "BLOCKED_DESTRUCTIVE"
BLOCKED_STATE_CHANGE = "BLOCKED_STATE_CHANGE"
BLOCKED_DATA_EXFILTRATION = "BLOCKED_DATA_EXFILTRATION"
BLOCKED_SHELL = "BLOCKED_SHELL"
BLOCKED_PRIVILEGE_ESCALATION = "BLOCKED_PRIVILEGE_ESCALATION"
MANUAL_APPROVAL_REQUIRED = "MANUAL_APPROVAL_REQUIRED"

BLOCKED_DECISIONS = {
    BLOCKED_BY_PROFILE, BLOCKED_BY_SCOPE, BLOCKED_DESTRUCTIVE, BLOCKED_STATE_CHANGE,
    BLOCKED_DATA_EXFILTRATION, BLOCKED_SHELL, BLOCKED_PRIVILEGE_ESCALATION,
}

# 항상 금지되는 위험 행위(어떤 프로파일에서도 허용 안 됨).
_DATA_EXFIL = _re.compile(
    r"\b(dump|--dump|dump-all|load_file|outfile|into\s+outfile|"
    r"password|passwd|hash|credential|creds|secret|private[_-]?key|shadow)\b", _re.I)
_SHELL = _re.compile(r"\b(os-shell|sql-shell|xp_cmdshell|reverse[_-]?shell|bind[_-]?shell|"
                     r"webshell|/bin/sh|/bin/bash|cmd\.exe|powershell)\b", _re.I)
_PRIVESC = _re.compile(r"\b(privilege\s*escalation|privesc|sudo\s|setuid|--priv|grant\s+all)\b", _re.I)
# XSS 세션 탈취/외부 전송(비콘) — 무해 검증이 아니므로 데이터 유출로 차단
_JS_EXFIL = _re.compile(r"(document\.cookie|localstorage|new\s+image\(\)|\.src\s*=|"
                        r"fetch\(|xmlhttprequest|navigator\.sendbeacon|keylog)", _re.I)
_STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_CLOUD_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata"}


def is_blocked(decision: str) -> bool:
    return decision in BLOCKED_DECISIONS or decision == MANUAL_APPROVAL_REQUIRED


def _res(decision: str, reason: str) -> dict:
    return {"decision": decision, "reason": reason, "allowed": decision == ALLOWED}


def _host_of(target: str) -> str:
    if not target:
        return ""
    t = target.strip()
    if "://" not in t:
        t = "//" + t
    try:
        return (urlparse(t).hostname or "").lower()
    except Exception:
        return ""


def in_scope(target: str, scope: list | None) -> bool:
    """대상이 승인된 Scope 안인지 확인. 내부망/메타데이터/loopback 은 항상 밖으로 간주.

    scope: 허용 host/도메인 목록(부분 일치 허용). None/빈 목록이면 내부·메타데이터가
    아닌 대상은 통과(공개 대상 기본 허용), 내부·메타데이터는 차단.
    """
    host = _host_of(target)
    if not host:
        return False
    if host in _CLOUD_METADATA_HOSTS:
        return False
    # loopback / 사설 / 링크로컬 IP 는 scope 밖(내부망 접근 금지)
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
            return False
    except ValueError:
        pass  # 호스트명 — 아래 allowlist 로 판단
    if scope:
        norm = [str(s).strip().lower() for s in scope if s]
        # 정확 일치 또는 서브도메인만 허용. (기존 's in host' 서브스트링 매칭은 스코프 우회
        #  — 예: scope 'corp.com' 이 'corp.com.attacker.net' 에 매칭되던 문제 — 제거)
        return any(host == s or host.endswith("." + s) for s in norm)
    return True


def _internal_allowlist() -> set:
    """관리자가 명시 인가한 내부 테스트 대상 호스트(SCAN_INTERNAL_ALLOW, 콤마구분).
    본인 소유의 로컬 취약 실습 대상(Juice Shop/DVWA 등)을 스캔하기 위한 예외.
    클라우드 메타데이터는 어떤 경우에도 예외 불가(아래 targets_internal 에서 선차단)."""
    import os
    raw = os.getenv("SCAN_INTERNAL_ALLOW", "") or ""
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def targets_internal(target: str) -> bool:
    """내부망/메타데이터/loopback 대상 여부(SSRF 등 내부 접근 차단용)."""
    host = _host_of(target)
    if not host:
        return False
    # 클라우드 메타데이터는 예외 없이 항상 차단(allowlist 로도 못 뚫음).
    if host in _CLOUD_METADATA_HOSTS:
        return True
    # 관리자가 명시 인가한 내부 테스트 대상은 예외(본인 소유 실습 대상 스캔 허용).
    if host.lower() in _internal_allowlist():
        return False
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def evaluate(action: dict, *, profile: str | None = None, scope: list | None = None,
             approved: bool | None = None, budget_state: dict | None = None) -> dict:
    """단일 Proof 검증 행위를 게이트로 평가한다.

    action 필드(모두 선택):
      family, technique, target, method, payload,
      changes_state(bool), writes_file(bool), external_callback(bool),
      internal_target(bool), data_scope(str: none|metadata|records|full),
      requires_approval(bool)
    """
    a = action or {}
    prof = (profile or vp.current_profile()).upper()
    fam = vp.norm_family(a.get("family", ""))
    tech = a.get("technique", "")
    method = (a.get("method") or "GET").upper()
    payload = a.get("payload") or ""
    data_scope = (a.get("data_scope") or "none").lower()

    # 1) 항상 금지: 데이터 추출/셸/권한상승 (payload·기법 무관하게 최우선 차단)
    if _SHELL.search(payload) or _SHELL.search(tech):
        return _res(BLOCKED_SHELL, "셸/웹쉘/코드실행 행위는 금지됩니다")
    if _PRIVESC.search(payload) or _PRIVESC.search(tech):
        return _res(BLOCKED_PRIVILEGE_ESCALATION, "권한 상승 자동화는 금지됩니다")
    if data_scope in ("records", "full") or _DATA_EXFIL.search(payload):
        return _res(BLOCKED_DATA_EXFILTRATION,
                    "데이터 추출(dump/credential/파일읽기)은 금지됩니다 — read-only metadata 만 허용")
    if fam == "xss" and _JS_EXFIL.search(payload):
        return _res(BLOCKED_DATA_EXFILTRATION,
                    "세션 탈취/외부 전송 스크립트는 금지됩니다 — alert 실행 증거만 허용")
    if a.get("writes_file"):
        return _res(BLOCKED_DESTRUCTIVE, "파일 쓰기/실행은 기본 차단됩니다")

    # 2) payload 안전 검증(기존 게이트 재사용) — 파괴/셸/시간지연/상태변경 차단
    if payload:
        pv = pval.validate_payload(payload, vuln_type=fam, method=method)
        if not pval.is_allowed(pv.get("verdict", "")):
            vmap = {
                pval.BLOCKED_SHELL: BLOCKED_SHELL,
                pval.BLOCKED_DESTRUCTIVE: BLOCKED_DESTRUCTIVE,
                pval.BLOCKED_STATE_CHANGE: BLOCKED_STATE_CHANGE,
                pval.BLOCKED_TIME_BASED: BLOCKED_DESTRUCTIVE,
                pval.MANUAL_APPROVAL_REQUIRED: MANUAL_APPROVAL_REQUIRED,
            }
            return _res(vmap.get(pv["verdict"], BLOCKED_DESTRUCTIVE),
                        pv.get("reason", "payload 안전 검증 실패"))

    # 3) 상태 변경 금지(조회만 허용)
    if a.get("changes_state") or (method in _STATE_METHODS and fam != "file_upload"):
        return _res(BLOCKED_STATE_CHANGE, "상태 변경 요청은 금지됩니다(조회만 허용)")

    # 4) Scope 밖 대상 차단
    target = a.get("target", "")
    if target and not in_scope(target, scope):
        return _res(BLOCKED_BY_SCOPE, "승인된 점검 범위(Scope) 밖 대상입니다")
    # SSRF 등 내부망/메타데이터 접근은 target/internal 신호로 별도 차단
    if a.get("internal_target") or (target and targets_internal(target)):
        return _res(BLOCKED_BY_SCOPE, "내부망/클라우드 메타데이터 접근은 금지됩니다")

    # 5) Profile 능력 검사 — 기법이 현재 프로파일에서 허용되는지
    if fam and tech:
        minp = vp.technique_min_profile(fam, tech)
        if minp is None:
            return _res(BLOCKED_BY_PROFILE, f"알 수 없거나 비허용 기법입니다: {fam}.{tech}")
        if vp.rank(prof) < vp.rank(minp):
            return _res(BLOCKED_BY_PROFILE,
                        f"'{tech}' 는 {minp} 이상 프로파일에서만 허용됩니다(현재 {prof})")

    # 6) PROOF 전용 기법은 명시 승인 필요
    if fam and tech and vp.technique_min_profile(fam, tech) == vp.PROOF:
        if not vp.allow_proof():
            return _res(BLOCKED_BY_PROFILE, "PROOF 기법은 ALLOW_PROOF_MODE 승인 시에만 허용됩니다")
        if approved is False:
            return _res(MANUAL_APPROVAL_REQUIRED, "PROOF 실증은 담당자 승인이 필요합니다")

    # 7) 명시적으로 승인이 필요한 행위
    if a.get("requires_approval") and not approved:
        return _res(MANUAL_APPROVAL_REQUIRED, "해당 행위는 담당자 승인이 필요합니다")

    # 8) 외부 callback 은 Eoseureum controlled 만 허용(그 외는 승인 필요)
    if a.get("external_callback") and not a.get("controlled_callback", True):
        return _res(MANUAL_APPROVAL_REQUIRED, "controlled callback 외 외부 연결은 승인이 필요합니다")

    # 9) Budget 초과 차단
    if budget_state is not None:
        b = vp.budget()
        if budget_state.get("actions", 0) >= b["max_actions"]:
            return _res(BLOCKED_BY_PROFILE, "Proof 검증 예산(max_actions)을 초과했습니다")

    return _res(ALLOWED, "안전 검증 허용(read-only 증거)")
