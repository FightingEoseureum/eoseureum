import asyncio
import io
import json as _json
import os
import pathlib
import re
import uuid
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from rule_engine import analyze_with_rules, merge_external_findings, finalize_trend
from finding_normalizer import (
    normalize as normalize_findings, merge_service_results, count_by_severity)
import technology_fingerprint
import attack_chain_engine
import adaptive_recon
from report import generate_report
from auth import create_token, decode_token, verify_password, ip_allowed
from database import (
    add_to_watchlist,
    count_domain_scans,
    count_user_scans,
    create_scan_record,
    set_scan_config,
    create_user,
    delete_scan_record,
    delete_user,
    delete_watchlist_item,
    get_all_users,
    get_domain_scan_history,
    get_scan_record,
    get_scans_for_user,
    get_user_by_id,
    get_user_by_username,
    get_watchlist,
    get_watchlist_item,
    get_watchlist_password,
    init_db,
    update_scan_record,
    save_checkpoint,
    load_checkpoint,
    update_user,
    update_watchlist_item,
    get_due_watchlist,
    mark_watchlist_ran,
    POLICY_ENV_KEYS,
    list_policies, get_policy, get_active_policy, create_policy, update_policy,
    delete_policy, set_active_policy,
    list_templates, get_template, get_default_template, create_template,
    update_template, delete_template, set_default_template,
)
import socket as _socket
from scanner import SERVICE_NAMES, scan_host
from screenshots import capture_screenshots_for_scan, capture_evidence_screenshots, SCREENSHOTS_DIR
from active_probing import probe_active_for_all_hosts, get_coverage as get_probe_coverage, ScanInterrupted
from external_tools import run_all_external_tools, available_tools
from url_discovery import URLDiscoveryEngine
from cleanup_manager import cleanup_scan_artifacts
from ai_provider import enhance_analysis as ai_enhance_analysis, check_provider_health, enrich_with_security_analyst, make_sync_ai_fn

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


_SCHEDULER_INTERVAL = int(os.getenv("SCHEDULER_INTERVAL_SEC", "60"))
_SCHEDULER_ENABLED = os.getenv("ENABLE_SCHEDULER", "true").lower() in ("1", "true", "yes")


class _HeadlessWS:
    """예약 스캔용 가짜 WebSocket — run_scan 의 send(ws.send_json) 만 충족(무동작)."""
    async def send_json(self, data):  # noqa: D401
        return None


async def _run_due_scheduled_scans():
    """next_run 이 도래한 watchlist 대상을 헤드리스로 점검한다(run_scan 재사용, 스캔 로직 불변)."""
    due = await get_due_watchlist()
    for item in due:
        domain = item.get("domain")
        uid = item.get("user_id")
        if not domain or not uid:
            continue
        # 동일 도메인 진행 중 스캔이 있으면 이번 주기는 건너뜀
        if any(v.get("domain") == domain and not v.get("done") for v in SCAN_PROGRESS.values()):
            continue
        owner = await get_user_by_id(uid)
        role = owner["role"] if owner else "user"
        scan_id = str(uuid.uuid4())
        print(f"[scheduler] 예약 점검 시작: {domain} (watchlist#{item.get('id')})")
        try:
            await run_scan(_HeadlessWS(), domain, scan_id, uid, role,
                           domain_notes="[예약 스캔] 자동 정기 점검")
        except Exception as e:
            print(f"[scheduler] 예약 점검 오류({domain}): {e}")
        finally:
            await mark_watchlist_ran(item.get("id"),
                                     item.get("scan_cycle") or "manual",
                                     item.get("scan_time") or "03:00",
                                     scan_day=item.get("scan_day"),
                                     scan_months=item.get("scan_months"))


async def _scheduler_loop():
    await asyncio.sleep(20)  # 기동 직후 부하 회피
    while True:
        try:
            await _run_due_scheduled_scans()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[scheduler] 루프 오류(무시): {e}")
        await asyncio.sleep(_SCHEDULER_INTERVAL)


def _next_finding_uid(findings: list) -> str:
    """기존 finding 들의 F<n> uid 중 최대+1 로 다음 uid 를 만든다(로그인SQLi·CSRF 확정 추가용)."""
    nums = [int(str(x.get("finding_uid", ""))[1:]) for x in (findings or [])
            if str(x.get("finding_uid", "")).startswith("F")
            and str(x.get("finding_uid", ""))[1:].isdigit()]
    return f"F{(max(nums) if nums else 0) + 1}"


def _recompute_risk_and_summary(analysis: dict) -> None:
    """확정 finding(로그인SQLi/CSRF 등)을 normalize/위험도 계산 '후'에 추가했을 때, 요약 수치와
    overall_risk/overall_summary 를 최종 findings/discovery 기준으로 다시 맞춘다(집계 누락 방지)."""
    findings = analysis.get("findings", []) or []
    by_sev = count_by_severity(findings)
    s = analysis.setdefault("summary", {})
    s["vulnerability_count"] = len(findings)
    s["by_severity"] = by_sev
    s["web_vulnerability_count"] = len([f for f in findings if f.get("scan_category") != "service"])
    s["service_vulnerability_count"] = len([f for f in findings if f.get("scan_category") == "service"])
    s["discovery_count"] = len(analysis.get("discovery_items", []) or [])
    s["attack_surface_count"] = len(analysis.get("attack_surface_items", []) or [])
    s["good_count"] = len(analysis.get("good_items", []) or [])
    # 확정(CONFIRMED) 수: 확정 finding(로그인SQLi/CSRF 등)이 normalize 뒤에 추가되므로 여기서 재집계.
    _promote = {"CONFIRMED", "CONFIG_CONFIRMED", "CONFIRMED_RESPONSE", "CONFIRMED_BROWSER"}
    s["confirmed_count"] = sum(
        1 for f in findings
        if f.get("probe_confirmed") is True or (f.get("confidence") or "").upper() in _promote)
    if by_sev.get("Critical") or by_sev.get("High"):
        analysis["overall_risk"] = "HIGH"
    elif by_sev.get("Medium"):
        analysis["overall_risk"] = "MEDIUM"
    elif by_sev.get("Low"):
        analysis["overall_risk"] = "LOW"
    else:
        analysis["overall_risk"] = "GOOD"
    vc = s["vulnerability_count"]
    rk = {"HIGH": "높음", "MEDIUM": "중간", "LOW": "낮음", "GOOD": "양호"}.get(analysis["overall_risk"], "")
    if vc == 0:
        analysis["overall_summary"] = "점검 항목에서 취약점이 발견되지 않았습니다. 보안 상태가 양호합니다."
    else:
        hi = by_sev.get("Critical", 0) + by_sev.get("High", 0)
        analysis["overall_summary"] = (
            f"전체 보안 위험도 {rk}. {vc}개 취약점 발견"
            + (f" (HIGH {hi}개 포함)" if hi else "")
            + f". 공격 표면 {s.get('attack_surface_count', 0)}건, 참고 {s.get('discovery_count', 0)}건 확인.")


def _harvest_jwt_texts(host_results: list) -> list[str]:
    """일반 크롤 산출물(쿠키 raw·응답 헤더값·URL)에서 JWT 후보 텍스트를 수집한다.
    기존엔 JWT 입력이 브라우저 발견 워커(기본 OFF)에서만 와서 사실상 휴면이었던 문제 보정.
    jwt_analyzer.analyze 가 텍스트에서 JWT 를 추출하므로 원문 문자열을 그대로 넘긴다."""
    texts: list[str] = []
    for hr in host_results or []:
        for svc in (hr.get("services") or []):
            hi = svc.get("http_info") or {}
            for ck in (hi.get("cookies") or []):
                if isinstance(ck, dict) and ck.get("raw"):
                    texts.append(str(ck["raw"]))
            for hk, hv in (hi.get("headers") or {}).items():
                # Authorization/Set-Cookie/X-* 등 값에 JWT 가 실릴 수 있음
                if isinstance(hv, str) and "ey" in hv:
                    texts.append(hv)
            if isinstance(hi.get("url"), str):
                texts.append(hi["url"])
    return texts


def _run_source_sqli(source_root: str) -> list[dict]:
    """화이트박스 소스 SQLi 정적 분석을 기본 파이프라인에서 직접 수행하고, analysis findings
    스키마의 취약점 목록으로 변환한다(orchestrator 경로 불필요). 실패 시 빈 목록."""
    try:
        import os as _os
        from source_sqli_analyzer import analyze_source_tree as _ast
    except Exception:
        return []
    if not source_root or not _os.path.exists(source_root):
        return []
    try:
        raw = _ast(source_root) or []
    except Exception:
        return []
    _title_map = {
        "filter_transform_mismatch": "필터 우회 SQL 인젝션 — 변환 불일치(화이트박스)",
        "bytes_repr_injection": "SQL 인젝션 — bytes/digest repr 삽입(화이트박스)",
        "dynamic_sql": "동적 SQL 구성 — 파라미터화 미적용(화이트박스)",
    }
    out: list[dict] = []
    for f in raw:
        try:
            loc = f"{f.file}:{f.line}"
            out.append({
                "host": "", "port": 0, "service": "source",
                "judgment": "취약", "severity": (f.severity or "HIGH"),
                "confidence": (f.confidence or "CONFIRMED"),
                "owasp": (f.owasp or "A03:2021 - 인젝션"), "cwe": (f.cwe or "CWE-89"),
                "title": _title_map.get(f.kind, "SQL 인젝션(소스 분석)"),
                "description": ("소스코드 정적 분석에서 사용자 입력이 파라미터화 없이 SQL 쿼리에 "
                                "삽입되는 경로가 확인되었습니다(화이트박스)."),
                "evidence_url": "", "affected_endpoint": loc,
                "evidence_detail": (
                    f"[{loc}] {getattr(f, 'snippet', '')}\n싱크: {getattr(f, 'sink', '')} | "
                    f"입력: {getattr(f, 'taint_source', '') or getattr(f, 'param', '') or '(정적)'}"
                    + (f" | 변환: {f.transform}" if getattr(f, 'transform', '') else "")
                    + (f" | 필터: {f.filter_applied}()" if getattr(f, 'filter_applied', '') else "")),
                "recommendation": (getattr(f, "recommendation", "")
                                   or "파라미터화 쿼리(Prepared Statement) 사용, 입력 검증."),
                "finding_type": "vulnerability", "scan_category": "source",
                "tags": ["whitebox", "source", "sqli", f.kind],
            })
        except Exception:
            continue
    return out


def _consolidate_service_version_items(items: list) -> list:
    """'서비스/버전 식별: <label> (포트 N)' 항목을 label 기준 하나로 병합하고 포트를 한 란에 나열."""
    import re as _re
    pat = _re.compile(r"^서비스/버전 식별: (.+) \(포트 (\d+)\)$")
    groups: dict = {}   # label -> {"item": 첫항목, "ports": [..]}
    others: list = []
    for it in (items or []):
        m = pat.match((it or {}).get("title", "") or "") if isinstance(it, dict) else None
        if not m:
            others.append(it)
            continue
        label, port = m.group(1), m.group(2)
        g = groups.setdefault(label, {"item": it, "ports": []})
        if port not in g["ports"]:
            g["ports"].append(port)
    for label, g in groups.items():
        it = dict(g["item"])
        ports = sorted(g["ports"], key=lambda p: int(p))
        it["title"] = f"서비스/버전 식별: {label} (포트 {', '.join(ports)})"
        it["ports"] = ports
        it.pop("port", None)
        others.append(it)
    return others


def _consolidate_version_findings(analysis: dict) -> None:
    """'서비스/버전 식별' LOW 취약점(nmap -sV)을 host+label 기준으로 포트 병합하고, 같은 host 의
    'Server 헤더 버전 정보 노출' finding 과 중복되면(포트가 포함되면) 제거하되 제품/버전 정보를
    그 finding 근거에 보강한다(정보 노출 LOW 를 host 당 1건으로 유지 — 이중 집계 방지)."""
    import re as _re
    findings = analysis.get("findings") or []
    pat = _re.compile(r"^서비스/버전 식별: (.+) \(포트 ([\d, ]+)\)$")

    # Server 헤더 버전 노출 finding: host -> (finding, 포트집합)
    srv_hdr: dict = {}
    for f in findings:
        t = f.get("title", "") or ""
        if "버전 정보 노출" in t and "Server 헤더" in t:
            _ps = set(f.get("affected_ports") or ([f.get("port")] if f.get("port") else []))
            srv_hdr[f.get("host", "")] = (f, {p for p in _ps if p})

    # 서비스/버전 finding 을 host+label 로 묶어 포트 병합
    groups: dict = {}
    version_ids: set = set()
    for f in findings:
        m = pat.match(f.get("title", "") or "")
        if not m or f.get("judgment") != "취약":
            continue
        version_ids.add(id(f))
        label = m.group(1)
        try:
            fports = {int(x) for x in m.group(2).replace(" ", "").split(",") if x}
        except ValueError:
            fports = set()
        if not fports and f.get("port"):
            fports = {f.get("port")}
        g = groups.setdefault((f.get("host", ""), label), {"item": f, "ports": set()})
        g["ports"] |= fports

    kept: list = []
    for (host, label), g in groups.items():
        ports = sorted(g["ports"])
        it = g["item"]
        it["affected_ports"] = ports
        if len(ports) >= 1:
            it["title"] = f"서비스/버전 식별: {label} (포트 {', '.join(str(p) for p in ports)})"
            it["port"] = ports[0]
        # 같은 host 에 Server 헤더 버전 노출 finding 이 있고 포트가 모두 포함되면 → 중복 제거+보강
        hdr = srv_hdr.get(host)
        if hdr and set(ports) <= (hdr[1] or set(ports)):
            _hf = hdr[0]
            _detail = _hf.get("evidence_detail", "") or ""
            _add = f"서비스 배너 식별(nmap -sV): {label} [포트 {', '.join(str(p) for p in ports)}]"
            if _add not in _detail:
                _hf["evidence_detail"] = (_detail + ("\n" if _detail else "") + _add)
            continue   # version finding 은 버림(Server 헤더 finding 으로 통합)
        kept.append(id(it))

    # findings 재구성: 병합으로 사라진 버전 finding 제거(대표 1건만 유지)
    if version_ids:
        new_list = []
        seen_group = set()
        for f in findings:
            if id(f) not in version_ids:
                new_list.append(f)
                continue
            if id(f) in kept and id(f) not in seen_group:
                seen_group.add(id(f))
                new_list.append(f)
        analysis["findings"] = new_list


def _apply_policy_env(config: dict) -> None:
    """점검 정책 config(허용 env 키)를 프로세스 env 에 즉시 반영한다.
    → 이후 시작되는 스캔이 이 설정을 사용(ScanConfig.from_env/os.getenv 가 실행 시 읽음)."""
    if not isinstance(config, dict):
        return
    for k in POLICY_ENV_KEYS:
        if k in config and config[k] is not None:
            os.environ[k] = str(config[k])


# 보고서 템플릿 옵션 → 보고서 env 매핑
_TEMPLATE_ENV_MAP = {
    "org_name": "REPORT_ORG_NAME",
    "show_ai": "REPORT_SHOW_AI",
    "show_coverage": "REPORT_SHOW_COVERAGE",
    "show_attack_chain": "REPORT_SHOW_ATTACK_CHAIN",
    "show_service_scan": "REPORT_SHOW_SERVICE_SCAN",
    "show_engine_internal": "REPORT_SHOW_ENGINE_INTERNAL",  # 엔진내부/대시보드/개발자부록(기본 숨김)
}


def _template_env(options: dict) -> dict:
    """템플릿 옵션을 보고서 env dict 로 변환(org_name 은 문자열, 나머지는 true/false)."""
    env = {}
    for opt, envk in _TEMPLATE_ENV_MAP.items():
        if opt not in (options or {}):
            continue
        v = options[opt]
        if opt == "org_name":
            env[envk] = str(v)
        else:
            env[envk] = "true" if v else "false"
    return env


async def _apply_active_policy_on_startup():
    try:
        pol = await get_active_policy()
        if pol and pol.get("config"):
            _apply_policy_env(pol["config"])
            print(f"[policy] 활성 정책 적용: {pol.get('name')}")
    except Exception as e:
        print(f"[policy] 활성 정책 적용 실패(무시): {e}")


async def _wsl_keepalive_loop():
    """i7 WSL 상시 깨어있게 유지 — DVWA 타겟·오프로드 워커가 i7 WSL(리눅스) 안에서 돌기 때문에,
    WSL2 가 유휴로 VM 을 종료하면 i7 이 켜져 있어도 Mac 에서 도달 불가(프리뷰/스캔 실패)해진다.
    ssh 로 긴 sleep 세션을 유지·재기동해 백엔드가 도는 동안 WSL 을 항상 깨워둔다.
    I7_KEEPALIVE_ENABLED=false 로 끌 수 있음(기본 ON). 실패는 조용히 재시도."""
    if os.getenv("I7_KEEPALIVE_ENABLED", "true").strip().lower() not in ("1", "true", "yes", "on"):
        return
    host = os.getenv("EGRESS_SSH_HOST", "i7")
    proc = None
    try:
        while True:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ssh", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=30",
                    "-o", "ServerAliveCountMax=3", host, "wsl -d Ubuntu sleep 3300",
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                    stdin=asyncio.subprocess.DEVNULL)
                await proc.wait()          # 55분 만료 또는 연결 끊김까지 대기
            except Exception:
                pass
            await asyncio.sleep(5)          # 재기동 전 짧은 대기
    except asyncio.CancelledError:
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass
        raise


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # 서버 재시작/크래시로 끊긴 'running' 스캔을 'interrupted' 로 정리 → 재개 버튼 노출
    try:
        from database import reconcile_orphan_running_scans
        _orphans = await reconcile_orphan_running_scans()
        if _orphans:
            print(f"[startup] 고아 running 스캔 {len(_orphans)}건 → interrupted 정리: {_orphans}")
    except Exception as _e:
        print(f"[startup] 고아 스캔 정리 실패(무시): {_e}")
    await _apply_active_policy_on_startup()
    # 암호화 저장된 인증 자격증명을 env 로 복원(env 비어있을 때만) — 재시작에도 유지
    try:
        import secrets_store as _ss
        for _name in ("AUTH_PASSWORD", "AUTH_PASSWORD_B"):
            if not os.getenv(_name) and _ss.has_secret(_name):
                _v = _ss.load_secret(_name)
                if _v:
                    os.environ[_name] = _v
    except Exception:
        pass
    task = asyncio.create_task(_scheduler_loop()) if _SCHEDULER_ENABLED else None
    # i7 WSL 상시 킵얼라이브(DVWA 타겟·워커 도달성 유지) — 백엔드 생명주기 동안.
    ka_task = asyncio.create_task(_wsl_keepalive_loop())
    try:
        yield
    finally:
        if task:
            task.cancel()
        ka_task.cancel()


app = FastAPI(
    title="Eoseureum API",
    description="Eoseureum — 보이지 않는 공격 표면을 발견하고 증거 기반으로 위험을 검증하는 "
                "AI 기반 Security Assessment Platform.",
    version="1.0.0",
    lifespan=lifespan,
)

FRONTEND_DIST = pathlib.Path(__file__).parent.parent / "frontend" / "dist"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 사이트 IP 게이트 ──────────────────────────────────────────────────────────
# 미등록 IP는 홈페이지(정적 페이지)조차 못 열게 차단한다. '등록 IP' = 어떤 계정에든 등록된 IP의 합집합
# (+ IP_ALWAYS_ALLOW env). 완전 일치만. localhost 는 항상 허용(서버 복구용). 계정별 로그인 제한은 그 위에 별도.
_IP_UNION_CACHE: dict = {"ts": 0.0, "set": frozenset()}


async def _registered_ip_set() -> frozenset:
    import time as _t
    now = _t.time()
    if now - _IP_UNION_CACHE["ts"] < 5 and _IP_UNION_CACHE["set"]:
        return _IP_UNION_CACHE["set"]
    s = set()
    try:
        for u in await get_all_users():
            for e in re.split(r"[,\s]+", (u.get("allowed_ips") or "")):
                e = e.strip()
                if e:
                    s.add(e)
    except Exception:
        pass
    for e in re.split(r"[,\s]+", os.getenv("IP_ALWAYS_ALLOW", "")):
        e = e.strip()
        if e:
            s.add(e)
    _IP_UNION_CACHE.update(ts=now, set=frozenset(s))
    return _IP_UNION_CACHE["set"]


@app.middleware("http")
async def _ip_site_gate(request: Request, call_next):
    ip = (request.client.host if request.client else "") or ""
    if os.getenv("TRUST_XFF", "false").strip().lower() in ("1", "true", "yes"):
        xff = request.headers.get("x-forwarded-for")
        if xff:
            ip = xff.split(",")[0].strip()
    # 서버 로컬/테스트는 항상 통과(복구용)
    if ip in ("127.0.0.1", "::1", "", "localhost", "testclient"):
        return await call_next(request)
    reg = await _registered_ip_set()
    if ip not in reg:                       # 어떤 계정에도 등록되지 않은 IP → 홈페이지 자체 차단
        # 정보 최소화: 서비스명·IP·차단 방식 노출 안 함. 일반 403 만.
        accept = (request.headers.get("accept") or "").lower()
        if request.url.path.startswith("/api/") or "application/json" in accept:
            return JSONResponse(status_code=403, content={"detail": "Forbidden"})
        return HTMLResponse(_ip_blocked_page(), status_code=403)
    return await call_next(request)


def _ip_blocked_page() -> str:
    """미등록 IP 차단 페이지 — 최소 정보만(서비스명·IP·차단방식 비노출)."""
    return """<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>403 Forbidden</title>
<style>
 :root{color-scheme:light dark}
 html,body{height:100%;margin:0}
 body{display:flex;align-items:center;justify-content:center;
  font-family:system-ui,"맑은 고딕","Malgun Gothic",sans-serif;background:#0b1220;color:#94a3b8}
 .box{text-align:center}
 .code{font-size:56px;font-weight:800;color:#e2e8f0;letter-spacing:.02em}
 .msg{margin-top:8px;font-size:15px}
</style></head><body>
 <div class="box"><div class="code">403</div><div class="msg">접근할 수 없습니다.</div></div>
</body></html>"""


def _client_ip(request: Request | None) -> str:
    """클라이언트 IP. 기본은 TCP 연결 IP(위조 불가). 신뢰 프록시 뒤면 TRUST_XFF=true 로 X-Forwarded-For 사용."""
    if request is None:
        return ""
    if os.getenv("TRUST_XFF", "false").strip().lower() in ("1", "true", "yes"):
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)) -> dict:
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = await get_user_by_id(int(payload["sub"]))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    # 사용자별 접근 허용 IP 강제 — 등록 IP와 다르거나(미등록=빈 값 포함) 맞지 않으면 차단.
    # 예외 IP(localhost/IP_ALWAYS_ALLOW)만 통과.
    if not ip_allowed(_client_ip(request), user.get("allowed_ips") or ""):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="허용되지 않은 IP에서의 접근입니다.")
    return user


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    return user


# ── Auth routes ──────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends()):
    user = await get_user_by_username(form.username)
    if not user or not verify_password(form.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="아이디 또는 비밀번호가 올바르지 않습니다.")
    # 접근 허용 IP 강제 — 로그인 단계에서 차단(허용 IP 밖이면 토큰 발급 안 함).
    # PC IP 가 등록 IP 와 다르면(또는 미등록=빈 값) 로그인 불가. 예외 IP(localhost/IP_ALWAYS_ALLOW)만 통과.
    if not ip_allowed(_client_ip(request), user.get("allowed_ips") or ""):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="허용되지 않은 IP에서의 접근입니다. 관리자에게 문의하세요.")
    token = create_token(user["id"], user["username"], user["role"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "can_scan": bool(user["can_scan"]),
        },
    }


@app.get("/api/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "can_scan": bool(user["can_scan"]),
    }


# ── User management (admin only) ─────────────────────────────────────────────

class CreateUserBody(BaseModel):
    username: str
    password: str
    role: str = "user"
    can_scan: bool = True
    scan_quota: int = 0          # 총 스캔 쿼터(0 = 무제한). 관리자만 부여.
    max_concurrent_scans: int = 0  # 동시 스캔 제한(0 = 전역 기본값). 관리자는 항상 무제한.
    allowed_ips: str = ""        # 접근 허용 IP/CIDR(콤마·줄바꿈 구분). 빈값=제한 없음.


class UpdateUserBody(BaseModel):
    role: str | None = None
    can_scan: bool | None = None
    password: str | None = None
    scan_quota: int | None = None
    max_concurrent_scans: int | None = None
    allowed_ips: str | None = None


@app.get("/api/users")
async def list_users(admin: dict = Depends(require_admin)):
    users = await get_all_users()
    for u in users:                       # 쿼터 사용량(보유 스캔 수) 첨부 — 관리 UI 표시용
        u["scans_used"] = await count_user_scans(u["id"])
    return users


@app.post("/api/users", status_code=201)
async def add_user(body: CreateUserBody, admin: dict = Depends(require_admin)):
    existing = await get_user_by_username(body.username)
    if existing:
        raise HTTPException(status_code=409, detail="이미 존재하는 아이디입니다.")
    # 접근 허용 IP 필수 — IP 없이는 계정을 만들 수 없다(빈 값=전부 차단 정책과 일관).
    if not (body.allowed_ips or "").strip():
        raise HTTPException(status_code=400, detail="접근 허용 IP를 입력해야 사용자를 생성할 수 있습니다.")
    user = await create_user(body.username, body.password, body.role, body.can_scan,
                             scan_quota=body.scan_quota,
                             max_concurrent_scans=body.max_concurrent_scans,
                             allowed_ips=body.allowed_ips)
    return user


# 보호 슈퍼관리자 계정(기본 admin) — 본인만 수정/삭제 가능, 다른 admin 은 차단.
_SUPERADMIN_USERNAME = (os.getenv("SUPERADMIN_USERNAME", "admin") or "admin").strip().lower()


def _guard_protected_account(admin: dict, target: dict) -> None:
    """보호 슈퍼관리자 계정은 '본인'만 수정/삭제할 수 있다(다른 관리자 차단)."""
    tgt = (target.get("username") or "").strip().lower()
    act = (admin.get("username") or "").strip().lower()
    if tgt == _SUPERADMIN_USERNAME and act != _SUPERADMIN_USERNAME:
        raise HTTPException(status_code=403,
                            detail="이 계정은 본인만 수정/삭제할 수 있습니다.")


@app.patch("/api/users/{user_id}")
async def edit_user(user_id: int, body: UpdateUserBody, admin: dict = Depends(require_admin)):
    target = await get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")
    _guard_protected_account(admin, target)   # admin 는 본인만 수정 가능
    updated = await update_user(user_id, role=body.role, can_scan=body.can_scan,
                                password=body.password, scan_quota=body.scan_quota,
                                max_concurrent_scans=body.max_concurrent_scans,
                                allowed_ips=body.allowed_ips)
    return updated


@app.delete("/api/users/{user_id}", status_code=204)
async def remove_user(user_id: int, admin: dict = Depends(require_admin)):
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="자신의 계정은 삭제할 수 없습니다.")
    target = await get_user_by_id(user_id)
    if target:
        _guard_protected_account(admin, target)   # admin 는 다른 admin 이 삭제 불가
    await delete_user(user_id)


# ── Domain Watchlist ─────────────────────────────────────────────────────────

class WatchlistBody(BaseModel):
    domain: str
    description: str = ""
    notes: str = ""
    scan_day: int = 1        # 월 중 점검 일자(1~31)
    scan_months: int = 0     # 점검 주기(개월). 0=수동
    scan_time: str = "03:00"
    enabled: bool = False
    # 등록 대상(URL)별 스캔 설정 — 위저드 프리필용(비밀번호 미저장)
    exclude_urls: list[str] = []
    time_budget_minutes: int = 0
    login_url: str = ""
    login_username: str = ""
    login_password: str = ""       # 저장 시 Fernet 암호화(at-rest). 응답엔 has_login_password 플래그만.
    update_schedule: bool = True   # False = 새 스캔에서의 등록(스케줄 보존, 설정만 갱신)


class WatchlistUpdateBody(BaseModel):
    description: str | None = None
    notes: str | None = None
    scan_cycle: str | None = None   # manual | weekly | monthly | quarterly
    scan_time: str | None = None    # "HH:MM"
    enabled: bool | None = None
    scan_day: int | None = None     # 월 중 점검 일자(1~31)
    scan_months: int | None = None  # 점검 주기(개월)


class PolicyBody(BaseModel):
    name: str
    description: str = ""
    config: dict = {}


class PolicyUpdateBody(BaseModel):
    name: str | None = None
    description: str | None = None
    config: dict | None = None


class TemplateBody(BaseModel):
    name: str
    description: str = ""
    options: dict = {}


class TemplateUpdateBody(BaseModel):
    name: str | None = None
    description: str | None = None
    options: dict | None = None


@app.get("/api/watchlist")
async def list_watchlist(user: dict = Depends(get_current_user)):
    items = await get_watchlist(user["id"], user["role"])
    enriched = []
    for item in items:
        history = await get_domain_scan_history(item["domain"], user["id"], user["role"], limit=1)
        last = history[0] if history else None
        try:
            _excl = _json.loads(item.get("exclude_urls") or "[]")
        except Exception:
            _excl = []
        enriched.append({
            **item,
            "exclude_urls": _excl,   # JSON 문자열 → 배열
            "last_scan": last["created_at"] if last else None,
            "last_risk": last["analysis"]["overall_risk"] if last and last.get("analysis") else None,
            "scan_count": await count_domain_scans(item["domain"], user["id"], user["role"]),
        })
    return enriched



@app.post("/api/watchlist", status_code=201)
async def add_watchlist(body: WatchlistBody, user: dict = Depends(get_current_user)):
    domain = body.domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
    try:
        item = await add_to_watchlist(
            domain, user["id"], body.description, body.notes,
            scan_day=max(1, min(31, int(body.scan_day or 1))),
            scan_months=max(0, int(body.scan_months or 0)),
            scan_time=body.scan_time or "03:00", enabled=bool(body.enabled),
            exclude_urls=[str(u).strip() for u in (body.exclude_urls or []) if str(u).strip()][:500],
            time_budget_minutes=max(0, min(int(body.time_budget_minutes or 0), 2880)),
            login_url=(body.login_url or "").strip(), login_username=(body.login_username or "").strip(),
            login_password=(body.login_password or ""),   # 비어있지 않을 때만 암호화 저장(기존 보존)
            update_schedule=bool(body.update_schedule),
        )
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return item


@app.patch("/api/watchlist/{item_id}")
async def update_watchlist(item_id: int, body: WatchlistUpdateBody, user: dict = Depends(get_current_user)):
    item = await get_watchlist_item(item_id, user["id"], user["role"])
    if not item:
        raise HTTPException(status_code=404)
    # 점검 주기 값 검증(허용된 값만)
    if body.scan_cycle is not None and body.scan_cycle not in ("manual", "weekly", "monthly", "quarterly"):
        raise HTTPException(status_code=400, detail="invalid scan_cycle")
    return await update_watchlist_item(
        item_id, body.description, body.notes,
        scan_cycle=body.scan_cycle, scan_time=body.scan_time, enabled=body.enabled,
        scan_day=body.scan_day, scan_months=body.scan_months,
    )


@app.delete("/api/watchlist/{item_id}", status_code=204)
async def remove_watchlist(item_id: int, user: dict = Depends(get_current_user)):
    item = await get_watchlist_item(item_id, user["id"], user["role"])
    if not item:
        raise HTTPException(status_code=404)
    await delete_watchlist_item(item_id)


@app.get("/api/watchlist/{item_id}/history")
async def watchlist_history(item_id: int, user: dict = Depends(get_current_user)):
    item = await get_watchlist_item(item_id, user["id"], user["role"])
    if not item:
        raise HTTPException(status_code=404)
    # 정기 스캔 페이지의 이력 → 예약(정기) 스캔만 표시(새 스캔 이력 제외)
    return await get_domain_scan_history(item["domain"], user["id"], user["role"], limit=20, scheduled_only=True)


# ── Scan history ──────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats(user: dict = Depends(get_current_user)):
    from collections import Counter, defaultdict
    import json as _json

    scans = await get_scans_for_user(user["id"], user["role"])
    complete = [s for s in scans if s["status"] == "complete"]

    risk_dist: Counter = Counter()
    vuln_titles: Counter = Counter()
    vuln_services: Counter = Counter()
    open_ports: Counter = Counter()
    daily: defaultdict = defaultdict(int)
    user_counts: Counter = Counter()

    total_vulns = 0
    high_count = 0

    for s in complete:
        risk = (s.get("analysis") or {}).get("overall_risk")
        if risk:
            risk_dist[risk] += 1
            if risk == "HIGH":
                high_count += 1

        date_str = (s.get("created_at") or "")[:10]
        if date_str:
            daily[date_str] += 1

        uname = s.get("username", "unknown")
        user_counts[uname] += 1

        findings = (s.get("analysis") or {}).get("findings", [])
        for f in findings:
            if f.get("judgment") == "취약":
                total_vulns += 1
                if f.get("title"):
                    vuln_titles[f["title"]] += 1
                if f.get("service"):
                    vuln_services[f["service"]] += 1

        results = s.get("results") or []
        for host in results:
            for p in (host.get("open_ports") or []):
                open_ports[str(p)] += 1

    from datetime import date, timedelta
    today = date.today()
    timeline = []
    for i in range(29, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        timeline.append({"date": d, "count": daily.get(d, 0)})

    unique_domains = len({s["domain"] for s in complete})

    return {
        "summary": {
            "total_scans": len(complete),
            "unique_domains": unique_domains,
            "total_vulnerabilities": total_vulns,
            "high_risk_count": high_count,
        },
        "risk_distribution": dict(risk_dist),
        "timeline": timeline,
        "top_vuln_titles": [{"title": t, "count": c} for t, c in vuln_titles.most_common(10)],
        "top_vuln_services": [{"service": s, "count": c} for s, c in vuln_services.most_common(10)],
        "top_open_ports": [{"port": p, "count": c} for p, c in open_ports.most_common(10)],
        "user_activity": [{"username": u, "count": c} for u, c in user_counts.most_common()] if user["role"] == "admin" else [],
    }


@app.get("/api/scans")
async def scan_history(user: dict = Depends(get_current_user)):
    scans = await get_scans_for_user(user["id"], user["role"])
    # 스캔 #순번: 생성 시각 오름차순으로 1..N 안정 부여(가장 오래된 = #1). 목록 정렬과 무관하게 표시용.
    _ordered = sorted(scans, key=lambda s: (s.get("created_at") or "", str(s.get("scan_id") or "")))
    _seq = {s["scan_id"]: i + 1 for i, s in enumerate(_ordered)}
    out = []
    for s in scans:
        analysis = s.get("analysis") or {}
        summary = analysis.get("summary") or {}
        item = {
            "scan_id": s["scan_id"],
            "seq": _seq.get(s["scan_id"]),
            "domain": s["domain"],
            "status": s["status"],
            "username": s.get("username"),
            "created_at": s["created_at"],
            "overall_risk": analysis.get("overall_risk") if analysis else None,
            # 완료 스캔의 요약 카운트(이력 목록에서 바로 보이도록)
            "vulnerability_count": summary.get("vulnerability_count"),
            "web_vulnerability_count": summary.get("web_vulnerability_count"),
            "service_vulnerability_count": summary.get("service_vulnerability_count"),
            "attack_surface_count": summary.get("attack_surface_count"),
            "discovery_count": summary.get("discovery_count"),
        }
        # 진행 중 스캔이면 실시간 진행 상태 첨부
        if s["status"] == "running":
            item["progress"] = SCAN_PROGRESS.get(s["scan_id"])
        out.append(item)
    return out


class ScanPreviewBody(BaseModel):
    url: str


class TriageBody(BaseModel):
    # 취약점 오탐 트리아지 상태. 허용값: "open" | "false_positive" | "accepted_risk"
    status: str


_PREVIEW_LINK_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_PREVIEW_RAWURL_RE = re.compile(r'https?://[^\s"\'<>)\]]+', re.IGNORECASE)
_PREVIEW_PAGELIKE = (".html", ".htm", ".jsp", ".php", ".aspx", ".asp", "/")


@app.post("/api/scan/preview")
async def scan_preview(body: ScanPreviewBody, user: dict = Depends(get_current_user)):
    """타겟에서 함께 확인되는 URL을 넉넉히(~9초) 수집해 **오리진(도메인) 단위**로 묶어 반환한다.
    홈페이지 + robots.txt + sitemap.xml + 동일 출처 1레벨 크롤로 링크를 모으고, 오리진별로 집계.
    (마법사 스캔범위 단계용 — 사용자가 스캔할 도메인을 고르면 그 오리진 하부만 점검)."""
    import aiohttp as _ah
    import urllib.parse
    import time as _t
    from collections import defaultdict as _dd
    raw = (body.url or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="url 이 필요합니다")
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = "http://" + raw
    base = urllib.parse.urlparse(raw)
    base_host = base.netloc
    base_origin = f"{base.scheme}://{base_host}"
    deadline = _t.time() + 9.0
    all_urls: set[str] = set()

    # P4: 프리뷰는 per-scan 거버너 이전에 실행되므로 '독립' SAFE 리미터(5rps/단독)로 페이싱
    # (마법사 URL 수집도 대상 서버에 요청을 보내므로 버스트 방지). env EOSEUREUM_SAFE_MAX_RPS 로 조절.
    import adaptive_throttle as _agov
    _plim = _agov.AdaptiveThrottle("conservative", concurrency=1, hard_cap=True, label="preview")

    async def _fetch(sess, url):
        await _plim.before()
        _pt0 = _t.monotonic()
        _pst = 0
        try:
            async with sess.get(url, timeout=_ah.ClientTimeout(total=6), ssl=False,
                                allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (Eoseureum Scanner)"}) as r:
                _pst = r.status
                ct = (r.headers.get("Content-Type") or "").lower()
                if ("html" in ct or "xml" in ct or "text" in ct or ct == ""
                        or url.endswith((".xml", ".txt"))):
                    return await r.text(errors="ignore")
        except Exception:
            return ""
        finally:
            _plim.after(_t.monotonic() - _pt0, _pst, None)
        return ""

    def _extract(text, from_url):
        if not text:
            return
        for m in _PREVIEW_LINK_RE.finditer(text):
            try:
                u = urllib.parse.urljoin(from_url, m.group(1))
            except Exception:
                continue
            p = urllib.parse.urlparse(u)
            if p.scheme in ("http", "https"):
                all_urls.add(u.split("#")[0])
        # robots/sitemap 등 원문 URL 도 수집
        for m in _PREVIEW_RAWURL_RE.finditer(text):
            all_urls.add(m.group(0).split("#")[0])

    reachable = False
    home_status = None
    try:
        async with _ah.ClientSession() as sess:
            # 1) 대상 홈 — 도달성(상태코드) 우선 확인 후 링크 추출(독립 리미터 페이싱)
            await _plim.before()
            _ph0 = _t.monotonic()
            _phst = 0
            try:
                async with sess.get(raw, timeout=_ah.ClientTimeout(total=6), ssl=False,
                                    allow_redirects=True,
                                    headers={"User-Agent": "Mozilla/5.0 (Eoseureum Scanner)"}) as r0:
                    reachable = True
                    home_status = r0.status
                    _phst = r0.status
                    ct = (r0.headers.get("Content-Type") or "").lower()
                    if "html" in ct or "xml" in ct or "text" in ct or ct == "":
                        _extract(await r0.text(errors="ignore"), str(r0.url))
            except Exception:
                reachable = False
            finally:
                _plim.after(_t.monotonic() - _ph0, _phst, None)
            # 2) robots.txt / sitemap.xml
            seeds = [urllib.parse.urljoin(base_origin, "/robots.txt"),
                     urllib.parse.urljoin(base_origin, "/sitemap.xml")]
            for txt, src in zip(await asyncio.gather(*[_fetch(sess, u) for u in seeds]), seeds):
                _extract(txt, src)
            # 3) 동일 출처 '페이지형' 링크를 1레벨 더 크롤(시간 예산 내)
            same = [u for u in all_urls
                    if urllib.parse.urlparse(u).netloc == base_host
                    and urllib.parse.urlparse(u).path.lower().endswith(_PREVIEW_PAGELIKE)]
            same = sorted(same)[:14]
            if same and _t.time() < deadline:
                for txt, src in zip(await asyncio.gather(*[_fetch(sess, u) for u in same]), same):
                    _extract(txt, src)
    except Exception as e:
        return {"base_origin": base_origin, "origins": [], "urls": [], "count": 0,
                "reachable": False, "error": f"미리보기 실패: {type(e).__name__}"}

    # 대상에 아예 연결되지 않았고 수집된 URL 도 없으면 명확히 오류로 안내(링크 0개와 구분)
    if not reachable and not all_urls:
        return {"base_origin": base_origin, "origins": [], "urls": [], "count": 0,
                "reachable": False,
                "error": "대상에 연결할 수 없습니다. URL·포트·프로토콜(http/https)·네트워크(방화벽)를 확인하세요."}

    by_origin: dict = _dd(list)
    for u in all_urls:
        p = urllib.parse.urlparse(u)
        by_origin[f"{p.scheme}://{p.netloc}"].append(u)
    # 오리진 목록 — 대상 오리진을 맨 앞, 나머지는 URL 많은 순
    origins = sorted(
        [{"origin": o, "count": len(us), "sample": sorted(us)[:5]} for o, us in by_origin.items()],
        key=lambda d: (d["origin"] != base_origin, -d["count"], d["origin"]),
    )
    # 대상 오리진은 링크가 발견되지 않아도 항상 선택 가능하게 포함
    # (SPA·JS 렌더링·로그인 전용·링크 희소 사이트 → 대상 자체는 반드시 점검 가능해야 함)
    if not any(o["origin"] == base_origin for o in origins):
        origins.insert(0, {"origin": base_origin, "count": 0, "sample": [raw]})
    return {"base_origin": base_origin, "origins": origins,
            "urls": sorted(all_urls)[:400], "count": len(all_urls),
            "reachable": reachable}


@app.post("/api/scans/{scan_id}/recover")
async def recover_scan_endpoint(scan_id: str, user: dict = Depends(get_current_user)):
    """중단(interrupted/failed/stopped)된 스캔을 체크포인트에서 이어받아 재개한다.
    (참고: /resume 는 '일시정지된 진행 중 스캔'을 다시 시작하는 별개 기능)"""
    rec = await get_scan_record(scan_id)
    if not rec:
        raise HTTPException(status_code=404, detail="스캔을 찾을 수 없습니다")
    if user["role"] != "admin" and rec.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="권한이 없습니다")
    if rec.get("status") == "running":
        raise HTTPException(status_code=409, detail="이미 진행 중인 스캔입니다")
    if rec.get("status") == "complete":
        raise HTTPException(status_code=400, detail="이미 완료된 스캔입니다")
    ckpt = await load_checkpoint(scan_id)
    if not ckpt:
        raise HTTPException(status_code=400,
                            detail="재개할 체크포인트가 없습니다 — 처음부터 새로 스캔하세요")
    owner = await get_user_by_id(rec.get("user_id"))
    orole = owner["role"] if owner else "user"
    _uid = rec.get("user_id")

    # 동시 스캔 한도 확인(소유자 기준). HTTP 라 대기 불가 → 초과 시 거부(WS 는 대기열).
    _lim = _effective_concurrency_limit({"role": orole, "id": _uid})
    if _lim is not None and RUNNING_BY_USER.get(_uid, 0) >= _lim:
        raise HTTPException(status_code=429,
                            detail=f"동시 실행 한도({_lim}개) 초과 — 진행 중 스캔이 끝난 뒤 재개하세요")

    # 슬롯 확보(동시성 집계) + running 표시
    RUNNING_BY_USER[_uid] = RUNNING_BY_USER.get(_uid, 0) + 1
    await update_scan_record(scan_id, "running")

    # 예산 복원 — 체크포인트에 budget_min 이 있으면 깊이 스케일·자동중지 재적용(없으면 예산 없이 완주)
    try:
        _bud = int(ckpt.get("budget_min") or 0)
    except (TypeError, ValueError):
        _bud = 0
    if _bud > 0:
        import time as _tb
        SCAN_BUDGET[scan_id] = {"total_min": _bud, "deadline_ts": _tb.time() + _bud * 60}
        SCAN_DEADLINE[scan_id] = asyncio.create_task(_auto_stop_after(scan_id, _bud))

    # 관리 래퍼로 실행 + SCAN_TASKS 등록 → 취소 가능·동시성 집계·부분보고·상태정리 보장(고스트 스캔 방지)
    task = asyncio.create_task(
        _run_managed_scan(_HeadlessWS(), rec.get("domain"), scan_id, _uid, orole,
                          resume_ckpt=ckpt))
    SCAN_TASKS[scan_id] = task
    return {"ok": True, "scan_id": scan_id, "resumed_from_stage": ckpt.get("stage")}


@app.get("/api/techstack")
async def techstack(user: dict = Depends(get_current_user)):
    """수집된 기술 스택(fingerprint + nmap -sV + adaptive_recon)을 조회한다.

    데이터가 없으면 빈 items 와 0 요약을 반환한다(500 금지). 시크릿/계정 미노출.
    """
    try:
        scans = await get_scans_for_user(user["id"], user["role"])
        import inventory
        return inventory.build_techstack(scans)
    except Exception:
        return {"items": [], "summary": {
            "total_hosts": 0, "total_technologies": 0,
            "high_confidence": 0, "medium_confidence": 0, "low_confidence": 0,
        }}


@app.get("/api/reports")
async def reports(user: dict = Depends(get_current_user)):
    """생성 가능한 보고서 목록을 스캔 이력 기반으로 반환한다(기존 export API 재사용)."""
    try:
        scans = await get_scans_for_user(user["id"], user["role"])
        import inventory
        return inventory.build_report_list(scans)
    except Exception:
        return {"items": [], "summary": {
            "total_reports": 0, "high_risk_reports": 0, "latest_report_at": "-",
        }}


# ── 정책 및 템플릿 (Scan Policy / Report Template) ──────────────────────────────
@app.get("/api/policies")
async def api_list_policies(user: dict = Depends(get_current_user)):
    return {"items": await list_policies(), "env_keys": list(POLICY_ENV_KEYS)}


@app.post("/api/policies", status_code=201)
async def api_create_policy(body: PolicyBody, user: dict = Depends(require_admin)):
    return await create_policy(body.name, body.description, body.config)


@app.patch("/api/policies/{policy_id}")
async def api_update_policy(policy_id: int, body: PolicyUpdateBody, user: dict = Depends(require_admin)):
    item = await update_policy(policy_id, body.name, body.description, body.config)
    if not item:
        raise HTTPException(status_code=404)
    # 활성 정책을 수정한 경우 즉시 env 재적용
    if item.get("is_active"):
        _apply_policy_env(item.get("config") or {})
    return item


@app.delete("/api/policies/{policy_id}", status_code=204)
async def api_delete_policy(policy_id: int, user: dict = Depends(require_admin)):
    pol = await get_policy(policy_id)
    if not pol:
        raise HTTPException(status_code=404)
    if pol.get("builtin"):
        raise HTTPException(status_code=400, detail="내장 정책은 삭제할 수 없습니다.")
    if pol.get("is_active"):
        raise HTTPException(status_code=400, detail="활성 정책은 삭제할 수 없습니다. 먼저 다른 정책을 활성화하세요.")
    await delete_policy(policy_id)


@app.post("/api/policies/{policy_id}/activate")
async def api_activate_policy(policy_id: int, user: dict = Depends(require_admin)):
    pol = await set_active_policy(policy_id)
    if not pol:
        raise HTTPException(status_code=404)
    _apply_policy_env(pol.get("config") or {})   # 즉시 라이브 반영
    return pol


@app.get("/api/templates")
async def api_list_templates(user: dict = Depends(get_current_user)):
    return {"items": await list_templates(), "option_keys": list(_TEMPLATE_ENV_MAP.keys())}


@app.post("/api/templates", status_code=201)
async def api_create_template(body: TemplateBody, user: dict = Depends(require_admin)):
    return await create_template(body.name, body.description, body.options)


@app.patch("/api/templates/{template_id}")
async def api_update_template(template_id: int, body: TemplateUpdateBody, user: dict = Depends(require_admin)):
    item = await update_template(template_id, body.name, body.description, body.options)
    if not item:
        raise HTTPException(status_code=404)
    return item


@app.delete("/api/templates/{template_id}", status_code=204)
async def api_delete_template(template_id: int, user: dict = Depends(require_admin)):
    tpl = await get_template(template_id)
    if not tpl:
        raise HTTPException(status_code=404)
    if tpl.get("builtin"):
        raise HTTPException(status_code=400, detail="내장 템플릿은 삭제할 수 없습니다.")
    if tpl.get("is_default"):
        raise HTTPException(status_code=400, detail="기본 템플릿은 삭제할 수 없습니다. 먼저 다른 템플릿을 기본으로 지정하세요.")
    await delete_template(template_id)


@app.post("/api/templates/{template_id}/default")
async def api_set_default_template(template_id: int, user: dict = Depends(require_admin)):
    tpl = await set_default_template(template_id)
    if not tpl:
        raise HTTPException(status_code=404)
    return tpl


# 인증 정보는 전역 저장 대신 스캔 시작 시 per-scan 으로 받는다(run_scan.scan_auth).
# 예약/헤드리스 스캔은 AUTH_* 서버 env 를 폴백으로 사용(probe_policy.auth_crawl_config).


@app.get("/api/scans/{scan_id}")
async def scan_detail(scan_id: str, user: dict = Depends(get_current_user)):
    scan = await get_scan_record(scan_id)
    if not scan:
        raise HTTPException(status_code=404)
    if user["role"] != "admin" and scan["user_id"] != user["id"]:
        raise HTTPException(status_code=403)
    # 상세에도 #순번(seq) 부여 — 목록과 동일 규칙·스코프(조회 사용자 기준, 생성 시각 오름차순 1..N).
    try:
        _all = await get_scans_for_user(user["id"], user["role"])
        _ordered = sorted(_all, key=lambda s: (s.get("created_at") or "", str(s.get("scan_id") or "")))
        for i, s in enumerate(_ordered):
            if s.get("scan_id") == scan_id:
                scan = {**scan, "seq": i + 1}
                break
    except Exception:
        pass
    # 대기 스캔 '설정 수정' 프리필용 — 저장된 제출 설정을 config 로 노출(비밀번호 미포함).
    _cfg = scan.pop("scan_config", None)
    if isinstance(_cfg, dict):
        scan["config"] = _cfg
    return scan


_TRIAGE_STATES = ("open", "false_positive", "accepted_risk")


@app.patch("/api/scans/{scan_id}/findings/{finding_uid}/triage")
async def triage_finding(scan_id: str, finding_uid: str, body: TriageBody,
                         user: dict = Depends(get_current_user)):
    """취약점(finding)에 오탐 트리아지 상태를 부여한다. false_positive 는 점수/심각도 집계에서
    제외되도록 _fp_suppressed 플래그를 세운다. 판정(룰 엔진 결과)은 보존하고 사용자 표시만 갱신."""
    status = body.status
    if status not in _TRIAGE_STATES:
        raise HTTPException(status_code=422,
                            detail=f"status must be one of {_TRIAGE_STATES}")
    scan = await get_scan_record(scan_id)
    if not scan:
        raise HTTPException(status_code=404)
    if user["role"] != "admin" and scan["user_id"] != user["id"]:
        raise HTTPException(status_code=403)

    # analysis 는 get_scan_record 에서 dict 로 파싱되지만, 문자열로 남아있을 수 있어 방어적으로 처리.
    analysis = scan.get("analysis")
    if isinstance(analysis, str):
        try:
            analysis = json.loads(analysis)
        except Exception:
            analysis = {}
    if not isinstance(analysis, dict):
        analysis = {}

    findings = analysis.get("findings")
    if not isinstance(findings, list):
        findings = []

    target = None
    for f in findings:
        if isinstance(f, dict) and str(f.get("finding_uid")) == str(finding_uid):
            target = f
            break
    if target is None:
        raise HTTPException(status_code=404, detail="finding not found")

    target["user_triage"] = status
    target["_fp_suppressed"] = (status == "false_positive")

    # 기존 status/results 를 보존한 채 analysis 만 갱신 저장(results 미전달 시 소실됨에 주의).
    await update_scan_record(scan_id, scan["status"],
                             results=scan.get("results"), analysis=analysis)
    return {"ok": True, "finding_uid": finding_uid, "status": status}


@app.post("/api/scans/{scan_id}/stop")
async def stop_scan(scan_id: str, user: dict = Depends(get_current_user)):
    """진행 중인 스캔을 중지한다. 그때까지의 부분 결과로 보고서를 만들고 status='stopped' 로 저장."""
    scan = await get_scan_record(scan_id)
    if not scan:
        raise HTTPException(status_code=404)
    if user["role"] != "admin" and scan["user_id"] != user["id"]:
        raise HTTPException(status_code=403)
    # 대기(queued) 스캔 취소: 아직 시작 전이라 부분 보고서 없음. WS 대기 루프가 SCAN_CANCEL 을
    # 보고 스스로 종료한다. WS 핸들이 유실됐으면(서버 재시작 등) 여기서 바로 중단 처리.
    if scan["status"] == "queued":
        SCAN_CANCEL[scan_id] = True
        try:
            await update_scan_record(scan_id, "stopped")
        except Exception:
            pass
        return {"status": "cancelled", "scan_id": scan_id}
    if scan["status"] != "running":
        return {"status": scan["status"], "message": "진행 중이거나 대기 중인 스캔이 아닙니다."}
    SCAN_CANCEL[scan_id] = True
    task = SCAN_TASKS.get(scan_id)
    if task is not None and not task.done():
        task.cancel()          # 멈춘 스캔도 강제 종료 → 부분 보고서 생성
    else:
        # task 핸들이 없으면(서버 재시작 등으로 유실) 유령 running 레코드를 중단 처리
        try:
            await update_scan_record(scan_id, "stopped")
        except Exception:
            pass
        SCAN_PROGRESS.pop(scan_id, None)
    return {"status": "stopping", "scan_id": scan_id}


@app.post("/api/scans/{scan_id}/pause")
async def pause_scan(scan_id: str, user: dict = Depends(get_current_user)):
    """진행 중인 스캔을 다음 단계 경계에서 일시정지한다(네트워크 활동 중단, 상태 유지)."""
    scan = await get_scan_record(scan_id)
    if not scan:
        raise HTTPException(status_code=404)
    if user["role"] != "admin" and scan["user_id"] != user["id"]:
        raise HTTPException(status_code=403)
    if scan["status"] != "running":
        return {"status": scan["status"], "message": "진행 중인 스캔이 아닙니다."}
    SCAN_PAUSE[scan_id] = True
    # 요청 단위 즉시 반영 — rate 거버너 게이트에 pause 등록(긴 단계 중에도 네트워크 즉시 중단).
    try:
        import adaptive_throttle as _thrp
        _thrp.pause(scan_id)
    except Exception:
        pass
    _set_progress(scan_id, paused=True, message="일시정지됨 — 진행 중인 요청 완료 후 멈춤")
    return {"status": "pausing", "scan_id": scan_id}


@app.post("/api/scans/{scan_id}/resume")
async def resume_scan(scan_id: str, user: dict = Depends(get_current_user)):
    """일시정지된 스캔을 재개한다."""
    scan = await get_scan_record(scan_id)
    if not scan:
        raise HTTPException(status_code=404)
    if user["role"] != "admin" and scan["user_id"] != user["id"]:
        raise HTTPException(status_code=403)
    SCAN_PAUSE[scan_id] = False
    try:
        import adaptive_throttle as _thrp
        _thrp.resume(scan_id)
    except Exception:
        pass
    _set_progress(scan_id, paused=False, message="재개됨")
    return {"status": "resuming", "scan_id": scan_id}


@app.delete("/api/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, user: dict = Depends(get_current_user)):
    scan = await get_scan_record(scan_id)
    if not scan:
        raise HTTPException(status_code=404)
    if user["role"] != "admin" and scan["user_id"] != user["id"]:
        raise HTTPException(status_code=403)
    await delete_scan_record(scan_id)


@app.get("/api/scans/{scan_id}/export")
async def export_scan(scan_id: str, template_id: int | None = None,
                      format: str = "docx", include: str | None = None,
                      user: dict = Depends(get_current_user)):
    """보고서 다운로드. format=docx(기본)/pdf/html. PDF 변환 불가 시 DOCX 로 폴백.
    include: 보고서에 포함할 취약점(findings) 인덱스 CSV(예 "0,2,5"). 미지정이면 전체."""
    scan = await get_scan_record(scan_id)
    if not scan:
        raise HTTPException(status_code=404)
    if user["role"] != "admin" and scan["user_id"] != user["id"]:
        raise HTTPException(status_code=403)
    if not scan.get("analysis"):
        raise HTTPException(status_code=400, detail="분석 결과가 없는 스캔입니다.")

    # 취약점 선택 필터: findings 를 선택 인덱스만 남긴 얕은 복사본으로 교체(원본 불변).
    # include 파라미터가 '존재'하면(빈 문자열이어도) 필터 적용 — 전체 해제(빈 선택)면 취약점 0건 보고서.
    # (미지정=None 이면 전체 보고서.) 요약 심각도 분포·전체 위험도도 선택분 기준으로 재계산한다.
    if include is not None:
        try:
            _idx = {int(x) for x in include.split(",") if x.strip().lstrip("-").isdigit()}
        except Exception:
            _idx = set()
        _an = dict(scan.get("analysis") or {})
        _findings = _an.get("findings") or []
        _sel = [f for i, f in enumerate(_findings) if i in _idx]
        _an["findings"] = _sel
        _sum = dict(_an.get("summary") or {})
        # 선택분(양호 제외) 기준으로 분포 재집계. by_severity 는 억제 포함(다운스트림 _eff_severity_counts
        # 가 억제분을 차감), 위험도/취약점수는 '표시되는' 유효(억제·양호 제외) 기준으로 산정.
        _sel_ng = [f for f in _sel if f.get("judgment") != "양호"]
        _sum["by_severity"] = count_by_severity(_sel_ng)
        _eff = [f for f in _sel_ng if not f.get("_fp_suppressed")]
        _ebs = count_by_severity(_eff)
        _sum["vulnerability_count"] = len(_eff)
        try:
            _sum["web_vulnerability_count"] = sum(1 for f in _eff if f.get("scan_category") != "service")
            _sum["service_vulnerability_count"] = sum(1 for f in _eff if f.get("scan_category") == "service")
        except Exception:
            pass
        _an["summary"] = _sum
        _an["overall_risk"] = ("HIGH" if (_ebs["Critical"] or _ebs["High"])
                               else "MEDIUM" if _ebs["Medium"]
                               else "LOW" if _ebs["Low"] else "GOOD")
        # 증거 레벨 대시보드는 선택된 findings 로 재유도되도록 비운다(_eff_levels 가 findings 에서 재집계).
        _an["evidence_levels"] = {}
        # 부록 '탐지 커버리지'도 선택 정합: 선택된 취약점과 매칭 안 되는 'confirmed(취약 확인)'·
        # 'possible(가능·검토)' 는 '검사·안전(tested_clean)' 으로 강등 → 선택 안 한 항목은 부록에서도
        # '안전'으로만 표기(선택 0건이면 전부 안전). 이 리포트는 '선택된 취약점만 다루는 문서'이므로,
        # 미선택 항목이 노란 '가능·검토'로 남아 오해를 사지 않게 한다. tested_clean·미도달은 그대로.
        _cov = _an.get("detection_coverage")
        if isinstance(_cov, dict) and isinstance(_cov.get("matrix"), list):
            _keys = set()
            for f in _eff:
                for k in (f.get("family"), f.get("vuln_type"), f.get("cwe"), f.get("title")):
                    if k:
                        _keys.add(str(k).lower())
            _newm = []
            for r in _cov["matrix"]:
                r2 = dict(r)
                if r2.get("status") in ("confirmed", "possible"):
                    _t = str(r2.get("technique") or "").lower()
                    if not (_t and any(_t in k or k in _t for k in _keys)):
                        # 완전 안전화 — status 뿐 아니라 DOCX 표가 읽는 confirmed/possible 카운트도 0으로.
                        r2["confirmed"] = 0
                        r2["possible"] = 0
                        r2["manual_review"] = 0
                        if r2.get("tested"):
                            r2["status"] = "tested_clean"
                            r2["status_label"] = "검사함 · 안전"
                            r2["reason"] = "검사 수행 · 보고서 선택 항목 아님(안전)"
                        else:
                            r2["status"] = "not_reached"
                            r2["status_label"] = "미도달(표면 없음)"
                            r2["reason"] = "해당 입력 표면 미발견(도달 못 함)"
                _newm.append(r2)
            _cov2 = dict(_cov)
            _cov2["matrix"] = _newm
            # 요약 재집계 — HTML(status 기준)·DOCX(techniques_* / total_* 키) 양쪽 일치.
            _cs = dict(_cov2.get("summary") or {})
            _cs["confirmed"] = sum(1 for r in _newm if r.get("status") == "confirmed")
            _cs["possible"] = sum(1 for r in _newm if r.get("status") == "possible")
            _cs["tested_clean"] = sum(1 for r in _newm if r.get("status") == "tested_clean")
            _cs["total_confirmed"] = sum(int(r.get("confirmed") or 0) for r in _newm)
            _cs["total_possible"] = sum(int(r.get("possible") or 0) for r in _newm)
            _cs["techniques_with_findings"] = sum(1 for r in _newm if r.get("confirmed") or r.get("possible"))
            _cs["techniques_tested_clean"] = sum(1 for r in _newm if r.get("status") == "tested_clean")
            _cs["techniques_not_reached"] = sum(1 for r in _newm if r.get("status") == "not_reached")
            _cov2["summary"] = _cs
            _an["detection_coverage"] = _cov2
        # 취약점/증거/익스플로잇에서 '유도된' 대시보드·부록(엔진 내부) 필드는 선택과 어긋나 잔존하면
        # "취약인데 뺀 것"처럼 보인다 → 필터 export 에선 비운다(전체 스캔 스코프/표면/자산/서비스/커버리지
        # 등 '취약점이 아닌' 정보는 유지). 모두 .get() 접근이라 None 이면 렌더러가 빈 것으로 처리.
        for _k in ("evidence_levels", "proof_evidence_cards", "proof_validation", "proof_validation_summary",
                   "business_impact", "business_impact_summary", "service_business_impact",
                   "attack_chains", "attack_paths", "attack_path_summary", "attack_path_graph",
                   "prioritized_paths", "path_priority_summary", "exploit_summary",
                   "priority_action_plan", "remediation_items", "remediation_summary", "service_remediation_plan",
                   "validation_summary", "validation_candidates", "candidate_verification",
                   "service_validation_summary", "service_validation_candidates",
                   "fp_risk_summary", "solver_results", "solver_summary", "service_solver_results",
                   "agent_results", "service_agent_results", "ai_analysis", "ai_payload_plan",
                   "evidence_chains", "evidence_graph_summary", "security_knowledge_graph",
                   "graph_risk_context", "overall_summary"):
            if _k in _an:
                _an[_k] = None
        # 증거 레벨은 findings 에서 재유도되도록 빈 dict(위 None 대신). 유효 findings 로 대시보드 재계산.
        _an["evidence_levels"] = {}
        scan = {**scan, "analysis": _an}

    # 보고서 템플릿 적용: 지정 template_id 또는 기본 템플릿의 옵션을 env 로 변환해
    # 생성 동안만 적용(save/restore — 동시 export 영향 최소화).
    tpl = await get_template(template_id) if template_id else await get_default_template()
    _saved_env = {}
    if tpl and tpl.get("options"):
        for k, v in _template_env(tpl["options"]).items():
            _saved_env[k] = os.environ.get(k)
            os.environ[k] = v

    safe_domain = scan["domain"].replace("/", "_").replace(".", "_")
    date_str = (scan.get("created_at") or "")[:10]
    fmt = (format or "docx").lower()
    _DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

    def _cd(fn):
        return {"Content-Disposition": f"attachment; filename*=UTF-8''{fn}"}

    try:
        # ── HTML: HTML/CSS 기반 Professional Report ──
        if fmt == "html":
            import report_html_renderer as _hr
            data = _hr.generate_html(scan).encode("utf-8")
            fn = f"security_report_{safe_domain}_{date_str}.html"
            return StreamingResponse(io.BytesIO(data), media_type="text/html; charset=utf-8",
                                     headers={**_cd(fn), "X-Report-Format": "html"})

        # ── PDF: HTML(CSS)→PDF 우선, 실패 시 DOCX→PDF, 그래도 실패 시 DOCX 폴백 ──
        if fmt == "pdf":
            pdf, served = None, None
            try:
                import report_html_renderer as _hr
                import report_html_pdf as _hp
                pdf = await _hp.html_to_pdf_async(_hr.generate_html(scan))
                if pdf:
                    served = "pdf-html"
            except Exception:
                pdf = None
            if not pdf:
                try:
                    import report_pdf
                    _buf = generate_report(scan)
                    pdf = report_pdf.convert_docx_to_pdf(_buf.getvalue())
                    if pdf:
                        served = "pdf-docx"
                except Exception:
                    pdf = None
            if pdf:
                fn = f"security_report_{safe_domain}_{date_str}.pdf"
                return StreamingResponse(io.BytesIO(pdf), media_type="application/pdf",
                                         headers={**_cd(fn), "X-Report-Format": served})
            # PDF 변환 불가 → DOCX 폴백(헤더로 안내)
            buf = generate_report(scan); buf.seek(0)
            fn = f"security_report_{safe_domain}_{date_str}.docx"
            return StreamingResponse(buf, media_type=_DOCX_MIME,
                                     headers={**_cd(fn), "X-Report-Format": "docx-fallback",
                                              "X-PDF-Unavailable": "html/docx PDF unavailable"})

        # ── DOCX (기본) ──
        buf = generate_report(scan)
        fn = f"security_report_{safe_domain}_{date_str}.docx"
        return StreamingResponse(buf, media_type=_DOCX_MIME, headers=_cd(fn))
    finally:
        for k, old in _saved_env.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


@app.get("/api/report/pdf-available")
async def report_pdf_available(user: dict = Depends(get_current_user)):
    """PDF/HTML 출력 가능 여부 — 프론트 버튼 노출 제어용.
    pdf_available = HTML→PDF(Playwright) 또는 DOCX→PDF(LibreOffice) 중 하나라도 가능하면 True."""
    html_pdf = docx_pdf = False
    try:
        import report_html_pdf
        html_pdf = report_html_pdf.available()
    except Exception:
        html_pdf = False
    try:
        import report_pdf
        docx_pdf = report_pdf.pdf_available()
    except Exception:
        docx_pdf = False
    return {"pdf_available": bool(html_pdf or docx_pdf),
            "html_pdf": html_pdf, "docx_pdf": docx_pdf, "html_available": True}


# ── WebSocket scan ─────────────────────────────────────────────────────────────

# 진행 중 스캔의 실시간 진행 상태(인메모리). 스캔 이력 화면에서 단계/진행률을 보여주기 위함.
# 단계명 → (한글 라벨, 누적 진행률%)
_STAGE_META = {
    "recon":            ("정보 수집",            10),
    "url_discovery":    ("URL 탐색",             25),
    "active_probing":   ("능동 취약점 점검",      50),
    "external_scan":    ("외부 도구 점검",        70),
    "penetration":      ("증거 수집·스크린샷",     85),
    "recrawl":          ("추가 점검 (재크롤)",     90),
    "lateral_movement": ("분석·보고서 생성",       95),
    "ai_analysis":      ("AI 분석",              98),
}
SCAN_PROGRESS: dict[str, dict] = {}


def _set_progress(scan_id: str, **kw):
    cur = SCAN_PROGRESS.get(scan_id, {})
    cur.update(kw)
    # 스캔별 이벤트 로그 버퍼(최근 50개) — 이 서버의 어느 진행중 스캔이든 폴링으로 진행상황 조회 가능
    # (WS 는 시작한 탭에서만 보이므로, 동시 스캔의 진행상황을 목록에서 확인하려면 서버측 버퍼가 필요)
    _msg = kw.get("message")
    _stage = kw.get("stage_label") or kw.get("stage")
    _stage_changed = bool(_stage) and _stage != cur.get("_last_stage")
    if _msg or _stage_changed:
        from datetime import datetime as _dt
        log = cur.get("log") or []
        # B3 2칸 UX: 이벤트 출처 태그(mac/i7). i7 외부도구 오프로드 진행 메시지는 '[i7' 접두로
        # 온다(_offload_external_tools_i7). 그 외(맥 능동점검·오케스트레이션)는 mac 레인.
        _m2 = _msg or ""
        _source = "i7" if _m2.startswith("[i7") else "mac"
        log.append({"t": _dt.now().isoformat(timespec="seconds"),
                    "stage": _stage or cur.get("stage_label") or cur.get("stage") or "",
                    "message": _m2, "source": _source})
        # 진행 로그는 사실상 전부 유지(긴 시간-박스 스캔의 전체 경과 확인용). env 로 상한 조정.
        try:
            _cap = int(os.getenv("SCAN_LOG_MAX", "1000"))
        except (TypeError, ValueError):
            _cap = 1000
        cur["log"] = log[-_cap:] if _cap > 0 else log
        if _stage:
            cur["_last_stage"] = _stage
    SCAN_PROGRESS[scan_id] = cur


# 스캔 취소(중지) 제어용 인메모리 상태
SCAN_CANCEL: dict[str, bool] = {}     # scan_id -> 중지 요청 여부
SCAN_TASKS: dict[str, object] = {}    # scan_id -> asyncio.Task (강제 중지용)
SCAN_STATE: dict[str, dict] = {}      # scan_id -> {"host_results": [...], "domain": ...} (부분 보고용)
SCAN_PAUSE: dict[str, bool] = {}      # scan_id -> 일시정지 요청 여부
RUNNING_BY_USER: dict[int, int] = {}  # user_id -> 현재 실행 중 스캔 수(동시 스캔 제한용, 인메모리)
SCAN_EXCLUDE: dict[str, list] = {}    # scan_id -> 제외 URL/경로 목록(발견 URL 필터, 부분일치)
SCAN_INCLUDE: dict[str, list] = {}    # scan_id -> 허용(allowlist) URL 목록. 있으면 그 목록에 없는 발견 URL 은 점검 안 함
SCAN_DEADLINE: dict[str, object] = {} # scan_id -> auto-stop asyncio.Task (허용 시간 초과 시 중지)
SCAN_BUDGET: dict[str, dict] = {}     # scan_id -> {"total_min", "deadline_ts"} (심층 반복 재크롤 연동용)


async def _auto_stop_after(scan_id: str, minutes: float):
    """허용 시간(분) 경과 후 스캔을 중지(부분 보고서 생성). 스캔이 먼저 끝나면 취소됨."""
    try:
        await asyncio.sleep(max(1.0, float(minutes)) * 60)
    except asyncio.CancelledError:
        return
    if scan_id in SCAN_TASKS and not SCAN_CANCEL.get(scan_id):
        SCAN_CANCEL[scan_id] = True
        _t = SCAN_TASKS.get(scan_id)
        if _t:
            _t.cancel()


def _cleanup_scan_state(scan_id: str, user_id: int | None) -> None:
    """스캔 종료 시 인메모리 상태 정리 + 동시성 카운터 감소(WS/recover 공용)."""
    SCAN_TASKS.pop(scan_id, None)
    SCAN_CANCEL.pop(scan_id, None)
    SCAN_STATE.pop(scan_id, None)
    SCAN_PROGRESS.pop(scan_id, None)
    SCAN_PAUSE.pop(scan_id, None)
    try:
        import adaptive_throttle as _thrp
        _thrp.resume(scan_id)   # 일시정지 레지스트리 정리(누수 방지)
    except Exception:
        pass
    SCAN_EXCLUDE.pop(scan_id, None)
    SCAN_INCLUDE.pop(scan_id, None)
    SCAN_BUDGET.pop(scan_id, None)
    _dl = SCAN_DEADLINE.pop(scan_id, None)
    if _dl:
        try:
            _dl.cancel()
        except Exception:
            pass
    if user_id is not None:
        RUNNING_BY_USER[user_id] = max(0, RUNNING_BY_USER.get(user_id, 0) - 1)


async def _run_managed_scan(ws, domain: str, scan_id: str, user_id: int, role: str, **kw) -> None:
    """detached(recover/스케줄러) 경로용 — run_scan 을 '취소·부분보고·상태정리' 수명주기로 감싼다.
    WS 경로는 자체 try/await/finally 를 가지지만, recover 는 HTTP 라 await 할 수 없어 이 래퍼를
    create_task 로 띄우고 SCAN_TASKS 에 등록한다 → 취소 가능·동시성 카운트·부분보고·정리를 보장
    (recover 가 이를 누락해 '취소 불가·동시성 미집계·미정리' 고스트 스캔이 되던 문제 해결)."""
    try:
        await run_scan(ws, domain, scan_id, user_id, role, **kw)
    except asyncio.CancelledError:
        try:
            await _finalize_partial(scan_id, domain)
        except Exception:
            pass
    except Exception as _e:
        print(f"[managed_scan] run_scan 오류(무시): {_e}", flush=True)
    finally:
        _cleanup_scan_state(scan_id, user_id)


# 일시정지 최대 대기(초) — 무한 대기 방지(이 시간 지나면 자동 재개)
_PAUSE_MAX_WAIT = int(os.getenv("SCAN_PAUSE_MAX_WAIT", "3600"))


def _default_max_concurrent() -> int:
    """일반 사용자의 전역 기본 동시 스캔 제한(사용자별 값 0 일 때 적용). 기본 2(초과분은 대기열)."""
    try:
        return max(1, int(os.getenv("DEFAULT_MAX_CONCURRENT_SCANS", "2")))
    except (TypeError, ValueError):
        return 2


def _effective_concurrency_limit(user: dict) -> int | None:
    """사용자의 동시 스캔 제한. 관리자는 None(무제한). 일반은 사용자값>0 또는 전역 기본값."""
    if user.get("role") == "admin":
        return None  # 관리자 무제한
    per_user = int(user.get("max_concurrent_scans") or 0)
    return per_user if per_user > 0 else _default_max_concurrent()


def _effective_auth(scan_auth: dict | None) -> dict:
    """스캔에 적용할 인증정보를 결정한다.

    - 스캔 시작 시 자격증명(scan_auth)이 오면 '그 스캔에만' 사용한다(전역 설정과 병합하지 않아
      다른 타깃의 잔여 자격증명 오염을 막는다). login_url+username+password 중 하나라도 있으면
      per-scan 으로 간주.
    - scan_auth 가 없으면 전역 env(AUTH_*, 인증 설정 페이지)로 폴백(예약/헤드리스 호환).
    - 자격증명이 0개/1개(A만)/2개(A+B) 모두 허용 — 각 기능이 필요한 자격증명 유무를 스스로 확인.
    비밀번호는 로그/스캔기록에 저장하지 않는다(메모리 전용).
    """
    import probe_policy as _pp
    # 세션 주입 인증(캡챠·OTP·SSO 대상) — 사람이 1회 로그인한 세션(헤더/쿠키)을 재사용, 로그인 폼 스킵
    if isinstance(scan_auth, dict) and any(
            scan_auth.get(k) for k in ("session_headers", "session_token", "session_cookies")):
        return {
            "enabled": True,
            "auth_method": "session",
            "session_headers": scan_auth.get("session_headers") or "",
            "session_token": (scan_auth.get("session_token") or "").strip(),
            "session_cookies": scan_auth.get("session_cookies") or "",
            "_source": "per_scan_session",
        }
    if isinstance(scan_auth, dict) and any(
            scan_auth.get(k) for k in ("login_url", "username", "password")):
        try:
            _mp = int(scan_auth.get("max_pages") or 50)
        except (TypeError, ValueError):
            _mp = 50
        return {
            "enabled": True,
            "login_url": (scan_auth.get("login_url") or "").strip(),
            "username": scan_auth.get("username") or "",
            "password": scan_auth.get("password") or "",
            "username_b": scan_auth.get("username_b") or "",
            "password_b": scan_auth.get("password_b") or "",
            "role_a": scan_auth.get("role_a") or "",
            "role_b": scan_auth.get("role_b") or "",
            "success_pattern": scan_auth.get("success_pattern") or "",
            "failure_pattern": scan_auth.get("failure_pattern") or "",
            "max_pages": _mp,
            "username_selector": scan_auth.get("username_selector") or "",
            "password_selector": scan_auth.get("password_selector") or "",
            "submit_selector": scan_auth.get("submit_selector") or "",
            "login_action": (scan_auth.get("login_action") or "").strip(),
            "login_body_mode": scan_auth.get("login_body_mode") or "form",
            "login_method": scan_auth.get("login_method") or "auto",
            "extra_fields": scan_auth.get("extra_fields") if isinstance(scan_auth.get("extra_fields"), dict) else {},
            "_source": "per_scan",
        }
    cfg = _pp.auth_crawl_config()
    cfg["role_a"] = os.getenv("AUTH_A_ROLE", "")
    cfg["role_b"] = os.getenv("AUTH_B_ROLE", "")
    cfg["_source"] = "global_env"
    return cfg


def _apply_auth_to_scanconfig(cfg, a: dict):
    """ScanConfig 객체에 인증정보 dict 를 주입(env 대신 per-scan 값 사용)."""
    cfg.enable_auth_scan = True
    cfg.auth_login_url = a.get("login_url", "") or ""
    cfg.auth_username = a.get("username", "") or ""
    cfg.auth_password = a.get("password", "") or ""
    cfg.auth_username_b = a.get("username_b", "") or ""
    cfg.auth_password_b = a.get("password_b", "") or ""
    cfg.auth_role_a = a.get("role_a", "") or ""
    cfg.auth_role_b = a.get("role_b", "") or ""
    cfg.auth_success_pattern = a.get("success_pattern") or "auto"
    # 로그인 고도화: 실제 요청 URL(override)·본문형식(form/json)·방식(auto/browser/http)·추가필드·셀렉터
    cfg.auth_login_action = a.get("login_action", "") or ""
    cfg.auth_login_body_mode = a.get("login_body_mode", "form") or "form"
    cfg.auth_login_method = a.get("login_method", "auto") or "auto"
    cfg.auth_extra_fields = a.get("extra_fields") if isinstance(a.get("extra_fields"), dict) else {}
    cfg.auth_username_selector = a.get("username_selector", "") or ""
    cfg.auth_password_selector = a.get("password_selector", "") or ""
    cfg.auth_submit_selector = a.get("submit_selector", "") or ""
    try:
        cfg.auth_max_pages = int(a.get("max_pages") or 50)
    except (TypeError, ValueError):
        cfg.auth_max_pages = 50
    return cfg


def _is_cancelled(scan_id: str) -> bool:
    return bool(SCAN_CANCEL.get(scan_id))


def _is_paused(scan_id: str) -> bool:
    return bool(SCAN_PAUSE.get(scan_id))


async def _wait_if_paused(scan_id: str, send=None) -> None:
    """일시정지 상태면 단계 경계에서 대기한다(네트워크 활동 없음). 재개/중지 시 빠져나온다.

    _PAUSE_MAX_WAIT 초가 지나면 자동 재개(무한 대기/유령 정지 방지)."""
    if not _is_paused(scan_id):
        return
    _set_progress(scan_id, paused=True, message="일시정지됨 — 재개 대기 중")
    if send:
        try:
            await send({"type": "info", "message": "스캔 일시정지됨 — 재개를 기다립니다."})
        except Exception:
            pass
    waited = 0
    while _is_paused(scan_id) and not _is_cancelled(scan_id) and waited < _PAUSE_MAX_WAIT:
        await asyncio.sleep(1)
        waited += 1
    SCAN_PAUSE[scan_id] = False
    _set_progress(scan_id, paused=False)
    if send and not _is_cancelled(scan_id):
        try:
            await send({"type": "info", "message": "스캔 재개됨."})
        except Exception:
            pass


async def _finalize_partial(scan_id: str, domain: str, send=None):
    """스캔 중단 시 그때까지 수집된 host_results 로 부분 보고서를 만들어 status='stopped' 로 저장.
    (한 번만 처리 — idempotent)"""
    if scan_id not in SCAN_STATE:
        return
    state = SCAN_STATE.pop(scan_id, {}) or {}
    host_results = state.get("host_results", []) or []
    pct = SCAN_PROGRESS.get(scan_id, {}).get("percent", 0)
    try:
        analysis = analyze_with_rules(host_results)
        _n = normalize_findings(analysis.get("findings", []))
        analysis["findings"] = _n["findings"]
        analysis["attack_surface_items"] = _n["attack_surface_items"]
        analysis["discovery_items"] = _n["discovery_items"]
        analysis["good_items"] = _n["good_items"]
        analysis["noise_items"] = _n["noise_items"]
        analysis["summary"] = _n["summary"]
        _bs = _n["summary"]["by_severity"]
        analysis["overall_risk"] = (
            "HIGH" if (_bs.get("Critical") or _bs.get("High"))
            else "MEDIUM" if _bs.get("Medium")
            else "LOW" if _bs.get("Low") else "GOOD"
        )
        _vc = _n["summary"]["vulnerability_count"]
        analysis["partial"] = True
        analysis["stopped_at_percent"] = pct
        analysis["overall_summary"] = (
            f"[중단된 스캔] 진행률 {pct}%까지 수집된 부분 결과입니다. "
            f"취약점 {_vc}건, 공격 표면 {_n['summary'].get('attack_surface_count', 0)}건 (부분 결과)."
        )
    except Exception as e:
        analysis = {
            "partial": True, "stopped_at_percent": pct,
            "findings": [], "attack_surface_items": [], "discovery_items": [],
            "good_items": [], "noise_items": [],
            "summary": {"vulnerability_count": 0},
            "overall_risk": "GOOD",
            "overall_summary": f"[중단된 스캔] 진행률 {pct}%에서 중단됨 (부분 분석 실패: {str(e)[:60]}).",
        }
    _set_progress(scan_id, stage="stopped", stage_label="중단됨", done=True,
                  message=f"사용자 요청으로 중단됨 (진행률 {pct}%)")
    try:
        await update_scan_record(scan_id, "stopped", results=host_results, analysis=analysis)
    except Exception:
        pass
    if send:
        try:
            await send({"type": "stopped", "scan_id": scan_id, "percent": pct})
        except Exception:
            pass


_MULTI_TLDS = {"co.kr", "ne.kr", "or.kr", "go.kr", "ac.kr", "co.jp", "co.uk", "com.au",
               "com.cn", "com.br", "co.in", "co.nz", "org.uk"}


def _registrable_domain(host: str) -> str:
    """호스트에서 등록가능도메인(대략)을 추출. 흔한 2단계 TLD(co.kr 등) 처리."""
    parts = (host or "").strip().lower().strip(".").split(".")
    if len(parts) < 2:
        return host or ""
    last2 = ".".join(parts[-2:])
    if last2 in _MULTI_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def _subdomain_seeds_from_scan(host_results: list, base_host: str) -> list[dict]:
    """서브도메인 탈취 점검 시드를 넓힌다: 대상 호스트 + '크롤로 발견한 동일 등록도메인 하위
    호스트'. (포트스캔 대상은 확대하지 않는다 — DNS/GET 지문만 하는 비침습 점검 전용 시드.)
    권한 밖 제3자 확대를 막기 위해 등록가능도메인이 대상과 같은 호스트만 포함한다."""
    reg = _registrable_domain(base_host)
    seeds: dict = {}
    if base_host:
        seeds[base_host.lower()] = {"subdomain": base_host}
    from urllib.parse import urlparse as _up
    for hr in host_results or []:
        for svc in (hr.get("services") or []):
            for u in (svc.get("discovered_urls") or []):
                try:
                    h = _up(u).netloc.split("@")[-1].split(":")[0].lower()
                except Exception:
                    continue
                if not h or h in seeds:
                    continue
                # 동일 등록가능도메인의 하위 호스트만(권한 밖 제3자 제외)
                if reg and (h == reg or h.endswith("." + reg)):
                    seeds[h] = {"subdomain": h}
    return list(seeds.values())[:20]


async def _collect_subdomain_takeover_info(subdomains: list) -> list:
    """서브도메인 CNAME(best-effort) + 미클레임 판단용 응답 본문 수집. SAFE(DNS+GET).
    dnspython 미설치 환경에서는 socket alias 로 best-effort 만 수행한다."""
    try:
        import subdomain_takeover as _sdt
    except Exception:
        return []
    out, loop = [], asyncio.get_event_loop()
    for sub in (subdomains or [])[:20]:
        host = (sub.get("subdomain") if isinstance(sub, dict) else str(sub)) or ""
        if not host:
            continue
        cname = ""
        try:
            _name, aliases, _ips = await loop.run_in_executor(None, _socket.gethostbyname_ex, host)
            cname = next((a for a in (aliases or []) if _sdt._match_service(a)), "")
        except Exception:
            continue
        if not cname:                      # 알려진 탈취 대상 서비스 CNAME 아니면 스킵(오탐 회피)
            continue
        body, st = "", None
        # rate 거버너 적용(SAFE: 전역 5rps 합산에 포함)
        import adaptive_throttle as _gov0
        import time as _time0
        _g = _gov0.stage("active_probing")
        if _g is not None:
            await _g.before()
        _t0 = _time0.monotonic()
        try:
            import aiohttp
            async with aiohttp.ClientSession() as _s:
                async with _s.get(f"http://{host}", timeout=aiohttp.ClientTimeout(total=8),
                                  ssl=False) as _r:
                    st = _r.status
                    body = (await _r.text())[:5000]
        except Exception:
            pass
        finally:
            if _g is not None:
                _g.after(_time0.monotonic() - _t0, st or 0, None)
        out.append({"subdomain": host, "cname": cname, "body": body, "status": st})
    return out


def _derive_base_root(host_results: list, domain: str) -> str:
    """스캔 대상의 실제 base URL 루트(scheme://netloc)를 host_results 의 http_info.url 에서 유도한다.

    기존 코드가 http 를 하드코딩해 https 전용 타깃에서 인증 크롤/IDOR 가 조용히 실패하던 문제 보정.
    발견된 http_info.url 이 없으면 https 를 기본으로(현대 웹 기본), 그것도 없으면 http 로 폴백.
    """
    from urllib.parse import urlparse as _urlparse
    for hr in host_results or []:
        for svc in (hr.get("services") or []):
            hi = svc.get("http_info") or {}
            u = hi.get("url")
            if u:
                p = _urlparse(u)
                if p.scheme in ("http", "https") and p.netloc:
                    return f"{p.scheme}://{p.netloc}"
    return f"https://{domain}"


def _hybrid_enabled() -> bool:
    """B2 하이브리드: external_tools 를 i7 워커로 오프로드해 Mac 능동점검과 '병렬' 실행할지.
    기본 OFF — 켜기 전 i7 워커(:8100)가 떠 있고 WORKER_URL/WORKER_TOKEN 이 설정돼야 한다."""
    return os.getenv("HYBRID_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")


async def _offload_external_tools_i7(scan_id: str, domain: str, host_results: list,
                                     config: dict, send, poll_interval: float = 3.0) -> list | None:
    """external_tools 를 i7 워커로 오프로드하고 폴링으로 결과(external_findings)를 회수한다.

    반환: findings 리스트(성공) 또는 None(워커 미설정/미가용/디스패치 실패/에러/타임아웃 → 로컬 폴백).
    콜백이 아니라 폴링 방식이라 워커→맥 도달성이 필요 없다. 회로차단기는 worker_client 가 관리.
    """
    try:
        import worker_client as _wcl
        import worker_config as _wc
    except Exception:
        return None
    if not _wc.worker_enabled():
        return None
    import time as _t
    try:
        budget = float(os.getenv("WORKER_EXTERNAL_MAX_WAIT", "5400"))  # 90분 상한
    except (TypeError, ValueError):
        budget = 5400.0
    # WSL 유휴 종료 방지: WSL2 는 활성 세션이 없으면 VM 을 종료해 8100 포워딩이 끊긴다.
    # 오프로드 동안 ssh 로 WSL 을 깨어있게 유지한다(availability 체크도 WSL 이 떠 있어야 성공).
    # 자체 만료 sleep(budget+여유)이라 스캔이 죽어도 흔적이 남지 않고, 완료 시 finally 에서 정리.
    _ka = None
    try:
        import subprocess as _sp
        _ka = _sp.Popen(["ssh", "-o", "ConnectTimeout=10",
                         os.getenv("EGRESS_SSH_HOST", "i7"),
                         f"wsl -d Ubuntu sleep {int(budget) + 120}"],
                        stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, stdin=_sp.DEVNULL)
        await asyncio.sleep(2.0)               # WSL 기상 여유
    except Exception:
        _ka = None
    try:
        if not await _wcl.worker_available():
            return None
        # 딥스캔 정책 env(ENABLE_SQLMAP 등)를 워커로 전달 → i7 에서도 Mac 과 같은 도구가 돈다
        # (안 넘기면 워커 기본 env 라 sqlmap 등이 꺼진 채 실행돼 탐지·로그가 빠짐).
        _POLICY_ENV_KEYS = ("ENABLE_SQLMAP", "SQLMAP_ENUM_DBS", "ENABLE_TIME_BASED_SQLI",
                            "PROBE_PAYLOAD_LEVEL", "ENABLE_ADVANCED_PAYLOADS")
        _probe_env = {_k: os.environ[_k] for _k in _POLICY_ENV_KEYS if _k in os.environ}
        if _probe_env:
            config = {**(config or {}), "probe_env": _probe_env}
        disp = await _wcl.dispatch_scan(scan_id, domain, host_results, config,
                                        callback_url="", phase="external_tools")
        if not disp.get("ok"):
            return None
        t0 = _t.monotonic()
        _last_msg = ""
        while True:
            await asyncio.sleep(poll_interval)
            stt = await _wcl.get_status(scan_id)
            if not stt.get("ok"):
                return None                    # 폴링 실패 → 로컬 폴백
            data = stt.get("data") or {}
            status = data.get("status")
            prog = data.get("progress") or {}
            _m = prog.get("message") or ""
            if _m and _m != _last_msg:
                _last_msg = _m
                await send({"type": "info", "message": f"[i7 외부도구] {_m}"})
            if status == "complete":
                return data.get("external_findings") or []
            if status in ("error", "stopped", "interrupted"):
                return None
            if _t.monotonic() - t0 > budget:
                return None
    finally:
        if _ka is not None:
            try:
                _ka.terminate()
            except Exception:
                pass


async def run_scan(ws: WebSocket, domain: str, scan_id: str, user_id: int, user_role: str,
                   domain_notes: str = "", scan_auth: dict | None = None,
                   resume_ckpt: dict | None = None):
    # 재개 시에는 기존 스캔 레코드를 재사용(새로 만들지 않음). domain_notes(예약 마커 등) 저장.
    if not resume_ckpt:
        await create_scan_record(scan_id, user_id, domain, notes=domain_notes or "")
    # 이 스캔에 적용할 인증정보(per-scan 우선, 없으면 전역 env 폴백). 메모리 전용·비저장.
    _scan_auth = _effective_auth(scan_auth)

    # ── 스캔 재개(Phase 1): 체크포인트의 완료 스테이지까지 건너뛰고 부분결과를 복원 ──
    _RESUME_ORDER = ["recon", "url_discovery", "active_probing", "external_scan", "penetration"]

    def _stage_done(stage: str) -> bool:
        if not resume_ckpt:
            return False
        cs = resume_ckpt.get("stage")
        return (cs in _RESUME_ORDER and stage in _RESUME_ORDER
                and _RESUME_ORDER.index(stage) <= _RESUME_ORDER.index(cs))

    async def _save_ckpt(stage: str, host_results: list):
        """스테이지 완료 체크포인트 저장(재개용). 실패는 무시(스캔 진행 우선).
        budget_min 을 함께 저장해 recover 시 예산(깊이 스케일·자동중지)을 복원할 수 있게 한다."""
        try:
            _bmin = (SCAN_BUDGET.get(scan_id) or {}).get("total_min", 0)
            await save_checkpoint(scan_id, {"stage": stage, "host_results": host_results,
                                            "budget_min": _bmin})
        except Exception:
            pass

    _resume_hr = (resume_ckpt or {}).get("host_results") or []
    SCAN_STATE[scan_id] = {"host_results": list(_resume_hr), "domain": domain}
    try:  # 저장형 XSS 주입 레지스트리 초기화(재크롤 재확인용, 스캔별)
        import active_probing as _ap0
        _ap0.clear_stored_xss_injections(scan_id)
        # 네트워크 헬스 카운터를 스캔 태스크 컨텍스트에 미리 set → recon/url_discovery 단계의
        # 연결 실패도 공유 카운터에 기록(하위 태스크로 ContextVar 전파). 능동 점검 단계에서
        # probe_active_for_all_hosts 가 재초기화하지만, 그 전 단계 감지를 위해 여기서 먼저 설정.
        _ap0.net_reset()
    except Exception:
        pass
    _set_progress(scan_id, stage="recon", stage_label="시작", percent=2, message="스캔 준비 중...", done=False)

    async def send(data: dict):
        # WebSocket 전송과 별개로 진행 상태를 인메모리에 기록 (이력 화면 폴링용)
        try:
            t = data.get("type")
            if t == "stage":
                st = data.get("stage", "")
                label, pct = _STAGE_META.get(st, (st, SCAN_PROGRESS.get(scan_id, {}).get("percent", 0)))
                _set_progress(scan_id, stage=st, stage_label=label, percent=pct,
                              message=data.get("message", ""), done=False)
            elif t in ("info", "warning") and scan_id in SCAN_PROGRESS:
                _set_progress(scan_id, message=data.get("message", ""))
            elif t == "complete":
                _set_progress(scan_id, stage="complete", stage_label="완료", percent=100, done=True)
            elif t == "error":
                _set_progress(scan_id, stage="error", stage_label="실패", done=True,
                              message=data.get("message", ""))
        except Exception:
            pass
        # WS 전송 실패(탭 종료/네트워크 끊김)해도 스캔은 계속 진행 (진행상태는 폴링으로 확인)
        try:
            await ws.send_json(data)
        except Exception:
            pass

    # ── 단일출구(egress) 프리플라이트 — EGRESS_ENABLED=true 면 i7 SOCKS5 터널 보장 ──
    # 스캔 대상 트래픽은 이 터널(i7)로만 나간다(fail-closed: 터널 없으면 대상 요청 실패, 직접 누출 없음).
    try:
        import egress as _eg
        if _eg.enabled():
            if _eg.ensure_tunnel():
                await send({"type": "info",
                            "message": f"🔒 단일출구 활성 — 스캔 트래픽은 i7({_eg._ssh_host()}) SOCKS5 로만 나갑니다."})
            else:
                await send({"type": "warning",
                            "message": ("⚠️ 단일출구(i7 SOCKS5) 터널 기동 실패 — 대상 요청이 차단됩니다"
                                        "(직접 송신 없음/fail-closed). i7 SSH 연결을 확인하세요.")})
    except Exception as _ege:
        print(f"[egress] 프리플라이트 스킵(무시): {_ege}", flush=True)

    # 하이브리드(B2) 오프로드 상태 — run_scan 전역(재개로 능동점검을 건너뛰어도 3단계에서 안전 참조).
    _ext_offload_task = None       # i7 external_tools 오프로드 태스크(능동점검과 병렬)
    _ext_offload_findings = None   # None = 오프로드 미사용/실패 → 3단계에서 로컬 실행

    # 세션 주입 인증(캡챠·OTP·SSO 대상) — 제공된 세션 헤더/쿠키를 '대상 호스트로 나가는' 모든 요청에
    # 주입(로그인 폼 스킵). 스코프 밖(제3자) 호스트로는 토큰 미주입(유출 방지). 이 스캔 태스크에만 적용.
    # (send 정의 이후에 배치 — 설치 안내를 send 로 보내야 하므로. 실제 대상 요청 전이라 타이밍 안전.)
    try:
        if _scan_auth.get("auth_method") == "session":
            import session_inject as _sinj
            _sh = _sinj.host_from_target(domain) or domain
            _hdr = _scan_auth.get("session_headers") or ""
            if _scan_auth.get("session_token") and not _hdr:
                _tok = _scan_auth["session_token"]
                _hdr = _tok if ":" in _tok.split(" ", 1)[0] else f"Authorization: {_tok}"
            _installed = _sinj.install(headers=_hdr,
                                       cookies=_scan_auth.get("session_cookies"),
                                       host=_sh)
            if _installed:
                _hk = ", ".join(sorted(_installed.get("headers", {}).keys()))
                await send({"type": "info",
                            "message": (f"🔑 세션 주입 인증 — 로그인 폼 없이 제공된 세션으로 점검"
                                        f"(헤더: {_hk}, 대상 {_sh} 로만 주입)")})
    except Exception as _sie:
        print(f"[session_inject] 설치 스킵(무시): {_sie}", flush=True)

    # ── 스캔 권한/동의 게이트 — 내부망/메타데이터 대상 차단 + 감사 기록 ──────────
    try:
        import proof_policy as _pp
        if _pp.targets_internal(domain if "://" in domain else "http://" + domain):
            await send({"type": "error",
                        "message": "내부망/클라우드 메타데이터 대상은 점검할 수 없습니다(정책 차단)."})
            _set_progress(scan_id, stage="error", stage_label="차단", done=True,
                          message="scope 정책 위반")
            return
    except Exception:
        pass
    try:
        import audit_log as _al
        _al.log("scan_started", user=str(user_id), role=user_role, target=domain, scan_id=scan_id)
    except Exception:
        pass

    # 이전 스캔 이력 로드
    previous_scans = await get_domain_scan_history(domain, user_id, user_role, limit=3)
    scan_count = len(previous_scans)
    deep_mode = scan_count > 0

    # ── 예산·PROOF 연동 깊이 설정(P2) — 이 스캔 태스크 컨텍스트에만 적용(동시 스캔 격리) ──
    try:
        import scan_depth as _sd0
        import validation_profiles as _vp0
        _brec0 = (SCAN_BUDGET.get(scan_id) or {})
        _bud0 = _brec0.get("total_min", 0)
        # 시간-박스: 자동중지 시각(deadline_ts)을 넘겨 후반부 깊이를 baseline 까지 페이싱한다.
        _sd0.set_depth(budget_min=_bud0, proof=_vp0.proof_active(),
                       deadline_ts=_brec0.get("deadline_ts"))
        _dsc = _sd0.current()
        if _dsc and _dsc["scale"] > 1.0:
            await send({"type": "info",
                        "message": (f"🔬 깊이 에스컬레이션 — 시간 예산 {_bud0}분"
                                    + (" · PROOF" if _dsc["proof"] else "")
                                    + f" → 깊이 배수 ×{_dsc['scale']}(주입점·파라미터·blind 샘플 확대)"
                                    + (" · 시간-박스 페이싱(후반부 자동 축소로 예산 내 완주)"
                                       if _brec0.get("deadline_ts") else ""))})
    except Exception:
        pass

    # ── rate 거버너 설치(동시 스캔 격리) ──
    #   Safe(비-PROOF): 전 단계 공유 '전역 합산 상한'(기본 5rps, 증속 끔) — 서버에 무리 최소.
    #   PROOF: '단계별 독립 상한'(전역 하드캡 없음, 각 단계 정의된 상한) — 더 깊고 빠르게.
    # 미설치 시 모든 요청 경로는 no-op. EOSEUREUM_SAFE_THROTTLE=off 로 전체 비활성 가능.
    try:
        import validation_profiles as _vp1
        import adaptive_throttle as _thr0
        import response_cache as _rc0
        if os.getenv("EOSEUREUM_SAFE_THROTTLE", "").strip().lower() != "off":
            _prof = _vp1.current_profile()        # SAFE / STANDARD / ADVANCED / PROOF
            _gov = _thr0.install_profile(_prof, scan_id=scan_id)   # scan_id → 요청단위 일시정지 게이트
            if _gov is None:
                # PROOF = 완전 무제한(거버너 미설치) — 각 도구가 최고속으로 딥하게
                await send({"type": "info",
                            "message": "🔬 PROOF — 초당 상한 없음(무제한). 디렉터리 퍼징·nuclei 등 최고속 딥 점검"})
            else:
                _sh = _gov._shared
                _conc_txt = "단독(순차)" if _sh.conc <= 1 else f"동시 요청 {_sh.conc}"
                await send({"type": "info",
                            "message": (f"🛡️ {_prof} rate 거버너 — 전 단계 합산 ≤{_sh.max_rps:g}rps"
                                        f"(증속 {'on' if _sh.ramp else 'off'}), {_conc_txt} — 서버 부하 제어")})
            # S4: 응답 재사용 캐시 설치(동일 GET 중복요청 제거). PROOF 포함 전 모드 공통(부하↓·커버리지 동일).
            if os.getenv("EOSEUREUM_SAFE_CACHE", "").strip().lower() != "off":
                _rc0.install()
    except Exception:
        pass

    # ── 1단계: 정보수집 (Reconnaissance) ────────────────────────────────────────
    recon_msg = f"[정보수집] {domain} IP 조회 + 고위험 포트 스캔"
    if deep_mode:
        recon_msg += f" | 이전 점검 {scan_count}회 이력 있음 → 심층 모드"
    await send({"type": "stage", "stage": "recon", "message": recon_msg + "..."})

    # 입력한 도메인만 대상으로 스캔 (www 추가·서브도메인 탐색 없음)
    # 대상에 명시 포트(예: host:13006, http://host:13006)가 있으면 파싱해 그 포트를
    # 직접 점검 대상으로 삼는다(비표준 포트도 스캔 가능 — 포트스캔에 의존하지 않음).
    import scanner as _scn
    _tgt = _scn.parse_target(domain)
    _scan_host_name = _tgt["host"] or domain
    _explicit_port = _tgt["port"]
    _explicit_ssl = _tgt["scheme"] == "https"
    try:
        ip = await asyncio.get_event_loop().run_in_executor(
            None, _socket.gethostbyname, _scan_host_name
        )
    except Exception as e:
        await update_scan_record(scan_id, "failed")
        await send({"type": "error", "message": f"도메인 '{_scan_host_name}' IP 주소 조회 실패: {e}"})
        return

    # 해석된 IP 재검사 — 공개처럼 보이는 도메인이 사설/메타데이터 IP 로 해석되는 DNS 리바인딩/SSRF 차단.
    # (사전 게이트는 '문자열 호스트'만 검사했음. 관리자 허용목록의 내부 실습 대상은 예외로 유지.)
    try:
        import proof_policy as _pp2
        if (_pp2.targets_internal("http://" + str(ip))
                and _scan_host_name.lower() not in _pp2._internal_allowlist()):
            await update_scan_record(scan_id, "failed")
            await send({"type": "error",
                        "message": (f"대상 '{_scan_host_name}' 이 내부/메타데이터 IP({ip})로 해석됩니다 — "
                                    "DNS 리바인딩/SSRF 방지를 위해 차단(정책).")})
            _set_progress(scan_id, stage="error", stage_label="차단", done=True,
                          message="해석 IP scope 위반")
            return
    except Exception:
        pass

    if _explicit_port:
        await send({"type": "info",
                    "message": f"명시 포트 {_explicit_port} 감지 — 포트스캔 대신 해당 포트를 직접 "
                               f"{'HTTPS' if _explicit_ssl else 'HTTP'} 서비스로 점검합니다."})

    subdomains = [{"subdomain": _scan_host_name, "ip": ip}]
    await send({"type": "subdomain_found", "subdomain": _scan_host_name, "ip": ip})

    if _stage_done("recon"):
        # 재개: 포트스캔은 이미 끝났으므로 체크포인트의 결과를 사용하고 건너뛴다.
        host_results = list(_resume_hr)
        await send({"type": "info", "message": "[재개] 정보수집(포트스캔) 단계 건너뜀 — 이전 결과 사용"})
    else:
        host_results = []
        for sub in subdomains:
            await send({"type": "scanning_host", "host": sub["subdomain"], "ip": sub["ip"]})
            try:
                result = await scan_host(
                    sub["subdomain"], sub["ip"], deep=deep_mode,
                    extra_ports=[_explicit_port] if _explicit_port else None,
                    force_http_ports=[_explicit_port] if (_explicit_port and not _explicit_ssl) else None,
                    force_ssl_ports=[_explicit_port] if (_explicit_port and _explicit_ssl) else None,
                    # 명시 포트 지정 시 그 포트만(스코프 봉쇄 — 같은 호스트의 다른 서비스 미점검)
                    only_ports=[_explicit_port] if _explicit_port else None)
                host_results.append(result)
                for svc in result.get("services", []):
                    port = svc["port"]
                    await send({
                        "type": "port_open",
                        "host": sub["subdomain"],
                        "port": port,
                        "service": SERVICE_NAMES.get(port, "Unknown"),
                    })
                    pv = svc.get("port_vuln")
                    if pv and pv.get("vulnerable"):
                        await send({
                            "type": "warning",
                            "message": f"포트 취약점: {sub['subdomain']}:{port} — {pv['reason'][:80]}",
                        })
            except Exception as e:
                await send({"type": "warning", "message": f"{sub['subdomain']} 스캔 오류: {e}"})
        await _save_ckpt("recon", host_results)

    # 중지/일시정지 체크포인트 (recon 완료) + 부분 보고용 상태 갱신
    SCAN_STATE[scan_id] = {"host_results": host_results, "domain": domain}
    await _wait_if_paused(scan_id, send)
    if _is_cancelled(scan_id):
        await _finalize_partial(scan_id, domain, send)
        return

    # ── 1.5단계: URL Discovery (+ 기술 스택 인식 기반 추가 점검 경로) ──────────────
    # 진행률 25% 스테이지 방출(누락 시 recon 10% → active_probing 50% 로 점프해 보임)
    if _stage_done("url_discovery"):
        await send({"type": "info", "message": "[재개] URL 탐색/브라우저 발견 건너뜀 — 이전 결과 사용"})
    else:
        await send({"type": "stage", "stage": "url_discovery",
                    "message": "[URL 탐색] robots·sitemap·크롤로 점검 대상 경로 수집 중..."})
        try:
            _crawl_pages = max(1, min(5000, int(os.getenv("MAX_CRAWL_PAGES", "200"))))
        except (TypeError, ValueError):
            _crawl_pages = 200
        try:
            _crawl_depth = max(1, min(8, int(os.getenv("MAX_CRAWL_DEPTH", "2"))))
        except (TypeError, ValueError):
            _crawl_depth = 2
        _url_engine = URLDiscoveryEngine(max_urls=_crawl_pages, max_depth=_crawl_depth,
                                         rate_limit=0.3, concurrency=3)
        for hr in host_results:
            # 기술 스택 인식 (recon 결과 기반) → 추천 점검 경로 도출
            try:
                _tech = technology_fingerprint.from_host_result(hr).get("technologies", [])
            except Exception:
                _tech = []
            hr["technologies"] = _tech
            _reco_paths = []
            for _t in _tech:
                for _p in (_t.get("recommended_probes") or []):
                    if _p and _p not in _reco_paths:
                        _reco_paths.append(_p)
            if _tech:
                await send({"type": "info",
                            "message": f"기술 스택 인식: {', '.join(t['name'] for t in _tech[:4])}"
                                       + (f" → 추가 점검 경로 {len(_reco_paths)}개" if _reco_paths else "")})
            _ai_crawl_extra = None   # AI 제안 경로(호스트당 1회만 계산 — 바운드)
            for svc in hr.get("services", []):
                http_info = svc.get("http_info")
                if not http_info:
                    continue
                port = svc.get("port", 80)
                base = http_info.get("url") or (
                    f"{'https' if port in (443, 8443) else 'http'}://{hr['host']}:{port}"
                )
                try:
                    await send({"type": "info", "message": f"[URL 탐색] {base} 크롤링 중..."})
                    # AI 크롤 보조(opt-in ENABLE_AI_CRAWL_ASSIST): 숨은 경로 후보 제안 → extra_paths 병합.
                    # AI 는 '동일 출처 상대경로'만 제안하고, 스코프/한도는 결정적 크롤러가 강제한다.
                    _extra = list(_reco_paths or [])
                    if _ai_crawl_extra is None:
                        try:
                            import ai_crawl_assist as _aca
                            _ai_crawl_extra = (await _aca.suggest_crawl_paths(
                                base, known_paths=_extra)) if _aca.crawl_assist_enabled() else []
                            if _ai_crawl_extra:
                                await send({"type": "info",
                                            "message": f"[URL 탐색] AI 제안 경로 {len(_ai_crawl_extra)}개 추가"})
                        except Exception:
                            _ai_crawl_extra = []
                    if _ai_crawl_extra:
                        _extra = _extra + [p for p in _ai_crawl_extra if p not in _extra]
                    # 사용자 스캔 스코프를 '크롤 전에' 주입 경로(recon+AI)에 적용한다.
                    # extra_paths 는 discover 가 실제로 크롤(fetch)하므로, 여기서 거르지 않으면
                    # 제외(blocklist)/허용(origin) 밖 경로가 재크롤돼 스코프를 이탈할 수 있다.
                    # (discover 의 exclude_urls 는 정확-URL 매칭이라 부분일치 blocklist 와 안 맞음 → 여기서 처리)
                    _incl0 = SCAN_INCLUDE.get(scan_id) or []
                    _excl0 = SCAN_EXCLUDE.get(scan_id) or []
                    if _extra and (_incl0 or _excl0):
                        from urllib.parse import urljoin as _urljoin

                        def _path_in_scope(_p, _base=base, _inc=_incl0, _exc=_excl0):
                            _u = _urljoin(_base, _p)
                            if _exc and any(x and x in _u for x in _exc):
                                return False   # 제외 범위(부분일치) → 크롤 금지
                            if _inc and not (_u == _base or any(o and _u.startswith(o) for o in _inc)):
                                return False   # 허용 오리진 밖 → 크롤 금지
                            return True

                        _before = len(_extra)
                        _extra = [p for p in _extra if _path_in_scope(p)]
                        if _before - len(_extra) > 0:
                            await send({"type": "info",
                                        "message": f"[URL 탐색] 스코프 밖 주입 경로 {_before - len(_extra)}개 제외(제외/허용 범위 준수)"})
                    # 링크추적/known-path 크롤도 제외 범위를 건드리지 않도록 blocklist 를 크롤러에 전달.
                    disc_result = await _url_engine.discover(
                        base, extra_paths=_extra, exclude_patterns=_excl0)
                    svc["discovered_urls"] = disc_result.unique_url_strings()
                    # 스캔 옵션 적용(부분일치):
                    #  - 허용목록(include): 마법사에서 확인한 URL 목록. 있으면 그 목록에 없는 발견 URL 은
                    #    점검하지 않는다(예: Swagger 로 URL 이 바뀌어 목록 밖이면 스캔 중단/제외).
                    #  - 제외목록(exclude): 명시 제외한 URL/경로 제거.
                    # include = 허용 오리진(scheme://host) 목록. 해당 오리진의 모든 하부 URL 은
                    # 점검하되, 오리진이 다르면(목록 밖 도메인) 점검하지 않는다.
                    _incl = SCAN_INCLUDE.get(scan_id) or []
                    if _incl:
                        svc["discovered_urls"] = [
                            u for u in svc["discovered_urls"]
                            if u == base or any(o and u.startswith(o) for o in _incl)
                        ]
                    _excl = SCAN_EXCLUDE.get(scan_id) or []
                    if _excl:
                        svc["discovered_urls"] = [
                            u for u in svc["discovered_urls"]
                            if not any(x and x in u for x in _excl)
                        ]
                    svc["discovery_stats"] = {
                        "total": len(disc_result.urls),
                        "known_path_hits": len(disc_result.known_path_hits),
                        "js_endpoints": len(disc_result.js_endpoints),
                        "sitemap_count": len(disc_result.sitemap_urls),
                    }
                    # Phase 6: Discovery 확장 결과 저장
                    svc["discovery_result"] = {
                        "urls": [{"url": u.url, "source": u.source, "status_code": u.status_code}
                                 for u in disc_result.urls],
                        "admin_hits": disc_result.admin_hits,
                        "api_hits": disc_result.api_hits,
                        "framework_hints": disc_result.framework_hints,
                    }
                    url_count = len(svc["discovered_urls"])
                    hit_count = len(disc_result.known_path_hits)
                    admin_count = len(disc_result.admin_hits)
                    api_count = len(disc_result.api_hits)
                    await send({
                        "type": "info",
                        "message": (
                            f"URL 탐색 완료: {base} — {url_count}개 URL 발견"
                            + (f", 민감경로 {hit_count}개" if hit_count else "")
                            + (f", 관리자 {admin_count}개" if admin_count else "")
                            + (f", 내부API {api_count}개" if api_count else "")
                        ),
                    })
                    for kp in disc_result.known_path_hits[:5]:
                        await send({"type": "warning", "message": f"민감경로 노출: {kp}"})
                    for ah in disc_result.admin_hits[:3]:
                        await send({"type": "warning",
                                    "message": f"관리자 페이지 발견: {ah['url']} (HTTP {ah['status_code']})"})
                    for api_h in disc_result.api_hits[:3]:
                        await send({"type": "warning",
                                    "message": f"내부 API 노출: {api_h['url']} (HTTP {api_h['status_code']})"})
                    for fh in disc_result.framework_hints[:2]:
                        await send({"type": "info",
                                    "message": f"프레임워크 탐지: {fh['framework']} ({fh['marker']})"})
                except Exception as _ue:
                    await send({"type": "warning", "message": f"URL 탐색 오류 (무시): {_ue}"})

        # ── 1.7단계: 인증 후 크롤 (ENABLE_AUTH_CRAWL=true 일 때만, 기본 off) ──────────
        #   로그인 → same-origin 인증 페이지 크롤 → 인증 URL 을 각 서비스 discovered_urls 에 합류.
        #   자격증명/쿠키는 평문 노출 금지. 실패해도 전체 스캔 실패 없음.
        SCAN_STATE.setdefault(scan_id, {})["auth"] = {
            "enabled": False, "login_success": None, "pages": 0, "reason": "ENABLE_AUTH_CRAWL=false",
        }
        try:
            import probe_policy as _pp
            _acfg = _scan_auth                      # per-scan 인증정보(없으면 전역 env 폴백)
            _skip = _pp.auth_crawl_skip_reason(_acfg)
            # 반복 재크롤이 켜져 있으면 1차는 '비인증'으로 두고, 인증 크롤은 재크롤 루프가 단계적으로
            # 수행한다(사용자 요구: 첫 스캔은 인증정보 없이 → 이후 인증 후 새 경로만).
            try:
                import iterative_recrawl as _irc0
                if _irc0.enabled():
                    _skip = _skip or "iterative_recrawl 이 인증 크롤을 단계적으로 수행"
            except Exception:
                pass
            if not _skip:
                from probes.config import ScanConfig as _SC
                _authcfg = _apply_auth_to_scanconfig(_SC.from_env(), _acfg)
                import authenticated_scan as _auth
                await send({"type": "info", "message": "[인증 크롤] 로그인 후 인증 페이지 크롤 시작..."})
                # 크롤 루트는 scheme://netloc 만 사용(login_url 이 경로 포함 전체 URL 일 수 있음).
                _lu = _acfg.get("login_url") or ""
                if _lu:
                    from urllib.parse import urlparse as _up
                    _p = _up(_lu)
                    _base = (f"{_p.scheme}://{_p.netloc}" if _p.scheme in ("http", "https") and _p.netloc
                             else _derive_base_root(host_results, domain))
                else:
                    _base = _derive_base_root(host_results, domain)
                _ar = await _auth.perform_login_and_crawl(_authcfg, _base)
                _auth_urls = _ar.get("urls") or []
                SCAN_STATE[scan_id]["auth"] = {
                    "enabled": True, "login_success": bool(_ar.get("logged_in")),
                    "pages": len(_auth_urls), "reason": _ar.get("reason") or "",
                }
                # 세션 인지 능동 점검(ENABLE_AUTH_PROBE): 로그인 세션 쿠키를 능동 점검에 등록 →
                # 인증 영역 주입 표면도 로그인 상태로 점검. 기본 OFF 라 기존 익명 점검 동작 불변.
                try:
                    import active_probing as _apc
                    if _ar.get("logged_in") and _apc.auth_probe_enabled():
                        _sess = _ar.get("session")
                        _ck = []
                        if _sess is not None and getattr(_sess, "cookie_jar", None) is not None:
                            for _c in _sess.cookie_jar:
                                try:
                                    _ck.append({"name": _c.key, "value": _c.value})
                                except Exception:
                                    continue
                        if _ck:
                            _apc.register_auth_cookies(scan_id, _ck)
                            await send({"type": "info",
                                        "message": f"[인증 점검] 로그인 세션 쿠키 {len(_ck)}개 등록 — 세션 인지 능동 점검 활성"})
                except Exception:
                    pass
                # 인증 URL 을 HTTP 서비스의 discovered_urls 에 합류(능동 점검이 인증 입력점도 점검)
                if _ar.get("logged_in") and _auth_urls:
                    for hr in host_results:
                        for svc in hr.get("services", []):
                            if svc.get("http_info"):
                                merged = list(svc.get("discovered_urls") or []) + list(_auth_urls)
                                _cap_du = max(50, min(5000, int(os.getenv("MAX_DISCOVERED_URLS", "500"))))
                                _deduped = list(dict.fromkeys(merged))
                                if len(_deduped) > _cap_du:
                                    await send({"type": "info",
                                                "message": f"[인증 크롤] discovered_urls 상한({_cap_du}) 적용 — "
                                                           f"{len(_deduped) - _cap_du}개 절단"})
                                svc["discovered_urls"] = _deduped[:_cap_du]
                # 인증 크롤에서 수집한 상태변경 폼(파라미터 보유)을 주입점으로 등록 —
                # 기존에는 forms 를 버려 인증 영역 폼이 능동 점검되지 않던 공백을 보정.
                _auth_forms = _ar.get("forms") or []
                if _ar.get("logged_in") and _auth_forms:
                    try:
                        import active_probing as _apf
                        from urllib.parse import urlparse as _upf
                        _by_host: dict = {}
                        for _f in _auth_forms:
                            if not isinstance(_f, dict) or not _f.get("params"):
                                continue
                            _fh = _upf(_f.get("url", "")).netloc.split(":")[0]
                            _by_host.setdefault(_fh, []).append(_f)
                        _reg = 0
                        for hr in host_results:
                            _pts = _by_host.get(hr.get("host")) or []
                            if _pts:
                                _apf.register_browser_injection_points(scan_id, hr["host"], _pts)
                                _reg += len(_pts)
                        if _reg:
                            await send({"type": "info",
                                        "message": f"[인증 크롤] 인증 영역 폼 {_reg}개를 능동 점검 주입점으로 등록"})
                    except Exception:
                        pass
                await send({"type": "info",
                            "message": f"[인증 크롤] 로그인 {'성공' if _ar.get('logged_in') else '실패'} — 인증 페이지 {len(_auth_urls)}개"})
            else:
                SCAN_STATE[scan_id]["auth"]["reason"] = _skip
        except Exception as _ace:
            SCAN_STATE[scan_id]["auth"] = {"enabled": True, "login_success": False, "pages": 0,
                                           "reason": f"auth crawl error: {str(_ace)[:80]}"}
            await send({"type": "warning", "message": f"인증 크롤 (무시): {_ace}"})

        # ── Browser Discovery 2.0 (능동 점검 前) — 발견 입력점을 능동 점검 대상에 투입 ──
        # 브라우저에서 실제 오가는 Request 를 안전 수집 → injection point 로 변환해 등록하면,
        # 아래 능동 점검(probe_active_for_all_hosts)이 이 지점들도 함께 점검한다. 기본 OFF.
        _bd_merged = None
        _jwt_candidates: list = []
        try:
            import discovery_worker as _dw
            # SPA(React/Vue/Angular/Next/Nuxt/Svelte) 감지 시 브라우저 발견 자동 활성 —
            # 클라이언트 렌더 앱은 서버 HTML 만으론 공격 표면이 거의 안 보이기 때문.
            _all_tech_for_bd = []
            for _hr in host_results:
                _all_tech_for_bd.extend(_hr.get("technologies") or [])
            _bd_auto = _dw.policy.auto_enable_for_tech(_all_tech_for_bd)
            if _dw.enabled() or _bd_auto:
                if _bd_auto and not _dw.enabled():
                    await send({"type": "info",
                                "message": "[브라우저 발견] SPA 프레임워크 감지 → 자동 활성(클라이언트 렌더 표면 수집)"})
                import active_probing as _apm
                _apm.clear_browser_injection_points(scan_id)
                # 이 스캔의 인증정보(per-scan)를 Browser Discovery 에 전달(로그인 후 표면 수집)
                _bd_auth = None
                try:
                    if _dw.policy.auth_crawl_enabled() and _scan_auth.get("username") and _scan_auth.get("password"):
                        _bd_auth = {"login_url": _scan_auth.get("login_url"),
                                    "username": _scan_auth.get("username"),
                                    "password": _scan_auth.get("password")}
                except Exception:
                    _bd_auth = None
                _bd_all = []
                for _hr in host_results:
                    if not _hr.get("host"):
                        continue
                    _bd_url = None
                    for _svc in _hr.get("services", []):
                        _hi = _svc.get("http_info") or {}
                        if _hi.get("url"):
                            _bd_url = _hi["url"]
                            break
                    if not _bd_url:
                        continue
                    print(f"[browser_discovery] start host={_hr['host']} base={_bd_url} "
                          f"auth={'on' if _bd_auth else 'off'}", flush=True)
                    await send({"type": "info",
                                "message": f"🌐 Browser Discovery 시작: {_hr['host']} "
                                           f"(능동 점검 前 공격 표면 수집{' · 인증 후' if _bd_auth else ''})"})
                    _job = _dw.DiscoveryJob(job_id=f"{scan_id}:{_hr['host']}", base_url=_bd_url,
                                            scope=[_hr["host"]], auth=_bd_auth)
                    _bd_res = await _dw.run_browser_job(_job)
                    _bd_all.append(_bd_res)
                    _jwt_candidates.extend((_bd_res.summary or {}).get("jwt_candidates") or [])
                    _ipts = _dw.to_injection_points(_bd_res.inputs)
                    _apm.register_browser_injection_points(scan_id, _hr["host"], _ipts)
                    _bsum = _bd_res.summary or {}
                    print(f"[browser_discovery] host={_hr['host']} status={_bd_res.status} "
                          f"requests={_bsum.get('requests', 0)} inputs={len(_bd_res.inputs)} "
                          f"inj={len(_ipts)} errors={_bd_res.errors}", flush=True)
                    # 인증 크롤 시 실제 로그인 성공 여부를 표면화(has_jwt/authenticated_crawl).
                    # (자격증명을 넣어도 SPA 로그인 실패 시 결과가 익명 크롤과 같아 오해 소지 → 정직성)
                    _auth_note = ""
                    if _bd_auth:
                        _got_session = bool(_bsum.get("has_jwt") or _bsum.get("authenticated_crawl"))
                        _auth_note = (" · 🔐 인증 세션 획득(로그인 성공 추정)" if _bsum.get("has_jwt")
                                      else " · ⚠️ 인증 세션 미획득(로그인 실패 가능 — 계정/로그인URL 확인)")
                    await send({"type": "info",
                                "message": f"🌐 Browser Discovery: {_hr['host']} — 페이지 "
                                           f"{_bsum.get('pages_visited', 0)} · 요청 "
                                           f"{_bsum.get('requests', 0)} · 입력점 {len(_bd_res.inputs)} · "
                                           f"능동점검 투입 {len(_ipts)} · 차단클릭 "
                                           f"{_bsum.get('blocked_clicks', 0)}" + _auth_note
                                           + (f" · 오류 {_bd_res.errors[:1]}" if _bd_res.errors else "")})
                if _bd_all:
                    _bd_merged = _dw.merge_results(_bd_all, job_id=str(scan_id))
            else:
                print("[browser_discovery] disabled (ENABLE_BROWSER_DISCOVERY!=true)", flush=True)
        except Exception as _bd_e:
            print(f"[browser_discovery] EXCEPTION: {_bd_e}", flush=True)
            await send({"type": "warning", "message": f"Browser Discovery 오류 (무시): {_bd_e}"})

    # ── 2단계: 능동 취약점 점검 (Active Probing) ─────────────────────────────────
    http_service_count = sum(
        1 for hr in host_results for svc in hr.get("services", []) if svc.get("http_info")
    )
    if not _stage_done("url_discovery"):
        await _save_ckpt("url_discovery", host_results)   # 재개 체크포인트(URL 탐색 완료)
    # Phase 3b: recon/url_discovery 중 네트워크가 죽었으면(연속 연결 실패 임계 초과)
    # 방금 저장한 url_discovery 체크포인트를 남기고 여기서 중단 → 재개 가능.
    try:
        if _ap0.net_tripped():
            raise ScanInterrupted("URL 탐색 단계 네트워크 연결 불가 — 스캔 중단(재개 가능)")
    except NameError:
        pass
    await send({
        "type": "stage",
        "stage": "active_probing",
        "message": (
            f"[능동 점검] HTTP 서비스 {http_service_count}개 대상 "
            "XSS·SQLi·CSRF·LFI·CMDi 등 주요 웹 취약점 능동 점검 중..."
        ),
    })
    if _stage_done("active_probing"):
        # 재개: 능동 점검은 이미 끝났으므로 체크포인트 결과를 사용하고 건너뛴다.
        await send({"type": "info", "message": "[재개] 능동 점검 단계 건너뜀 — 이전 결과 사용"})
    elif http_service_count > 0:
        probed_count = [0]

        async def _probe_progress(host: str, port: int):
            probed_count[0] += 1
            await send({
                "type": "probe_progress",
                "host": host,
                "port": port,
                "message": f"능동 점검 완료: {host}:{port} ({probed_count[0]}/{http_service_count})",
            })

        # Phase 2: 서비스(host:port) 단위 재개 — 이미 점검한 서비스는 건너뛰고, 서비스마다 체크포인트.
        _ap_done = list((resume_ckpt or {}).get("completed_hosts") or [])
        _ap_skip = set(_ap_done)
        if _ap_skip:
            await send({"type": "info",
                        "message": f"[재개] 이미 점검한 서비스 {len(_ap_skip)}개 건너뜀 — 나머지만 점검"})

        async def _on_service_done(key: str, hr: list):
            if key not in _ap_done:
                _ap_done.append(key)
            try:
                await save_checkpoint(scan_id, {"stage": "url_discovery",
                                                "completed_hosts": _ap_done,
                                                "host_results": hr,
                                                "budget_min": (SCAN_BUDGET.get(scan_id) or {}).get("total_min", 0)})
            except Exception:
                pass

        # ── 하이브리드(B2): external_tools 를 i7 로 오프로드해 아래 능동점검과 '병렬' 실행(기본 OFF) ──
        # active 가 host_results 를 in-place 로 바꾸므로, 오프로드엔 능동점검 전 스냅샷을 넘긴다.
        if _hybrid_enabled() and _ext_offload_task is None:
            try:
                import copy as _copy
                _ext_snap = _copy.deepcopy(host_results)
                _ext_offload_task = asyncio.create_task(
                    _offload_external_tools_i7(scan_id, domain, _ext_snap, {}, send))
                await send({"type": "info",
                            "message": "[하이브리드] 외부도구를 i7로 오프로드 — 맥 능동점검과 병렬 시작"})
            except Exception as _hy:
                _ext_offload_task = None
                print(f"[hybrid] 오프로드 시작 실패(무시, 로컬 폴백): {_hy}", flush=True)

        try:
            host_results = await probe_active_for_all_hosts(
                host_results,
                max_concurrent=3,
                progress_cb=_probe_progress,
                scan_id=scan_id,
                skip_keys=_ap_skip,
                on_service_done=_on_service_done,
                log_cb=(lambda _m: send({"type": "info", "message": _m})),
            )
            total_vulns_found = sum(
                len(svc.get("active_probes") or {})
                for hr in host_results
                for svc in hr.get("services", [])
            )
            await send({
                "type": "info",
                "message": f"✅ CPU1(Mac) 능동 취약점 점검 완료 — 취약점 후보 {total_vulns_found}건",
            })
            await _save_ckpt("active_probing", host_results)   # 재개 체크포인트(능동 점검 전부 완료)
            # 하이브리드: 병렬로 돌던 i7 외부도구 결과 회수(양쪽 완료 = 병렬 종료점 → 합침).
            if _ext_offload_task is not None:
                try:
                    _ext_offload_findings = await _ext_offload_task
                    if _ext_offload_findings is not None:
                        await send({"type": "info",
                                    "message": f"[i7 외부도구] ✅ CPU2(i7) 외부도구 점검 완료 — {len(_ext_offload_findings)}건"})
                        await send({"type": "info",
                                    "message": "🔗 CPU1·CPU2 완료 — 결과 합침"})
                    else:
                        await send({"type": "warning",
                                    "message": "[i7 외부도구] ⚠️ CPU2(i7) 미완/실패 — 로컬(Mac) 실행으로 폴백"})
                except Exception as _hy2:
                    _ext_offload_findings = None
                    print(f"[hybrid] 오프로드 회수 실패(무시, 로컬 폴백): {_hy2}", flush=True)
        except ScanInterrupted as _si:
            # 하이브리드: 능동점검 중단 시 병렬 오프로드 태스크도 정리(누수 방지).
            if _ext_offload_task is not None and not _ext_offload_task.done():
                _ext_offload_task.cancel()
            # Phase 3: 능동 점검 중 네트워크 죽음 감지 → 완료 서비스까지 체크포인트 + interrupted 저장.
            # (Phase 2: completed_hosts 를 함께 저장 → 재개 시 나머지 서비스만 점검)
            try:
                await save_checkpoint(scan_id, {"stage": "url_discovery",
                                                "completed_hosts": _ap_done,
                                                "host_results": host_results,
                                                "budget_min": (SCAN_BUDGET.get(scan_id) or {}).get("total_min", 0)})
            except Exception:
                pass
            await update_scan_record(scan_id, "interrupted", results=host_results)
            _set_progress(scan_id, stage="interrupted", stage_label="중단(재개 가능)",
                          done=True, message=str(_si))
            await send({"type": "error",
                        "message": f"네트워크 중단 감지 — 스캔을 '재개 가능'으로 저장했습니다. "
                                   f"목록에서 ▶ 재개로 이어받으세요. ({_si})"})
            await send({"type": "scan_complete", "scan_id": scan_id})
            SCAN_STATE.pop(scan_id, None)
            return
        except Exception as e:
            await send({"type": "warning", "message": f"능동 취약점 점검 오류 (무시): {e}"})

    # ── 1.9단계: IDOR 교차 계정 검증 (계정 B 설정 시에만, 읽기 전용·비파괴) ──────────
    idor_verification = None
    try:
        # 계정 B(교차검증용 2번째 계정)가 이 스캔의 인증정보에 있을 때만 수행
        if (_scan_auth.get("username_b") and _scan_auth.get("password_b")
                and _scan_auth.get("login_url")):
            # 능동 점검에서 수집된 IDOR 후보(GET 객체참조)를 모은다
            _idor_cands = []
            for hr in host_results:
                for svc in hr.get("services", []):
                    ap = svc.get("active_probes")
                    if isinstance(ap, dict):
                        _ic = ap.get("idor_candidate") or {}
                        _idor_cands.extend(_ic.get("candidates") or [])
            if _idor_cands:
                import authenticated_scan as _auth
                from probes.config import ScanConfig as _SC
                _vcfg = _apply_auth_to_scanconfig(_SC.from_env(), _scan_auth)
                await send({"type": "info", "message": f"IDOR 교차검증 시작 — 후보 {len(_idor_cands)}건(읽기 전용)"})
                _idor_base = _derive_base_root(host_results, domain)
                idor_verification = await _auth.verify_idor_dual_account(_vcfg, _idor_base, _idor_cands)
                _sm = idor_verification.get("summary", {})
                await send({"type": "info",
                            "message": f"IDOR 교차검증 완료 — 검증 {_sm.get('verified',0)}건 / "
                                       f"승격 {_sm.get('promoted',0)}건 / 수동검토 {_sm.get('manual_review',0)}건"})
    except Exception as e:
        await send({"type": "warning", "message": f"IDOR 교차검증 오류 (무시): {e}"})

    # ── 1.95단계: 쓰기 권한(BAC on WRITE) 검증 + CSRF 탐지 ──────────────────────────
    #   본인 소유 테스트 계정 A/B 로만, '수정-후-원복'(비파괴)으로 "B 가 A 소유 데이터를
    #   수정할 수 있는가"를 검증한다. 제3자 데이터는 절대 건드리지 않는다. 삭제 기본 미수행.
    #   ENABLE_WRITE_AUTHZ_TESTS=true + A(username/password) 자격증명 필요(없으면 생략).
    #   CSRF 는 요청 전송 없이 폼 토큰/SameSite 부재를 정적 탐지한다.
    write_authz_verification = None
    _csrf_findings = []
    try:
        import os as _os2
        if (_os2.getenv("ENABLE_WRITE_AUTHZ_TESTS", "false").strip().lower()
                in ("1", "true", "yes", "on")
                and _scan_auth.get("username") and _scan_auth.get("password")
                and _scan_auth.get("login_url")):
            import authenticated_scan as _auth2
            import authz_write as _aw
            from probes.config import ScanConfig as _SC2
            _wcfg = _apply_auth_to_scanconfig(_SC2.from_env(), _scan_auth)
            _wbase_root = _wcfg.auth_login_url or f"https://{domain}"
            # 계정 A 로 인증 크롤 → 상태변경 폼 수집(쓰기 후보 + CSRF 분석 입력)
            await send({"type": "info", "message": "[쓰기 권한] 인증 후 상태변경 폼 수집 중..."})
            _acr = await _auth2.perform_login_and_crawl(_wcfg, _wbase_root)
            _forms = _acr.get("forms") or []
            # CSRF 정적 탐지(요청 전송 없음)
            try:
                _csrf_findings = _aw.analyze_csrf(_forms, cookies=[])
                if _csrf_findings:
                    await send({"type": "warning",
                                "message": f"CSRF 방어 부재 가능성 {len(_csrf_findings)}건(정적 탐지)"})
            except Exception:
                _csrf_findings = []
            # 쓰기 권한 교차검증(수정-후-원복) — A/B 두 계정 필요
            _cands = _aw.gather_write_candidates(host_results, _forms)
            if _cands and _scan_auth.get("username_b") and _scan_auth.get("password_b"):
                await send({"type": "info",
                            "message": f"[쓰기 권한] A/B 교차검증 시작 — 후보 {len(_cands)}건(수정 후 원복)"})
                write_authz_verification = await _auth2.verify_write_authz_dual_account(
                    _wcfg, _wbase_root, _cands)
                _ws = write_authz_verification.get("summary", {})
                await send({"type": "info",
                            "message": f"[쓰기 권한] 완료 — 검증 {_ws.get('tested',0)}건 / "
                                       f"실증 {_ws.get('confirmed',0)}건 / 가능성 {_ws.get('possible',0)}건"})
            elif _cands:
                await send({"type": "info",
                            "message": "[쓰기 권한] 계정 B 미설정 — 교차검증 생략(CSRF 정적 탐지만 수행)"})
    except Exception as _we:
        await send({"type": "warning", "message": f"쓰기 권한 검증 (무시): {_we}"})

    # ── 1.97단계: BFLA(함수 수준 인가) 매트릭스 검증 ─────────────────────────────
    #   관리/특권 엔드포인트에 익명·낮은 권한(계정 B)이 접근 가능한지 '읽기 전용(GET)'으로 관측.
    #   상태 변경 없음(SAFE). 익명 강제 브라우징은 자격증명 없이도 수행, A/B 있으면 매트릭스 확장.
    #   ENABLE_BFLA_TESTS=true 필요. 권한 등급은 AUTH_A_ROLE/AUTH_B_ROLE(선택)로 판정 정밀도↑.
    bfla_verification = None
    try:
        import os as _os3
        # BFLA 기본 ON: 익명 강제 브라우징은 SAFE(읽기전용 GET)이며, 특권 엔드포인트가
        # 익명/저권한에 노출되는지 관측한다(계정 A/B 있으면 매트릭스 확장). 끄려면 =false.
        if _os3.getenv("ENABLE_BFLA_TESTS", "true").strip().lower() in ("1", "true", "yes", "on"):
            import authz_matrix as _am
            # ④ 성숙화: OpenAPI 스펙/swagger 가 노출한 admin·auth 엔드포인트를 매트릭스 대상에 추가
            # (스펙 흡수 → 역할별 인가 매트릭스로 더 많은 특권 엔드포인트를 A/B/익명 교차 검증)
            _extra_priv: list = []
            for _hr in host_results:
                for _svc in _hr.get("services", []):
                    _ap = _svc.get("active_probes")
                    if not isinstance(_ap, dict):
                        continue
                    _sw = _ap.get("swagger_openapi")
                    _summ = (_sw.get("api_summary") if isinstance(_sw, dict) else None) or {}
                    _host = _hr.get("host", "")
                    _port = _svc.get("port", 0)
                    _sch = "https" if (_svc.get("ssl_info") or _port in (443, 8443)) else "http"
                    # admin 엔드포인트만 공급(auth/payment/user 는 공개 API 인 경우가 많아 BFLA 오탐 유발).
                    # 실제 특권 여부는 gather_privileged_endpoints 의 is_privileged 가 재차 필터링.
                    for _e in (_summ.get("admin_endpoints") or []):
                        _path = str(_e).split(" ", 1)[-1] if " " in str(_e) else str(_e)
                        if _path.startswith("/"):
                            _extra_priv.append(f"{_sch}://{_host}:{_port}{_path}")
            _bfla_eps = _am.gather_privileged_endpoints(host_results, extra_urls=_extra_priv or None)
            if _bfla_eps:
                import authenticated_scan as _auth3
                from probes.config import ScanConfig as _SC3
                # BFLA 는 익명 강제 브라우징은 무자격도 수행, A/B 있으면 매트릭스 확장(per-scan 인증)
                _bcfg = _apply_auth_to_scanconfig(_SC3.from_env(), _scan_auth)
                _bbase = _bcfg.auth_login_url or _derive_base_root(host_results, domain)
                await send({"type": "info",
                            "message": f"[BFLA] 인가 매트릭스 검증 시작 — 특권 엔드포인트 {len(_bfla_eps)}개(읽기 전용)"})
                bfla_verification = await _auth3.verify_bfla_matrix(_bcfg, _bbase, _bfla_eps)
                _bs = bfla_verification.get("summary", {})
                await send({"type": "info",
                            "message": f"[BFLA] 완료 — 검증 {_bs.get('tested',0)}건 / "
                                       f"실증 {_bs.get('confirmed',0)}건 / 가능성 {_bs.get('possible',0)}건"})
    except Exception as _be:
        await send({"type": "warning", "message": f"BFLA 검증 (무시): {_be}"})

    # 중지/일시정지 체크포인트 (능동 점검 완료) — 여기까지면 취약점 후보가 수집되어 부분 보고 의미 있음
    SCAN_STATE[scan_id] = {"host_results": host_results, "domain": domain}
    await _wait_if_paused(scan_id, send)
    if _is_cancelled(scan_id):
        await _finalize_partial(scan_id, domain, send)
        return

    # ── 3단계: 외부 도구 심층 점검 (External Tools) ──────────────────────────────
    await send({
        "type": "stage",
        "stage": "external_scan",
        "message": "[외부 도구] testssl.sh · nuclei · ffuf · katana · ghauri 심층 점검 중...",
    })

    external_findings = []
    try:
        async def _ext_progress(msg: str):
            await send({"type": "info", "message": msg})

        if _ext_offload_findings is not None:
            # 하이브리드: i7 에서 능동점검과 병렬로 이미 수행됨 → 로컬 재실행 생략(중복 방지).
            external_findings = _ext_offload_findings
            await send({"type": "info",
                        "message": f"외부 도구 점검 완료(i7 병렬) — {len(external_findings)}건 발견"})
        else:
            external_findings = await run_all_external_tools(
                host_results, scan_id=scan_id, progress_cb=_ext_progress
            )
            await send({"type": "info", "message": f"외부 도구 점검 완료 — {len(external_findings)}건 발견"})
    except Exception as e:
        await send({"type": "warning", "message": f"외부 도구 점검 오류 (무시): {e}"})

    # 외부도구 실행 상태를 산출해 리포트 산출물(analysis)에 정직하게 기록한다.
    # (예전엔 미실행/미설치가 일시적 진행 로그에만 있고 최종 리포트엔 없었음 — 정직성 갭)
    try:
        _avail = available_tools()
        import external_tools as _et
        _has_ssl = any(svc.get("port") in (443, 8443) or "https" in str(svc.get("service", "")).lower()
                       for hr in host_results for svc in hr.get("services", []))
        _ran_tools = set()
        for _f in (external_findings or []):
            for _t in (_f.get("tools") or ([_f.get("tool_source")] if _f.get("tool_source") else [])):
                if _t:
                    _ran_tools.add(str(_t).lower())

        def _tool_status(name: str, *, flag_ok: bool = True, applicable: bool = True) -> dict:
            if not flag_ok:
                return {"status": "disabled", "label": "정책 비활성(플래그 off)"}
            if not _avail.get(name, False):
                return {"status": "missing", "label": "미설치(건너뜀)"}
            if not applicable:
                return {"status": "not_applicable", "label": "대상 없음"}
            if name in _ran_tools:
                return {"status": "ran", "label": "실행됨(결과 반영)"}
            return {"status": "available", "label": "실행 시도(결과 없음/대상 제한)"}

        _sqlmap_on = _et._sqlmap_enabled()
        # analysis 는 뒤 lateral_movement 단계에서 생성되므로 여기서는 로컬 변수에 담아두고
        # analysis 생성 후 부착한다(예전엔 미생성 analysis 참조로 조용히 실패했음).
        _ext_tools_status = {
            "sqlmap":  _tool_status("sqlmap", flag_ok=_sqlmap_on),
            "nuclei":  _tool_status("nuclei"),
            "testssl": _tool_status("testssl", applicable=_has_ssl),
            "wpscan":  _tool_status("wpscan"),
        }
    except Exception as _ets_e:
        _ext_tools_status = {}
        print(f"[external_tools_status] 산출 오류(무시): {_ets_e}", flush=True)

    # 중지/일시정지 체크포인트 (외부 도구 완료)
    SCAN_STATE[scan_id] = {"host_results": host_results, "domain": domain}
    await _wait_if_paused(scan_id, send)
    if _is_cancelled(scan_id):
        await _finalize_partial(scan_id, domain, send)
        return

    # ── 4단계: 시스템 침투 (Initial Penetration) — 스크린샷 ──────────────────────
    await send({
        "type": "stage",
        "stage": "penetration",
        "message": f"[시스템 침투] HTTP 서비스 {http_service_count}개 스크린샷 캡처 중...",
    })
    if http_service_count > 0:
        try:
            host_results = await capture_screenshots_for_scan(scan_id, host_results)
        except Exception as e:
            await send({"type": "warning", "message": f"스크린샷 캡처 오류 (무시): {e}"})

    # ── 5단계: 공격 횡이동 분석 (Lateral Movement) ───────────────────────────────
    lateral_msg = "[공격 횡이동] 취약점 분석 및 공격 체인 평가"
    if deep_mode:
        lateral_msg += f" (이전 {scan_count}회 이력 비교)"
    await send({"type": "stage", "stage": "lateral_movement", "message": lateral_msg + "..."})

    try:
        analysis = analyze_with_rules(
            host_results,
            previous_scans=previous_scans if deep_mode else None,
            domain_notes=domain_notes,
        )

        # 외부도구 실행 상태(external_scan 단계에서 산출)를 이제 생성된 analysis 에 부착 → 리포트에 노출.
        try:
            if _ext_tools_status:
                analysis["external_tools_status"] = _ext_tools_status
        except NameError:
            pass

        # 외부 도구 발견 결과 병합 (도구별 중복 제거 + 경로 기준 통합)
        if external_findings:
            analysis["findings"] = merge_external_findings(
                analysis["findings"], external_findings
            )

        # ── JWT 오프라인 취약점 분석(alg=none·약한 시크릿 크랙·민감 클레임·만료) ──
        # 입력: 브라우저 발견 워커(선택) + 일반 크롤 쿠키/헤더 하베스트(항상) — 후자로 기본 스캔에서도 동작.
        try:
            _jwt_inputs = list(_jwt_candidates or []) + _harvest_jwt_texts(host_results)
            if _jwt_inputs:
                import jwt_analyzer as _ja
                _jwtf = _ja.analyze(_jwt_inputs, source="크롤 쿠키/헤더")
                if _jwtf:
                    analysis.setdefault("findings", []).extend(_jwtf)
                    await send({"type": "info",
                                "message": f"🔐 JWT 분석: {len(_jwtf)}건 발견"})
        except Exception as _jwt_e:
            print(f"[jwt_analyzer] 오류(무시): {_jwt_e}", flush=True)

        # ── 화이트박스 소스 SQLi 정적 분석(EOSEUREUM_SOURCE_ROOT 지정 시) ──
        # 기존엔 USE_PROBE_ORCHESTRATOR=true 경로에만 연결돼 기본 스캔에서 미가동이었다.
        # source_root 만 지정되면 기본 파이프라인에서도 직접 수행(비파괴·정적 분석).
        try:
            _src_root = (os.getenv("EOSEUREUM_SOURCE_ROOT", "") or "").strip()
            if _src_root and os.getenv("ENABLE_SOURCE_SQLI", "true").lower() in ("1", "true", "yes"):
                _srcf = _run_source_sqli(_src_root)
                if _srcf:
                    analysis.setdefault("findings", []).extend(_srcf)
                    await send({"type": "info",
                                "message": f"🔎 화이트박스 소스 SQLi: {len(_srcf)}건 (정적 분석)"})
        except Exception as _src_e:
            print(f"[source_sqli] 오류(무시): {_src_e}", flush=True)

        # ── 서브도메인 탈취 탐지(CNAME 미클레임 지문) — best-effort/SAFE ──
        # 시드: 대상 호스트 + 크롤로 발견한 동일 등록도메인 하위 호스트(자기 호스트 1개뿐 문제 보정).
        try:
            _takeover_seeds = _subdomain_seeds_from_scan(host_results, _scan_host_name) or subdomains
            _sub_infos = await _collect_subdomain_takeover_info(_takeover_seeds)
            if _sub_infos:
                import subdomain_takeover as _sdt
                _sdtf = _sdt.analyze(_sub_infos)
                if _sdtf:
                    analysis.setdefault("findings", []).extend(_sdtf)
                    await send({"type": "info",
                                "message": f"🌐 서브도메인 탈취 점검: {len(_sdtf)}건 발견"})
        except Exception as _sdt_e:
            print(f"[subdomain_takeover] 오류(무시): {_sdt_e}", flush=True)

        # IDOR 교차검증 결과 → 승격 항목을 finding 으로 주입(CONFIRMED_RESPONSE/POSSIBLE만).
        # MANUAL_REVIEW 는 기존 idor_candidate(참고)로 이미 보고되므로 중복 추가하지 않는다.
        if idor_verification and idor_verification.get("results"):
            _grade_bucket = {"CONFIRMED_RESPONSE": "vulnerability", "POSSIBLE": "attack_surface"}
            _grade_sev = {"CONFIRMED_RESPONSE": "HIGH", "POSSIBLE": "MEDIUM"}
            for _vr in idor_verification["results"]:
                _g = _vr.get("grade")
                if _g not in _grade_bucket:
                    continue
                _cd = _vr.get("candidate") or {}
                analysis.setdefault("findings", []).append({
                    "host": domain, "port": 0, "service": "http",
                    "judgment": "취약" if _g == "CONFIRMED_RESPONSE" else "참고",
                    "severity": _grade_sev[_g], "confidence": _g,
                    "force_finding_type": _grade_bucket[_g],
                    "owasp": "A01:2021 - 접근 제어 취약점", "cwe": "CWE-639",
                    "title": (f"IDOR {'실증(응답 기반)' if _g=='CONFIRMED_RESPONSE' else '가능성'} — "
                              f"교차 계정 접근 검증"),
                    "description": ("두 테스트 계정(A/B)으로 동일 객체를 교차 접근해 응답을 비교했습니다. "
                                    + " ".join(_vr.get("reasons") or [])),
                    "evidence_url": _cd.get("url", ""),
                    "evidence_detail": " / ".join(_vr.get("reasons") or []),
                    "detection_steps": [
                        f"계정 A 로 객체 접근: {_cd.get('url','')}",
                        "계정 B 세션으로 동일 URL 접근(읽기 전용)",
                        f"응답 비교 신호: {_vr.get('signals')}",
                    ],
                    "recommendation": ("객체 접근 시 세션 사용자의 소유/권한을 서버에서 검증하십시오."),
                    "is_verified_idor": True,
                })
            analysis["candidate_verification"] = {
                "idor": idor_verification.get("summary", {}),
                "idor_performed": idor_verification.get("performed", False),
                "idor_reason": idor_verification.get("reason", ""),
            }

        # ── 쓰기 권한(BAC on WRITE) 검증 결과 + CSRF 탐지 → finding 주입 ──
        # CONFIRMED_WRITE → 취약(HIGH), POSSIBLE → 참고(MEDIUM). 판정 근거는 '수정-후-원복' 실증.
        if _csrf_findings:
            analysis.setdefault("findings", []).extend(_csrf_findings)
        if write_authz_verification and write_authz_verification.get("results"):
            _wgrade_bucket = {"CONFIRMED_WRITE": "vulnerability", "POSSIBLE": "attack_surface"}
            _wgrade_sev = {"CONFIRMED_WRITE": "HIGH", "POSSIBLE": "MEDIUM"}
            for _wr in write_authz_verification["results"]:
                _wg = _wr.get("grade")
                if _wg not in _wgrade_bucket:
                    continue
                _wc = _wr.get("candidate") or {}
                analysis.setdefault("findings", []).append({
                    "host": domain, "port": 0, "service": "http",
                    "judgment": "취약" if _wg == "CONFIRMED_WRITE" else "참고",
                    "severity": _wgrade_sev[_wg], "confidence": _wg,
                    "force_finding_type": _wgrade_bucket[_wg],
                    "owasp": "A01:2021 - 접근 제어 취약점", "cwe": "CWE-639",
                    "title": (f"쓰기 권한 통제 실패 — 타 계정이 소유자 데이터 수정 "
                              f"({'실증' if _wg == 'CONFIRMED_WRITE' else '가능성'})"),
                    "description": ("본인 소유 테스트 계정 A/B 로 '수정-후-원복'(비파괴) 검증을 수행했습니다. "
                                    f"계정 B 로 계정 A 소유 객체({_wc.get('url','')})의 필드 "
                                    f"'{_wc.get('field','')}' 수정을 시도했습니다. " + (_wr.get("reason") or "")),
                    "evidence_url": _wc.get("url", ""),
                    "evidence_detail": (f"method={_wc.get('method','')} · B응답={_wr.get('b_status')} · "
                                        f"A재조회 마커반영={_wr.get('readback_marker')} · 원복={_wr.get('reverted')}"),
                    "detection_steps": [
                        f"계정 A 로 객체 소유/접근 확인: {_wc.get('url','')}",
                        f"계정 B 세션으로 '{_wc.get('field','')}' 필드 수정 시도(고유 마커)",
                        "계정 A 재조회로 마커 반영 여부 확인",
                        "계정 A 가 원본값으로 원복(비파괴)",
                    ],
                    "recommendation": ("객체 수정/삭제 시 세션 사용자의 소유·권한을 서버에서 강제하십시오"
                                       "(오브젝트 수준 접근 제어). 클라이언트 식별자만 신뢰하지 마십시오."),
                    "discovered_by": "write_authz_dual_account",
                })
            analysis.setdefault("candidate_verification", {}).update({
                "write_authz": write_authz_verification.get("summary", {}),
                "write_authz_performed": write_authz_verification.get("performed", False),
                "write_authz_reason": write_authz_verification.get("reason", ""),
            })

        # ── BFLA(함수 수준 인가) 매트릭스 결과 → finding 주입 ──
        # CONFIRMED → 취약(missing_auth: HIGH, bfla: HIGH), POSSIBLE → 참고(MEDIUM).
        if bfla_verification and bfla_verification.get("results"):
            # BFLA 결과를 (카테고리, 등급)별로 '한 건'으로 병합한다 — 엔드포인트마다 별도 finding 을
            # 만들면 동일 취약점이 수십 건 중복되어 노이즈·오탐처럼 보인다(엔드포인트는 목록으로 나열).
            _bfla_groups: dict = {}
            for _br in bfla_verification["results"]:
                _bg = _br.get("grade")
                if _bg not in ("CONFIRMED", "POSSIBLE"):
                    continue
                _cat = _br.get("category", "")
                _key = (_cat, _bg)
                _bfla_groups.setdefault(_key, []).append(_br)
            for (_cat, _bg), _brs in _bfla_groups.items():
                _missing_auth = (_cat == "missing_auth")
                _cwe = "CWE-306" if _missing_auth else "CWE-285"
                _eps = []
                for _br in _brs:
                    _u = (_br.get("endpoint") or {}).get("url", "")
                    if _u and _u not in _eps:
                        _eps.append(_u)
                _steps = [f"익명={_br.get('anon')} · B={_br.get('b')} · A={_br.get('a')} · {(_br.get('endpoint') or {}).get('url','')}"
                          for _br in _brs[:8]]
                analysis.setdefault("findings", []).append({
                    "host": domain, "port": (_scn.parse_target(domain).get("port") or 0), "service": "http",
                    "judgment": "취약" if _bg == "CONFIRMED" else "참고",
                    "severity": "HIGH" if _bg == "CONFIRMED" else "MEDIUM",
                    "confidence": _bg,
                    "force_finding_type": "vulnerability" if _bg == "CONFIRMED" else "attack_surface",
                    "owasp": "A01:2021 - 접근 제어 취약점", "cwe": _cwe,
                    "title": (("인증 없이 관리/특권 기능 접근(Missing Function-Level Auth)"
                               if _missing_auth else "함수 수준 인가 실패(BFLA) — 낮은 권한의 특권 기능 접근")
                              + (f" {'실증' if _bg == 'CONFIRMED' else '가능성'}")
                              + (f" — 엔드포인트 {len(_eps)}개" if len(_eps) > 1 else "")),
                    "description": (f"특권 엔드포인트 {len(_eps)}개에 대한 익명/계정B/계정A 접근을 읽기 전용으로 "
                                    f"비교했습니다. " + (_brs[0].get("reason") or "")),
                    "evidence_url": _eps[0] if _eps else "",
                    "affected_endpoints": _eps[:20],
                    "evidence_detail": "영향 엔드포인트:\n" + "\n".join(f"- {u}" for u in _eps[:20]),
                    "detection_steps": _steps,
                    "recommendation": ("모든 관리/특권 기능에 서버 측 함수 수준 인가(역할·권한 검증)를 "
                                       "적용하십시오. 클라이언트 은닉(메뉴 숨김)만으로는 통제되지 않습니다."),
                    "discovered_by": "bfla_matrix",
                })
            analysis.setdefault("candidate_verification", {}).update({
                "bfla": bfla_verification.get("summary", {}),
                "bfla_performed": bfla_verification.get("performed", False),
                "bfla_matrix": bfla_verification.get("matrix", {}),
            })

        # ── 반복 재크롤/재점검 (ENABLE_ITERATIVE_RECRAWL=true 일 때만, 기본 off) ──
        # 1차 스캔(발견→점검→룰엔진)이 끝난 뒤, 정규화/후처리(리포트) 직전에:
        # 취약점(인증 우회 등)으로 새로 열린 경로 + 인증 이후 경로를 추가 크롤하고
        # '새 경로만' 재점검해 새 finding 을 병합한다. AI 가 라운드마다 '크롤 필요?'를
        # 판단하되, 라운드 상한(5~10)+수렴(새 URL 없음)+시간예산으로 무한루프가 불가능하다.
        try:
            import iterative_recrawl as _irc
            # 허용 시간이 지정되면(SCAN_BUDGET) 남은 시간만큼 심층 반복 재크롤을 강제 활성화한다.
            _bud = SCAN_BUDGET.get(scan_id)
            if _irc.enabled() or _bud:
                _tb_override = _mr_override = None
                if _bud:
                    import time as _trc
                    _remain = _bud["deadline_ts"] - _trc.time()
                    # 남은 시간의 85%를 재크롤에 배정(15%는 정규화·보고서 여유), 최소 60초.
                    _tb_override = max(60, int(_remain * 0.85))
                    _mr_override = 30   # 시간이 허용하는 한 라운드 상한 확대
                    await send({"type": "info",
                                "message": (f"[반복 재크롤] 허용 시간 연동 — 재크롤 예산 약 "
                                            f"{_tb_override // 60}분, 최대 {_mr_override}회 심층 반복")})
                # 단계 표기: 재크롤은 '추가 점검'(스캐닝)이지 분석이 아니다 — 명확히 분리.
                await send({"type": "stage", "stage": "recrawl",
                            "message": "[추가 점검] 새 경로·인증 영역 재크롤 및 재점검(수렴까지)..."})
                # 하이브리드: 재크롤 라운드마다 i7 외부도구를 병렬 재오프로드(2칸 재분기)하도록 콜백 주입.
                _recrawl_ext_offload = (
                    (lambda _hr: _offload_external_tools_i7(scan_id, domain, _hr, {}, send))
                    if _hybrid_enabled() else None)
                await _irc.run(host_results, analysis, scan_id, domain,
                               send=send, domain_notes=domain_notes, auth=_scan_auth,
                               time_budget_sec_override=_tb_override,
                               max_rounds_override=_mr_override,
                               exclude_patterns=SCAN_EXCLUDE.get(scan_id) or [],
                               ext_offload=_recrawl_ext_offload,
                               merge_external_fn=merge_external_findings)
                # 재크롤 수렴 → 분석·보고서 생성 단계로 복귀(라벨 정정).
                await send({"type": "stage", "stage": "lateral_movement",
                            "message": "🔗 모든 점검 수렴 — 결과 합쳐 분석·보고서 생성 시작..."})
                # 반복 재크롤의 인증 크롤 결과를 커버리지로 승격(step1.7 스킵 시 auth_login_success/
                # authenticated_pages 가 None/0 으로 오표기되던 문제 보정 — 커버리지 정직성).
                _acr = analysis.pop("_auth_crawl_result", None)
                if _acr:
                    SCAN_STATE.setdefault(scan_id, {})["auth"] = {
                        "enabled": True,
                        "login_success": _acr.get("login_success"),
                        "pages": _acr.get("pages", 0),
                        "reason": _acr.get("reason") or "",
                    }
        except Exception as _irce:
            await send({"type": "warning", "message": f"반복 재크롤 (무시): {_irce}"})

        # 중앙 정규화: 실제 취약점 / 참고 발견 / 양호 / 노이즈 분리 + summary
        # (보고서·UI의 취약점 수와 항목이 이 결과로 단일화된다)
        _norm = normalize_findings(analysis.get("findings", []))
        analysis["findings"] = _norm["findings"]            # 취약점만
        analysis["attack_surface_items"] = _norm["attack_surface_items"]
        analysis["discovery_items"] = _norm["discovery_items"]
        analysis["good_items"] = _norm["good_items"]
        analysis["noise_items"] = _norm["noise_items"]
        analysis["summary"] = _norm["summary"]

        # ── S3 패시브 감사(추가 요청 0) — safe 모드 응답 캐시 코퍼스로 하드닝 미흡 통합 검출 ──
        # 이미 능동 프로브가 다루는 항목(클릭재킹/CSRF/버전노출)은 제외, '참고(discovery)'로만 분류.
        try:
            import response_cache as _rc1
            _cache = _rc1.current()
            if _cache is not None:
                import passive_audit as _pa
                _corpus = _cache.snapshot()
                _pa_base = domain if "://" in domain else "http://" + domain
                _passive_items = _pa.audit(_corpus, base_url=_pa_base)
                if _passive_items:
                    analysis.setdefault("discovery_items", []).extend(_passive_items)
                    if isinstance(analysis.get("summary"), dict):
                        analysis["summary"]["discovery_count"] = len(
                            analysis.get("discovery_items") or [])
                    _cst = _cache.stats()
                    await send({"type": "info",
                                "message": (f"🔎 패시브 감사 — 하드닝 미흡 {len(_passive_items)}건"
                                            f"(추가 요청 0). 응답 캐시로 아낀 요청 {_cst.get('saved_requests', 0)}건"
                                            f"(적중률 {int(_cst.get('hit_rate', 0)*100)}%)")})
        except Exception as _pae:
            print(f"[passive_audit] 스킵(무시): {_pae}")

        # 각 취약점 Finding 에 '안정적' 고유 식별자 부여(finding_uid). Proof/KG/Report/HTML 이
        # 모두 이 값으로 자기 자신의 evidence/proof/fingerprint 만 매핑한다(교차 오염 방지).
        for _i, _f in enumerate(analysis.get("findings") or [], 1):
            if isinstance(_f, dict) and not _f.get("finding_uid"):
                _f["finding_uid"] = f"F{_i}"

        # 오탐 억제(자문) — soft-404/WAF/동적콘텐츠/비실행 반사 위험을 finding 에 표기(판정 불변).
        try:
            import false_positive_filter as _fpf
            analysis["fp_risk_summary"] = _fpf.annotate(analysis).get("fp_risk_summary")
        except Exception:
            pass

        # ── Browser Discovery 2.0 결과를 보고서 analysis 에 반영 ──────────────────
        # (입력점은 이미 능동 점검 前에 등록되어 점검·입력점 기록에 반영됨. 여기선 보고서용.)
        try:
            if _bd_merged is not None:
                import discovery_worker as _dw
                _dw.apply_to_analysis(analysis, _bd_merged)
        except Exception as _bda_e:
            print(f"[browser_discovery] apply_to_analysis 오류(무시): {_bda_e}", flush=True)

        # AI 서술 브리지(동기 ai_fn) — ENABLE_AI_ANALYSIS 시에만. 스캔당 호출 예산 공유(폭주 방지),
        # 실패/예산소진 시 "" → 각 빌더의 결정적 백스톱 유지(판정·증거 불변). None 이면 미주입과 동일.
        _ai_fn = None
        _ai_fn_poc = None
        if os.getenv("ENABLE_AI_ANALYSIS", "false").strip().lower() in ("true", "1", "yes"):
            try:
                # 역할→모델 라우팅(ai_roles.json). 분석/계획=analysis 역할, PoC=poc(코드 특화) 역할.
                # 모델 없으면 자동 폴백 → 단일 모델 환경에서도 동일 동작.
                _ai_fn = make_sync_ai_fn(role="analysis")
                _ai_fn_poc = make_sync_ai_fn(role="poc")
            except Exception:
                _ai_fn = None
                _ai_fn_poc = None

        # ── Attack Surface Planner → AI Payload Planner (계획·검증·우선순위, 실행 없음) ──
        # 1) 입력점 의미/공격표면 분석·점수화 → 예산(budget) 내 상위 표면 선별(Probe 최적화)
        # 2) 선별 표면만 AI Payload Planner 로 전달. AI 는 후보 제안만, 판정은 Rule Engine.
        try:
            import attack_surface_planner as _asp
            import ai_exploit_planning as _aep
            from active_probing import get_input_points as _gip
            _ips = _gip(scan_id)   # Browser Discovery 입력점은 능동 점검 단계에서 이미 병합·기록됨
            if _ips:
                try:
                    _budget = max(0, int(os.getenv("ATTACK_SURFACE_BUDGET", "0")))
                except (TypeError, ValueError):
                    _budget = 0
                _surface = _asp.plan_attack_surface(_ips, budget=_budget)
                analysis["attack_surface_plan"] = _surface
                _sel = _asp.selected_points(_surface, _ips) or _ips
                # ai_fn 주입 시 워커 스레드에서 실행(ai_fn 이 asyncio.run 을 돌리므로).
                if _ai_fn:
                    _ai_plan = await asyncio.to_thread(_aep.build_plan, _sel, ai_fn=_ai_fn)
                else:
                    _ai_plan = _aep.build_plan(_sel)   # 결정적 안전 베이스라인
                _aep.merge_executed_verdicts(
                    _ai_plan, _norm["findings"],
                    _norm.get("attack_surface_items"), _norm.get("discovery_items"))
                analysis["ai_payload_plan"] = _ai_plan
        except Exception as _aep_e:
            await send({"type": "warning", "message": f"Attack Surface/AI Planner 오류 (무시): {_aep_e}"})

        # ── ⑤ AI 비즈니스 로직 가설(SAFE·advisory) ────────────────────────────
        # 자동 프로브가 못 잡는 로직 취약점(가격조작·워크플로우회 등)을 AI 가 '가설'로 제시.
        # MANUAL_REVIEW 항목으로만 표면화 — 확정 판정/개수/severity 불변.
        try:
            if (_ai_fn and os.getenv("ENABLE_AI_BIZLOGIC", "true").strip().lower()
                    in ("1", "true", "yes", "on")
                    and os.getenv("ENABLE_AI_ANALYSIS", "false").lower() in ("true", "1", "yes")):
                import business_logic_ai as _bla
                _biz = await asyncio.to_thread(_bla.analyze, analysis, _ai_fn, host_results)
                if _biz:
                    analysis.setdefault("discovery_items", []).extend(_biz)
                    analysis["ai_business_logic_count"] = len(_biz)
                    await send({"type": "info",
                                "message": f"🧠 AI 비즈니스 로직 가설 {len(_biz)}건 제시(수동 검증 권장 · 확정 아님)"})
        except Exception as _bla_e:
            await send({"type": "warning", "message": f"AI 비즈니스 로직 분석 (무시): {_bla_e}"})

        # ── 증거 중심 검증 수준(Level 0~3) 요약 ──────────────────────────────
        try:
            import evidence_levels as _evl
            analysis["evidence_levels"] = _evl.summarize_levels(
                _norm["findings"], _norm.get("attack_surface_items"),
                _norm.get("discovery_items"), _norm.get("good_items"))
        except Exception:
            pass

        # ── Attack Graph Engine: 기존 Evidence/Rule Engine 결과를 공격 경로로 연결 ──
        # 새 공격 실행 없음. 경로 존재/신뢰도는 증거 수준 기반(AI 는 설명만 보강).
        try:
            import attack_graph as _ag
            if _ai_fn:
                _graph = await asyncio.to_thread(_ag.build_attack_graph, analysis, ai_fn=_ai_fn)
            else:
                _graph = _ag.build_attack_graph(analysis)   # 결정적 설명
            analysis["attack_graph"] = _graph.get("attack_graph")
            analysis["attack_nodes"] = _graph.get("attack_nodes")
            analysis["attack_edges"] = _graph.get("attack_edges")
            analysis["attack_paths"] = _graph.get("attack_paths")
            analysis["attack_path_summary"] = _graph.get("attack_path_summary")
        except Exception as _ag_e:
            await send({"type": "warning", "message": f"Attack Graph Engine 오류 (무시): {_ag_e}"})

        # ── Attack Path Prioritizer → Solver Orchestrator → Evidence Correlation ──
        # 우선순위 경로에만 Solver 배정(신규 탐색 없음). Solver 는 Level 변경 불가.
        try:
            import attack_path_prioritizer as _app
            import solver_orchestrator as _so
            import evidence_correlation as _ec
            try:
                _max_paths = max(0, int(os.getenv("SOLVER_MAX_PATHS", "5")))
            except (TypeError, ValueError):
                _max_paths = 5
            try:
                _max_solvers = max(0, int(os.getenv("SOLVER_MAX_RUNS", "5")))
            except (TypeError, ValueError):
                _max_solvers = 5
            _prio = _app.prioritize(
                analysis.get("attack_paths") or [],
                (analysis.get("attack_graph") or {}).get("nodes") or [],
                max_paths=_max_paths)
            analysis["prioritized_paths"] = _prio.get("selected")
            analysis["path_priority_summary"] = _prio.get("summary")
            _solv = _so.run_solvers(_prio, analysis, max_solvers=_max_solvers)
            analysis["solver_results"] = _solv.get("results")
            _corr = _ec.correlate(analysis)
            analysis["evidence_chains"] = _corr.get("chains")
            # 최소 보고 저장(이번 단계: 전체 개편 없이 수치만)
            analysis["solver_summary"] = {
                "total_attack_paths": (analysis.get("attack_path_summary") or {}).get("total_paths", 0),
                "prioritized_paths": _prio.get("summary", {}).get("prioritized_paths", 0),
                "solver_runs": _solv.get("summary", {}).get("solver_runs", 0),
                "by_solver": _solv.get("summary", {}).get("by_solver", {}),
                "evidence_chains": _corr.get("summary", {}).get("evidence_chains", 0),
                "level_changes_by_solver": _solv.get("summary", {}).get("level_changes", 0),
                "discovery_runs_by_solver": _solv.get("summary", {}).get("discovery_runs", 0),
            }

            # ── Multi-Agent Solver → Evidence Graph Engine ──────────────────
            # Agent 는 기존 증거 해석·보강만(신규 탐색/Level 변경/판정 불가).
            try:
                from agents import agent_orchestrator as _ao
                import evidence_graph as _eg
                _agents_out = _ao.run_agents(_prio, _solv, analysis, max_paths=_max_paths)
                analysis["agent_results"] = _agents_out.get("results")
                analysis["agent_summary"] = _agents_out.get("summary")
                _egraph = _eg.build_evidence_graph(analysis, agent_out=_agents_out,
                                                   prioritized=_prio)
                analysis["evidence_graph"] = _egraph.get("evidence_graph")
                analysis["evidence_graph_nodes"] = _egraph.get("evidence_graph_nodes")
                analysis["evidence_graph_edges"] = _egraph.get("evidence_graph_edges")
                analysis["evidence_graph_summary"] = _egraph.get("evidence_graph_summary")
                # 최소 보고 수치 병합(이번 단계: 전체 개편 없이 수치만)
                _egs = _egraph.get("evidence_graph_summary") or {}
                analysis["solver_summary"].update({
                    "agent_runs": _agents_out.get("summary", {}).get("agent_runs", 0),
                    "agent_groups": _agents_out.get("summary", {}).get("by_group", {}),
                    "evidence_graph_nodes": _egs.get("total_nodes", 0),
                    "evidence_graph_edges": _egs.get("total_edges", 0),
                    "manual_review_nodes": _egs.get("manual_review_nodes", 0),
                    "blocked_action_nodes": _egs.get("blocked_actions", 0),
                    "top_recommendations": len(_egs.get("top_recommendations", []) or []),
                    "agent_level_changes": _agents_out.get("summary", {}).get("level_changes", 0),
                    "agent_discovery_runs": _agents_out.get("summary", {}).get("discovery_runs", 0),
                })
            except Exception as _ag2_e:
                await send({"type": "warning", "message": f"Multi-Agent/Evidence Graph 오류 (무시): {_ag2_e}"})
        except Exception as _so_e:
            await send({"type": "warning", "message": f"Solver Framework 오류 (무시): {_so_e}"})

        # ── Business Impact Engine → Remediation Planner (기술 결과 → 영향/조치 계획) ──
        # 새 탐지/판정 없음. Executive Risk Score/Level 은 증거 기반(AI 변경 불가).
        try:
            import business_impact_engine as _bie
            import remediation_planner as _rp
            _impact = _bie.build_business_impact(analysis)
            analysis["business_impact"] = _impact.get("items")
            analysis["business_impact_summary"] = _impact.get("summary")
            _remed = _rp.plan_remediation(_impact)
            analysis["remediation_items"] = _remed.get("items")
            analysis["priority_action_plan"] = _remed.get("priority_action_plan")
            analysis["remediation_summary"] = _remed.get("summary")
        except Exception as _bie_e:
            await send({"type": "warning", "message": f"Business Impact/Remediation 오류 (무시): {_bie_e}"})

        # ── Validation Readiness — 관찰→증거→실증 승격 후보 + 검증 우선순위 ──────
        # 새 탐지/판정 없음. Level/Confidence 변경 불가(Rule Engine 전담).
        try:
            import validation_readiness as _vr
            _vrout = _vr.build_validation_readiness(analysis)
            analysis["validation_candidates"] = _vrout.get("validation_candidates")
            analysis["validation_summary"] = _vrout.get("validation_summary")
            analysis["validation_backlog"] = _vrout.get("validation_backlog")
        except Exception as _vr_e:
            await send({"type": "warning", "message": f"Validation Readiness 오류 (무시): {_vr_e}"})

        # ── Proof-Oriented Validation Framework v1 — '증거 기반 확인' 정리 ────────
        # 기본 SAFE(신규 공격 실행 없음). 강한 검증은 승인 프로파일에서만 허용되며,
        # 위험 행위(dump/shell/exfil/write/state-change/brute/internal)는 Proof Policy
        # Gate 로 항상 차단·기록한다. Level/판정 변경은 Rule Engine 전담(본 단계는 문서화).
        try:
            import proof_validation as _pv
            _pvout = _pv.run_proof_validation(analysis)
            analysis["proof_validation"] = _pvout.get("proof_validation")
            analysis["proof_validation_summary"] = _pvout.get("proof_validation_summary")
            analysis["proof_validation_config"] = _pvout.get("proof_validation_config")
            # proof_validation 확보 후 오탐 억제 재평가 — family↔검증방법 불일치(B)까지 반영
            try:
                import false_positive_filter as _fpf2
                analysis["fp_risk_summary"] = _fpf2.annotate(analysis).get("fp_risk_summary")
            except Exception:
                pass
        except Exception as _pv_e:
            await send({"type": "warning", "message": f"Proof Validation 오류 (무시): {_pv_e}"})

        # ── Proof Evidence Detail Engine v1 — Evidence→Proof→Business 카드/점수 ────
        # 판정(Rule Engine/Severity/Confidence/Validation/Evidence/Risk) 변경 없음.
        # 이미 확보된 무해 증거를 재현·설명 가능한 형태로 정리하고 fingerprint/proof quality/
        # business function 을 산출(표현·설명·점수 전용, SAFE).
        try:
            import proof_evidence as _pe
            _peout = _pe.build_all(analysis)
            analysis["proof_evidence_cards"] = _peout.get("proof_evidence_cards")
            analysis["proof_quality_summary"] = _peout.get("proof_quality_summary")
            analysis["fingerprints"] = _peout.get("fingerprints")
            analysis["business_process_map"] = _peout.get("business_process_map")
        except Exception as _pe_e:
            await send({"type": "warning", "message": f"Proof Evidence 오류 (무시): {_pe_e}"})

        # ── Security Knowledge Graph v1 — Asset→…→Finding→Proof→Business→Remediation 관계 ──
        # 신규 탐지/판정 없음. 이미 산출된 데이터로 관계 그래프·공격경로·우선순위 근거 '구성'만.
        try:
            import security_knowledge_graph as _kg
            _kgout = _kg.build_all(analysis)
            analysis["security_knowledge_graph"] = _kgout.get("security_knowledge_graph")
            analysis["attack_path_graph"] = _kgout.get("attack_path_graph")
            analysis["graph_risk_context"] = _kgout.get("graph_risk_context")
        except Exception as _kg_e:
            await send({"type": "warning", "message": f"Knowledge Graph 오류 (무시): {_kg_e}"})

        # ── Detection Coverage / Result Matrix — 무엇을 검사했고 안 했는지 집계 ────
        try:
            import detection_coverage as _dc
            analysis["detection_coverage"] = _dc.build_coverage(analysis).get("detection_coverage")
        except Exception as _dc_e:
            await send({"type": "warning", "message": f"Detection Coverage 오류 (무시): {_dc_e}"})

        # ── 확정 취약점별 독립 실행 PoC 스크립트 생성(재현 산출물) ──
        try:
            import poc_generator as _pg
            # ai_fn 주입 시 확정 finding 에 'AI 생성 PoC'(안전검증 통과분)도 부착. 결정적 PoC 는 불변.
            # ai_fn 이 asyncio.run 을 돌리므로 워커 스레드에서 실행. (예산은 _ai_fn 이 공유·제한)
            if _ai_fn_poc or _ai_fn:
                _npoc = await asyncio.to_thread(_pg.attach_pocs, analysis, 30, _ai_fn_poc or _ai_fn)
            else:
                _npoc = _pg.attach_pocs(analysis)
            if _npoc:
                await send({"type": "info", "message": f"📝 재현 PoC 스크립트 {_npoc}건 생성"})
        except Exception as _pg_e:
            print(f"[poc_generator] 오류(무시): {_pg_e}", flush=True)

        # ── AI 앙상블 오탐 판정(advisory) — CONFIRMED 를 다계열 투표로 재검증 ──
        # 원칙: 룰 1차·AI 2차. 삭제/판정 변경 금지 — confidence 표시 하향 + 검토표시만(미탐 방지).
        # 앙상블 패널 모델(ai_roles.json)이 없으면 no-op. GPU 서버 연결 시 자동 활성.
        if os.getenv("ENABLE_AI_ANALYSIS", "false").strip().lower() in ("true", "1", "yes"):
            try:
                import ai_provider as _aip
                _fpr = await _aip.apply_fp_ensemble(analysis)
                # 스캔 시점의 AI 모드·패널을 결과에 각인(보고서/상세에서 정확 표시, 과거 스캔 보존)
                try:
                    _roles = _aip.load_ai_roles()
                    _ens = _roles.get("fp_judge_ensemble") or {}
                    _summary = {
                        "mode": "ensemble" if _ens.get("enabled") else "solo",
                        "panel": _ens.get("panel") or [],
                        "checked": _fpr.get("checked", 0),
                        "flagged": _fpr.get("flagged", 0),
                    }
                    analysis["ai_ensemble"] = _summary
                    if isinstance(analysis.get("ai_analysis"), dict):
                        analysis["ai_analysis"]["ai_ensemble"] = _summary
                except Exception:
                    pass
                if _fpr.get("flagged"):
                    await send({"type": "info",
                                "message": f"🧪 AI 앙상블 오탐 재검토: {_fpr['flagged']}건 검토표시(삭제 안 함)"})
            except Exception as _fe:
                print(f"[fp_ensemble] 오류(무시): {_fe}", flush=True)

        # ── Detection Intelligence v1 — 컨텍스트 기반 탐지 전략(계획, 실행/판정 아님) ──
        try:
            import detection_intelligence as _di
            _diout = _di.build_strategies(analysis)
            analysis["detection_strategies"] = _diout.get("detection_strategies")
            analysis["detection_strategy_summary"] = _diout.get("summary")
        except Exception as _di_e:
            await send({"type": "warning", "message": f"Detection Intelligence 오류 (무시): {_di_e}"})

        # ── Report Quality Checker — 보고서 생성 직전 자동 QA(표현 결함만 정리) ──────
        try:
            import report_qa as _rqa
            analysis["report_qa"] = _rqa.check(analysis)
        except Exception as _rqa_e:
            await send({"type": "warning", "message": f"Report QA 오류 (무시): {_rqa_e}"})

        # 기술 스택 인식 결과 취합 (recon 단계에서 host별로 부여됨)
        _all_tech: list[dict] = []
        for _hr in host_results:
            for _t in (_hr.get("technologies") or []):
                if not any(x.get("name") == _t.get("name") for x in _all_tech):
                    _all_tech.append(_t)
        analysis["technologies"] = _all_tech

        # 공격 체인 엔진 (규칙 기반) — finding 개수/severity 변경 없음, 보고서 요약용
        try:
            analysis["attack_chains"] = attack_chain_engine.build_chains(
                _norm["findings"], _norm["attack_surface_items"],
                _norm["discovery_items"], _all_tech,
            ).get("chains", [])
        except Exception:
            analysis["attack_chains"] = []

        # 추가 점검 권고 후보 (자동 실행은 ENABLE_ADAPTIVE_RECON 일 때만)
        try:
            analysis["adaptive_recon"] = adaptive_recon.suggest_checks(
                _all_tech, _norm["findings"], _norm["attack_surface_items"],
            ).get("suggested_checks", [])
        except Exception:
            analysis["adaptive_recon"] = []

        # ── 서비스/포트 보안 점검 (ENABLE_SERVICE_SCAN=true 일 때만, 안전 모드) ──
        # 운영 영향 없는 비파괴 점검만. 결과를 analysis 버킷에 병합하고 summary 재계산.
        try:
            if os.getenv("ENABLE_SERVICE_SCAN", "false").lower() in ("true", "1", "yes"):
                import service_scan
                _scan_mode = os.getenv("SCAN_MODE", "safe")
                for _hr in host_results:
                    _ports = _hr.get("open_ports") or [
                        s.get("port") for s in _hr.get("services", []) if s.get("port")
                    ]
                    _ports = [p for p in _ports if p]
                    if not _ports:
                        continue
                    await send({"type": "info",
                                "message": f"[서비스 점검] {_hr.get('host')} 열린 포트 {len(_ports)}개 안전 점검 중..."})
                    _sr = service_scan.scan_services(_hr.get("host", ""), _ports, scan_mode=_scan_mode)
                    merge_service_results(analysis, _sr)
                _svc_n = analysis.get("summary", {}).get("service_vulnerability_count", 0)
                await send({"type": "info", "message": f"서비스 점검 완료 — 서비스 취약점 {_svc_n}건"})
        except Exception as _ss_e:
            await send({"type": "warning", "message": f"서비스 점검 실패 (무시): {_ss_e}"})

        # ── Service Security Framework v2: 서비스 영역 전체 파이프라인 통합 ──────
        # 표면 → 경로 → Prioritizer → Solver → Agent → Evidence Graph → Validation →
        # Business Impact → Remediation. 새 능동 탐색 없음(기존 포트/서비스 식별 결과만).
        try:
            import service_pipeline as _sp
            _svc = _sp.run_service_pipeline(analysis, host_results)
            if _svc.get("ran"):
                _surfaces = _svc["service_surfaces"]
                analysis["service_surfaces"] = _surfaces
                analysis["service_surface_summary"] = _svc["service_summary"]["surface_summary"]
                analysis["service_prioritized_paths"] = _svc["service_prioritized_paths"]
                analysis["service_solver_results"] = _svc["service_solver_results"]
                analysis["service_agent_results"] = _svc["service_agent_results"]
                analysis["service_evidence_graph"] = _svc["service_evidence_graph"]
                analysis["service_validation_candidates"] = _svc["service_validation_candidates"]
                analysis["service_validation_summary"] = _svc["service_validation_summary"]
                analysis["service_business_impact"] = _svc["service_business_impact"]
                analysis["service_remediation_plan"] = _svc["service_remediation_plan"]
                analysis["service_remediation_items"] = _svc["service_remediation_items"]
                analysis["service_security_controls"] = _svc["service_security_controls"]
                analysis["service_summary"] = _svc["service_summary"]
                # 통합 보고서용: 서비스 경로/영향/통제를 기존 버킷에도 합류
                _svc_paths = _svc["service_attack_paths"]
                analysis.setdefault("attack_paths", []).extend(_svc_paths)
                _aps = analysis.setdefault("attack_path_summary", {})
                _aps["total_paths"] = _aps.get("total_paths", 0) + len(_svc_paths)
                if _svc["service_business_impact"]:
                    analysis.setdefault("business_impact", []).extend(_svc["service_business_impact"])
                analysis["service_controls"] = _svc["service_security_controls"]
                await send({"type": "info",
                            "message": f"서비스 보안 프레임워크 v2: 표면 {len(_surfaces)}개 · "
                                       f"Solver {_svc['service_summary']['service_solver_runs']} · "
                                       f"Agent {_svc['service_summary']['service_agent_runs']} 실행"})
        except Exception as _svc_e:
            await send({"type": "warning", "message": f"Service Security Framework v2 오류 (무시): {_svc_e}"})

        # ── Network Discovery Framework v1: Target 판별 + Asset Inventory/Graph ──
        # CIDR/IP 라이브 디스커버리는 안전 정책(보수적 기본값)으로 가드. 자산 인벤토리/그래프는
        # 기존 host_results(포트/서비스)만으로 구성(새 탐색 없음).
        try:
            import target_input as _tinp
            import network_discovery as _nd
            import asset_inventory as _ainv
            import asset_graph as _agraph
            _norm_t = _tinp.normalize_targets(domain)
            analysis["target_type"] = _norm_t["target_type"]
            analysis["normalized_targets"] = _norm_t["normalized_targets"]
            analysis["scan_scope_summary"] = _norm_t["scan_scope_summary"]
            # Scope Guard(대역 입력 시 안전 판정)
            _guard = _nd.scope_guard(_norm_t)
            analysis["network_scope_guard"] = _guard
            if _guard["blocked"]:
                await send({"type": "warning",
                            "message": f"네트워크 범위 안전 가드: {len(_guard['blocked'])}개 대상 차단 "
                                       f"({'; '.join(_guard['blocked_reasons'][:2])})"})
            # 자산 인벤토리 + 그래프(기존 스캔된 host_results 기반)
            _inv = _ainv.build_inventory(host_results)
            analysis["asset_inventory"] = _inv["assets"]
            _ag2 = _agraph.build_asset_graph(_inv["assets"], _norm_t["normalized_targets"], analysis)
            analysis["asset_graph"] = _ag2["asset_graph"]
            analysis["asset_nodes"] = _ag2["asset_nodes"]
            analysis["asset_edges"] = _ag2["asset_edges"]
            analysis["asset_summary"] = _ag2["asset_summary"]
            # Network Exposure Summary
            _ssum = analysis.get("service_surface_summary") or {}
            analysis["network_exposure_summary"] = {
                "input_targets": [t["value"] for t in _norm_t["normalized_targets"]],
                "target_type": _norm_t["target_type"],
                "live_hosts": _inv["summary"]["total_assets"],
                "open_ports": _inv["summary"]["open_ports"],
                "services": _inv["summary"]["services"],
                "web_candidates": _inv["summary"]["web_candidates"],
                "auth_services": _ssum.get("authentication_surfaces", 0),
                "db_services": _ssum.get("database_surfaces", 0) + _ssum.get("data_exposure_surfaces", 0),
                "file_sharing_services": _ssum.get("file_sharing_surfaces", 0),
                "container_services": _ssum.get("container_surfaces", 0),
                "unknown_services": _inv["summary"]["unknown"],
                "internet_exposed": _inv["summary"]["internet_exposed"],
                "high_priority_assets": _inv["summary"]["high_priority"],
                "blocked_ranges": len(_guard["blocked"]),
            }
        except Exception as _net_e:
            await send({"type": "warning", "message": f"Network Discovery Framework 오류 (무시): {_net_e}"})

        # 정규화 결과로 전체 위험도·요약 문구 정합화 (서비스 병합 반영된 analysis.summary 기준)
        _sev = analysis.get("summary", {}).get("by_severity", _norm["summary"]["by_severity"])
        if _sev.get("Critical"):   analysis["overall_risk"] = "HIGH"
        elif _sev.get("High"):     analysis["overall_risk"] = "HIGH"
        elif _sev.get("Medium"):   analysis["overall_risk"] = "MEDIUM"
        elif _sev.get("Low"):      analysis["overall_risk"] = "LOW"
        else:                      analysis["overall_risk"] = "GOOD"
        _vc = analysis.get("summary", {}).get("vulnerability_count", _norm["summary"]["vulnerability_count"])
        _risk_kr = {"HIGH": "높음", "MEDIUM": "중간", "LOW": "낮음", "GOOD": "양호"}.get(analysis["overall_risk"], "")
        if _vc == 0:
            analysis["overall_summary"] = "점검 항목에서 취약점이 발견되지 않았습니다. 보안 상태가 양호합니다."
        else:
            _hi = _sev.get("Critical", 0) + _sev.get("High", 0)
            analysis["overall_summary"] = (
                f"전체 보안 위험도 {_risk_kr}. {_vc}개 취약점 발견"
                + (f" (HIGH {_hi}개 포함)" if _hi else "")
                + f". 공격 표면 {analysis.get('summary', {}).get('attack_surface_count', 0)}건, "
                + f"참고 발견 항목 {analysis.get('summary', {}).get('discovery_count', 0)}건."
            )

        # AI 분석 보강 (AI_PROVIDER != "none"일 때만 실제 호출)
        vuln_findings_for_ai = [f for f in analysis.get("findings", []) if f.get("judgment") == "취약"]

        # Phase 6: Discovery 자산 수집 (AI 컨텍스트용)
        discovered_assets_for_ai: dict = {
            "admin_pages": [], "admin_apis": [], "swagger_found": [], "graphql_found": [],
            "framework_hints": [],
        }
        for hr in host_results:
            for svc in hr.get("services", []):
                disc = svc.get("discovery_result") or {}
                discovered_assets_for_ai["admin_pages"].extend(disc.get("admin_hits", []))
                discovered_assets_for_ai["admin_apis"].extend(disc.get("api_hits", []))
                discovered_assets_for_ai["framework_hints"].extend(disc.get("framework_hints", []))
                # active_probes 는 기존 경로=dict / orchestrator 경로=list.
                # introspection(swagger/graphql)은 dict 형태에만 존재하므로 list 면 빈 dict 로 취급.
                _ap = svc.get("active_probes")
                ap = _ap if isinstance(_ap, dict) else {}
                if ap.get("swagger_openapi"):
                    sw = ap["swagger_openapi"]
                    discovered_assets_for_ai["swagger_found"].append({
                        "url": sw.get("url", ""),
                        "api_count": (sw.get("api_summary") or {}).get("total_endpoints", 0),
                    })
                if ap.get("graphql_introspection"):
                    gql = ap["graphql_introspection"]
                    schema_info = gql.get("schema_info") or {}
                    discovered_assets_for_ai["graphql_found"].append({
                        "url": gql.get("url", ""),
                        "mutations": len(schema_info.get("mutations", [])),
                        "admin_mutations": schema_info.get("admin_mutations", []),
                    })

        if (vuln_findings_for_ai
                and os.getenv("ENABLE_AI_ANALYSIS", "false").strip().lower() in ("true", "1", "yes")):
            # AI 분석 단계로 전환(라벨) — 로컬 32b 는 수 분 걸릴 수 있어 침묵처럼 보이던 것 해소.
            await send({"type": "stage", "stage": "ai_analysis",
                        "message": "[AI 분석] 로컬 LLM(32b)으로 취약점 서사·오탐판정 분석 중 — 수 분 소요될 수 있음..."})
            try:
                await send({"type": "info", "message": "[AI 분석] 취약점 AI 보강 분석 중(전체 요약 생성)..."})
                analysis = await ai_enhance_analysis(
                    domain, analysis, vuln_findings_for_ai,
                    discovered_assets=discovered_assets_for_ai,
                )
                ai_info = analysis.get("ai_analysis", {})
                if ai_info.get("ai_used"):
                    await send({"type": "info", "message": f"AI 보강 분석 완료 ({ai_info.get('ai_provider', '')})"})
                else:
                    # AI 미사용(규칙기반 fallback) — '왜' 를 반드시 표기(과거 '완료(fallback)' 오해 해소)
                    _reason = ai_info.get("ai_error") or "AI 미사용"
                    await send({"type": "warning",
                                "message": f"AI 보강 분석 fallback — 규칙기반 요약 사용 (사유: {_reason})"})
            except Exception as _ai_e:
                await send({"type": "warning", "message": f"AI 분석 실패 (무시): {_ai_e}"})

        # ── AI 보안 분석가 의견 + RAG 보강 (ENABLE_AI_ANALYSIS=true 일 때만) ──
        # finding_normalizer/attack_chain 결과를 '해석·설명'만 하며 개수·severity 는 변경하지 않음.
        try:
            if os.getenv("ENABLE_AI_ANALYSIS", "false").lower() in ("true", "1", "yes"):
                await send({"type": "info", "message": "[AI 보안 분석가] RAG 기반 취약점 해석 중..."})
                analysis = await enrich_with_security_analyst(domain, analysis)
        except Exception as _sa_e:
            await send({"type": "warning", "message": f"AI 보안 분석가 분석 실패 (무시): {_sa_e}"})

        # 취약 항목별 증거 스크린샷 캡처
        vuln_count = sum(1 for f in analysis.get("findings", []) if f.get("judgment") == "취약")
        if vuln_count > 0:
            await send({"type": "info", "message": f"취약점 {vuln_count}개에 대한 증거 스크린샷 캡처 중..."})
            try:
                updated_findings = await capture_evidence_screenshots(scan_id, analysis["findings"])
                analysis["findings"] = updated_findings
            except Exception as e:
                await send({"type": "warning", "message": f"증거 스크린샷 캡처 실패 (무시): {e}"})

        # ── 테스트 데이터 정리 + 검증 (생성한 모든 아티팩트가 정리·원복됐는지 정직하게 확인) ──
        # (1) finding 기반 정리(저장형 XSS/업로드 CONFIRMED) (2) 저장형 XSS '주입 전체' 검증·정리
        #     (확정 여부 무관 — 점검 중 폼에 제출한 모든 마커) (3) 쓰기권한 원복 실패 집계.
        # 잔여물이 있으면 숨기지 않고 경고 + cleanup_summary.residue 로 보고(수동 정리 안내).
        try:
            import cleanup_verify as _cv
            import active_probing as _apc
            _fc = None
            findings_needing_cleanup = [
                f for f in analysis.get("findings", [])
                if isinstance(f.get("cleanup_status"), dict) and f["cleanup_status"].get("required")
            ]
            if findings_needing_cleanup:
                await send({"type": "info",
                            "message": f"테스트 데이터 정리 중 ({len(findings_needing_cleanup)}건)..."})
                _fc = (await cleanup_scan_artifacts(findings_needing_cleanup, scan_id)).to_dict()
            # 저장형 XSS: 주입한 '모든' 마커를 검증·정리(확정 취약점만이 아니라 전부)
            _sx = await _apc.cleanup_stored_xss_injections(scan_id)
            # 쓰기권한(수정-후-원복) 원복 실패 집계 — 본인 A 계정 필드가 마커로 남았을 수 있음
            _wa_reverts = []
            if write_authz_verification and write_authz_verification.get("results"):
                for _r in write_authz_verification["results"]:
                    if _r.get("grade") and _r.get("reverted") is False:
                        _c = _r.get("candidate", {})
                        _wa_reverts.append({"url": _c.get("url"), "field": _c.get("field")})
            _report = _cv.build_cleanup_report(_fc, _sx, _wa_reverts)
            analysis["cleanup_summary"] = _report
            # 상태변경형 실증이 자동 원복에 실패해 남긴 산출물을 '삭제 요청'으로 정규화 →
            # 보고서 하단 섹션 + 프론트 '삭제요청' 패널이 공통 사용({경로, 작성내용, 방법}).
            analysis["deletion_requests"] = _cv.build_deletion_requests(_report)
            if analysis["deletion_requests"]:
                await send({"type": "warning",
                            "message": f"삭제 요청 {len(analysis['deletion_requests'])}건 — 자동 원복 실패분, "
                                       "보고서·결과 화면의 '삭제요청'에서 확인하세요."})
            if _report["verified_clean"]:
                if _report["attempted"]:
                    await send({"type": "info",
                                "message": f"테스트 데이터 정리 검증 완료 — 잔여물 없음"
                                           f"(정리 {_report['cleaned']}/{_report['attempted']}건)"})
            else:
                await send({"type": "warning", "message": _cv.residue_message(_report)})
        except Exception as _ce:
            await send({"type": "warning", "message": f"테스트 데이터 정리 오류 (무시): {_ce}"})

        # ── 점검 커버리지 요약 채우기 (보고서 3.5) ──────────────────────────────
        try:
            try:
                from probes.config import ScanConfig as _SC
                _cfg = _SC.from_env()
            except Exception:
                _cfg = None
            _cov = get_probe_coverage(scan_id)
            _ai = analysis.get("ai_status") or {}
            _disc_urls = sum(
                len(svc.get("discovered_urls") or [])
                for hr in host_results for svc in hr.get("services", [])
            )
            try:
                _ext = available_tools()
                _ext_count = sum(1 for v in _ext.values() if v)
            except Exception:
                _ext_count = None
            # 인증 후 크롤 + 입력점 컨텍스트 + XSS 게이트 수치
            try:
                import probe_policy as _pp
                _acfg = _pp.auth_crawl_config()
                _auth_reason = _pp.auth_crawl_skip_reason(_acfg)
            except Exception:
                _acfg, _auth_reason = {"enabled": False}, "probe_policy 로드 실패"
            # 검색 입력점/로그인 폼 수(발견된 입력점 기준)
            _search_inputs = sum(
                len((svc.get("discovery_result") or {}).get("search_inputs") or [])
                for hr in host_results for svc in hr.get("services", [])
            )
            _login_forms = sum(
                1 for hr in host_results for svc in hr.get("services", [])
                for ah in ((svc.get("discovery_result") or {}).get("admin_hits") or [])
                if isinstance(ah, dict) and ah.get("has_login_form")
            )

            # 오픈 포트 수(distinct) — 보고서 점검 카운트용
            _open_ports = set()
            for hr in host_results:
                for _p in (hr.get("open_ports") or []):
                    _open_ports.add(str(_p))
                for svc in hr.get("services", []):
                    if svc.get("port"):
                        _open_ports.add(str(svc.get("port")))
            analysis["open_ports_count"] = len(_open_ports)

            # ── 로그인 폼 SQLi 안전 점검 결과 집계 + 참고 항목 삽입 ──────────────
            _lf_found = _lf_tested = _lf_perf = 0
            _lf_pages = _lf_struct_failed = 0
            _probe_skip_reasons: list[str] = []
            _auth_bypass_checked = False
            # 동일 논리 로그인 폼이 포트 80/443/8080 에서 각각 확증되면 같은 취약점이 3건으로
            # 중복 집계된다. (host, action 경로, 필드) 기준으로 1건으로 병합하고 포트를 한 란에 나열한다.
            _lsqli_by_key: dict = {}
            for hr in host_results:
                for svc in hr.get("services", []):
                    _ap = svc.get("active_probes")
                    _ls = _ap.get("login_sqli") if isinstance(_ap, dict) else None
                    if not isinstance(_ls, dict):
                        continue
                    _lf_found += _ls.get("login_forms_found", 0)
                    _lf_tested += _ls.get("login_forms_tested", 0)
                    _lf_pages += _ls.get("login_pages_seen", 0)
                    _lf_struct_failed += _ls.get("structure_failed", 0)
                    if _ls.get("skip_reason"):
                        _probe_skip_reasons.append(_ls["skip_reason"])
                    if _ls.get("attempts", 0) > 0:
                        _lf_perf += _ls.get("login_forms_tested", 0)
                        _auth_bypass_checked = True
                    for _fr in _ls.get("flagged", []):
                        _st = _fr.get("status")
                        if _st == "CONFIRMED_AUTH_BYPASS":
                            # 음성 대조 차등 확증 → 확정 취약점으로 승격(참고 아님).
                            # uid/fp 주석은 이미 앞 단계에서 부여됐으므로 여기서 자체 부여한다.
                            from urllib.parse import urlparse as _lup
                            _uf0 = _fr.get("username_field", "username")
                            _pf0 = _fr.get("password_field", "password")
                            _apath = _lup(_fr.get("action", "")).path or _fr.get("action", "")
                            _lkey = (hr.get("host", ""), _apath, _uf0, _pf0)
                            _prev = _lsqli_by_key.get(_lkey)
                            if _prev is not None:
                                # 같은 논리 폼이 다른 포트에서 재확증 → 포트만 추가(중복 finding 생성 안 함)
                                _pp = svc.get("port")
                                if _pp is not None and _pp not in _prev["_ports"]:
                                    _prev["_ports"].append(_pp)
                                _auth_bypass_checked = True
                                continue
                            _uid = _next_finding_uid(analysis.get("findings") or [])
                            _pl, _cpl = _fr.get("payload"), _fr.get("control_payload")
                            _uf = _fr.get("username_field", "username")
                            _pf = _fr.get("password_field", "password")
                            _lsqli_finding = {
                                "host": hr.get("host", ""), "port": svc.get("port"),
                                "service": "HTTP", "judgment": "취약", "severity": "HIGH",
                                "confidence": "CONFIRMED", "cvss_estimate": 9.1,
                                "exploitation_difficulty": "Easy",
                                "owasp": "A03:2021 - 인젝션", "cwe": "CWE-89",
                                "title": "SQL 인젝션 인증 우회 — 로그인 폼(음성 대조 차등 확증)",
                                "description": ("로그인 폼 입력값이 SQL 쿼리에 그대로 삽입되어, 올바른 "
                                                "패스워드 없이 인증을 우회할 수 있습니다."),
                                "attack_vector": f"로그인 파라미터에 SQL payload 삽입: {_pl}",
                                "attack_scenario": ("1. 로그인 폼에 항상 참(OR '1'='1') payload 삽입 → 인증 우회\n"
                                                    "2. 관리자/타 사용자 계정으로 로그인\n3. 민감 데이터 접근"),
                                "tools": ["sqlmap"],
                                "recommendation": ("파라미터화 쿼리(Prepared Statement) 적용, 입력 검증, "
                                                   "DB 계정 최소권한."),
                                "evidence_url": _fr.get("action", ""),
                                "evidence_detail": (
                                    f"음성 대조 차등 확증: 우회 payload '{_pl}' → 로그인 성공, "
                                    f"음성 대조 '{_cpl}'(항상 거짓) → 로그인 실패, "
                                    f"baseline(엉뚱한 자격증명) → 실패. 응답이 payload 의 참/거짓에 따라 "
                                    f"갈림 = 입력이 SQL 쿼리에 삽입됨을 실증."),
                                "reproduction_cmd": (
                                    f"curl -s -i -X POST '{_fr.get('action','')}' "
                                    f"--data '{_uf}={_pl}&{_pf}={_pl}'"),
                                "finding_type": "vulnerability", "report_severity": "High",
                                "confidence_score": 95, "finding_uid": _uid,
                                "_fp_risk": "low",
                                "_fp_reasons": ["음성 대조 차등으로 확증됨 — 오탐 위험 낮음"],
                                "_fp_suppressed": False,
                                "_ports": [svc.get("port")] if svc.get("port") is not None else [],
                            }
                            analysis.setdefault("findings", []).append(_lsqli_finding)
                            _lsqli_by_key[_lkey] = _lsqli_finding
                            _auth_bypass_checked = True
                            continue
                        _mr = _st == "MANUAL_REVIEW_REQUIRED"
                        analysis.setdefault("discovery_items", []).append({
                            "title": "[참고] 로그인 폼 SQLi 안전 점검 신호" + (" — 수동 검토 필요" if _mr else ""),
                            "host": hr.get("host", ""), "port": svc.get("port"),
                            "finding_type": "discovery", "judgment": "참고",
                            "confidence": "MANUAL_REVIEW", "severity": "Low",
                            "scan_category": "web",
                            "evidence_detail": (
                                f"로그인 폼({_fr.get('action')}) 안전 점검 상태: {_fr.get('status')}. "
                                f"payload: {_fr.get('payload')}. (브루트포스/Credential Stuffing 미수행, 최대 3회)"
                            ),
                            "recommendation": "로그인 폼 파라미터에 대한 수동 SQLi 검증 권고(파라미터화 쿼리 적용).",
                        })
            if _lf_found:
                try:
                    analysis.setdefault("summary", {})
                    if isinstance(analysis["summary"].get("discovery_count"), int):
                        analysis["summary"]["discovery_count"] = len(analysis.get("discovery_items") or [])
                except Exception:
                    pass

            # 로그인 SQLi: 다중 포트에서 확증된 동일 폼은 제목에 포트를 한 란에 나열하고 임시키 제거
            for _lf in _lsqli_by_key.values():
                _ports = [p for p in (_lf.pop("_ports", []) or []) if p is not None]
                def _pk(_x):
                    try:
                        return (0, int(_x))
                    except (TypeError, ValueError):
                        return (1, str(_x))
                _ports_sorted = sorted(set(_ports), key=_pk)
                # 단일 포트라도 affected_ports 를 세팅해 다른 finding(rule_engine dedup)과 표기 일관성 유지
                if _ports_sorted:
                    _lf["affected_ports"] = _ports_sorted
                if len(_ports_sorted) > 1:
                    _lf["title"] = (
                        "SQL 인젝션 인증 우회 — 로그인 폼(음성 대조 차등 확증) "
                        f"[포트 {', '.join(str(p) for p in _ports_sorted)}]")
                    _lf["port"] = _ports_sorted[0]

            # ── 동적 CSRF 검증 결과 집계 (인증 독립 · 영향 기반 심각도) ─────────────
            from urllib.parse import urlparse as _cup
            _csrf_dyn_hosts: set = set()
            _csrf_dyn_paths: set = set()   # 동적으로 검증한 엔드포인트 경로(정적 중복 억제용)
            # 같은 엔드포인트를 포트 80/443/8080 로 각각 확정하면 동일 취약점이 중복 집계된다.
            # (host, 경로, 취약여부) 기준 1건으로 병합하고 포트를 한 란에 나열(로그인 SQLi 와 동일 처리).
            _csrf_by_key: dict = {}
            for _hr in host_results:
                for _svc in _hr.get("services", []):
                    _apc = _svc.get("active_probes")
                    _cd = _apc.get("csrf_dynamic") if isinstance(_apc, dict) else None
                    if not isinstance(_cd, dict):
                        continue
                    for _cr in _cd.get("flagged", []):
                        _csrf_dyn_hosts.add(_hr.get("host", ""))
                        _cpath = _cup(_cr.get("action", "")).path
                        if _cpath:
                            _csrf_dyn_paths.add(_cpath)
                        _sev = (_cr.get("severity") or "LOW").upper()
                        _is_vuln = _sev in ("HIGH", "MEDIUM")
                        # 같은 (host, 경로, 취약여부) 가 다른 포트에서 재확정되면 포트만 추가하고 중복 생성 안 함
                        _ckey = (_hr.get("host", ""), _cpath, _is_vuln)
                        _cprev = _csrf_by_key.get(_ckey)
                        if _cprev is not None:
                            _cpp = _svc.get("port")
                            if _cpp is not None and _cpp not in _cprev["_ports"]:
                                _cprev["_ports"].append(_cpp)
                            continue
                        _citem = {
                            "host": _hr.get("host", ""), "port": _svc.get("port"),
                            "service": "HTTP",
                            "severity": _sev if _is_vuln else "Low",
                            "judgment": "취약" if _is_vuln else "참고",
                            "confidence": "CONFIRMED",
                            "owasp": "A01:2021 - 접근 제어 취약점", "cwe": "CWE-352",
                            "title": ("CSRF 방어 부재 — 동적 검증(교차출처 요청 수락)"
                                      if _is_vuln else "[참고] CSRF 방어 부재 — 동적 검증(영향 제한적)"),
                            "finding_type": "vulnerability" if _is_vuln else "discovery",
                            "scan_category": "web",
                            "evidence_url": _cr.get("action", ""),
                            "evidence_detail": _cr.get("evidence", ""),
                            "reproduction_cmd": _cr.get("curl", ""),
                            "recommendation": ("CSRF 토큰 검증 + SameSite 쿠키 + Origin/Referer 검증 적용. "
                                               "상태변경 엔드포인트엔 rate limit/안티오토메이션 병행."),
                        }
                        if _is_vuln:
                            _citem.update({"finding_uid": _next_finding_uid(analysis.get("findings") or []),
                                           "_fp_risk": "low",
                                           "_fp_reasons": ["동적 교차출처 재전송으로 실측됨"],
                                           "_fp_suppressed": False})
                            _citem["_ports"] = [_svc.get("port")] if _svc.get("port") is not None else []
                            analysis.setdefault("findings", []).append(_citem)
                            _csrf_by_key[_ckey] = _citem
                        else:
                            _citem["_ports"] = [_svc.get("port")] if _svc.get("port") is not None else []
                            analysis.setdefault("discovery_items", []).append(_citem)
                            _csrf_by_key[_ckey] = _citem
            # CSRF: 다중 포트에서 확정된 동일 엔드포인트는 제목에 포트를 한 란에 나열하고 임시키 제거
            for _cf in _csrf_by_key.values():
                _cports = [p for p in (_cf.pop("_ports", []) or []) if p is not None]
                def _cpk(_x):
                    try:
                        return (0, int(_x))
                    except (TypeError, ValueError):
                        return (1, str(_x))
                _cps = sorted(set(_cports), key=_cpk)
                if _cps:
                    _cf["affected_ports"] = _cps   # 단일 포트라도 표기 일관성(다른 finding 과 통일)
                if len(_cps) > 1:
                    _base_title = _cf.get("title", "")
                    _cf["title"] = f"{_base_title} [포트 {', '.join(str(p) for p in _cps)}]"
                    _cf["port"] = _cps[0]

            # CSRF 동적 확정이 있는 엔드포인트의 정적 CSRF 참고/공격표면 항목은 억제(동적이 실증 → 중복 제거).
            # 엔드포인트 정밀: 동적으로 검증하지 않은 엔드포인트의 정적 항목은 정보 손실 방지를 위해 유지한다.
            if _csrf_dyn_hosts:
                def _is_dup_static_csrf(_item) -> bool:
                    _t = _item.get("title", "") or ""
                    if "CSRF" not in _t or "동적" in _t:   # 동적 검증 결과 자신은 제외
                        return False
                    _h = _item.get("host")
                    # host 가 있으면 동적 확정 host 와 일치 요구, 없으면(정적 후보는 host 미기재 흔함)
                    # 경로만으로 판정 — 과거 host=None 이라 억제가 아예 안 걸리던 버그 수정.
                    if _h and _h not in _csrf_dyn_hosts:
                        return False
                    # 동적으로 검증한 경로가 제목에 포함될 때만 억제(미검증 엔드포인트는 정보 손실 방지 위해 유지)
                    return any(_p and _p in _t for _p in _csrf_dyn_paths)
                analysis["discovery_items"] = [
                    _d for _d in (analysis.get("discovery_items") or [])
                    if not _is_dup_static_csrf(_d)
                ]
                analysis["attack_surface_items"] = [
                    _a for _a in (analysis.get("attack_surface_items") or [])
                    if not _is_dup_static_csrf(_a)
                ]

            # IDOR: A/B 교차계정 '검증' 결과가 있으면 원시 idor_candidate 참고(객체참조 파라미터 발견)는
            # 하위 granularity 중복이므로 억제(검증본이 더 실증적 → 대체).
            _idor_verified_hosts = set()
            for _vf in ((analysis.get("findings") or []) + (analysis.get("attack_surface_items") or [])):
                if "교차 계정 접근" in (_vf.get("title", "") or ""):
                    _idor_verified_hosts.add(_vf.get("host") or domain)
            if _idor_verified_hosts:
                analysis["discovery_items"] = [
                    _d for _d in (analysis.get("discovery_items") or [])
                    if not ("객체 참조 파라미터" in (_d.get("title", "") or "")
                            and (_d.get("host") or domain) in _idor_verified_hosts)
                ]

            # 확정 SQLi 가 있는 엔드포인트/호스트의 SQLi '참고' 신호는 중복이므로 억제.
            # (예: /doLogin 이 CONFIRMED 인데 "SQLMap 미확인"·"로그인 폼 SQLi 신호"가 참고에 또 뜨는 노이즈)
            from urllib.parse import urlparse as _sup
            _sqli_conf_paths, _sqli_conf_hosts = set(), set()
            for _ff in (analysis.get("findings") or []):
                _t = _ff.get("title", "") or ""
                if "SQL 인젝션" in _t and (_ff.get("confidence") or "").upper().startswith("CONFIRMED"):
                    _h = _ff.get("host", "")
                    _p = _sup(_ff.get("evidence_url", "") or "").path
                    _sqli_conf_hosts.add(_h)
                    if _p:
                        _sqli_conf_paths.add((_h, _p))
            if _sqli_conf_hosts:
                def _is_dup_sqli_ref(_d) -> bool:
                    _t = _d.get("title", "") or ""
                    if "SQL" not in _t and "SQLi" not in _t:
                        return False
                    if _d.get("judgment") != "참고":
                        return False
                    _h = _d.get("host", "")
                    _p = _sup(_d.get("evidence_url", "") or "").path
                    # 엔드포인트 일치(확정과 같은 경로) 또는 경로 없는 호스트 단위 로그인 SQLi 신호
                    if _p and (_h, _p) in _sqli_conf_paths:
                        return True
                    if not _p and "로그인 폼 SQLi" in _t and _h in _sqli_conf_hosts:
                        return True
                    return False
                analysis["discovery_items"] = [
                    _d for _d in (analysis.get("discovery_items") or [])
                    if not _is_dup_sqli_ref(_d)
                ]

            # 서비스/버전 식별 항목을 포트별 중복 → label 기준 하나로 병합(포트 한 란에 나열)
            # (제품 미식별 Info 항목은 discovery 로 남고, 제품 식별된 것은 LOW finding 으로 승격됨)
            if analysis.get("discovery_items"):
                analysis["discovery_items"] = _consolidate_service_version_items(
                    analysis["discovery_items"])
            # 서비스/버전 식별은 취약점이 아니라 공격표면(attack_surface)으로 분류되므로, 포트별로
            # 쪼개진 '서비스/버전 식별: X (포트 N)' 항목을 label 기준 하나로 병합(포트 한 란에 나열).
            if analysis.get("attack_surface_items"):
                analysis["attack_surface_items"] = _consolidate_service_version_items(
                    analysis["attack_surface_items"])
            # 서비스/버전 식별 LOW finding 을 포트 병합 + Server 헤더 버전노출 finding 과 중복 제거
            _consolidate_version_findings(analysis)

            # 트렌드(신규/지속/해결) 최종 계산 — 모든 finding(rule_engine + login_sqli/csrf/jwt/external)이
            # 조립된 지금 시점에 안정 제목 기준으로 정확히 산정. 실제로 사라진 취약점만 '해결(양호)'로
            # 표기하고, 포트 접미사 변화로 같은 취약점이 '해결'로 오판돼 good_items 에 새던 문제를 방지한다.
            try:
                finalize_trend(analysis, previous_scans if deep_mode else None)
            except Exception as _fte:
                await send({"type": "warning", "message": f"[트렌드] 계산 경고: {_fte}"})

            # A1/A2: 로그인SQLi·CSRF 확정 finding 및 discovery 병합/정리 반영해 요약·위험도 재집계
            _recompute_risk_and_summary(analysis)

            # 발견 수 = (admin discovery 로그인 페이지) ∪ (login_sqli 가 본 페이지/파싱 폼)
            _login_discovered = max(_login_forms, _lf_found, _lf_pages)
            _login_forms_total = _login_discovered
            # 미수행 사유 — 발견 수와 모순되지 않게 결정(순수 헬퍼)
            try:
                import login_sqli as _lsq
                _login_skip = _lsq.login_coverage_reason(
                    _login_discovered, _lf_found, _lf_perf,
                    probe_reason=(_probe_skip_reasons[0] if _probe_skip_reasons else ""))
            except Exception:
                _login_skip = "" if _lf_perf else "점검 조건 불충족"
            # 점검 대상 수: 파싱된 폼이 없고 페이지만 발견된 경우 발견 페이지 수로 보정(0 모순 방지)
            if _lf_tested == 0 and _login_discovered > 0:
                _lf_tested_display = _lf_found  # 구조 분석 실패 시 0 이 맞음(파싱된 폼 없음)
            else:
                _lf_tested_display = _lf_tested

            # 적용된 점검 정책명(보고서 표시용)
            try:
                _active_pol = await get_active_policy()
                _scan_policy_name = (_active_pol or {}).get("name") or "기본(정책 미지정)"
            except Exception:
                _scan_policy_name = "기본(정책 미지정)"
            analysis["scan_policy"] = _scan_policy_name
            # 이 스캔이 실제 적용한 '검증 프로파일'(SAFE/STANDARD/ADVANCED/PROOF)을 저장 →
            # 표지·요약이 정책 템플릿명이 아니라 '실제 적용 프로파일'을 정확히 표기한다.
            try:
                import validation_profiles as _vpp
                analysis["validation_profile"] = _vpp.current_profile()
                analysis["validation_profile_requested"] = _vpp.requested_profile()
            except Exception:
                pass

            # 후보(IDOR/CSRF/비즈니스로직/파일업로드) 수집 카운트 집계(보고서 검증 요약용)
            _cand_counts = {"idor": 0, "csrf": 0, "business_logic": 0, "file_upload": 0}
            for _hr in host_results:
                for _svc in _hr.get("services", []):
                    _ap2 = _svc.get("active_probes")
                    if not isinstance(_ap2, dict):
                        continue
                    for _k, _dst in (("idor_candidate", "idor"), ("csrf_candidate", "csrf"),
                                     ("business_logic_candidate", "business_logic"),
                                     ("file_upload_candidate", "file_upload")):
                        _cand_counts[_dst] += int((_ap2.get(_k) or {}).get("count", 0) or 0)
            _cand_block = {"counts": _cand_counts}
            if analysis.get("candidate_verification"):
                _cand_block.update(analysis["candidate_verification"])
            analysis["candidate_verification"] = _cand_block

            analysis["coverage"] = {
                "scan_policy": _scan_policy_name,
                "payload_level": (_cfg.payload_level if _cfg else os.getenv("PROBE_PAYLOAD_LEVEL", "safe")),
                "use_probe_orchestrator": bool(_cfg.use_orchestrator) if _cfg else False,
                "ai_enabled": bool(_ai.get("enabled")),
                "ai_provider": _ai.get("provider") or "-",
                "ai_model": _ai.get("model") or "-",
                "forms_found": _cov.get("forms"),
                "inputs_found": _cov.get("params"),
                "discovered_urls": _disc_urls,
                "discovered_forms": _cov.get("forms"),
                "search_inputs": _search_inputs,
                "login_forms": _login_forms_total,
                "login_forms_found": _login_forms_total,
                "login_forms_tested": _lf_tested_display,
                "login_forms_performed": _lf_perf,
                "login_forms_structure_failed": _lf_struct_failed,
                "login_skip_reason": _login_skip or "-",
                "auth_bypass_checked": _auth_bypass_checked,
                "sqli_attempts": _cov.get("sqli_attempts"),
                "xss_attempts": _cov.get("xss_attempts"),
                "reflected_xss_attempts": _cov.get("xss_attempts"),
                "dom_xss_attempts": _cov.get("dom_xss_attempts", 0),
                "stored_xss_attempts": _cov.get("stored_xss_attempts", 0),
                "cmdi_attempts": _cov.get("cmdi_attempts"),
                "login_sqli_attempts": _cov.get("login_sqli_attempts", 0),
                "auth_bypass_attempts": _cov.get("auth_bypass_attempts", 0),
                "external_tool_count": _ext_count,
                "time_based_sqli": bool(_cfg.enable_time_based_sqli) if _cfg else False,
                "rate_limit": (f"{_cfg.global_rps} rps" if _cfg and getattr(_cfg, 'global_rps', None) else "-"),
                # 인증 후 크롤 (1.7단계 실행 결과 반영)
                "auth_crawl_enabled": bool(_acfg.get("enabled")),
                "auth_login_success": (SCAN_STATE.get(scan_id, {}).get("auth") or {}).get("login_success"),
                "authenticated_pages": (SCAN_STATE.get(scan_id, {}).get("auth") or {}).get("pages", 0),
                "auth_scan_reason": (SCAN_STATE.get(scan_id, {}).get("auth") or {}).get("reason") or _auth_reason or "",
            }
        except Exception as _cov_e:
            await send({"type": "warning", "message": f"커버리지 집계 (무시): {_cov_e}"})

        await update_scan_record(scan_id, "complete", results=host_results, analysis=analysis)
        await send({"type": "analysis_complete", "analysis": analysis})
    except ScanInterrupted as _si:
        # Phase 3(방어): 후속 스테이지에서 네트워크 죽음이 전파돼도 '재개 가능'으로 저장.
        try:
            _ck2 = await load_checkpoint(scan_id)
        except Exception:
            _ck2 = None
        await _save_ckpt((_ck2 or {}).get("stage", "recon"), host_results)
        await update_scan_record(scan_id, "interrupted", results=host_results)
        _set_progress(scan_id, stage="interrupted", stage_label="중단(재개 가능)",
                      done=True, message=str(_si))
        await send({"type": "error", "message": f"네트워크 중단 감지(재개 가능): {_si}"})
    except Exception as e:
        # 부분 진행(체크포인트)이 있으면 처음부터 재시작 대신 '재개 가능(interrupted)'으로 표시.
        try:
            _ck = await load_checkpoint(scan_id)
        except Exception:
            _ck = None
        if _ck:
            await _save_ckpt(_ck.get("stage", "recon"), host_results)  # 최신 host_results 로 갱신
            await update_scan_record(scan_id, "interrupted", results=host_results)
            await send({"type": "error",
                        "message": f"스캔 중단(재개 가능): {e} — '재개'로 이어받을 수 있습니다."})
        else:
            await update_scan_record(scan_id, "failed", results=host_results)
            await send({"type": "error", "message": f"분석 실패: {e}"})

    await send({"type": "scan_complete", "scan_id": scan_id})
    # 완료/실패 후 인메모리 진행 상태 정리 (이력은 DB status 로 표시됨)
    SCAN_PROGRESS.pop(scan_id, None)
    SCAN_STATE.pop(scan_id, None)


@app.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket, token: str = Query(...)):
    payload = decode_token(token)
    if not payload:
        await websocket.close(code=4001)
        return

    user = await get_user_by_id(int(payload["sub"]))
    if not user:
        await websocket.close(code=4001)
        return

    if not user["can_scan"] and user["role"] != "admin":
        await websocket.close(code=4003)
        return

    await websocket.accept()

    try:
        data = await websocket.receive_json()
        if data.get("action") != "start_scan" or not data.get("domain"):
            await websocket.send_json({"type": "error", "message": "domain 파라미터가 필요합니다."})
            return

        domain = data["domain"].strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
        domain_notes = data.get("domain_notes", "")
        # 스캔별 인증정보(선택) — 이 스캔에만 사용하고 저장하지 않는다. 0/1/2 계정 모두 허용.
        scan_auth = data.get("auth") if isinstance(data.get("auth"), dict) else None
        # 등록 대상의 저장된 비밀번호 사용: 계정(username)은 있는데 비번이 비었으면, 암호화 저장분을
        # 복호화해 이 스캔에만 주입(메모리 전용). 저장이 없거나 비번을 직접 넣었으면 그대로 둔다.
        try:
            if isinstance(scan_auth, dict) and scan_auth.get("username") and not scan_auth.get("password"):
                _stored_pw = await get_watchlist_password(domain, user["id"])
                if _stored_pw:
                    scan_auth = {**scan_auth, "password": _stored_pw}
        except Exception:
            pass
        # 계정만 있고 비번이 없으면(저장분도 없음) 비인증으로만 점검됨을 명시 경고 — 조용히 넘어가
        # 인증 영역이 빠진 채 취약점이 적게 나오던 혼란 방지.
        if isinstance(scan_auth, dict) and scan_auth.get("username") and not scan_auth.get("password") \
                and not any(scan_auth.get(k) for k in ("session_headers", "session_token", "session_cookies")):
            try:
                await websocket.send_json({
                    "type": "warning",
                    "message": "로그인 계정만 입력되고 비밀번호가 없어 비인증(공개 표면)으로만 점검합니다. "
                               "인증 영역(로그인 후 페이지)은 점검되지 않습니다.",
                })
            except Exception:
                pass
        # 스캔 옵션(선택): 제외/허용 URL + 허용 시간(분, 최대 2일) + 예약 시작(epoch초). 마법사에서 전달.
        _opts = data.get("options") if isinstance(data.get("options"), dict) else {}
        _exclude = [str(u).strip() for u in (_opts.get("exclude_urls") or []) if str(u).strip()][:1000]
        _include = [str(u).strip() for u in (_opts.get("include_urls") or []) if str(u).strip()][:2000]
        try:
            _budget_min = int(_opts.get("time_budget_minutes") or 0)
        except (TypeError, ValueError):
            _budget_min = 0
        _budget_min = max(0, min(_budget_min, 2880))   # 최대 2일
        try:
            _start_ts = int(_opts.get("start_ts") or 0)
        except (TypeError, ValueError):
            _start_ts = 0

        # ── 사용자 ID별 총 스캔 쿼터(관리자 부여) ──────────────────────────────
        # user.scan_quota 가 0 이면 무제한. 초과 시 새 스캔을 거부(기존 스캔 삭제로 여유 확보 가능).
        _quota = int(user.get("scan_quota") or 0)
        if _quota > 0:
            _used = await count_user_scans(user["id"])
            if _used >= _quota:
                await websocket.send_json({
                    "type": "error",
                    "message": f"총 스캔 쿼터({_quota}개)를 모두 사용했습니다(현재 {_used}개). "
                               "관리자에게 상향을 요청하거나 기존 스캔을 삭제하세요.",
                })
                return

        scan_id = str(uuid.uuid4())
        # 레코드를 즉시 생성(대기열도 목록에 노출). 이후 run_scan 의 create 는 OR IGNORE 로 무해.
        await create_scan_record(scan_id, user["id"], domain)
        # 제출 설정을 저장(대기 중 '설정 수정' 프리필용). 비밀번호는 저장하지 않는다.
        try:
            await set_scan_config(scan_id, {
                "domain": domain,
                "exclude_urls": _exclude,
                "include_urls": _include,
                "time_budget_minutes": _budget_min,
                "start_ts": _start_ts,
                "login_url": (scan_auth or {}).get("login_url", ""),
                "login_username": (scan_auth or {}).get("username", ""),
            })
        except Exception:
            pass
        await websocket.send_json({"type": "scan_started", "scan_id": scan_id})

        # ── 예약 시작(허용 시간 '몇시부터') — 시작 시각까지 대기 ─────────────────────
        import time as _time
        _delay = (_start_ts - _time.time()) if _start_ts else 0
        if _delay > 0:
            await update_scan_record(scan_id, "queued")
            await websocket.send_json({
                "type": "scheduled", "scan_id": scan_id, "start_ts": _start_ts,
                "message": "예약 시작 시각까지 대기 중입니다(창을 닫으면 취소됩니다).",
            })
            _target = min(_delay, 48 * 3600)   # 최대 48시간
            _waited = 0.0
            while _waited < _target and not SCAN_CANCEL.get(scan_id):
                await asyncio.sleep(min(5.0, _target - _waited))
                _waited += 5.0

        # 예약 대기 중 취소(설정 수정/취소)됐으면 시작하지 않고 종료.
        if SCAN_CANCEL.get(scan_id):
            SCAN_CANCEL.pop(scan_id, None)
            await update_scan_record(scan_id, "stopped")
            try:
                await websocket.send_json({"type": "cancelled", "scan_id": scan_id})
            except Exception:
                pass
            return

        # ── 동시 스캔 제한 → 대기열 ───────────────────────────────────────────
        # 관리자는 무제한(_effective_concurrency_limit → None). 일반 사용자는 최대 _limit(기본 2)개
        # 동시 실행, 초과분은 슬롯이 빌 때까지 대기(거부하지 않고 대기열로 유지).
        _limit = _effective_concurrency_limit(user)
        if _limit is not None and RUNNING_BY_USER.get(user["id"], 0) >= _limit:
            await update_scan_record(scan_id, "queued")
            await websocket.send_json({
                "type": "queued",
                "message": (f"대기열 — 동시 실행 한도({_limit}개)에 도달해 대기 중입니다. "
                            "진행 중 스캔이 끝나면 자동으로 시작됩니다."),
            })
            # 슬롯이 빌 때까지 대기(WS 유지). WS 끊기면 WebSocketDisconnect 로 대기 종료.
            # 대기 중 취소(설정 수정/취소) 요청이 오면 즉시 대기를 끝낸다.
            while RUNNING_BY_USER.get(user["id"], 0) >= _limit:
                if SCAN_CANCEL.get(scan_id):
                    break
                await asyncio.sleep(3)
        # 대기열 대기 중 취소됐으면 시작하지 않고 종료.
        if SCAN_CANCEL.get(scan_id):
            SCAN_CANCEL.pop(scan_id, None)
            await update_scan_record(scan_id, "stopped")
            try:
                await websocket.send_json({"type": "cancelled", "scan_id": scan_id})
            except Exception:
                pass
            return
        # 슬롯 확보 — 마지막 조건검사와 증가 사이에 await 없음(단일 스레드 원자성 보장).
        RUNNING_BY_USER[user["id"]] = RUNNING_BY_USER.get(user["id"], 0) + 1
        await update_scan_record(scan_id, "running")
        if _exclude:
            SCAN_EXCLUDE[scan_id] = _exclude
        if _include:
            SCAN_INCLUDE[scan_id] = _include
        # ── 스캔을 WS(클라이언트) 연결과 분리해 detached 로 실행 ─────────────────────────
        # 클라이언트가 컴퓨터 잠금·로그아웃·탭 종료로 WS 를 끊어도 스캔은 서버(A6000)에서 계속
        # 진행된다(재접속/폴링으로 확인). 취소·부분보고·상태정리·동시성 카운트는 _run_managed_scan
        # 이 보장한다(recover 와 동일 수명주기). 스캔을 끝내는 건 명시적 중지(/stop)와 자동중지
        # (시간 예산 deadline)뿐 — 더 이상 '클라이언트 연결 종료'로는 멈추지 않는다.
        task = asyncio.create_task(
            _run_managed_scan(websocket, domain, scan_id, user["id"], user["role"],
                              domain_notes=domain_notes, scan_auth=scan_auth)
        )
        SCAN_TASKS[scan_id] = task
        # 허용 시간(분)이 지정되면: (1) 초과 시 자동 중지 예약 + (2) 심층 반복 재크롤에 연동
        if _budget_min > 0:
            import time as _tbudget
            SCAN_BUDGET[scan_id] = {"total_min": _budget_min,
                                    "deadline_ts": _tbudget.time() + _budget_min * 60}
            SCAN_DEADLINE[scan_id] = asyncio.create_task(_auto_stop_after(scan_id, _budget_min))
        # WS 는 진행상황 '뷰어'일 뿐 — shield 로 감싸 WS 핸들러가 취소돼도(클라이언트 끊김) 스캔
        # task 는 취소되지 않는다. 상태 정리는 _run_managed_scan 의 finally 가 수행한다(중복 금지).
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            # 클라이언트 연결 종료(잠금/로그아웃/이탈) 또는 중지 요청 → 스캔 자체는 detached
            # 수명주기(_run_managed_scan)가 처리. WS 핸들러만 조용히 종료한다.
            return

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/ai/health")
async def ai_health():
    """현재 설정된 AI 프로바이더 상태를 반환합니다."""
    return await check_provider_health()


class AIModeBody(BaseModel):
    """AI 모드 전환(admin) — ensemble(다중 패널 다수결) / solo(단일 72b)."""
    mode: str


@app.get("/api/ai/mode")
async def api_get_ai_mode(user: dict = Depends(get_current_user)):
    """현재 AI 모드(앙상블/솔로)와 역할→모델 라우팅 스냅샷."""
    import ai_provider as _aip
    roles = _aip.load_ai_roles()
    ens = roles.get("fp_judge_ensemble") or {}
    return {
        "mode": "ensemble" if ens.get("enabled") else "solo",
        "roles": {k: (v or {}).get("model") for k, v in (roles.get("roles") or {}).items()},
        "fallback_model": roles.get("fallback_model") or "",
        "panel": ens.get("panel") or [],
        "editable": user.get("role") == "admin",
    }


@app.post("/api/ai/mode")
async def api_set_ai_mode(body: AIModeBody, user: dict = Depends(require_admin)):
    """AI 모드를 프리셋 파일로 교체(런타임 반영, 재시작 불필요)."""
    import ai_provider as _aip
    mode = (body.mode or "").strip().lower()
    preset = {"ensemble": "ai_roles_ensemble.json", "solo": "ai_roles_solo72b.json"}.get(mode)
    if not preset:
        raise HTTPException(status_code=400, detail="mode 는 'ensemble' 또는 'solo' 여야 합니다")
    base = os.path.dirname(os.path.abspath(_aip.__file__))
    src = os.path.join(base, preset)
    if not os.path.exists(src):
        raise HTTPException(status_code=404, detail=f"프리셋 파일이 없습니다: {preset}")
    import json as _json
    with open(src, encoding="utf-8") as f:
        data = _json.load(f)
    with open(_aip._ROLES_PATH, "w", encoding="utf-8") as f:
        _json.dump(data, f, ensure_ascii=False, indent=2)
    try:
        _aip._ROLES_CACHE.update(mtime=0.0, data=None)   # 캐시 무효화 → 다음 로드에서 재반영
    except Exception:
        pass
    try:
        import audit_log as _al
        _al.log("ai_mode_changed", user=user.get("username", ""), role=user.get("role", ""), mode=mode)
    except Exception:
        pass
    return {"saved": True, "mode": mode,
            "note": "AI 모드가 변경되었습니다. 다음 AI 분석부터 적용(프로세스 재시작 불필요)."}


@app.get("/api/validation/profile")
async def validation_profile(user: dict = Depends(get_current_user)):
    """현재 Validation Profile 설정 스냅샷(기본 SAFE) — 프론트 설정 화면 표시용."""
    import validation_profiles as _vp
    return _vp.config_snapshot()


def _bool_env(name: str, default=False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@app.get("/api/benchmark/golden")
async def api_benchmark_golden(user: dict = Depends(get_current_user)):
    """사용 가능한 정확도 골든셋 목록."""
    from benchmark import golden as _bg
    return {"golden": _bg.available()}


@app.get("/api/benchmark/aggregate")
async def api_benchmark_aggregate(user: dict = Depends(get_current_user)):
    """정확도 루프: 골든셋이 있는 모든 완료 스캔을 대조해 전체 precision/recall/F1(마이크로 평균)과
    대상별 내역을 반환한다. 스캐너 품질을 '수치'로 추적하기 위한 집계 지표."""
    from benchmark import golden as _bg, evaluate as _be
    scans = await get_scans_for_user(user["id"], user["role"])
    per_scan = []
    tot_tp = tot_fn = tot_fp = 0
    for s in scans:
        if s.get("status") != "complete":
            continue
        dom = s.get("domain", "")
        gd = _bg.resolve_golden(dom)
        if not gd:
            continue
        rec = await get_scan_record(s.get("scan_id"))
        if not rec:
            continue
        r = _be.evaluate(rec.get("analysis") or {}, gd)
        tp = r.get("true_positive", 0)
        fn = r.get("false_negative", 0)
        fp = r.get("false_positive", 0)
        tot_tp += tp; tot_fn += fn; tot_fp += fp
        _detail = r.get("detail") or []
        matched = [d["family"] for d in _detail if str(d.get("status", "")).startswith("TP")]
        missed = [d["family"] for d in _detail if str(d.get("status", "")).startswith("FN")]
        per_scan.append({
            "scan_id": s.get("scan_id"), "domain": dom, "label": r.get("label"),
            "created_at": s.get("created_at"),
            "recall": r.get("recall"), "precision": r.get("precision"), "f1": r.get("f1"),
            "verdict": r.get("verdict"),
            "tp": tp, "fn": fn, "fp": fp,
            "matched": matched, "missed": missed,
        })
    micro_recall = round(tot_tp / (tot_tp + tot_fn), 3) if (tot_tp + tot_fn) else None
    micro_prec = round(tot_tp / (tot_tp + tot_fp), 3) if (tot_tp + tot_fp) else None
    micro_f1 = (round(2 * micro_prec * micro_recall / (micro_prec + micro_recall), 3)
                if (micro_prec and micro_recall and (micro_prec + micro_recall)) else None)
    # 최신순
    per_scan.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)
    return {
        "benchmarked_scans": len(per_scan),
        "micro": {"recall": micro_recall, "precision": micro_prec, "f1": micro_f1,
                  "tp": tot_tp, "fn": tot_fn, "fp": tot_fp},
        "per_scan": per_scan,
        "available_golden": _bg.available(),
    }


@app.get("/api/benchmark/{scan_id}")
async def api_benchmark_scan(scan_id: str, target: str | None = None,
                             user: dict = Depends(get_current_user)):
    """저장된 스캔을 골든셋과 대조 → 정탐/오탐/누락(정확도 지표)."""
    scan = await get_scan_record(scan_id)
    if not scan:
        raise HTTPException(status_code=404)
    if user["role"] != "admin" and scan["user_id"] != user["id"]:
        raise HTTPException(status_code=403)
    from benchmark import golden as _bg, evaluate as _be
    analysis = scan.get("analysis") or {}
    gd = _bg.resolve_golden(target or scan.get("domain", ""))
    if not gd:
        return {"available": False, "domain": scan.get("domain"),
                "message": "이 대상에 대한 골든셋이 없습니다. target 지정 또는 골든셋 등록 필요.",
                "golden": _bg.available()}
    return {"available": True, "result": _be.evaluate(analysis, gd)}


@app.get("/api/config")
async def api_get_config(user: dict = Depends(get_current_user)):
    """플랫폼 환경 설정 현황(검증 프로파일·Discovery·보고서·탐지). 런타임 os.env 기준."""
    import validation_profiles as _vp
    try:
        import report_theme as _rt
        themes = _rt.available_themes(); theme = _rt.active_theme_name()
    except Exception:
        themes, theme = [], "corporate_blue"
    try:
        import report as _r; font = _r.FONT
    except Exception:
        font = "맑은 고딕"
    html_pdf = docx_pdf = False
    try:
        import report_html_pdf; html_pdf = report_html_pdf.available()
    except Exception:
        pass
    try:
        import report_pdf; docx_pdf = report_pdf.pdf_available()
    except Exception:
        pass
    return {
        "validation": _vp.config_snapshot(),
        "discovery": {
            "browser_discovery": _bool_env("ENABLE_BROWSER_DISCOVERY"),
            "auth_browser_crawl": _bool_env("ENABLE_AUTH_BROWSER_CRAWL"),
            "graphql_discovery": _bool_env("ENABLE_GRAPHQL_DISCOVERY", True),
            "websocket_discovery": _bool_env("ENABLE_WEBSOCKET_DISCOVERY", True),
        },
        "detection": {
            "sqlmap": _bool_env("ENABLE_SQLMAP"),
            "time_based_sqli": _bool_env("ENABLE_TIME_BASED_SQLI"),
            "rce_proof_mode": _bool_env("RCE_PROOF_MODE"),
            "unauth_write_bac": _bool_env("ENABLE_UNAUTH_WRITE_BAC", True),
            "cve_intel": _bool_env("ENABLE_CVE_INTEL", True),
            "oob_collaborator": _bool_env("ENABLE_OOB"),
        },
        "advanced": {
            "auth_scan": _bool_env("ENABLE_AUTH_SCAN"),
            "auth_crawl": _bool_env("ENABLE_AUTH_CRAWL"),
            "known_credential_check": _bool_env("ENABLE_KNOWN_CREDENTIAL_CHECK"),
        },
        "report": {"theme": theme, "themes": themes, "font": font,
                   "pdf_available": bool(html_pdf or docx_pdf),
                   "html_pdf": html_pdf, "docx_pdf": docx_pdf},
        "editable": user.get("role") == "admin",
    }


class ConfigBody(BaseModel):
    """환경 설정 변경(admin). 지정된 안전 키만 런타임 os.env 에 반영(다음 스캔/보고서부터 적용)."""
    validation_profile: str | None = None
    allow_advanced_validation: bool | None = None
    allow_proof_mode: bool | None = None
    browser_discovery: bool | None = None
    auth_browser_crawl: bool | None = None
    graphql_discovery: bool | None = None
    websocket_discovery: bool | None = None
    auth_scan: bool | None = None
    auth_crawl: bool | None = None
    known_credential_check: bool | None = None
    unauth_write_bac: bool | None = None
    cve_intel: bool | None = None
    oob_collaborator: bool | None = None
    report_theme: str | None = None


@app.post("/api/config")
async def api_set_config(body: ConfigBody, user: dict = Depends(require_admin)):
    """안전한 설정 부분집합만 런타임 반영(판정 로직/위험행위 정책은 변경하지 않음)."""
    import validation_profiles as _vp
    changed = {}

    def _b(flag: bool):
        return "true" if flag else "false"

    if body.validation_profile is not None:
        p = body.validation_profile.strip().upper()
        if p in _vp._RANK:
            os.environ["VALIDATION_PROFILE"] = p; changed["VALIDATION_PROFILE"] = p
    for attr, env in (("allow_advanced_validation", "ALLOW_ADVANCED_VALIDATION"),
                      ("allow_proof_mode", "ALLOW_PROOF_MODE"),
                      ("browser_discovery", "ENABLE_BROWSER_DISCOVERY"),
                      ("auth_browser_crawl", "ENABLE_AUTH_BROWSER_CRAWL"),
                      ("graphql_discovery", "ENABLE_GRAPHQL_DISCOVERY"),
                      ("websocket_discovery", "ENABLE_WEBSOCKET_DISCOVERY"),
                      ("auth_scan", "ENABLE_AUTH_SCAN"),
                      ("auth_crawl", "ENABLE_AUTH_CRAWL"),
                      ("known_credential_check", "ENABLE_KNOWN_CREDENTIAL_CHECK"),
                      ("unauth_write_bac", "ENABLE_UNAUTH_WRITE_BAC"),
                      ("cve_intel", "ENABLE_CVE_INTEL"),
                      ("oob_collaborator", "ENABLE_OOB")):
        val = getattr(body, attr)
        if val is not None:
            os.environ[env] = _b(val); changed[env] = _b(val)
    if body.report_theme is not None:
        try:
            import report_theme as _rt
            if body.report_theme in _rt.available_themes():
                os.environ["REPORT_THEME"] = body.report_theme; changed["REPORT_THEME"] = body.report_theme
        except Exception:
            pass
    try:
        import audit_log as _al
        _al.log("config_changed", user=user.get("username", ""), role=user.get("role", ""),
                changed=changed)
    except Exception:
        pass
    return {"saved": True, "changed": changed,
            "note": "런타임 반영됨(다음 스캔/보고서부터 적용). 프로세스 재시작 없이 동작합니다."}


class ReportThemeBody(BaseModel):
    theme: str


@app.post("/api/config/report-theme")
async def api_set_report_theme(body: ReportThemeBody, user: dict = Depends(get_current_user)):
    """보고서 테마 변경 — 모든 인증 사용자 허용(테마는 표현 전용이라 판정/정책과 무관)."""
    try:
        import report_theme as _rt
        if body.theme in _rt.available_themes():
            os.environ["REPORT_THEME"] = body.theme
            try:
                import audit_log as _al
                _al.log("report_theme_changed", user=user.get("username", ""),
                        role=user.get("role", ""), theme=body.theme)
            except Exception:
                pass
            return {"saved": True, "theme": body.theme}
    except Exception:
        pass
    raise HTTPException(status_code=400, detail="알 수 없는 테마입니다.")


@app.get("/api/audit")
async def api_audit(limit: int = 100, user: dict = Depends(require_admin)):
    """보안 감사 로그(최근순, 관리자 전용). 민감값은 마스킹되어 기록됨."""
    import audit_log as _al
    return {"entries": _al.recent(max(1, min(500, limit)))}


@app.get("/api/screenshots/{filename}")
async def get_screenshot(filename: str, user: dict = Depends(get_current_user)):
    # Prevent path traversal
    safe_name = pathlib.Path(filename).name
    file_path = SCREENSHOTS_DIR / safe_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Screenshot not found")
    return FileResponse(file_path, media_type="image/png")


# ── 프론트엔드 정적 파일 서빙 (빌드된 경우에만) ────────────────────────────────
_DIST_INDEX = FRONTEND_DIST / "index.html"

if FRONTEND_DIST.exists():
    # /assets 등 Vite 빌드 산출물
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    # index.html 은 항상 재검증(no-cache)해 새 프론트 배포가 하드새로고침 없이 즉시 반영되게 한다.
    # (에셋은 Vite 가 내용 해시 파일명을 쓰므로 새 배포 = 새 URL → 자동으로 새로 받음.)
    _NO_CACHE = {"Cache-Control": "no-cache, must-revalidate"}

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        # API / WS 경로는 위에서 이미 처리됨
        file_path = FRONTEND_DIST / full_path
        if file_path.is_file():
            if file_path.name == "index.html":
                return FileResponse(file_path, headers=_NO_CACHE)
            return FileResponse(file_path)
        # SPA fallback = index.html → 캐시 재검증(옛 index 를 물어 옛 화면이 남던 문제 해결)
        return FileResponse(_DIST_INDEX, headers=_NO_CACHE)

