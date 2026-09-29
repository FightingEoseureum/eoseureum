"""
probes/orchestrator.py — Probe 오케스트레이터.

역할: enabled probe 로드 → ProbeContext 생성 → 각 probe 격리 실행(오류 무시) →
ProbeResult 병합 → (호환) 레거시 finding 으로 변환.

probe 모듈은 각자 모듈 레벨 PROBE = XxxProbe() 인스턴스를 노출한다. 일부 모듈이 없거나
import 실패해도 전체는 계속 동작한다(resilient).
"""
from __future__ import annotations

from .base import ProbeContext, ProbeResult
from .config import ScanConfig
from .adapter import probe_results_to_findings
from .utils.rate_limiter import RateLimiter, CompositeRateLimiter
from .utils.evidence import EvidenceStore
from .utils.injection_points import extract_injection_points

# (category, module 경로) — 등록 순서대로 실행
_PROBE_MODULES = [
    ("xss",             "probes.xss_probe"),
    ("sqli",            "probes.sqli_probe"),
    ("source_sqli",     "probes.source_sqli_probe"),
    ("cmdi",            "probes.cmdi_probe"),
    ("auth",            "probes.auth_probe"),
    ("credential",      "probes.credential_probe"),
    ("cors",            "probes.cors_probe"),
    ("clickjacking",    "probes.clickjacking_probe"),
    ("http_method",     "probes.http_method_probe"),
    ("info_disclosure", "probes.info_disclosure_probe"),
    ("admin_exposure",  "probes.admin_exposure_probe"),
    # 참고: lfi/ssrf/file_exposure/service 는 빈 stub 이었고 실로직이 active_probing 에 있어 제거함
    # (LFI=_probe_lfi, 백업파일=_probe_backup_file, 서비스=service_scan). SSRF 는 OOB 부재로 미탐지.
]


def load_probes() -> list:
    """등록된 probe 모듈에서 PROBE 인스턴스를 수집(없거나 실패하면 건너뜀)."""
    probes = []
    import importlib
    for _cat, modpath in _PROBE_MODULES:
        try:
            mod = importlib.import_module(modpath)
            probe = getattr(mod, "PROBE", None)
            if probe is not None:
                probes.append(probe)
        except Exception:
            continue
    return probes


def get_enabled_probes(config: ScanConfig | None = None) -> list:
    config = config or ScanConfig.from_env()
    out = []
    for p in load_probes():
        cat = getattr(p, "category", "")
        if config.enabled.get(cat, getattr(p, "enabled_by_default", True)):
            out.append(p)
    return out


async def build_context(host: str, port: int, scheme: str, http_info: dict | None,
                        cookies: list | None, session, scan_id: str = "",
                        discovered_urls: list | None = None,
                        config: ScanConfig | None = None) -> ProbeContext:
    config = config or ScanConfig.from_env()
    base_url = (http_info or {}).get("url") or f"{scheme}://{host}:{port}"
    # 프로파일 연동: 거버너 설치 시(SAFE/STANDARD/ADVANCED) orchestrator 리미터를 프로파일 상한으로 클램프
    # (PROOF/미설치면 config.global_rps 그대로). orchestrator 는 기본 off 지만 켜질 때 SAFE 5rps 를 넘지 않게.
    _rps = config.global_rps
    _arps = config.auth_rps
    try:
        import adaptive_throttle as _gov
        _lim = _gov.stage("active_probing")
        if _lim is not None:
            _rps = min(_rps, _lim.max_rps)
            _arps = min(_arps, _lim.max_rps)
    except Exception:
        pass
    _global = RateLimiter(_rps)
    _auth = CompositeRateLimiter(_global, RateLimiter(_arps))
    ctx = ProbeContext(
        target_url=base_url, host=host, port=port, scheme=scheme,
        discovered_urls=discovered_urls or [],
        session=session, cookies=cookies or [],
        rate_limiter=_global, auth_rate_limiter=_auth,
        scan_config=config, evidence_store=EvidenceStore(), scan_id=scan_id,
    )
    if session is not None:
        try:
            ctx.injection_points = await extract_injection_points(session, base_url)
        except Exception:
            ctx.injection_points = []
    # 인증 스캔 (ENABLE_AUTH_SCAN=true + 계정 제공 시에만) — authenticated_scan 에 위임
    if config.enable_auth_scan and config.auth_login_url and config.auth_username and config.auth_password:
        try:
            import authenticated_scan
            auth_res = await authenticated_scan.perform_login_and_crawl(config, base_url)
            if auth_res and auth_res.get("logged_in"):
                ctx.authenticated_session = auth_res.get("session")
                ctx.authenticated_urls = auth_res.get("urls", []) or []
                ctx.authenticated_forms = auth_res.get("forms", []) or []
                # 인증 후 폼/파라미터를 주입 지점에 합류(중복 제거)
                from .utils.injection_points import dedup_points
                ctx.injection_points = dedup_points(ctx.injection_points + ctx.authenticated_forms)
        except Exception as e:
            if ctx.evidence_store:
                ctx.evidence_store.add_error("auth_scan", str(e))
    return ctx


async def run_probes(context: ProbeContext, config: ScanConfig | None = None) -> list[ProbeResult]:
    """enabled probe 들을 격리 실행하여 ProbeResult 목록을 반환한다.
    개별 probe 실패는 evidence_store.errors 에 기록되고 전체는 계속된다."""
    config = config or context.scan_config or ScanConfig.from_env()
    results: list[ProbeResult] = []
    for probe in get_enabled_probes(config):
        res = await probe.execute(context)   # execute() 가 예외를 격리함
        for r in (res or []):
            if isinstance(r, ProbeResult):
                results.append(r)
    return results


async def run_active_probes_orchestrated(host: str, port: int, is_ssl: bool,
                                         http_info: dict, cookies: list,
                                         scan_id: str = "",
                                         discovered_urls: list | None = None) -> list[dict]:
    """레거시 호환 진입점: orchestrator 로 probe 를 돌려 '레거시 finding 목록'으로 반환한다.
    (세션은 내부에서 생성/정리)"""
    from .utils.http_client import make_session
    config = ScanConfig.from_env()
    scheme = "https" if is_ssl else "http"
    async with make_session(timeout=config.request_timeout, cookies=cookies) as session:
        ctx = await build_context(host, port, scheme, http_info, cookies, session,
                                  scan_id=scan_id, discovered_urls=discovered_urls, config=config)
        results = await run_probes(ctx, config)
    return probe_results_to_findings(results, host, port)
