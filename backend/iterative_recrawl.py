"""
iterative_recrawl.py — 반복 재크롤/재점검 오케스트레이터.

목적:
  1차 스캔(발견→점검→룰엔진)이 끝난 뒤, "취약점(예: 인증 우회)으로 새로 접근 가능해진
  경로" 또는 "인증 이후에만 보이는 경로"를 추가로 크롤하고, 그 **새 경로만** 다시 점검한다.

설계 원칙(코드로 강제되는 안전 경계):
  - 종료 보장: 아래 임계치가 백스톱이라 무한 루프가 불가능하다.
      (a) 라운드 상한 MAX_RECRAWL_ROUNDS(기본 5, 1~10)
      (b) 진행 보장: 매 라운드는 new = 발견 - seen 만 처리. seen 은 커지기만 하고
          URL 우주는 유한 → new 는 반드시 언젠가 공집합이 되어 자동 종료.
      (c) 페이지/시간 예산(RECRAWL_MAX_NEW_PER_ROUND, RECRAWL_TIME_BUDGET_SEC).
  - AI 의 역할은 '조언(이번 라운드 크롤이 가치 있는가 + 우선순위)'뿐이다. AI 가 계속
    "crawl" 해도 위 임계치가 종료를 보장한다. AI 미가용/실패/타임아웃이면 결정적 판단으로
    폴백한다(폴백 기본값은 '새 대상이 있으면 진행').
  - 판정/severity 는 여전히 Rule Engine 전담(analyze_fn). 이 모듈은 새 경로를 점검해
    '추가 finding'만 만들어 병합할 뿐, 기존 판정을 바꾸지 않는다.
  - best-effort: 어떤 예외도 전체 스캔을 실패시키지 않는다(호출부에서 try 로 감싸고,
    내부에서도 라운드별로 방어).

이 모듈은 main.py 만 import 한다(순환참조 없음). rule_engine/active_probing/url_discovery/
authenticated_scan/ai_provider 는 함수 내부에서 지연 import 한다.
"""
from __future__ import annotations

import asyncio
import copy
import json
import os
import re
import time
from urllib.parse import urlparse


# ── env 게이트 (순수 함수) ────────────────────────────────────────────────────
def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.getenv(name, str(default)))))
    except (TypeError, ValueError):
        return default


def enabled() -> bool:
    # 기본 ON: 확정 finding 을 시드로 심화 재점검(약한 이음새 개선). bounded — max_rounds(5)·
    # time_budget(600s)·조기종료(새 시드 없으면 즉시 종료)로 시간 폭주 방지. 끄려면 =false.
    return _bool("ENABLE_ITERATIVE_RECRAWL", True)


def max_rounds() -> int:
    # 사용자 요구: 5~10회. 기본 5, 상한 10.
    return _int("MAX_RECRAWL_ROUNDS", 5, 1, 10)


def max_new_per_round() -> int:
    return _int("RECRAWL_MAX_NEW_PER_ROUND", 60, 1, 500)


def time_budget_sec() -> int:
    return _int("RECRAWL_TIME_BUDGET_SEC", 600, 30, 3600)


def ai_gate_enabled() -> bool:
    """AI 에게 '크롤 필요?'를 물을지. 기본 True(단, 미가용이면 자동 결정적 폴백)."""
    return _bool("RECRAWL_AI_GATE", True)


# ── 순수 헬퍼 (네트워크 없음 — 단위테스트 대상) ────────────────────────────────
def _norm(url: str) -> str:
    """비교/차집합용 정규화(스킴+호스트+경로, 쿼리/프래그먼트 제거, 후행 슬래시 정리)."""
    try:
        p = urlparse((url or "").strip())
        if p.scheme not in ("http", "https"):
            return ""
        path = p.path or "/"
        clean = f"{p.scheme}://{p.netloc}{path}"
        return clean.rstrip("/") or clean
    except Exception:
        return ""


def collect_seen_urls(host_results: list) -> set:
    """지금까지 발견된 모든 URL(전 서비스 union)을 정규화해 seen 집합으로."""
    seen: set = set()
    for hr in host_results or []:
        for svc in (hr.get("services") or []):
            for u in (svc.get("discovered_urls") or []):
                n = _norm(u)
                if n:
                    seen.add(n)
            dr = svc.get("discovery_result") or {}
            for u in dr.get("urls") or []:
                n = _norm(u.get("url") if isinstance(u, dict) else u)
                if n:
                    seen.add(n)
    return seen


def diff_new(discovered: list, seen: set) -> list:
    """discovered 중 seen 에 없는 URL 만 순서 보존해 반환(정규화 기준 중복 제거)."""
    out, added = [], set()
    for u in discovered or []:
        n = _norm(u)
        if not n or n in seen or n in added:
            continue
        added.add(n)
        out.append(u)
    return out


# 새 표면을 열 가능성이 높은 finding 유형(트리거 힌트) — 재크롤 가치가 높음.
_SURFACE_OPENING = re.compile(
    r"(인증\s*우회|auth[\s_-]*bypass|로그인.*우회|권한|접근\s*제어|access\s*control|"
    r"idor|open\s*redirect|리다이렉트|ssrf|lfi|파일\s*포함|path\s*traversal|경로\s*순회)",
    re.IGNORECASE,
)


def _finding_urls(analysis: dict) -> list:
    """finding 의 evidence_url/url 을 seed 후보로 추출."""
    out = []
    for f in (analysis.get("findings") or []):
        if not isinstance(f, dict):
            continue
        for k in ("evidence_url", "url", "affected_url"):
            v = f.get(k)
            if isinstance(v, str) and v.strip():
                out.append(v.strip())
    return out


def newly_reachable_seeds(analysis: dict, host_results: list, seen: set) -> list:
    """이번 라운드 크롤 시작점 후보(새로 접근 가능해졌을 만한 페이지).

    - finding 의 evidence URL(취약점 페이지에서 보호 영역으로 연결될 수 있음)
    - discovery 의 관리자/내부 API/로그인 필요 추정 URL
    seed 는 seen 여부와 무관하게 '시작점'으로 쓸 수 있으나(그 페이지에서 링크를 캔다),
    새 URL 판정은 이후 diff_new 로 한다.
    """
    cands: list = []
    cands += _finding_urls(analysis)
    for hr in host_results or []:
        for svc in (hr.get("services") or []):
            dr = svc.get("discovery_result") or {}
            for a in (dr.get("admin_hits") or []):
                if isinstance(a, dict) and a.get("url"):
                    cands.append(a["url"])
            for a in (dr.get("api_hits") or []):
                if isinstance(a, dict) and a.get("url"):
                    cands.append(a["url"])
    # 순서 보존 중복 제거
    out, s = [], set()
    for u in cands:
        n = _norm(u)
        if n and n not in s:
            s.add(n)
            out.append(u)
    return out


def _sig(f: dict) -> tuple:
    """finding 중복 판정 시그니처(제목 + 대상 URL)."""
    if not isinstance(f, dict):
        return ("", "")
    title = str(f.get("title") or f.get("name") or "").strip().lower()
    url = _norm(f.get("evidence_url") or f.get("url") or f.get("affected_url") or "")
    return (title, url)


def merge_new_findings(existing: list, scoped: list) -> tuple[list, int]:
    """scoped(재점검 결과) 중 기존에 없는 것만 추가. (병합리스트, 추가개수) 반환."""
    existing = list(existing or [])
    seen_sig = {_sig(f) for f in existing}
    added = 0
    for f in (scoped or []):
        if not isinstance(f, dict):
            continue
        sg = _sig(f)
        if sg in seen_sig:
            continue
        seen_sig.add(sg)
        f.setdefault("discovered_by", "iterative_recrawl")
        existing.append(f)
        added += 1
    return existing, added


def deterministic_should_crawl(round_idx: int, mx: int, seed_count: int,
                               do_auth: bool, findings_delta: int) -> tuple[bool, str]:
    """AI 미가용 시 결정적 판단. 진행 여지가 있으면 True."""
    if round_idx > mx:
        return False, f"라운드 상한({mx}) 도달"
    if do_auth:
        return True, "인증 크롤 예정"
    if seed_count <= 0:
        return False, "새 크롤 시작점 없음"
    return True, f"크롤 시작점 {seed_count}개 존재"


def prioritize_new_urls(new_urls: list, cap: int, ai_order: list | None = None) -> list:
    """새 URL 을 우선순위로 정렬 후 cap 개로 제한.

    AI 우선순위(ai_order: 정규화 URL 리스트)가 있으면 그 순서를 우선 반영하고,
    없거나 부족하면 결정적 우선순위(관리자/인증/API 경로 > 일반)로 채운다.
    """
    def _score(u: str) -> int:
        p = _norm(u).lower()
        s = 0
        if any(k in p for k in ("/admin", "/manage", "/backend", "/console", "/dashboard")):
            s += 5
        if any(k in p for k in ("/api/", "/graphql", "/actuator", "/internal", "/private")):
            s += 4
        if any(k in p for k in ("login", "auth", "account", "user", "config", "setting")):
            s += 3
        if "?" in (u or ""):
            s += 1  # 쿼리 파라미터 = 주입 입력점 가능
        return s

    ranked = sorted(new_urls, key=_score, reverse=True)
    if ai_order:
        order_index = {u: i for i, u in enumerate(ai_order)}
        ranked.sort(key=lambda u: order_index.get(_norm(u), 10_000))
    return ranked[:cap]


# ── AI 조언자 (게이트 아님) ────────────────────────────────────────────────────
def _findings_brief(analysis: dict, limit: int = 12) -> str:
    lines = []
    for f in (analysis.get("findings") or [])[:limit]:
        if isinstance(f, dict):
            sev = f.get("severity", "")
            title = f.get("title") or f.get("name") or ""
            lines.append(f"- [{sev}] {title}")
    return "\n".join(lines) or "(취약점 없음)"


async def ai_decide_crawl(analysis: dict, seed_count: int, round_idx: int,
                          do_auth: bool) -> tuple[bool | None, str, list]:
    """AI 에게 '이번 라운드 재크롤이 가치 있는가 + 어떤 영역 우선'을 묻는다.

    반환: (crawl: True/False/None, reason, priority_hints: list[str])
      crawl=None 이면 'AI 판단 불가 → 결정적 폴백'.
    실패/미가용/파싱오류 시 항상 (None, 사유, []).
    """
    if not ai_gate_enabled():
        return None, "RECRAWL_AI_GATE=false", []
    try:
        from ai_provider import get_ai_provider, NoneProvider
    except Exception:
        return None, "ai_provider import 실패", []
    try:
        provider = get_ai_provider()
        if isinstance(provider, NoneProvider):
            return None, "AI 프로바이더 미설정", []
        surface_hint = any(
            _SURFACE_OPENING.search(str(f.get("title", "")))
            for f in (analysis.get("findings") or []) if isinstance(f, dict)
        )
        prompt = (
            "당신은 웹 취약점 진단의 '재크롤 필요성' 판단 보조자입니다. 아래 정보를 보고, "
            "이번 라운드에 추가 크롤+점검을 수행할 가치가 있는지 판단하세요. "
            "인증 우회/IDOR/오픈리다이렉트/권한 관련 취약점이 있으면 새로 접근 가능한 경로가 "
            "생겼을 가능성이 높습니다.\n\n"
            f"[라운드] {round_idx}\n"
            f"[인증 크롤 예정] {'예' if do_auth else '아니오'}\n"
            f"[새 크롤 시작점 후보 수] {seed_count}\n"
            f"[표면확장형 취약점 감지] {'예' if surface_hint else '아니오'}\n"
            f"[현재 취약점 요약]\n{_findings_brief(analysis)}\n\n"
            '반드시 JSON 하나만 출력: {"crawl": true/false, "reason": "간단한 사유", '
            '"priority": ["우선 재점검할 경로 키워드(선택)"]}'
        )
        raw = await provider.complete(prompt)
        if not raw:
            return None, "AI 빈 응답", []
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        data = json.loads(m.group(0)) if m else {}
        crawl = data.get("crawl")
        reason = str(data.get("reason") or "")[:200]
        pri = data.get("priority") or []
        pri = [str(x) for x in pri if isinstance(x, (str, int, float))][:10] if isinstance(pri, list) else []
        if isinstance(crawl, bool):
            return crawl, reason or "AI 판단", pri
        return None, "AI 응답에 crawl 불명확", pri
    except Exception as e:
        return None, f"AI 판단 실패: {str(e)[:80]}", []


# ── 네트워크 단계 (지연 import) ────────────────────────────────────────────────
def _service_bases(host_results: list) -> list[tuple[str, str]]:
    """(host, base_url) 목록 — http_info 있는 서비스."""
    out = []
    for hr in host_results or []:
        host = hr.get("host") or ""
        for svc in (hr.get("services") or []):
            hi = svc.get("http_info") or {}
            base = hi.get("url")
            if not base:
                port = svc.get("port", 80)
                if host:
                    base = f"{'https' if port in (443, 8443) else 'http'}://{host}:{port}"
            if base:
                out.append((host, base))
    return out


async def _recrawl_hosts(host_results: list, seeds: list, seen: set,
                         exclude_patterns: list | None = None) -> list:
    """각 서비스 base 에서 seed 로부터 크롤(이미 본 것 제외, passive 재탐색 생략). 새 URL 리스트 반환."""
    from url_discovery import URLDiscoveryEngine
    try:
        max_pages = max(1, min(5000, int(os.getenv("MAX_CRAWL_PAGES", "200"))))
    except (TypeError, ValueError):
        max_pages = 200
    try:
        depth = max(1, min(8, int(os.getenv("MAX_CRAWL_DEPTH", "2"))))
    except (TypeError, ValueError):
        depth = 2
    exclude = list(seen)
    found: list = []
    for host, base in _service_bases(host_results):
        # 해당 호스트로 스코프된 seed 만 사용
        host_seeds = [s for s in seeds if urlparse(_norm(s)).netloc == urlparse(_norm(base)).netloc] or seeds
        engine = URLDiscoveryEngine(max_urls=max_pages, max_depth=depth, rate_limit=0.3, concurrency=3)
        try:
            res = await engine.discover(base, seed_urls=host_seeds, exclude_urls=exclude,
                                        exclude_patterns=exclude_patterns,
                                        skip_passive=True)
            found += res.unique_url_strings()
        except Exception:
            continue
    return found


async def _probe_and_analyze_new(host_results: list, new_urls: list, scan_id: str,
                                 domain_notes: str = "") -> list:
    """새 URL 만 스코프한 host_results 복사본으로 재점검+룰엔진 → 새 finding 리스트."""
    from active_probing import probe_active_for_all_hosts
    from rule_engine import analyze_with_rules

    scoped = copy.deepcopy(host_results)
    new_by_host: dict = {}
    for u in new_urls:
        host = urlparse(_norm(u)).netloc
        new_by_host.setdefault(host, []).append(u)
    any_target = False
    for hr in scoped:
        for svc in (hr.get("services") or []):
            if not svc.get("http_info"):
                continue
            host = urlparse(_norm(svc["http_info"].get("url") or "")).netloc or (hr.get("host") or "")
            svc["discovered_urls"] = list(new_by_host.get(host, new_urls))
            svc.pop("active_probes", None)  # 라운드별 새 점검 결과만 담기게 초기화
            if svc["discovered_urls"]:
                any_target = True
    if not any_target:
        return []
    # 재점검(커버리지는 누적 — reset_cov=False)
    await probe_active_for_all_hosts(scoped, max_concurrent=3, scan_id=scan_id, reset_cov=False)
    result = analyze_with_rules(scoped, previous_scans=None, domain_notes=domain_notes)
    return result.get("findings", []) or []


async def _auth_crawl(domain: str, auth: dict | None = None) -> tuple[list, bool, str, list]:
    """인증 로그인 후 크롤 — (urls, logged_in, reason, cookies).

    auth: 이 스캔의 인증정보(per-scan). None 이면 전역 env(probe_policy) 폴백.
    cookies: 로그인 세션 쿠키 [{'name','value'}...] — 인증 상태 능동 점검 등록용
             (기존엔 세션을 버려 인증 영역이 로그아웃 상태로 재점검되던 공백을 보정).
    """
    try:
        import probe_policy as pp
        cfg = auth if (auth and auth.get("login_url")) else pp.auth_crawl_config()
        skip = pp.auth_crawl_skip_reason(cfg)
        if skip:
            return [], False, skip, []
        from probes.config import ScanConfig
        authcfg = ScanConfig.from_env()
        authcfg.enable_auth_scan = True
        authcfg.auth_login_url = cfg["login_url"]
        authcfg.auth_username = cfg["username"]
        authcfg.auth_password = cfg["password"]
        authcfg.auth_success_pattern = cfg.get("success_pattern") or "auto"
        authcfg.auth_max_pages = cfg.get("max_pages", 50)
        import authenticated_scan as auth_mod
        # https 우선 시도, 실패 시 http (기존 코드의 http 하드코딩 버그 회피)
        base = cfg["login_url"] or f"https://{domain}"
        parsed = urlparse(base)
        base_root = f"{parsed.scheme or 'https'}://{parsed.netloc or domain}"
        ar = await auth_mod.perform_login_and_crawl(authcfg, base_root)
        # 로그인 세션 쿠키 추출(값 복사) → 인증 상태 능동 점검 등록에 사용.
        _sess = ar.get("session")
        _ck = []
        if _sess is not None and getattr(_sess, "cookie_jar", None) is not None:
            for _c in _sess.cookie_jar:
                try:
                    _ck.append({"name": _c.key, "value": _c.value})
                except Exception:
                    continue
        return (ar.get("urls") or []), bool(ar.get("logged_in")), (ar.get("reason") or ""), _ck
    except Exception as e:
        return [], False, f"auth crawl error: {str(e)[:80]}", []


def auth_available(auth: dict | None = None) -> bool:
    """이 스캔에서 인증 크롤이 가능한지(per-scan 인증정보 우선, 없으면 전역 env)."""
    try:
        import probe_policy as pp
        cfg = auth if (auth and auth.get("login_url")) else pp.auth_crawl_config()
        return pp.auth_crawl_skip_reason(cfg) is None
    except Exception:
        return False


# ── 메인 오케스트레이터 ────────────────────────────────────────────────────────
async def run(host_results: list, analysis: dict, scan_id: str, domain: str,
              send=None, domain_notes: str = "", auth: dict | None = None,
              time_budget_sec_override: int | None = None,
              max_rounds_override: int | None = None,
              exclude_patterns: list | None = None,
              ext_offload=None, merge_external_fn=None) -> dict:
    """반복 재크롤/재점검 실행. analysis["findings"] 를 in-place 로 보강하고 요약 dict 반환.

    auth: 이 스캔의 인증정보(per-scan). 인증 라운드에서 사용(없으면 전역 env 폴백).
    time_budget_sec_override/max_rounds_override: 스캔의 '허용 시간'과 연동해 심층 반복을 늘림
      (마법사에서 넉넉한 시간을 지정하면 남은 시간만큼 재크롤/재점검을 더 오래·여러 라운드 수행)."""
    summary = {
        "enabled": True, "rounds": 0, "added_findings": 0,
        "new_urls_total": 0, "stop_reason": "", "history": [],
    }

    async def _send(msg, typ="info"):
        if send:
            try:
                await send({"type": typ, "message": msg})
            except Exception:
                pass

    # 허용 시간 연동: override 가 오면 라운드 상한·시간예산을 스캔 허용 시간에 맞춰 확장.
    mx = max(1, min(30, int(max_rounds_override))) if max_rounds_override else max_rounds()
    cap = max_new_per_round()
    budget = (max(30, min(172800, int(time_budget_sec_override)))   # 최대 48시간
              if time_budget_sec_override else time_budget_sec())
    start = time.monotonic()
    seen = collect_seen_urls(host_results)
    auth_done = not auth_available(auth)  # 인증 정보 없으면 인증 단계 자체를 '완료'로 간주
    await _send(f"[반복 재크롤] 시작 — 상한 {mx}회, 시작 seen={len(seen)}개"
                + ("" if auth_done else ", 인증 단계 포함"))

    for r in range(1, mx + 1):
        added = 0   # 이번 라운드에 병합된 새 취약점 수(라운드마다 초기화 — 누락 시 NameError)
        if time.monotonic() - start > budget:
            summary["stop_reason"] = f"시간 예산({budget}s) 초과"
            break

        do_auth = not auth_done
        seeds = newly_reachable_seeds(analysis, host_results, seen)

        # 1) 크롤 판단: AI 조언 → 없으면 결정적 폴백. (임계치는 루프가 보장)
        ai_crawl, ai_reason, ai_pri = await ai_decide_crawl(analysis, len(seeds), r, do_auth)
        if ai_crawl is None:
            should, reason = deterministic_should_crawl(r, mx, len(seeds), do_auth, 0)
            decided_by = "결정적"
        else:
            should, reason, decided_by = ai_crawl, ai_reason, "AI"
        # 인증 단계(비인증→인증)는 사용자 의도상 최소 1회 보장 — AI 가 '불필요'라 해도 진행.
        if do_auth and not should:
            should, reason, decided_by = True, "인증 단계는 1회 보장(" + reason + ")", decided_by + "+정책"
        summary["history"].append({
            "round": r, "decided_by": decided_by, "crawl": bool(should),
            "reason": reason, "seed_candidates": len(seeds), "auth": do_auth,
        })
        await _send(f"[반복 재크롤] {r}회차 판단({decided_by}): "
                    f"{'진행' if should else '종료'} — {reason}")
        if not should:
            summary["stop_reason"] = summary["stop_reason"] or f"{decided_by} 판단: 종료({reason})"
            break

        # 2) 인증 단계(최초 1회): 로그인 후 인증 페이지를 seed 에 편입
        round_seeds = list(seeds)
        if do_auth:
            auth_urls, logged_in, auth_reason, auth_cookies = await _auth_crawl(domain, auth)
            auth_done = True
            await _send(f"[반복 재크롤] 인증 크롤: 로그인 {'성공' if logged_in else '실패'} "
                        f"— 인증 페이지 {len(auth_urls)}개 ({auth_reason})")
            round_seeds += auth_urls
            # 로그인 성공 → (1) 세션 쿠키를 능동 점검에 등록해 인증 상태로 점검,
            # (2) 인증 URL 을 각 HTTP 서비스 discovered_urls 에 합류(인증 입력점도 점검),
            # (3) 인증 결과를 analysis 에 기록(main.py 가 커버리지로 승격).
            if logged_in and auth_cookies:
                try:
                    import active_probing as _apc
                    _apc.register_auth_cookies(scan_id, auth_cookies)
                    # CSRF '실제 수행' 비파괴 실증용으로 로그인 비밀번호도 등록(메모리 전용·미저장).
                    # 주의: 이 스코프에는 `cfg` 가 없다(그건 _auth_crawl 지역변수) — 예전 코드는
                    # NameError 를 아래 except 가 삼켜 비번이 등록되지 않아 CSRF 실제수행이 스킵됐다.
                    # _auth_crawl 과 '동일한' 해석식으로 유효 비밀번호를 다시 구한다:
                    #   per-scan auth(login_url 보유 시) → 전역 AUTH_* 설정(AUTH_PASSWORD env).
                    try:
                        import probe_policy as _pp
                        _login_cfg = auth if (isinstance(auth, dict) and auth.get("login_url")) \
                            else _pp.auth_crawl_config()
                        _eff_pw = (_login_cfg or {}).get("password") or ""
                        _apc.register_auth_password(scan_id, _eff_pw)
                    except Exception:
                        pass
                    await _send(f"[반복 재크롤] 로그인 세션 쿠키 {len(auth_cookies)}개 등록 — 인증 상태 능동 점검 활성")
                except Exception:
                    pass
            if logged_in and auth_urls:
                try:
                    _cap_du = max(50, min(5000, int(os.getenv("MAX_DISCOVERED_URLS", "500"))))
                except (TypeError, ValueError):
                    _cap_du = 500
                # 인증 페이지를 scan_id 레지스트리에 '누적' 등록 — 라운드마다 discovered_urls 가 교체돼도
                # 세션 인지 프로브(csrf 구조확증·weak session·open redirect)가 항상 전체 인증 페이지를
                # 참조하도록 한다(발견→프로브 핸드오프 갭 보정).
                try:
                    import active_probing as _apu
                    _apu.register_auth_urls(scan_id, list(auth_urls))
                except Exception:
                    pass
                for hr in host_results:
                    for svc in hr.get("services", []):
                        if svc.get("http_info"):
                            _merged = list(svc.get("discovered_urls") or []) + list(auth_urls)
                            svc["discovered_urls"] = list(dict.fromkeys(_merged))[:_cap_du]
            analysis["_auth_crawl_result"] = {
                "login_success": bool(logged_in), "pages": len(auth_urls),
                "reason": auth_reason or "",
            }

        # 3) 재크롤(이미 본 것 제외) → 새 URL 차집합
        try:
            discovered = await _recrawl_hosts(host_results, round_seeds, seen,
                                              exclude_patterns=exclude_patterns)
        except Exception as e:
            discovered = []
            await _send(f"[반복 재크롤] 크롤 오류(무시): {str(e)[:80]}", "warning")
        # 인증 라운드: 로그인 크롤이 찾은 인증 페이지는 비인증 재크롤러가 재발견하지 못하므로
        # (로그인으로 리다이렉트) 프로빙 대상(new_urls)에 직접 포함한다 → 등록된 세션 쿠키로
        # 인증 상태에서 능동 점검(이게 없으면 인증 URL 을 찾고도 로그아웃 상태로만 점검됨).
        if do_auth and auth_urls:
            discovered = list(discovered) + list(auth_urls)
        new_urls = diff_new(discovered, seen)
        if not new_urls:
            summary["stop_reason"] = summary["stop_reason"] or "새 경로 없음(수렴)"
            await _send("[반복 재크롤] 새 경로 없음 → 수렴, 종료")
            summary["rounds"] = r - 1 if not do_auth else r
            # 인증 라운드였고 새 URL 이 없어도 인증 자체는 시도했으므로 다음 라운드 진행 여지 없음
            break

        # seen 갱신 + 우선순위/상한
        for u in new_urls:
            seen.add(_norm(u))
        prioritized = prioritize_new_urls(new_urls, cap, ai_order=[_norm(x) for x in ai_pri] if ai_pri else None)
        # 인증 라운드: 로그인 크롤이 찾은 인증 페이지(auth_urls)는 라운드 상한(cap)에 잘리지 않게
        # 모두 점검 대상에 포함한다. 이 라운드의 목적 자체가 인증 영역(로그인 후 취약 모듈) 점검이라,
        # 여기서 잘리면 인증 SQLi·XSS·CMDi 페이지가 프로브까지 도달 못 해 전멸했음(실측 원인).
        if do_auth and auth_urls:
            _seen_p = set(_norm(u) for u in prioritized)
            prioritized = prioritized + [u for u in auth_urls if _norm(u) not in _seen_p]
        summary["new_urls_total"] += len(prioritized)
        await _send(f"[반복 재크롤] {r}회차: 새 경로 {len(new_urls)}개 발견"
                    + (f" (상한 적용 {len(prioritized)}개 점검)" if len(prioritized) < len(new_urls) else "")
                    + (" · 인증 후" if do_auth else ""))

        # 4) 새 경로만 재점검 — CPU1(Mac 능동) ∥ CPU2(i7 외부도구) 재분기(2칸 UX)
        #    양쪽이 각각 끝나면 완료 표시 후 합친다(사용자 지정 흐름).
        await _send(f"[반복 재크롤] {r}회차 재점검 분기 — CPU1(Mac 능동) ∥ CPU2(i7 외부도구)")
        _mac_task = asyncio.create_task(
            _probe_and_analyze_new(host_results, prioritized, scan_id, domain_notes))
        _i7_task = None
        if ext_offload is not None:
            try:
                _scoped_for_i7 = copy.deepcopy(host_results)
                for _hr in _scoped_for_i7:
                    for _svc in (_hr.get("services") or []):
                        if _svc.get("http_info"):
                            _svc["discovered_urls"] = list(prioritized)
                _i7_task = asyncio.create_task(ext_offload(_scoped_for_i7))
            except Exception:
                _i7_task = None
        # CPU1(Mac) 완료
        try:
            new_findings = await _mac_task
        except Exception as e:
            new_findings = []
            await _send(f"[반복 재크롤] 재점검 오류(무시): {str(e)[:80]}", "warning")
        await _send(f"[반복 재크롤] {r}회차 ✅ CPU1(Mac) 능동 재점검 완료 — {len(new_findings)}건")
        # CPU2(i7) 완료 — 외부 findings 병합
        if _i7_task is not None:
            try:
                _ext_new = await _i7_task
            except Exception:
                _ext_new = None
            _ext_new = _ext_new or []
            await _send(f"[i7 외부도구] ✅ CPU2(i7) 외부도구 재점검 완료 — {len(_ext_new)}건")
            if _ext_new and merge_external_fn:
                try:
                    _before = len(analysis.get("findings", []) or [])
                    analysis["findings"] = merge_external_fn(analysis.get("findings", []) or [], _ext_new)
                    _ea = max(0, len(analysis["findings"]) - _before)
                    added += _ea
                    if _ea:
                        await _send(f"[반복 재크롤] {r}회차: i7 외부도구 새 취약점 {_ea}건 병합", "warning")
                except Exception:
                    pass
            await _send(f"[반복 재크롤] {r}회차 🔗 CPU1·CPU2 완료 — 결과 합침")
        # 재점검으로 새로 확인된 취약점을 실제로 병합한다(예전엔 new_findings 를 버려 기능이 무력화됨).
        if new_findings:
            analysis["findings"], _nfa = merge_new_findings(analysis.get("findings", []), new_findings)
            added += _nfa
            if _nfa:
                await _send(f"[반복 재크롤] {r}회차: 새 취약점 {_nfa}건 발견(재크롤 경로 표면화)", "warning")
        # 저장형 XSS 재확인: 1차에 주입한 마커가 이번 라운드의 새 페이지에서 실행되는지(읽기 전용).
        try:
            from active_probing import recheck_stored_xss as _recheck
            _bases = _service_bases(host_results)
            _sx_base = _bases[0][1] if _bases else ""
            _sx = await _recheck(scan_id, prioritized, _sx_base)
            if _sx:
                analysis["findings"], _sxa = merge_new_findings(analysis.get("findings", []), _sx)
                added += _sxa
                if _sxa:
                    await _send(f"[반복 재크롤] {r}회차: 저장형 XSS {_sxa}건 재확인(심층 페이지 표면화)", "warning")
        except Exception:
            pass
        summary["added_findings"] += added
        summary["rounds"] = r
        await _send(f"[반복 재크롤] {r}회차 완료: 새 취약점 {added}건 추가"
                    + (f" (누적 {summary['added_findings']}건)" if summary["added_findings"] else ""))

    if not summary["stop_reason"]:
        summary["stop_reason"] = f"라운드 상한({mx}) 도달"
    await _send(f"[반복 재크롤] 종료 — {summary['rounds']}회차, "
                f"새 경로 {summary['new_urls_total']}개, 추가 취약점 {summary['added_findings']}건 "
                f"({summary['stop_reason']})")
    analysis["iterative_recrawl"] = summary
    return summary
