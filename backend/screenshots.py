import asyncio
import json
import pathlib
import re

import browser_compat  # noqa: F401  (시스템 Chrome 폴백 패치 적용)

SCREENSHOTS_DIR = pathlib.Path(__file__).parent / "screenshots"
SCREENSHOTS_DIR.mkdir(exist_ok=True)
_THIS_FILE = pathlib.Path(__file__).resolve()

# Shared browser instance across captures in a scan
_playwright = None
_browser = None


def _safe_label(host: str, port: int, suffix: str = "") -> str:
    h = re.sub(r"[^\w\-.]", "_", host)[:50]
    s = re.sub(r"[^\w\-]", "_", suffix)[:30] if suffix else ""
    label = f"{h}_{port}" + (f"_{s}" if s else "")
    return label


async def _capture_single(page, url: str, filepath: pathlib.Path) -> bool:
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=12000)
        await page.screenshot(path=str(filepath), full_page=False, timeout=8000)
        return True
    except Exception:
        return False


async def capture_screenshots_for_scan(scan_id: str, host_results: list[dict]) -> list[dict]:
    """
    Capture screenshots for all HTTP/HTTPS services found in host_results.
    Mutates each service dict by adding a `screenshot` key (filename or None).
    Returns the modified host_results.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return host_results

    targets = []
    for host_data in host_results:
        for svc in host_data.get("services", []):
            hi = svc.get("http_info")
            if not hi:
                continue
            url = hi.get("url")
            if not url:
                continue
            label = _safe_label(host_data["host"], svc["port"])
            filename = f"{scan_id}_{label}.png"
            targets.append((svc, url, filename))

            # Also capture sensitive paths that responded with non-404
            for path_info in (svc.get("sensitive_paths") or []):
                if path_info.get("status") in (200, 301, 302, 401, 403):
                    path_label = _safe_label(
                        host_data["host"],
                        svc["port"],
                        path_info["path"].replace("/", "_").strip("_"),
                    )
                    path_filename = f"{scan_id}_{path_label}.png"
                    path_url = url.rstrip("/") + path_info["path"]
                    targets.append((path_info, path_url, path_filename))

    if not targets:
        return host_results

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-gpu", "--ignore-certificate-errors"],
        )
        context = await browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 800},
            user_agent="Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        )
        page = await context.new_page()

        for obj, url, filename in targets:
            filepath = SCREENSHOTS_DIR / filename
            ok = await _capture_single(page, url, filepath)
            obj["screenshot"] = filename if ok else None

        await context.close()
        await browser.close()

    return host_results


def _run_evidence_capture_sync(scan_id: str, targets_json: str) -> str:
    """
    Playwright를 동기 모드로 실행하여 3단계 스크린샷을 캡처합니다.
    uvicorn 이벤트 루프 내에서 asyncio.to_thread로 호출됩니다.
    targets_json: JSON-encoded list of {idx, evidence_url, base_url, step2_desc, step3_desc}
    returns: JSON-encoded list of {idx, shots: [filename, ...]}
    """
    import urllib.parse as _up

    targets = json.loads(targets_json)
    results = []

    _OVERLAY_JS = """([txt, bg, pos]) => {
        const b = document.createElement('div');
        const isCenter = pos === 'center';
        b.style.cssText = 'position:fixed;top:12px;'
            +(isCenter ? 'left:50%;transform:translateX(-50%);' : 'left:12px;')
            +'background:'+bg+';color:#fff;padding:10px 18px;border-radius:8px;'
            +'font-size:12px;font-weight:bold;z-index:2147483647;font-family:monospace;'
            +'max-width:820px;box-shadow:0 3px 16px rgba(0,0,0,.55);white-space:pre-wrap;'
            +(isCenter ? 'text-align:center;' : '');
        b.textContent = txt;
        document.body.appendChild(b);
    }"""

    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-gpu", "--ignore-certificate-errors"],
            )
            context = browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 900},
                user_agent="Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            )
            # 인증 세션 쿠키 주입 — 인증영역 페이지(업로드·저장형 XSS·SQLi 등)가 로그인 리다이렉트 없이
            # '실제 취약 화면'으로 캡처되도록 한다(과거: 무인증이라 로그인/DVWA 첫화면만 찍히던 문제).
            try:
                import active_probing as _apc
                _ck = _apc.get_auth_cookies(scan_id) or []
                _cookie_base = targets[0]["base_url"] if targets else ""
                _pcookies = [{"name": c["name"], "value": str(c.get("value", "")), "url": _cookie_base}
                             for c in _ck if isinstance(c, dict) and c.get("name") and _cookie_base]
                if _pcookies:
                    context.add_cookies(_pcookies)
            except Exception:
                pass
            page = context.new_page()

            for t in targets:
                idx = t["idx"]
                evidence_url = t["evidence_url"]
                base_url = t["base_url"]
                step2_desc = t["step2_desc"]
                step3_desc = t["step3_desc"]
                shots: list[str] = []

                fname1 = f"{scan_id}_ev_{idx:02d}_s1.png"
                try:
                    # s1 은 '취약점이 발견된 바로 그 페이지'의 공격 이전 정상 화면(과거엔 루트만 찍어
                    # 어느 페이지에서 찾았는지 알 수 없던 문제). 인증영역이면 쿠키로 실제 화면이 뜬다.
                    page.goto(evidence_url, wait_until="domcontentloaded", timeout=12000)
                    page.wait_for_timeout(400)
                    page.evaluate(_OVERLAY_JS, [
                        f"【1단계】 점검 대상 페이지 최초 접속\nURL: {evidence_url}\n"
                        "↑ 공격 시도 이전 정상 화면입니다",
                        "#1E3A5F", "left",
                    ])
                    page.screenshot(path=str(SCREENSHOTS_DIR / fname1), full_page=False)
                    shots.append(fname1)
                except Exception:
                    pass

                fname2 = f"{scan_id}_ev_{idx:02d}_s2.png"
                try:
                    page.goto(evidence_url, wait_until="domcontentloaded", timeout=12000)
                    page.wait_for_timeout(400)
                    page.evaluate(_OVERLAY_JS, [
                        f"【2단계】 취약점 점검 수행 중\n{step2_desc}",
                        "#B45309", "left",
                    ])
                    page.screenshot(path=str(SCREENSHOTS_DIR / fname2), full_page=False)
                    shots.append(fname2)
                except Exception:
                    pass

                fname3 = f"{scan_id}_ev_{idx:02d}_s3.png"
                try:
                    page.goto(evidence_url, wait_until="domcontentloaded", timeout=12000)
                    page.wait_for_timeout(400)
                    page.evaluate(_OVERLAY_JS, [step3_desc, "#DC2626", "center"])
                    page.screenshot(path=str(SCREENSHOTS_DIR / fname3), full_page=False)
                    shots.append(fname3)
                except Exception:
                    pass

                results.append({"idx": idx, "shots": shots})

            context.close()
            browser.close()
    except Exception:
        pass

    return json.dumps(results)


async def capture_evidence_screenshots(scan_id: str, findings: list[dict]) -> list[dict]:
    """
    For each vulnerable finding with evidence_url, capture 3 screenshots documenting
    the discovery process:
      s1 — 1단계: 점검 대상 서비스 최초 접속 (공격 이전 정상 화면)
      s2 — 2단계: 취약점 점검 수행 중 (점검 행위 및 발견 경위)
      s3 — 3단계: 취약점 확인 완료 (실증 증거 화면)
    Uses sync_playwright via asyncio.to_thread to avoid event-loop conflicts inside uvicorn.
    """
    import urllib.parse as _up

    # 헤더/설정 분석 기반 취약점 — 스크린샷 불필요 (증거는 evidence_detail에 기록됨)
    _HEADER_ONLY_TYPES = {
        "server_version", "cookie_flags", "http_plaintext",
        "hsts_missing", "cors_misconfiguration", "missing_headers",
        "cookie_samesite",
    }

    targets_data = []
    for i, f in enumerate(findings):
        if f.get("judgment") != "취약" or not f.get("evidence_url"):
            continue
        pd = f.get("probe_detail") or {}
        if pd.get("evidence_screenshots"):
            continue
        # 헤더 전용 패시브 규칙은 스크린샷 생략
        if f.get("check_type") in _HEADER_ONLY_TYPES and "probe_confirmed" not in f:
            continue

        evidence_url = f["evidence_url"]
        title = f.get("title", "취약점")
        evidence_detail = (f.get("evidence_detail") or "")[:200]
        detection_steps = f.get("detection_steps") or []

        try:
            _parsed = _up.urlparse(evidence_url)
            base_url = f"{_parsed.scheme}://{_parsed.netloc}" if _parsed.netloc else evidence_url
        except Exception:
            base_url = evidence_url

        is_server_version = "버전 정보 노출" in title or "Server 헤더" in title

        if is_server_version and evidence_detail:
            step2_desc = (
                "HTTP 응답 헤더 분석 중\n"
                "아래 헤더에 서버 소프트웨어 버전 정보가 포함됨:\n\n"
                + evidence_detail[:200]
            )
        elif len(detection_steps) > 1:
            step2_desc = str(detection_steps[1])[:180]
        elif detection_steps:
            step2_desc = str(detection_steps[0])[:180]
        else:
            step2_desc = f"취약점 점검 수행: {title}"

        if is_server_version and evidence_detail:
            step3_desc = (
                "★ 서버 소프트웨어 버전 정보 노출 확인됨\n\n"
                "[HTTP Response Header에서 발견]\n"
                + evidence_detail[:220]
                + "\n\n→ 공격자가 서버 버전을 파악해 알려진 CVE를 검색할 수 있음"
            )
        else:
            step3_desc = f"★ 취약점 확인됨\n제목: {title}"
            if evidence_detail:
                step3_desc += f"\n\n[발견 내용]\n{evidence_detail}"
        step3_desc = step3_desc[:350]

        targets_data.append({
            "idx": len(targets_data),
            "finding_idx": i,
            "evidence_url": evidence_url,
            "base_url": base_url,
            "step2_desc": step2_desc,
            "step3_desc": step3_desc,
        })

    if not targets_data:
        return findings

    try:
        results_json = await asyncio.to_thread(
            _run_evidence_capture_sync,
            scan_id,
            json.dumps(targets_data, ensure_ascii=False),
        )
        results = json.loads(results_json)
        for r in results:
            shots = r.get("shots", [])
            if shots:
                fi = targets_data[r["idx"]]["finding_idx"]
                findings[fi]["evidence_screenshots"] = shots
                findings[fi]["evidence_screenshot"] = shots[0]
    except Exception:
        pass

    return findings


def screenshot_url(filename: str) -> str:
    return f"/api/screenshots/{filename}"
