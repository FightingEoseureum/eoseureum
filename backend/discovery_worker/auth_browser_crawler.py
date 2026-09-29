"""
auth_browser_crawler.py — 인증 후 브라우저 크롤 + Safe Click Exploration.

안전 원칙:
  - 인증 크롤은 ENABLE_AUTH_BROWSER_CRAWL=true + 자격증명 제공 시에만 수행.
  - GET/Navigation(same-origin) 중심. 상태 변경 유발 요소는 클릭하지 않고 '기록만'.
  - 로그아웃/삭제/수정/등록/결제/업로드 등 자동 클릭·자동 제출 금지.
  - 로그인 폼 제출만 예외적으로 허용(인증 진입에 필요, 자격증명 명시 제공 시).
Playwright 는 함수 내부에서만 사용(모듈 import 는 항상 성공).
"""
from __future__ import annotations

from urllib.parse import urljoin

from . import discovery_policy as policy


def plan_safe_clicks(elements: list) -> dict:
    """앵커/버튼 후보 목록을 안전/차단으로 분류(순수·결정적).

    elements: [{text, href, role, onclick, element_type}]
    반환: {"safe": [...], "blocked": [{element, reason}]}
    """
    safe, blocked = [], []
    for el in elements or []:
        verdict = policy.is_safe_click(
            text=el.get("text", ""), href=el.get("href", ""), role=el.get("role", ""),
            onclick=el.get("onclick", ""), element_type=el.get("element_type", ""))
        if verdict["safe"]:
            safe.append(el)
        else:
            blocked.append({"element": el.get("text") or el.get("href") or "(요소)",
                            "href": el.get("href", ""), "reason": verdict["reason"]})
    return {"safe": safe, "blocked": blocked}


async def maybe_login(context, page, job) -> bool:
    """자격증명이 있고 인증 크롤이 활성일 때만 로그인. 성공 여부 반환."""
    auth = job.auth or {}
    if not policy.auth_crawl_enabled() or not (auth.get("username") and auth.get("password")):
        return False
    login_url = auth.get("login_url") or urljoin(job.base_url, "/login")
    try:
        await page.goto(login_url, wait_until="domcontentloaded",
                        timeout=policy.budget()["timeout"] * 1000)
        # 대표적 사용자/비밀번호 필드 선택자 시도
        for sel in ("input[name=username]", "input[name=email]", "input[type=email]",
                    "input[id=username]", "input[name=userid]", "input[name=user_id]"):
            if await page.query_selector(sel):
                await page.fill(sel, str(auth["username"]))
                break
        for sel in ("input[type=password]", "input[name=password]", "input[id=password]"):
            if await page.query_selector(sel):
                await page.fill(sel, str(auth["password"]))
                break
        # 로그인 폼 제출(인증 진입 — 유일하게 허용되는 제출)
        submit = await page.query_selector("button[type=submit], input[type=submit]")
        if submit:
            await submit.click()
        else:
            await page.keyboard.press("Enter")
        await page.wait_for_load_state("networkidle", timeout=10000)
        # 로그인 성공 추정: 로그인 URL 을 벗어났거나 password 필드가 사라짐
        moved = page.url != login_url
        still_pw = await page.query_selector("input[type=password]")
        return bool(moved or not still_pw)
    except Exception:
        return False


async def _collect_anchor_elements(page) -> list:
    """페이지의 앵커/버튼 요소 메타 수집(클릭 전, 판정용)."""
    try:
        return await page.eval_on_selector_all(
            "a, button, [role=button]",
            """els => els.map(e => ({
                text: (e.innerText||'').trim().slice(0,60),
                href: e.getAttribute('href')||'',
                role: e.getAttribute('role')||'',
                onclick: e.getAttribute('onclick')||'',
                element_type: (e.tagName||'').toLowerCase() +
                    (e.getAttribute('type')?('['+e.getAttribute('type')+']'):'')
            }))""")
    except Exception:
        return []


async def safe_crawl(page, job, *, budget: dict, page_sources: list,
                     dom_raw: list | None = None) -> tuple:
    """same-origin GET 네비게이션 중심의 안전 탐색(BFS). 반환: (pages_visited, blocked).
    dom_raw 리스트가 주어지면 페이지별 구조화 DOM 스냅샷(전체 HTML 미저장)도 수집한다."""
    from collections import deque
    from . import discovery3 as _d3
    visited: set = set()
    blocked_all: list = []
    start = job.base_url
    queue = deque([(start, 0)])
    max_pages = budget["max_pages"]
    max_depth = budget["max_depth"]

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue
        if not policy.in_scope(url, job.base_url, job.scope):
            continue
        visited.add(url)
        try:
            await page.goto(url, wait_until="domcontentloaded",
                            timeout=min(30, budget["timeout"]) * 1000)
            html = await page.content()
            page_sources.append({"url": url, "text": html})
            # DOM Snapshot 3.5: 구조화 정보만 수집(전체 HTML 미저장). 예산 내 상위 페이지만.
            if dom_raw is not None and len(dom_raw) < min(20, budget["max_pages"]):
                try:
                    dom_raw.append(await page.evaluate(_d3.DOM_SNAPSHOT_JS))
                except Exception:
                    pass
        except Exception:
            continue
        # 안전 클릭 후보 분류(클릭 대신 same-origin href 는 큐로 이동)
        els = await _collect_anchor_elements(page)
        plan = plan_safe_clicks(els)
        blocked_all.extend(plan["blocked"])
        for el in plan["safe"]:
            href = el.get("href", "")
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            nxt = urljoin(url, href)
            if policy.in_scope(nxt, job.base_url, job.scope) and nxt not in visited:
                queue.append((nxt, depth + 1))
    return len(visited), blocked_all
