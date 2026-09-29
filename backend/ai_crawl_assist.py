"""
ai_crawl_assist.py — 크롤 보조(AI 제안). AI 는 '숨은 경로/엔드포인트 후보'만 제안하고,
실제 크롤·스코프·요청한도는 결정적 URL 탐색기(url_discovery.discover)가 강제한다.

원칙:
  - AI 는 판정/실행을 하지 않는다. '동일 출처 상대경로 후보'만 낸다.
  - 스캔당 1회(바운드) 호출. 느린 로컬 LLM 폭주 방지.
  - 반환 경로는 반드시 '/...' 상대경로만(스킴/호스트 포함 문자열은 폐기) → 외부 유출·스코프 이탈 차단.
  - 기본 비활성(ENABLE_AI_CRAWL_ASSIST). 크롤은 시간 민감하므로 opt-in.

env:
  ENABLE_AI_CRAWL_ASSIST : "true" 면 활성(기본 false)
  AI_CRAWL_MAX_PATHS     : 제안 경로 상한(기본 20)
"""
from __future__ import annotations

import os
import re
import json

_PATH_RE = re.compile(r"^/[A-Za-z0-9_\-./]{0,120}$")   # 안전한 상대경로만(스킴/호스트/쿼리 배제)


def crawl_assist_enabled() -> bool:
    return os.getenv("ENABLE_AI_CRAWL_ASSIST", "false").strip().lower() in ("1", "true", "yes", "on")


def _max_paths() -> int:
    try:
        return max(1, min(60, int(os.getenv("AI_CRAWL_MAX_PATHS", "20"))))
    except (TypeError, ValueError):
        return 20


def _sanitize_paths(arr, known: set[str], cap: int) -> list[str]:
    """AI 출력에서 안전한 동일-출처 상대경로만 추린다. 스킴/호스트/쿼리/중복/기존경로 제거."""
    out: list[str] = []
    seen = set(known or set())
    for item in (arr or []):
        if not isinstance(item, str):
            continue
        p = item.strip()
        if not p.startswith("/"):
            continue
        if "://" in p or p.startswith("//"):     # 외부 URL/프로토콜-상대 배제
            continue
        p = p.split("?", 1)[0].split("#", 1)[0]  # 쿼리/프래그먼트 제거
        if not _PATH_RE.match(p):
            continue
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
        if len(out) >= cap:
            break
    return out


def _extract_json_array(raw: str):
    m = re.search(r"\[.*\]", raw or "", re.DOTALL)
    if not m:
        return []
    try:
        v = json.loads(m.group(0))
        return v if isinstance(v, list) else []
    except Exception:
        return []


async def suggest_crawl_paths(base_url: str, html_hint: str = "",
                              known_paths: list[str] | None = None,
                              provider=None, max_paths: int | None = None) -> list[str]:
    """base_url 앱에 있을 법한 '숨은 경로 후보'를 AI 에게 제안받아 안전 상대경로만 반환.

    미가용/비활성/실패 시 [] → 호출부는 AI 미사용과 동일(결정적 탐색만). 스코프는 크롤러가 강제."""
    if not crawl_assist_enabled() or not base_url:
        return []
    if provider is None:
        try:
            from ai_provider import get_ai_provider, NoneProvider
            provider = get_ai_provider()
            if isinstance(provider, NoneProvider):
                return []
        except Exception:
            return []
    cap = max_paths or _max_paths()
    known = set(known_paths or [])
    hint = (html_hint or "")[:2000]
    prompt = (
        "당신은 웹 앱의 '경로 후보 제안자'입니다. 아래 대상에서 존재할 가능성이 높은 "
        "숨은 경로/엔드포인트를 추측하세요(관리자/API/문서/디버그/업로드/인증 등).\n"
        "규칙: 반드시 '동일 출처 상대경로'만(예: /admin, /api/v1/users, /swagger.json). "
        "전체 URL/호스트/쿼리스트링 금지. 파괴적 동작·설명 금지.\n"
        f"대상: {base_url}\n"
        f"이미 아는 경로(제외): {sorted(known)[:30]}\n"
        f"홈페이지 단서(발췌):\n{hint}\n\n"
        f"최대 {cap}개. 반드시 JSON 문자열 배열 하나만 출력(예: [\"/admin\",\"/api/v1/users\"]). 다른 텍스트 금지."
    )
    try:
        raw = await provider.complete(prompt)
    except Exception:
        return []
    return _sanitize_paths(_extract_json_array(raw or ""), known, cap)
