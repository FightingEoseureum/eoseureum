"""probes/utils/injection_points.py — 주입 지점 수집/중복제거 + 입력점 발굴 확대.

검증된 active_probing._extract_injection_points 에 위임하여 base_url 의 폼/파라미터를 수집하고,
중복 지점을 제거한다. 추가로 이미 수집된 데이터(컨텍스트)를 가공하여 입력점을 확대 발굴한다.

원칙: 이 모듈은 네트워크 호출을 하지 않는다(extract_injection_points 만 위임으로 1회 호출).
gather_all_points / detect_search_points 는 이미 수집된 데이터 가공만 수행한다.
"""
from __future__ import annotations

import urllib.parse

# 검색 입력점으로 간주하는 파라미터/필드 이름
_SEARCH_NAMES = {"q", "query", "search", "keyword", "term", "s"}


async def extract_injection_points(session, base_url: str) -> list[dict]:
    try:
        import active_probing as ap
        points = await ap._extract_injection_points(session, base_url)
        return dedup_points(points or [])
    except Exception:
        return []


def dedup_points(points: list[dict]) -> list[dict]:
    """(method, url, 정렬된 파라미터 키) 기준으로 중복 주입 지점을 제거한다."""
    seen = set()
    out = []
    for pt in points or []:
        if not isinstance(pt, dict):
            continue
        key = (
            pt.get("method", "GET"),
            pt.get("url", ""),
            tuple(sorted((pt.get("params") or {}).keys())),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(pt)
    return out


def detect_search_points(points: list[dict]) -> list[dict]:
    """검색 입력점을 표시한다.

    input name/param 이 q,query,search,keyword,term,s 이거나
    form action(url) 에 'search' 가 포함되면 "is_search": True 를 부여한다.
    (입력점 dict 를 그대로 반환하되, 검색으로 판별된 항목에 플래그를 추가한다.
     동일 객체를 유지하기 위해 제자리에서 플래그를 설정한다.)
    """
    out: list[dict] = []
    for pt in points or []:
        if not isinstance(pt, dict):
            continue
        params = {str(k).lower() for k in (pt.get("params") or {})}
        url = str(pt.get("url", "")).lower()
        action = str(pt.get("action", "")).lower()
        is_search = bool(params & _SEARCH_NAMES) or ("search" in url) or ("search" in action)
        if is_search:
            pt["is_search"] = True
        out.append(pt)
    return out


def _points_from_url(url: str) -> dict | None:
    """쿼리 파라미터를 가진 URL → 주입 지점 dict (없으면 None)."""
    if not url or not isinstance(url, str):
        return None
    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        return None
    params = {k: (v[0] if v else "") for k, v in urllib.parse.parse_qs(p.query).items()}
    if not params:
        return None
    clean = f"{p.scheme}://{p.netloc}{p.path}" if p.scheme else url.split("?", 1)[0]
    return {
        "method": "GET",
        "url": clean,
        "params": params,
        "source": "url",
    }


def _coerce_point(item) -> dict | None:
    """문자열(URL) 또는 dict 입력을 주입 지점 dict 로 정규화한다."""
    if isinstance(item, str):
        return _points_from_url(item)
    if isinstance(item, dict):
        # 이미 주입 지점 형태(params 보유)이면 그대로 사용
        if item.get("params"):
            return item
        # url 만 있는 경우 쿼리 파라미터 추출 시도
        url = item.get("url") or item.get("action") or ""
        derived = _points_from_url(url) if url else None
        if derived:
            # 원본 메타데이터 보존(method/source 등)
            merged = dict(item)
            merged.setdefault("method", derived["method"])
            merged["url"] = derived["url"]
            merged["params"] = derived["params"]
            merged.setdefault("source", item.get("source", "url"))
            return merged
        return None
    return None


def gather_all_points(ctx) -> list[dict]:
    """컨텍스트에 이미 수집된 데이터를 합쳐 입력점을 확대 발굴한다(네트워크 호출 없음).

    합치는 대상:
      - ctx.injection_points (폼/input/쿼리 파라미터 — 기존 발굴 결과)
      - ctx.discovered_urls (쿼리 파라미터를 가진 URL → 주입 지점으로 추출)
      - ctx.authenticated_forms (인증 스캔으로 발견한 폼, 있을 때만)
    form/input/query parameter/form action URL/API path 를 모두 포함하며,
    (method, url, 파라미터 키) 기준으로 dedup 한다.
    """
    collected: list[dict] = []

    for pt in (getattr(ctx, "injection_points", None) or []):
        c = _coerce_point(pt)
        if c:
            collected.append(c)

    for url in (getattr(ctx, "discovered_urls", None) or []):
        c = _coerce_point(url)
        if c:
            collected.append(c)

    for form in (getattr(ctx, "authenticated_forms", None) or []):
        c = _coerce_point(form)
        if c:
            collected.append(c)

    return dedup_points(collected)
