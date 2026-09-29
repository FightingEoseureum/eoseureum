"""
param_miner.py — 숨은 파라미터 발굴(Parameter Mining) v1.

문서에 노출되지 않은 쿼리 파라미터를 발굴해 '테스트 입력점'을 늘린다(공격 표면 확장, P0).
arjun 방식의 청크 반사 탐지: 파라미터마다 고유 카나리를 심어 한 번의 요청으로 여러 개를
테스트하고, 응답에 반사되는 카나리만 '실재 파라미터'로 채택한다(고정밀 → 오탐 억제).

SAFE: GET·무해 카나리 값만 사용, 상태 변경 없음. 발굴 결과는 기존 probe 의 입력점이 될 뿐
새 판정을 만들지 않는다(판정은 Rule Engine 전담).
"""
from __future__ import annotations

import os
import pathlib
import re
import urllib.parse

# 반사 탐지용 카나리(자연 발생 확률이 극히 낮은 토큰)
_CANARY = "eoszx7q"

# 공통 파라미터 사전(카테고리별 — 과하지 않게 선별)
COMMON_PARAMS = [
    # id / object
    "id", "user", "userid", "user_id", "uid", "account", "account_id", "object", "obj",
    "item", "item_id", "pid", "no", "num", "order", "order_id", "invoice", "doc", "docid",
    # search / query / generic reflection (흔히 반사되는 고가치 이름 — 앞쪽 배치로 컷 방지)
    "q", "query", "search", "keyword", "kw", "term", "s", "text", "name", "title",
    "param", "params", "parameter", "memo", "comment", "body", "subject", "word",
    "html", "xss", "echo", "greeting", "hello", "result",
    # pagination / sort
    "page", "p", "offset", "limit", "start", "count", "size", "per_page", "sort", "order_by",
    "dir", "asc", "desc",
    # redirect / url
    "url", "redirect", "redirect_url", "return", "return_url", "returnto", "next", "target",
    "dest", "destination", "continue", "goto", "link", "out", "r", "u",
    # file / path
    "file", "filename", "path", "dir", "folder", "download", "load", "read", "doc_path",
    "template", "tpl", "view", "page_id", "include", "inc", "src",
    # format / callback
    "format", "type", "output", "callback", "jsonp", "cb", "func", "method", "action",
    # debug / admin / flags
    "debug", "test", "admin", "role", "mode", "env", "preview", "show", "enable", "flag",
    # lang / misc
    "lang", "locale", "l", "category", "cat", "tag", "filter", "status", "state", "key", "token",
    "data", "value", "val", "input", "content", "message", "msg", "email", "code", "ref",
]


def _dedup(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x); out.append(x)
    return out


# ── SecLists 파라미터 사전(burp-parameter-names) 흡수 — 내장 커리큘 앞쪽 + 확장 ──
_SECLISTS_PARAM_CANDIDATES = (
    "/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt",
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    str(pathlib.Path.home() / "SecLists/Discovery/Web-Content/burp-parameter-names.txt"),
)
# 유효 파라미터명만(문자로 시작 — 순수숫자/기호 정크 배제해 요청 낭비·노이즈 감소)
_PARAM_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-.\[\]]{0,39}$")
_PARAM_WL_CACHE: list | None = None


def _seclists_param_names() -> list[str]:
    """SecLists burp-parameter-names 에서 유효 파라미터명만 로드(없으면 빈 리스트). PARAM_WORDLIST env 우선."""
    env = (os.getenv("PARAM_WORDLIST") or "").strip()
    paths = ([env] if env else []) + list(_SECLISTS_PARAM_CANDIDATES)
    for c in paths:
        if not c:
            continue
        p = pathlib.Path(c)
        if p.exists():
            try:
                return [w.strip() for w in p.read_text("utf-8", errors="ignore").splitlines()
                        if w.strip() and not w.startswith("#") and _PARAM_NAME_RE.match(w.strip())]
            except Exception:
                return []
    return []


def load_param_wordlist() -> list[str]:
    """내장 커리큘(고가치, 앞쪽 배치) + SecLists 확장(정제) 병합. 캐시."""
    global _PARAM_WL_CACHE
    if _PARAM_WL_CACHE is None:
        _PARAM_WL_CACHE = _dedup(COMMON_PARAMS + _seclists_param_names())
    return _PARAM_WL_CACHE


def build_chunk_url(base_url: str, params: list[str]) -> tuple[str, dict]:
    """청크의 각 파라미터에 고유 카나리를 붙인 URL 과 {param: canary} 맵을 만든다."""
    p = urllib.parse.urlparse(base_url)
    existing = {k: v[0] for k, v in urllib.parse.parse_qs(p.query).items()}
    canaries = {}
    q = dict(existing)
    for i, name in enumerate(params):
        if name in existing:                 # 이미 있는 파라미터는 발굴 대상 아님
            continue
        c = f"{_CANARY}{i}"
        canaries[name] = c
        q[name] = c
    query = urllib.parse.urlencode(q)
    url = f"{p.scheme}://{p.netloc}{p.path}" + (f"?{query}" if query else "")
    return url, canaries


def reflected_params(body: str, canaries: dict) -> list[str]:
    """응답 본문에 카나리가 반사된 파라미터명 목록(실재 파라미터의 강한 증거)."""
    if not body:
        return []
    return [name for name, c in canaries.items() if c in body]


def chunks(seq: list, n: int):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


async def mine(fetch, base_url: str, *, wordlist: list[str] | None = None,
               chunk_size: int = 12, max_params: int | None = None) -> dict:
    """숨은 파라미터 발굴.

    fetch: async 콜러블 fetch(url) -> (status:int, body:str). active_probing 의 _get 을 감싼다.
    반환: {"discovered": [param, ...], "signals": [{"param","signal"}...], "requests": n}

    기본 워드리스트 = 내장 커리큘 + SecLists(burp-parameter-names, 설치 시). max_params 는
    PARAM_MINING_MAX env(기본 512)로 조절 — 반사기반이라 정크는 무해, 비용은 요청수뿐.
    """
    if max_params is None:
        try:
            import scan_depth as _sd
            max_params = _sd.param_mining_max()   # 예산·PROOF 연동 스케일(env 명시 시 사용자값 우선)
        except Exception:
            try:
                max_params = int(os.getenv("PARAM_MINING_MAX", "512"))
            except (TypeError, ValueError):
                max_params = 512
    words = _dedup(wordlist or load_param_wordlist())[:max_params]
    # 이미 URL 에 있는 파라미터는 제외
    p = urllib.parse.urlparse(base_url)
    existing = set(urllib.parse.parse_qs(p.query).keys())
    words = [w for w in words if w not in existing]

    discovered: list[str] = []
    signals: list[dict] = []
    requests = 0

    # 베이스라인(카나리 없는 상태) — 오검 방지용 상태 참조
    try:
        base_status, base_body = await fetch(base_url)
    except Exception:
        base_status, base_body = None, ""
    requests += 1

    for group in chunks(words, chunk_size):
        url, canaries = build_chunk_url(base_url, group)
        if not canaries:
            continue
        try:
            status, body = await fetch(url)
        except Exception:
            continue
        requests += 1
        # 강한 신호: 카나리 반사
        for name in reflected_params(body, canaries):
            if name not in discovered:
                discovered.append(name)
                signals.append({"param": name, "signal": "reflected"})
        # 약한 신호: 파라미터 처리로 서버 오류 유발(200→5xx) — 참고용(입력점 채택은 반사만)
        if base_status and status and base_status < 500 <= status and len(canaries) == 1:
            only = next(iter(canaries))
            if only not in discovered:
                signals.append({"param": only, "signal": "status_change", "status": status})

    return {"discovered": discovered, "signals": signals, "requests": requests}


def to_input_point(base_url: str, discovered: list[str]) -> dict | None:
    """발굴 파라미터를 기존 probe 입력점 포맷으로 변환(GET)."""
    if not discovered:
        return None
    p = urllib.parse.urlparse(base_url)
    clean = f"{p.scheme}://{p.netloc}{p.path}"
    params = {k: v[0] for k, v in urllib.parse.parse_qs(p.query).items()}
    for name in discovered:
        params.setdefault(name, "test")
    return {"method": "GET", "url": clean, "params": params,
            "source": "param_mining", "csrf_fields": []}
