"""response_cache.py — Safe 모드 '응답 재사용 차등'(S4): 스캔 내 동일 GET 중복요청 제거.

목적(사용자 목적): 서버에 무리를 주지 않으면서 최대 커버리지. 다수 프로브가 baseline/수집 목적으로
'같은 URL'을 반복 GET 한다(예: _collect_page_js 가 discovered_urls 전량 재페치, CSP/헤더 baseline 등).
스캔 1회 동안 이 '평범한 읽기'를 캐시해 재사용하면 같은 커버리지를 더 적은 요청으로 얻는다(부하↓).

정확성 불변식(중요):
  - GET(기본 헤더)만 캐시. 커스텀 헤더 요청(인증우회/JNDI 등)은 우회(캐시 미사용·미저장).
  - '모든 상태변경 요청(_post / 비-GET _send_method)'은 캐시를 통째 무효화한다.
    → 저장형 XSS(주입 POST 후 페이지 GET)·쓰기검증 등 '변경 후 재조회'가 항상 신선한 응답을 받는다
      (캐시가 변경 이전 응답을 돌려줘 미탐/오탐되는 일을 원천 차단).
  - 캐시 히트는 네트워크·스로틀을 소비하지 않는다(요청이 실제로 나가지 않으므로).

per-scan 격리: contextvar. 미설치 시(current() is None) 완전 무동작 → PROOF·기존 동작 무영향.
[[adaptive-throttle]] 와 같은 시점(safe 모드)에서 설치된다.
"""
from __future__ import annotations

import contextvars

_ctx: contextvars.ContextVar = contextvars.ContextVar("eos_respcache", default=None)


class ResponseCache:
    """스캔 1개에 대응하는 GET 응답 캐시(상태변경 시 무효화)."""

    def __init__(self, cap: int = 800, max_body: int = 2_000_000):
        self.cap = int(cap)
        self.max_body = int(max_body)
        self._store: dict = {}     # url -> (status, body, headers)
        self.hits = 0
        self.misses = 0
        self.stores = 0
        self.invalidations = 0
        self.saved_requests = 0    # 캐시로 아낀 실제 네트워크 요청 수

    def get(self, url: str):
        v = self._store.get(url)
        if v is not None:
            self.hits += 1
            self.saved_requests += 1
            # 헤더는 얕은 복사로 반환(호출측 변형이 캐시를 오염시키지 않도록)
            st, body, hdrs = v
            return st, body, dict(hdrs)
        self.misses += 1
        return None

    def put(self, url: str, resp) -> None:
        try:
            st, body, hdrs = resp
        except Exception:
            return
        # 대용량 본문은 캐시하지 않음(메모리 보호) — 단, 재요청은 그대로 나감
        if body is not None and len(body) > self.max_body:
            return
        if url not in self._store and len(self._store) >= self.cap:
            # 용량 초과 → 가장 오래된 항목 제거(삽입순서)
            try:
                oldest = next(iter(self._store))
                self._store.pop(oldest, None)
            except StopIteration:
                pass
        self._store[url] = (st, body, dict(hdrs))
        self.stores += 1

    def invalidate(self) -> None:
        """상태변경 발생 → 전체 무효화(변경 이후 조회는 반드시 신선한 응답)."""
        if self._store:
            self._store.clear()
            self.invalidations += 1

    def snapshot(self) -> dict:
        """S3 패시브 감사용 코퍼스 스냅샷: {url: (status, body, headers)} 얕은 복사."""
        return dict(self._store)

    def stats(self) -> dict:
        total = self.hits + self.misses
        return {
            "entries": len(self._store), "hits": self.hits, "misses": self.misses,
            "hit_rate": round(self.hits / total, 3) if total else 0.0,
            "stores": self.stores, "invalidations": self.invalidations,
            "saved_requests": self.saved_requests,
        }


def install(cap: int = 800, max_body: int = 2_000_000) -> ResponseCache:
    c = ResponseCache(cap=cap, max_body=max_body)
    _ctx.set(c)
    return c


def uninstall() -> None:
    _ctx.set(None)


def current() -> ResponseCache | None:
    return _ctx.get()
