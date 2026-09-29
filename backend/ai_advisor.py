"""
ai_advisor.py — 'AI 조언 + 결정적 백스톱' 패턴의 범용 조언자.

원칙(코드로 강제되는 안전 경계):
  - AI 는 '조언(우선순위 재정렬)'만 한다. 항목을 새로 만들거나 제거할 수 없고, 판정/severity 를
    바꾸지 않는다. 최종 순서는 'AI 선택 ∪ 결정적 정렬'이라 어떤 항목도 누락되지 않는다.
  - AI 미가용/실패/타임아웃/비활성 시 결정적 정렬 그대로 사용(동작 불변).
  - 여기서 다루는 것은 '무엇을 먼저 점검할지'(효율)일 뿐, '무엇이 취약한지'가 아니다.

대표 용도: 점검 예산(MAX_INJECTION_POINTS) 초과 시 어떤 입력점을 먼저 점검할지 우선순위 조언.
"""
from __future__ import annotations

import json
import os
import re


def probe_priority_enabled() -> bool:
    """점검 우선순위 AI 조언 활성 여부(기본 off)."""
    v = os.getenv("ENABLE_AI_PROBE_PRIORITY")
    if v is None:
        return False
    return v.strip().lower() in ("1", "true", "yes", "on")


# ── 순수 로직(테스트 대상) ──────────────────────────────────────────────────────
def sanitize_ai_order(raw, n: int) -> list[int]:
    """AI 가 반환한 인덱스 배열을 유효 범위 [0, n) 로 정제(중복/범위밖/비정수 제거, 순서 보존)."""
    out, seen = [], set()
    if not isinstance(raw, (list, tuple)):
        return out
    for x in raw:
        try:
            i = int(x)
        except (TypeError, ValueError):
            continue
        if 0 <= i < n and i not in seen:
            seen.add(i)
            out.append(i)
    return out


def reorder_by_ai(items: list, ai_order: list[int]) -> list:
    """items 를 ai_order(인덱스) 우선으로 재정렬. AI 가 고르지 않은 항목은 기존(결정적) 순서로 뒤에 붙인다.

    항목은 절대 누락되지 않는다(AI 는 순서만 바꿀 수 있고 드롭 불가).
    """
    n = len(items or [])
    valid = sanitize_ai_order(ai_order, n)
    if not valid:
        return list(items or [])
    chosen = set(valid)
    return [items[i] for i in valid] + [items[i] for i in range(n) if i not in chosen]


def _points_brief(points: list, limit: int = 60) -> str:
    lines = []
    for i, p in enumerate(points[:limit]):
        if not isinstance(p, dict):
            continue
        method = p.get("method", "GET")
        url = str(p.get("url", ""))[:120]
        params = ",".join(list((p.get("params") or {}).keys())[:8])
        lines.append(f"{i}: {method} {url} params=[{params}]")
    return "\n".join(lines)


def _extract_json_array(text: str):
    """텍스트에서 첫 JSON 배열을 추출."""
    if not text:
        return None
    m = re.search(r"\[[^\]]*\]", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


# ── AI 조언 호출(실패 시 None → 호출부는 결정적 순서 유지) ────────────────────────
async def advise_point_priority(points: list, provider=None) -> list[int] | None:
    """입력점 목록에 대해 '먼저 점검할 순서'(인덱스 배열)를 AI 에게 조언받는다.

    반환: 유효 인덱스 리스트(정제됨) 또는 None(미가용/실패). None 이면 호출부가 결정적 순서 유지.
    """
    if not probe_priority_enabled() or not points:
        return None
    try:
        if provider is None:
            from ai_provider import get_ai_provider, NoneProvider
            provider = get_ai_provider()
            if isinstance(provider, NoneProvider):
                return None
        brief = _points_brief(points)
        prompt = (
            "당신은 웹 취약점 점검의 '우선순위 조언자'입니다. 아래 HTTP 입력점 목록 중 "
            "취약점(인증/권한/주입 등)이 나타날 가능성이 높은 순서로 인덱스를 재정렬하세요. "
            "관리/인증/API/객체식별자(id)/검색 파라미터가 대체로 우선순위가 높습니다. "
            "인덱스를 새로 만들거나 빼지 말고 '순서만' 바꾸세요.\n\n"
            f"[입력점]\n{brief}\n\n"
            "반드시 JSON 배열 하나만 출력(예: [3,0,5,1,...]). 다른 텍스트 금지."
        )
        raw = await provider.complete(prompt)
        arr = _extract_json_array(raw or "")
        order = sanitize_ai_order(arr, len(points))
        return order or None
    except Exception:
        return None
