"""business_logic_ai.py — ⑤ AI 기반 비즈니스 로직 취약점 가설 생성(SAFE·advisory).

목적: 자동 프로브가 못 잡는 '비즈니스 로직' 취약점(가격 조작·수량 음수·워크플로 우회·쿠폰 남용·
      권한 경계 등)을 크롤한 앱 구조(엔드포인트/폼/파라미터/역할)로부터 로컬 LLM 이 '가설'로
      제시하게 한다. 능동 실증은 하지 않으며, 사람이 검증할 MANUAL_REVIEW 항목으로만 표면화한다.

원칙:
 - 판정 불변: 확정 finding 의 개수·severity 를 바꾸지 않는다(advisory 전용).
 - 완전 로컬: ai_fn 은 로컬 Ollama 라우팅(role="analysis"). 외부 호출 없음.
 - 무해: 가설·테스트 절차 '텍스트'만 생성, 스캐너가 자동 실행하지 않는다.
"""
from __future__ import annotations

import json
import re
import urllib.parse

_BIZ_CATEGORIES = (
    "price_manipulation", "quantity_abuse", "workflow_bypass", "coupon_discount_abuse",
    "insufficient_authorization", "race_condition", "parameter_tampering",
    "negative_value", "mass_assignment", "step_skipping",
)


def build_app_context(analysis: dict, max_endpoints: int = 40, host_results: list | None = None) -> dict:
    """analysis 에서 비즈니스 로직 가설에 필요한 앱 구조를 추출한다(경량·비식별).
    host_results 가 주어지면 그걸 우선 사용(analysis 에 host_results 가 없을 때 대비)."""
    findings = analysis.get("findings") or []
    techs = [t.get("name") if isinstance(t, dict) else str(t)
             for t in (analysis.get("technologies") or [])]
    _hrs = host_results if host_results is not None else (analysis.get("host_results") or [])
    # 엔드포인트 + 파라미터 수집(발견 URL·폼 액션·API)
    endpoints: list = []
    seen: set = set()

    def _add_ep(url: str, method: str = "GET"):
        if not url or len(endpoints) >= max_endpoints:
            return
        p = urllib.parse.urlparse(url)
        path = p.path or "/"
        params = sorted(urllib.parse.parse_qs(p.query).keys())
        key = (method, path, tuple(params))
        if key in seen:
            return
        seen.add(key)
        endpoints.append({"method": method, "path": path, "params": params})

    for hr in _hrs:
        for svc in (hr.get("services") or []):
            for u in (svc.get("discovered_urls") or [])[:200]:
                _add_ep(u)
            _ap = svc.get("active_probes") or {}
            _sw = _ap.get("swagger_openapi") if isinstance(_ap, dict) else None
            _summ = (_sw.get("api_summary") if isinstance(_sw, dict) else None) or {}
            for grp in ("admin_endpoints", "auth_endpoints", "payment_endpoints", "user_endpoints"):
                for e in (_summ.get(grp) or []):
                    parts = str(e).split(" ", 1)
                    if len(parts) == 2 and parts[1].startswith("/"):
                        _add_ep(parts[1], parts[0])
    # finding 요약(로직 취약점의 실마리 — 인증/결제/관리 관련)
    fin_titles = [f.get("title", "")[:60] for f in findings[:20] if f.get("title")]
    return {
        "technologies": techs[:10],
        "endpoints": endpoints,
        "finding_titles": fin_titles,
        "has_payment": any("pay" in e["path"].lower() or "order" in e["path"].lower()
                           or "checkout" in e["path"].lower() or "cart" in e["path"].lower()
                           or "basket" in e["path"].lower() for e in endpoints),
    }


def _build_prompt(ctx: dict) -> str:
    eps = "\n".join(f"- {e['method']} {e['path']}"
                    + (f" (params: {', '.join(e['params'])})" if e['params'] else "")
                    for e in ctx.get("endpoints", [])[:40])
    return (
        "당신은 웹 애플리케이션 비즈니스 로직 취약점 전문가입니다. 아래는 스캔으로 발견한 앱 구조입니다.\n"
        "자동 스캐너가 놓치는 '비즈니스 로직' 취약점을 최대 8개까지 '가설'로 제시하세요.\n"
        "실제 익스플로잇이 아니라, 사람이 수동으로 검증할 '테스트 가설'만 만듭니다.\n\n"
        f"기술스택: {', '.join(ctx.get('technologies', [])) or '미상'}\n"
        f"결제/주문 관련 엔드포인트 존재: {'예' if ctx.get('has_payment') else '아니오'}\n"
        f"엔드포인트:\n{eps or '(수집된 엔드포인트 없음)'}\n\n"
        "각 가설을 아래 JSON 배열로만 출력하세요(설명 문장 없이 JSON 만):\n"
        '[{"title":"짧은 제목","category":"' + "|".join(_BIZ_CATEGORIES) + '",'
        '"endpoint":"관련 경로","rationale":"왜 의심되는가","test_steps":"수동 검증 절차(1-3단계)"}]\n'
    )


def _parse_hypotheses(raw: str) -> list[dict]:
    """LLM 응답에서 JSON 배열을 견고하게 추출·검증한다."""
    if not raw:
        return []
    m = re.search(r"\[.*\]", raw, re.DOTALL)
    if not m:
        return []
    try:
        arr = json.loads(m.group(0))
    except Exception:
        return []
    out = []
    for h in arr if isinstance(arr, list) else []:
        if not isinstance(h, dict) or not h.get("title"):
            continue
        cat = str(h.get("category", "")).strip().lower()
        if cat not in _BIZ_CATEGORIES:
            cat = "workflow_bypass"
        out.append({
            "title": str(h.get("title"))[:120],
            "category": cat,
            "endpoint": str(h.get("endpoint", ""))[:200],
            "rationale": str(h.get("rationale", ""))[:400],
            "test_steps": str(h.get("test_steps", ""))[:500],
        })
        if len(out) >= 8:
            break
    return out


def hypotheses_to_findings(hyps: list[dict]) -> list[dict]:
    """가설을 advisory finding(MANUAL_REVIEW, family=business_logic)으로 변환.
    확정 판정이 아니며 개수·severity 산정에서 별도 취급(표면화 전용)."""
    findings = []
    for h in hyps:
        findings.append({
            "title": f"[AI 가설] 비즈니스 로직 의심: {h['title']}",
            "family": "business_logic",
            "category": "business_logic_ai",
            "severity": "Low",
            "report_severity": "정보",
            "confidence": "MANUAL_REVIEW",
            "judgment": "점검 필요",
            "is_vulnerable": False,
            "ai_hypothesis": True,
            "biz_category": h["category"],
            "affected_endpoints": [h["endpoint"]] if h["endpoint"] else [],
            "description": f"AI가 앱 구조로부터 도출한 비즈니스 로직 취약점 가설입니다(자동 실증 아님). "
                           f"근거: {h['rationale']}",
            "recommendation": f"수동 검증 절차: {h['test_steps']}",
            "evidence_detail": (f"[AI 비즈니스 로직 가설]\n분류: {h['category']}\n"
                                f"관련 엔드포인트: {h['endpoint']}\n근거: {h['rationale']}\n"
                                f"수동 검증: {h['test_steps']}"),
        })
    return findings


def analyze(analysis: dict, ai_fn, host_results: list | None = None) -> list[dict]:
    """앱 구조 → AI 가설 → advisory findings. ai_fn(prompt)->str|None. 실패/미가용 시 빈 리스트."""
    if ai_fn is None:
        return []
    ctx = build_app_context(analysis, host_results=host_results)
    if not ctx.get("endpoints"):
        return []
    try:
        raw = ai_fn(_build_prompt(ctx))
    except Exception:
        return []
    return hypotheses_to_findings(_parse_hypotheses(raw or ""))
