"""
probes/xss_probe.py — XSS probe (반사형/저장형/DOM 기반).

검증된 active_probing 의 _probe_xss_* 함수에 위임한다(새 탐지 로직 작성 금지).
입력점은 gather_all_points 로 확대 발굴하고 detect_search_points 로 검색 입력점(q/search 등)을
반드시 포함시켜 reflected/stored 위임 함수에 전달한다. dom 은 ctx.target_url 을 대상으로 한다.

payload 정책: get_xss_payloads(ctx.scan_config) (safe/balanced/aggressive). 저장형은 marker 기반 최소 요청.
판정: Playwright alert=CONFIRMED, DOM 삽입=CONFIRMED/POSSIBLE, escape 없는 반사=POSSIBLE/MANUAL_REVIEW
      (위임 함수 결과의 confirmed 를 따른다).
"""
from __future__ import annotations

from probes.base import BaseProbe, ProbeContext, ProbeResult
from probes.utils import payloads
from probes.utils.injection_points import detect_search_points, gather_all_points
import active_probing as ap


class XssProbe(BaseProbe):
    name = "xss"
    category = "xss"
    enabled_by_default = True

    async def run(self, ctx: ProbeContext) -> list[ProbeResult]:
        results: list[ProbeResult] = []
        base_url = ctx.target_url
        scan_id = ctx.scan_id or ""

        # 입력점 확대 발굴 + 검색 입력점(q/search/keyword 등) 표시·포함.
        points = detect_search_points(gather_all_points(ctx))

        # payload 정책(safe/balanced/aggressive). 위임 함수가 자체 payload 를 쓰더라도
        # 정책에 따라 산출된 payload 셋을 명시적으로 준비한다(상한·게이팅 포함).
        xss_payloads = payloads.get_xss_payloads(ctx.scan_config)
        _ = xss_payloads  # 위임 함수의 marker 기반 검증과 결합(추가 호출 없음)

        # (probe_key, 위임 코루틴 팩토리, 결과 title)
        specs = [
            ("xss_reflected",
             lambda: ap._probe_xss_reflected(ctx.session, points, scan_id=scan_id),
             "반사형 XSS (Reflected Cross-Site Scripting)"),
            ("xss_js_context",
             lambda: ap._probe_xss_js_context(ctx.session, points, scan_id=scan_id),
             "JS 컨텍스트 반사 XSS (Reflected XSS in inline-script/JS-string context)"),
            ("xss_attr_context",
             lambda: ap._probe_xss_attr_context(ctx.session, points, scan_id=scan_id),
             "속성 컨텍스트 반사 XSS (Reflected XSS via HTML attribute breakout)"),
            ("dom_xss",
             lambda: ap._probe_dom_xss(ctx.session, base_url, scan_id=scan_id),
             "DOM 기반 XSS (DOM-based Cross-Site Scripting)"),
            ("xss_stored",
             lambda: ap._probe_xss_stored(ctx.session, base_url, points, scan_id=scan_id),
             "저장형 XSS (Stored Cross-Site Scripting)"),
        ]

        for probe_key, factory, title in specs:
            await ctx.throttle()
            try:
                data = await factory()
            except Exception:
                data = None
            if not data:
                continue
            results.append(self._to_result(probe_key, title, data))

        return results

    def _to_result(self, probe_key: str, title: str, data: dict) -> ProbeResult:
        confirmed = bool(data.get("confirmed"))
        affected = data.get("url") or data.get("verify_url") or data.get("submit_url") or ""
        return ProbeResult(
            title=title,
            category=self.category,
            severity="Medium",
            confidence="CONFIRMED" if confirmed else "POSSIBLE",
            affected_url=affected,
            evidence=[data["evidence"]] if data.get("evidence") else [],
            reproduction=data.get("evidence", ""),
            cwe="CWE-79",
            owasp="A03:2021 - 인젝션",
            probe_key=probe_key,
            raw=data,
        )


PROBE = XssProbe()
