"""
probes/clickjacking_probe.py — Clickjacking probe.

검증된 active_probing._probe_clickjacking 에 위임한다.
(X-Frame-Options / CSP frame-ancestors 부재 + Playwright iframe 실제 로드 검증은 위임 함수가 수행)
"""
from __future__ import annotations

from probes.base import BaseProbe, ProbeContext, ProbeResult
import active_probing as ap


class ClickjackingProbe(BaseProbe):
    name = "clickjacking"
    category = "clickjacking"
    enabled_by_default = True

    async def run(self, ctx: ProbeContext) -> list[ProbeResult]:
        await ctx.throttle()

        if not ctx.target_url:
            return []

        data = await ap._probe_clickjacking(ctx.session, ctx.target_url, ctx.scan_id)
        if not data:
            return []

        confirmed = bool(data.get("confirmed"))
        evidence = []
        if data.get("evidence"):
            evidence.append(str(data["evidence"]))

        return [ProbeResult(
            title="클릭재킹(Clickjacking) 취약점",
            category=self.category,
            finding_type="vulnerability",
            severity="Medium",
            confidence="CONFIRMED" if confirmed else "POSSIBLE",
            affected_url=data.get("url", "") or ctx.target_url,
            evidence=evidence,
            recommendation=(
                "X-Frame-Options: DENY(또는 SAMEORIGIN) 또는 Content-Security-Policy "
                "frame-ancestors 지시자를 설정하여 외부 사이트의 iframe 삽입을 차단하라."
            ),
            cwe="CWE-1021",
            owasp="A05:2021",
            probe_key="clickjacking",
            raw=data,
        )]


PROBE = ClickjackingProbe()
