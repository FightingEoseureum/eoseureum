"""
probes/http_method_probe.py — 위험한 HTTP Method 활성화 probe.

검증된 scanner.probe_http_extras 에 위임한다.
판정은 verified_dangerous_methods(실제 호출로 검증된 메서드)만으로 한다.
OPTIONS Allow 헤더에 광고만 된 메서드(allowed_methods)는 오탐의 원인이므로 사용하지 않는다.
"""
from __future__ import annotations

from probes.base import BaseProbe, ProbeContext, ProbeResult
import scanner


class HttpMethodProbe(BaseProbe):
    name = "http_method"
    category = "http_method"
    enabled_by_default = True

    async def run(self, ctx: ProbeContext) -> list[ProbeResult]:
        await ctx.throttle()

        use_ssl = (ctx.scheme or "").lower() == "https"
        extras = await scanner.probe_http_extras(ctx.host, ctx.port, use_ssl)
        if not extras:
            return []

        verified = [m for m in (extras.get("verified_dangerous_methods") or []) if m]
        if not verified:
            return []

        # 실제 검증된 메서드만 제목/증거에 포함한다.
        title = ", ".join(verified) + " Method 활성화"

        return [ProbeResult(
            title=title,
            category=self.category,
            finding_type="vulnerability",
            severity="Medium",
            confidence="CONFIRMED",
            affected_url=ctx.target_url,
            evidence=["검증된 위험 메서드: " + ", ".join(verified)],
            recommendation="필요한 HTTP Method만 허용하고 TRACE 비활성화",
            cwe="CWE-16",
            owasp="A05:2021",
            probe_key="dangerous_methods",
            raw=extras,
        )]


PROBE = HttpMethodProbe()
