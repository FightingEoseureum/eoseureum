"""
probes/cors_probe.py — CORS 설정 점검 Probe.

1차 리팩토링: 검증된 active_probing._probe_cors 에 위임한다. 위임이 불가하거나
실패하면 빈 목록을 반환한다(전체 스캔 중단 방지).
"""
from __future__ import annotations

from probes.base import BaseProbe, ProbeContext, ProbeResult


class CorsProbe(BaseProbe):
    name = "cors"
    category = "cors"
    enabled_by_default = True

    async def run(self, context: ProbeContext) -> list[ProbeResult]:
        if context.session is None or not context.target_url:
            return []
        try:
            from active_probing import _probe_cors
        except Exception:
            return []
        try:
            await context.throttle()
            data = await _probe_cors(context.session, context.target_url, context.scan_id)
        except Exception:
            return []
        if not data:
            return []

        level = str(data.get("cors_level", "Medium")).title()
        confirmed = bool(data.get("confirmed"))
        return [ProbeResult(
            title="CORS 설정 미흡",
            category=self.category,
            finding_type="vulnerability",
            severity=level if level in ("High", "Medium", "Low", "Info") else "Medium",
            confidence="CONFIRMED" if confirmed else "POSSIBLE",
            confidence_score=80 if confirmed else 50,
            affected_url=data.get("url", context.target_url),
            evidence=[data.get("evidence", "")] if data.get("evidence") else [],
            recommendation="신뢰할 수 있는 Origin 화이트리스트만 허용하고 와일드카드/반사를 제거하세요.",
            owasp="A05:2021",
            cwe="CWE-942",
            probe_key="cors",
            raw=data,
        )]


PROBE = CorsProbe()
