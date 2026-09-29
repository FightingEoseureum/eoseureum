"""
probes/admin_exposure_probe.py — 관리자 페이지 인터넷 노출 점검 Probe.

1차 리팩토링: 검증된 active_probing._probe_admin_panel 에 위임한다. 위임이 불가하거나
실패하면 빈 목록을 반환한다.
"""
from __future__ import annotations

from probes.base import BaseProbe, ProbeContext, ProbeResult


class AdminExposureProbe(BaseProbe):
    name = "admin_exposure"
    category = "admin_exposure"
    enabled_by_default = True

    async def run(self, context: ProbeContext) -> list[ProbeResult]:
        if context.session is None or not context.target_url:
            return []
        try:
            from active_probing import _probe_admin_panel
        except Exception:
            return []
        try:
            await context.throttle()
            data = await _probe_admin_panel(context.session, context.target_url, context.scan_id)
        except Exception:
            return []
        if not data:
            return []

        # 로그인 폼만 노출된 경우는 공격 표면(attack_surface) 으로 분류.
        # 데이터로 판단이 어려우면 기본 "attack_surface".
        finding_type = "attack_surface"
        return [ProbeResult(
            title="관리자 페이지 인터넷 노출",
            category=self.category,
            finding_type=finding_type,
            severity="Medium",
            confidence="CONFIRMED" if data.get("confirmed") else "POSSIBLE",
            confidence_score=70 if data.get("confirmed") else 40,
            affected_url=data.get("url", context.target_url),
            evidence=[data.get("evidence", "")] if data.get("evidence") else [],
            recommendation="관리자 인터페이스를 인터넷에 직접 노출하지 말고 접근 제어(IP 제한/VPN)를 적용하세요.",
            owasp="A01:2021",
            cwe="CWE-284",
            probe_key="admin_panel",
            raw=data,
        )]


PROBE = AdminExposureProbe()
