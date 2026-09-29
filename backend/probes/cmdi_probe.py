"""
probes/cmdi_probe.py — 명령어 인젝션(Command Injection) probe.

검증된 active_probing._probe_cmdi 에 위임한다(echo marker / 검증 로직은 위임 함수가 수행).
입력점은 gather_all_points 로 확대 발굴한다.

payload 정책: get_cmdi_payloads(config) (echo marker 기반만; safe=기본, balanced=구분자 변형 ; && | ` $()).
sleep/ping/외부통신 금지 — payload 가 이미 echo marker 만 사용하므로 추가 호출을 하지 않는다.
marker 가 명확히 반사될 때에만 위임 함수가 confirmed 를 반환한다(POSSIBLE 이상).
"""
from __future__ import annotations

from probes.base import BaseProbe, ProbeContext, ProbeResult
from probes.utils import payloads
from probes.utils.injection_points import gather_all_points
import active_probing as ap


class CmdiProbe(BaseProbe):
    name = "cmdi"
    category = "cmdi"
    enabled_by_default = True

    async def run(self, ctx: ProbeContext) -> list[ProbeResult]:
        # 입력점 확대 발굴(form + query parameter + authenticated_forms).
        points = gather_all_points(ctx)
        if not points:
            return []

        # payload 정책 산출(echo marker 기반만; 상한·게이팅 포함).
        _ = payloads.get_cmdi_payloads(ctx.scan_config)

        await ctx.throttle()
        data = await ap._probe_cmdi(ctx.session, points, ctx.scan_id)
        if not data:
            return []

        confirmed = bool(data.get("confirmed"))
        evidence = []
        if data.get("evidence"):
            evidence.append(str(data["evidence"]))

        return [ProbeResult(
            title="명령어 인젝션(Command Injection)",
            category=self.category,
            finding_type="vulnerability",
            severity="High",
            confidence="CONFIRMED" if confirmed else "POSSIBLE",
            affected_url=data.get("url", "") or ctx.target_url,
            evidence=evidence,
            recommendation=(
                "사용자 입력을 OS 명령에 직접 전달하지 말고, 명령 실행 API 대신 "
                "안전한 라이브러리/파라미터화된 호출을 사용하며 입력값을 화이트리스트로 검증하라."
            ),
            cwe="CWE-78",
            owasp="A03:2021 - 인젝션",
            probe_key="cmd_injection",
            raw=data,
        )]


PROBE = CmdiProbe()
