"""
probes/auth_probe.py — 인증/접근 제어 probe.

로그인 폼을 공통 유틸(form_parser.find_login_points)로 탐지한 뒤, 검증된 active_probing 의
_probe_auth_bypass(IP 우회 등) 및 _probe_sqli_auth_bypass(로그인 폼 SQL 인증 우회)에
위임한다(새 탐지 로직 작성 금지).
"""
from __future__ import annotations

from probes.base import BaseProbe, ProbeContext, ProbeResult
from probes.utils import form_parser
import active_probing as ap


class AuthProbe(BaseProbe):
    name = "auth"
    category = "auth"
    enabled_by_default = True

    async def run(self, ctx: ProbeContext) -> list[ProbeResult]:
        results: list[ProbeResult] = []
        points = ctx.injection_points or []

        # 공통 유틸로 로그인 폼 지점 탐지(auth/sqli probe 공통 사용).
        login_points = form_parser.find_login_points(points)

        # 접근 제어(IP 제한) 우회 — target_url 대상.
        await ctx.throttle()
        try:
            data = await ap._probe_auth_bypass(ctx.session, ctx.target_url)
        except Exception:
            data = None
        if data:
            results.append(self._to_result(
                "auth_bypass",
                "접근 제어 우회 (Access Control / IP Restriction Bypass)", data))

        # 로그인 폼이 탐지된 경우에만 SQL 인증 우회 위임.
        if login_points:
            await ctx.throttle()
            try:
                data = await ap._probe_sqli_auth_bypass(ctx.session, login_points)
            except Exception:
                data = None
            if data:
                results.append(self._to_result(
                    "sqli_auth_bypass",
                    "SQL 인젝션 인증 우회 (Authentication Bypass)", data))

        # 인증 스캔 연동: authenticated_scan 이 로그인 후 크롤한 결과가 ctx 에 있으면
        #   그 사실을 evidence/discovery 로 보고한다(여기서 직접 크롤/로그인하지 않음).
        #   자동 로그인/브루트포스는 credential_probe 정책에 따라 금지.
        auth_urls = ctx.authenticated_urls or []
        auth_forms = ctx.authenticated_forms or []
        if ctx.authenticated_session is not None or auth_urls or auth_forms:
            results.append(ProbeResult(
                title="인증 스캔 수행됨 (Authenticated Crawl)",
                category=self.category,
                finding_type="discovery",
                severity="Info",
                confidence="CONFIRMED",
                affected_url=ctx.target_url,
                evidence=[
                    f"인증된 세션으로 {len(auth_urls)}개 페이지, "
                    f"{len(auth_forms)}개 폼/주입 지점을 수집했습니다."
                ],
                recommendation="인증 영역의 폼/엔드포인트가 각 probe 의 점검 대상에 포함됩니다.",
                probe_key="authenticated_scan",
                tags=["auth", "authenticated_scan", "discovery"],
                safe_check=True,
                raw={
                    "authenticated_url_count": len(auth_urls),
                    "authenticated_form_count": len(auth_forms),
                    "has_session": ctx.authenticated_session is not None,
                },
            ))

        return results

    def _to_result(self, probe_key: str, title: str, data: dict) -> ProbeResult:
        confirmed = bool(data.get("confirmed"))
        affected = data.get("url") or data.get("evidence_url") or data.get("redirect_to") or ""
        return ProbeResult(
            title=title,
            category=self.category,
            severity="High",
            confidence="CONFIRMED" if confirmed else "POSSIBLE",
            affected_url=affected,
            evidence=[data["evidence"]] if data.get("evidence") else [],
            reproduction=data.get("evidence", ""),
            cwe="CWE-287",
            owasp="A07:2021 - 식별 및 인증 실패",
            probe_key=probe_key,
            raw=data,
        )


PROBE = AuthProbe()
