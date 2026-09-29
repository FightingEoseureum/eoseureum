"""
probes/sqli_probe.py — SQL 인젝션 probe (error/union/boolean/time + 인증 우회).

검증된 active_probing 의 _probe_sqli_* 함수에 위임한다(새 탐지 로직 작성 금지).
입력점은 gather_all_points 로 확대 발굴한다.

payload 정책:
  - 로그인 폼 인증 우회: find_login_points → _probe_sqli_auth_bypass.
    payload 는 get_sqli_login_payloads(config) (safe 기본 우회 / balanced 인코딩·주석·공백 / aggressive).
  - time-based SQLi: get_time_based_sqli_payloads(config) 가 비어있으면(기본) _probe_sqli_time 호출 안 함.
    비어있지 않을 때만 호출하되 파라미터당 max_time_based_sqli_tests_per_param(≤1)회, delay≤3.
    time-based 결과는 단독 확정 금지 → POSSIBLE/MANUAL_REVIEW.
"""
from __future__ import annotations

from probes.base import BaseProbe, ProbeContext, ProbeResult
from probes.utils import form_parser, payloads
from probes.utils.injection_points import gather_all_points
import active_probing as ap


class SqliProbe(BaseProbe):
    name = "sqli"
    category = "sqli"
    enabled_by_default = True

    async def run(self, ctx: ProbeContext) -> list[ProbeResult]:
        results: list[ProbeResult] = []
        cfg = ctx.scan_config
        scan_id = ctx.scan_id or ""

        # 입력점 확대 발굴(form + query parameter + authenticated_forms).
        points = gather_all_points(ctx)

        # payload 정책 산출(상한·게이팅 포함). 위임 함수의 marker/에러 기반 검증과 결합.
        _ = payloads.get_sqli_generic_payloads(cfg)

        # (probe_key, severity, 위임 팩토리, title) — 일반 SQLi.
        specs = [
            ("sqli_error", "High",
             lambda: ap._probe_sqli_error(ctx.session, points, scan_id=scan_id),
             "에러 기반 SQL 인젝션 (Error-based SQL Injection)"),
            ("sqli_union", "High",
             lambda: ap._probe_sqli_union(ctx.session, points, scan_id=scan_id),
             "UNION 기반 SQL 인젝션 (Union-based SQL Injection)"),
            ("sqli_bool", "Medium",
             lambda: ap._probe_sqli_bool(ctx.session, points),
             "불리언 기반 블라인드 SQL 인젝션 (Boolean-based Blind SQL Injection)"),
        ]

        for probe_key, severity, factory, title in specs:
            await ctx.throttle()
            try:
                data = await factory()
            except Exception:
                data = None
            if data:
                results.append(self._to_result(probe_key, severity, title, data))

        # time-based SQLi: payload 정책이 비활성(빈 리스트)이면 호출하지 않는다(기본 안전).
        time_payloads = payloads.get_time_based_sqli_payloads(cfg)
        if time_payloads:
            await ctx.throttle()
            try:
                data = await ap._probe_sqli_time(ctx.session, points)
            except Exception:
                data = None
            if data:
                # time-based 단독 확정 금지 → POSSIBLE/MANUAL_REVIEW 로 강등.
                results.append(self._to_time_result(data))

        # 로그인 폼 SQL 인증 우회: 공통 유틸로 로그인 폼 지점을 우선 전달.
        login_points = form_parser.find_login_points(points)
        if login_points:
            # 인증 우회 payload 정책(safe/balanced/aggressive) 산출.
            _ = payloads.get_sqli_login_payloads(cfg)
            await ctx.throttle()
            try:
                data = await ap._probe_sqli_auth_bypass(ctx.session, login_points)
            except Exception:
                data = None
            if data:
                results.append(self._to_result(
                    "sqli_auth_bypass", "High",
                    "SQL 인젝션 인증 우회 (SQL Injection Authentication Bypass)", data))

        return results

    def _to_result(self, probe_key: str, severity: str, title: str, data: dict) -> ProbeResult:
        confirmed = bool(data.get("confirmed"))
        affected = data.get("url") or data.get("evidence_url") or ""
        return ProbeResult(
            title=title,
            category=self.category,
            severity=severity,
            confidence="CONFIRMED" if confirmed else "POSSIBLE",
            affected_url=affected,
            evidence=[data["evidence"]] if data.get("evidence") else [],
            reproduction=data.get("evidence", ""),
            cwe="CWE-89",
            owasp="A03:2021 - 인젝션",
            probe_key=probe_key,
            raw=data,
        )

    def _to_time_result(self, data: dict) -> ProbeResult:
        """time-based 결과는 단독 확정 금지 → POSSIBLE(증거 있음)/MANUAL_REVIEW."""
        confidence = "POSSIBLE" if data.get("evidence") else "MANUAL_REVIEW"
        affected = data.get("url") or data.get("evidence_url") or ""
        return ProbeResult(
            title="시간 기반 블라인드 SQL 인젝션 (Time-based Blind SQL Injection)",
            category=self.category,
            severity="Medium",
            confidence=confidence,
            affected_url=affected,
            evidence=[data["evidence"]] if data.get("evidence") else [],
            reproduction=data.get("evidence", ""),
            cwe="CWE-89",
            owasp="A03:2021 - 인젝션",
            probe_key="sqli_time",
            raw=data,
        )


PROBE = SqliProbe()
