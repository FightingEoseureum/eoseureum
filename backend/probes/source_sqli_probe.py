"""
probes/source_sqli_probe.py — 화이트박스 SQLi probe (소스코드 정적 분석).

블랙박스 SqliProbe(HTTP 페이로드)로는 트리거 불가능한 SQLi를 소스로부터 발견한다.
대표 사례: 사용자 입력이 md5/인코딩 등으로 '변환된 뒤' 쿼리에 삽입되어, 필터는
원본을 검사하지만 DB는 변환값을 받는 '필터↔싱크 변환 불일치'(WAF 우회 SQLi).

동작 조건: scan_config.source_root(또는 env EOSEUREUM_SOURCE_ROOT)가 지정된 경우에만.
승인된 grey-box 점검 전제이며, 대상 코드를 import/실행하지 않고 ast 로만 정적 분석한다.
"""
from __future__ import annotations

import os

from probes.base import BaseProbe, ProbeContext, ProbeResult

try:
    from source_sqli_analyzer import analyze_source_tree
except Exception:  # 모듈 없거나 import 실패해도 전체 스캔은 계속
    analyze_source_tree = None


class SourceSqliProbe(BaseProbe):
    name = "source_sqli"
    category = "source_sqli"
    enabled_by_default = True

    async def run(self, ctx: ProbeContext) -> list[ProbeResult]:
        cfg = ctx.scan_config
        if analyze_source_tree is None:
            return []
        root = (getattr(cfg, "source_root", "") or "").strip()
        if not root or not getattr(cfg, "enable_source_sqli", True):
            return []
        if not os.path.exists(root):
            return []

        try:
            findings = analyze_source_tree(root)
        except Exception:
            return []

        results: list[ProbeResult] = []
        for f in findings:
            results.append(self._to_result(f))
        return results

    def _to_result(self, f) -> ProbeResult:
        # 필터 우회/변환 불일치는 실증 신뢰도가 높다 → CONFIRMED 유지, 그 외는 원 신뢰도.
        title_map = {
            "filter_transform_mismatch":
                "필터 우회 SQL 인젝션 — 변환 불일치 (Filter-bypass SQLi via transform mismatch)",
            "bytes_repr_injection":
                "SQL 인젝션 — bytes/digest repr 삽입 (str(bytes) quote reintroduction)",
            "dynamic_sql":
                "동적 SQL 구성 (Unparameterized dynamic SQL)",
        }
        title = title_map.get(f.kind, "SQL 인젝션 (소스 분석)")
        loc = f"{f.file}:{f.line}"
        evidence = (
            f"[{loc}] {f.snippet}\n"
            f"싱크: {f.sink}  |  입력: {f.taint_source or f.param or '(정적)'}"
            + (f"  |  변환: {f.transform}" if f.transform else "")
            + (f"  |  필터: {f.filter_applied}()" if f.filter_applied else "")
            + f"\n{f.evidence}"
        )
        return ProbeResult(
            title=title,
            category=self.category,
            finding_type="vulnerability",
            severity=f.severity,
            confidence=f.confidence,
            affected_url="",
            affected_endpoint=loc,
            evidence=[evidence],
            reproduction=evidence,
            recommendation=f.recommendation,
            cwe=f.cwe,
            owasp=f.owasp,
            tags=["whitebox", "source", "sqli", f.kind],
            safe_check=True,
            probe_key=f"source_sqli_{f.kind}",
            raw=f.to_dict(),
        )


PROBE = SourceSqliProbe()
