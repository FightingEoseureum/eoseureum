"""
test_probe_result_adapter.py — probes.adapter (ProbeResult <-> 레거시 finding) 검증.

검증 항목:
  - convert_probe_result_to_legacy_finding 이 레거시 finding 구조를 생성.
  - severity 매핑(High→HIGH, Info→INFO), finding_type=="good" → judgment=="양호".
  - round-trip(legacy→probe_result) 시 핵심 필드 보존.
  - probe_results_to_findings(list) 가 list[dict] 반환.

실행:
  cd backend && venv_linux/bin/python -m pytest tests/test_probe_result_adapter.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from probes.base import ProbeResult
from probes.adapter import (
    convert_probe_result_to_legacy_finding,
    convert_legacy_finding_to_probe_result,
    probe_results_to_findings,
)


def _sample_probe_result(**over) -> ProbeResult:
    base = dict(
        title="CORS 설정 미흡",
        category="cors",
        finding_type="vulnerability",
        severity="High",
        confidence="CONFIRMED",
        confidence_score=80,
        affected_url="http://example.test/api",
        affected_endpoint="/api",
        evidence=["ACAO 반사 + credentials"],
        recommendation="화이트리스트만 허용",
        cwe="CWE-942",
        owasp="A05:2021",
        tags=["cors"],
    )
    base.update(over)
    return ProbeResult(**base)


def test_convert_builds_legacy_finding_structure():
    finding = convert_probe_result_to_legacy_finding(
        _sample_probe_result(), host="example.test", port=443)
    for key in ("title", "judgment", "severity", "confidence_score",
                "finding_type", "owasp", "cwe", "evidence_url", "recommendation"):
        assert key in finding, f"missing key: {key}"
    assert finding["title"] == "CORS 설정 미흡"
    assert finding["severity"] == "HIGH"
    assert finding["confidence_score"] == 80
    assert finding["cwe"] == "CWE-942"
    assert finding["owasp"] == "A05:2021"
    assert finding["evidence_url"] == "http://example.test/api"
    assert finding["host"] == "example.test"
    assert finding["port"] == 443


def test_severity_mapping_high_and_info():
    high = convert_probe_result_to_legacy_finding(_sample_probe_result(severity="High"))
    info = convert_probe_result_to_legacy_finding(_sample_probe_result(severity="Info"))
    assert high["severity"] == "HIGH"
    assert info["severity"] == "INFO"


def test_finding_type_good_maps_to_yangho_judgment():
    good = convert_probe_result_to_legacy_finding(
        _sample_probe_result(finding_type="good"))
    assert good["judgment"] == "양호"
    vuln = convert_probe_result_to_legacy_finding(
        _sample_probe_result(finding_type="vulnerability"))
    assert vuln["judgment"] == "취약"


def test_round_trip_preserves_core_fields():
    pr = _sample_probe_result()
    finding = convert_probe_result_to_legacy_finding(pr, host="example.test", port=443)
    back = convert_legacy_finding_to_probe_result(finding)

    assert back.title == pr.title
    assert back.category == pr.category
    assert back.finding_type == pr.finding_type
    assert back.severity == pr.severity            # High round-trips to High
    assert back.confidence == pr.confidence
    assert back.confidence_score == pr.confidence_score
    assert back.affected_url == pr.affected_url
    assert back.cwe == pr.cwe
    assert back.owasp == pr.owasp
    assert back.recommendation == pr.recommendation


def test_probe_results_to_findings_returns_list_of_dicts():
    results = [_sample_probe_result(), _sample_probe_result(severity="Low")]
    findings = probe_results_to_findings(results, host="example.test", port=80)
    assert isinstance(findings, list)
    assert len(findings) == 2
    assert all(isinstance(f, dict) for f in findings)
    assert findings[1]["severity"] == "LOW"
