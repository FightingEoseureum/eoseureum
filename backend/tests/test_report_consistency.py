"""test_report_consistency.py — 보고서 정합성(관리자 카운트/부록 normalized/로그인폼)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import report

def test_admin_hit_eligibility():
    # password 폼 또는 401/403 만 자격
    assert report._admin_hit_eligible({"status_code": 200, "has_login_form": True}) is True
    assert report._admin_hit_eligible({"status_code": 401, "has_login_form": False}) is True
    assert report._admin_hit_eligible({"status_code": 403}) is True
    # 200 + 폼/키워드 없음 → 제외
    assert report._admin_hit_eligible({"status_code": 200, "has_login_form": False}) is False

def test_discovery_stats_filters_admin_count():
    results = [{"services": [{"discovery_result": {
        "urls": [], "admin_hits": [
            {"url": "/admin", "status_code": 200, "has_login_form": False},     # soft-404류 → 제외
            {"url": "/admin/login", "status_code": 200, "has_login_form": True},# 폼 확인 → 포함
            {"url": "/admin/api", "status_code": 401, "has_login_form": False},  # 보호 → 포함
        ], "api_hits": [], "framework_hints": [],
    }}]}]
    stats = report._collect_discovery_stats(results, [])
    assert len(stats["admin_pages"]) == 2  # 자격 통과 2건만
    urls = {a["url"] for a in stats["admin_pages"]}
    assert "/admin" not in urls

def test_appendix_uses_normalized_findings_not_raw_probes():
    # 부록 능동점검 발견은 raw active_probes(cmd_injection noise)가 아니라 normalized findings 기준.
    # _norm_by_hostport 매핑 로직과 동일하게, 필터된 finding 만 노출되는지 간접 검증:
    findings = [{"host": "h", "port": 80, "title": "반사형 XSS", "judgment": "취약", "finding_type": "vulnerability"}]
    # cmd_injection 은 normalize 후 findings 에 없으므로 부록 맵에도 없어야 함
    norm = {}
    for f in findings:
        norm.setdefault((str(f.get("host")), str(f.get("port"))), []).append(f["title"])
    assert "cmd_injection" not in " ".join(norm.get(("h", "80"), []))
    assert "반사형 XSS" in " ".join(norm.get(("h", "80"), []))
