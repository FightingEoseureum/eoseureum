"""③ 로컬 CVE 피드 흡수 + NVD 인제스터 회귀."""
import json

import cve_intel as ci


def test_curated_db_still_works():
    # 기존 큐레이션 CVE(react2shell)는 그대로 상관됨
    hits = ci.correlate("__NEXT_DATA__ react-server-dom /_next/")
    assert any(h["cve"] == "CVE-2025-55182" for h in hits)


def test_feed_merge_and_keyword_match(monkeypatch, tmp_path):
    feed = [{"cve": "CVE-2099-0001", "title": "Test Struts", "cvss": "9.8",
             "severity": "Critical", "cwe": "CWE-502",
             "match_keywords": ["Apache Struts", "struts2"]}]
    fp = tmp_path / "cve_feed.json"; fp.write_text(json.dumps(feed))
    monkeypatch.setenv("CVE_FEED_PATH", str(fp))
    ci._FEED_CACHE.update(mtime=0.0, data=None)  # 캐시 무효화
    hits = ci.correlate("Server: Apache Struts/2.5")
    assert any(h["cve"] == "CVE-2099-0001" for h in hits)
    assert ci.get("CVE-2099-0001")["cwe"] == "CWE-502"


def test_feed_regex_string(monkeypatch, tmp_path):
    feed = [{"cve": "CVE-2099-0002", "match": r"log4j|jndi:ldap", "severity": "Critical"}]
    fp = tmp_path / "cve_feed.json"; fp.write_text(json.dumps(feed))
    monkeypatch.setenv("CVE_FEED_PATH", str(fp))
    ci._FEED_CACHE.update(mtime=0.0, data=None)
    assert any(h["cve"] == "CVE-2099-0002" for h in ci.correlate("uses log4j 2.14"))


def test_nvd_ingest_extracts_web_high_severity():
    nvd = [
        {"cve": {"id": "CVE-2021-44228", "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI RCE"}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]},
                 "weaknesses": [{"description": [{"value": "CWE-502"}]}],
                 "configurations": [{"nodes": [{"cpeMatch": [
                     {"criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}]}]}]}},
        {"cve": {"id": "CVE-2000-0000", "descriptions": [{"lang": "en", "value": "some desktop bug"}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.0}}]}}},  # 저위험+비웹 → 제외
    ]
    feed = ci.ingest_nvd(nvd, min_cvss=7.0)
    ids = {f["cve"] for f in feed}
    assert "CVE-2021-44228" in ids       # 웹·고위험 → 포함
    assert "CVE-2000-0000" not in ids     # 저위험 → 제외
    log4j = next(f for f in feed if f["cve"] == "CVE-2021-44228")
    assert log4j["severity"] == "Critical" and log4j["cwe"] == "CWE-502"
    assert any("log4j" in k.lower() for k in log4j["match_keywords"])
