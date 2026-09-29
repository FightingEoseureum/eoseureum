"""서브도메인 탈취 시드 확대(P2-#6) 회귀 테스트.

_subdomain_seeds_from_scan 이 크롤 발견 URL 에서 '동일 등록도메인 하위 호스트'만 시드로
모으고, 권한 밖 제3자 호스트는 제외하는지 확인.
"""
import main


def test_registrable_domain():
    assert main._registrable_domain("demo.testfire.net") == "testfire.net"
    assert main._registrable_domain("a.b.example.co.kr") == "example.co.kr"
    assert main._registrable_domain("example.com") == "example.com"


def test_seeds_include_same_domain_exclude_third_party():
    host_results = [{"services": [{"discovered_urls": [
        "http://demo.testfire.net/app",
        "http://api.testfire.net/v1",          # 동일 등록도메인 하위 → 포함
        "https://cdn.testfire.net/assets/x.js", # 포함
        "http://evil-third-party.com/x",        # 제3자 → 제외
        "http://www.google.com/",               # 제3자 → 제외
    ]}]}]
    seeds = main._subdomain_seeds_from_scan(host_results, "demo.testfire.net")
    hosts = {s["subdomain"] for s in seeds}
    assert "demo.testfire.net" in hosts       # 대상 호스트 항상 포함
    assert "api.testfire.net" in hosts
    assert "cdn.testfire.net" in hosts
    assert "evil-third-party.com" not in hosts
    assert "www.google.com" not in hosts


def test_seeds_dedup_and_target_only_when_empty():
    seeds = main._subdomain_seeds_from_scan([], "t.example.com")
    assert seeds == [{"subdomain": "t.example.com"}]
