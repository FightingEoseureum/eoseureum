# -*- coding: utf-8 -*-
"""iterative_recrawl 순수 로직 단위테스트(네트워크 없음)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import iterative_recrawl as irc


def test_norm():
    assert irc._norm("http://x/a/") == "http://x/a"
    assert irc._norm("https://x/a?b=1#f") == "https://x/a"
    assert irc._norm("ftp://x/a") == ""
    assert irc._norm("http://x/") == "http://x"


def test_collect_seen_and_diff():
    hr = [{"host": "x", "services": [{
        "http_info": {"url": "http://x"},
        "discovered_urls": ["http://x/a", "http://x/b/"],
        "discovery_result": {"urls": [{"url": "http://x/c"}]},
    }]}]
    seen = irc.collect_seen_urls(hr)
    assert irc._norm("http://x/a") in seen
    assert irc._norm("http://x/b") in seen
    assert irc._norm("http://x/c") in seen
    # diff_new: 이미 본 것은 제외, 새 것만
    new = irc.diff_new(["http://x/a", "http://x/d", "http://x/d"], seen)
    assert new == ["http://x/d"]  # a 제외, d 중복 제거


def test_diff_new_empty_converges():
    seen = {irc._norm("http://x/a")}
    assert irc.diff_new(["http://x/a/"], seen) == []  # 새 URL 없음 → 수렴 신호


def test_merge_new_findings_dedup():
    existing = [{"title": "XSS", "evidence_url": "http://x/s?q=1"}]
    scoped = [
        {"title": "XSS", "evidence_url": "http://x/s?q=1"},          # 중복(제거)
        {"title": "SQLi", "evidence_url": "http://x/login"},          # 신규
    ]
    merged, added = irc.merge_new_findings(existing, scoped)
    assert added == 1
    assert len(merged) == 2
    assert merged[-1]["discovered_by"] == "iterative_recrawl"


def test_deterministic_should_crawl():
    # 상한 초과 → 종료
    ok, _ = irc.deterministic_should_crawl(6, 5, 10, False, 0)
    assert ok is False
    # 인증 예정 → 진행
    ok, _ = irc.deterministic_should_crawl(1, 5, 0, True, 0)
    assert ok is True
    # 시드 없음 → 종료
    ok, _ = irc.deterministic_should_crawl(2, 5, 0, False, 0)
    assert ok is False
    # 시드 있음 → 진행
    ok, _ = irc.deterministic_should_crawl(2, 5, 3, False, 0)
    assert ok is True


def test_prioritize_admin_api_first():
    urls = ["http://x/blog/1", "http://x/admin/panel", "http://x/api/users", "http://x/about"]
    out = irc.prioritize_new_urls(urls, cap=10)
    assert out[0] in ("http://x/admin/panel", "http://x/api/users")
    # cap 적용
    assert len(irc.prioritize_new_urls(urls, cap=2)) == 2


def test_prioritize_ai_order_wins():
    urls = ["http://x/admin", "http://x/blog"]
    out = irc.prioritize_new_urls(urls, cap=10, ai_order=[irc._norm("http://x/blog")])
    assert out[0] == "http://x/blog"  # AI 우선순위가 결정적 점수를 이김


def test_newly_reachable_seeds():
    analysis = {"findings": [{"title": "IDOR", "evidence_url": "http://x/obj?id=1"}]}
    hr = [{"host": "x", "services": [{"http_info": {"url": "http://x"},
            "discovery_result": {"admin_hits": [{"url": "http://x/admin"}],
                                 "api_hits": [{"url": "http://x/api/z"}]}}]}]
    seeds = irc.newly_reachable_seeds(analysis, hr, set())
    ns = {irc._norm(s) for s in seeds}
    assert irc._norm("http://x/obj?id=1") in ns
    assert irc._norm("http://x/admin") in ns
    assert irc._norm("http://x/api/z") in ns


def test_env_gates(monkeypatch=None):
    os.environ.pop("ENABLE_ITERATIVE_RECRAWL", None)
    assert irc.enabled() is True          # 기본 ON(확정→심화 재점검, bounded)
    os.environ["ENABLE_ITERATIVE_RECRAWL"] = "false"
    assert irc.enabled() is False
    os.environ["ENABLE_ITERATIVE_RECRAWL"] = "true"
    assert irc.enabled() is True
    os.environ["MAX_RECRAWL_ROUNDS"] = "8"
    assert irc.max_rounds() == 8
    os.environ["MAX_RECRAWL_ROUNDS"] = "99"   # 상한 10 클램프
    assert irc.max_rounds() == 10
    os.environ["MAX_RECRAWL_ROUNDS"] = "0"    # 하한 1 클램프
    assert irc.max_rounds() == 1
    del os.environ["ENABLE_ITERATIVE_RECRAWL"]
    del os.environ["MAX_RECRAWL_ROUNDS"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)


def test_auth_crawl_returns_4tuple_with_cookies(monkeypatch):
    """_auth_crawl 는 (urls, logged_in, reason, cookies) 4-튜플 반환.
    크리덴셜이 없으면(skip 경로) 빈 쿠키를 포함해 4개 값을 돌려줘야 한다
    (기존 3-튜플에서 세션 쿠키 반환을 추가 — 인증 상태 능동 점검 등록용)."""
    import asyncio
    monkeypatch.delenv("AUTH_LOGIN_URL", raising=False)
    monkeypatch.setenv("ENABLE_AUTH_CRAWL", "true")
    res = asyncio.run(irc._auth_crawl("example.com", auth=None))
    assert isinstance(res, tuple) and len(res) == 4
    urls, logged_in, reason, cookies = res
    assert urls == [] and logged_in is False and cookies == []
    assert reason  # skip 사유 문자열 존재


def test_auth_probe_activates_on_registered_cookies(monkeypatch):
    """per-scan 로그인 쿠키가 등록되면 전역 ENABLE_AUTH_PROBE 없이도 인증 점검 게이트가 열린다."""
    import active_probing as ap
    monkeypatch.delenv("ENABLE_AUTH_PROBE", raising=False)
    sid = "test-scan-authgate"
    ap.clear_auth_cookies(sid)
    assert ap.auth_probe_enabled() is False
    # 쿠키 미등록 → 게이트 닫힘
    assert not (ap.auth_probe_enabled() or ap.get_auth_cookies(sid))
    # 로그인 쿠키 등록 → 게이트 열림(토글 없이)
    ap.register_auth_cookies(sid, [{"name": "PHPSESSID", "value": "abc"}])
    assert (ap.auth_probe_enabled() or ap.get_auth_cookies(sid))
    ap.clear_auth_cookies(sid)
