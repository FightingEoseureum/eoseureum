"""
test_open_redirect_hostmatch.py — 오픈 리다이렉트 판정의 오탐 차단(목적지 host 실제 일치) 검증.

핵심: Location 에 센티넬 문자열이 '포함'되기만 해서는 안 되고, 실제 리다이렉트 목적지
host 가 센티넬(또는 그 서브도메인)일 때만 취약으로 본다. same-site 리다이렉트의 쿼리에
센티넬이 값으로만 반사된 경우(정상 동작)는 오탐으로 잡지 않는다.

실행: cd backend && venv_linux/bin/python -m pytest tests/test_open_redirect_hostmatch.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from active_probing import _redirect_lands_on_sentinel as lands

REQ = "https://app.example.com/page?redirect=https%3A%2F%2Fevil.scanner-probe.example.com"


def test_real_external_redirect_is_flagged():
    assert lands("https://evil.scanner-probe.example.com/", REQ) is True


def test_subdomain_of_sentinel_is_flagged():
    assert lands("https://x.evil.scanner-probe.example.com/a", REQ) is True


def test_protocol_relative_to_sentinel_is_flagged():
    assert lands("//evil.scanner-probe.example.com/x", REQ) is True


def test_same_site_redirect_with_reflected_value_is_NOT_flagged():
    # 의도한(같은 사이트) 페이지로 가지만 URL 쿼리에 센티넬이 값으로만 반사된 경우 → 안전
    loc = "https://app.example.com/login?next=https://evil.scanner-probe.example.com"
    assert lands(loc, REQ) is False


def test_relative_same_site_redirect_is_NOT_flagged():
    assert lands("/dashboard", REQ) is False


def test_lookalike_suffix_domain_is_NOT_flagged():
    # evil.scanner-probe.example.com.attacker.com 은 attacker.com 소유 → 센티넬 아님
    assert lands("https://evil.scanner-probe.example.com.attacker.com/", REQ) is False


def test_empty_location_is_NOT_flagged():
    assert lands("", REQ) is False
    assert lands(None, REQ) is False
