"""사용자별 접근 허용 IP(allowed_ips) — IP/CIDR 매칭 로직 검증.

정책: 빈 값 = 전부 차단. 예외로 항상 허용: localhost, IP_ALWAYS_ALLOW(기본 10.25.2.16).
"""
from auth import ip_allowed


def test_empty_denies_all_except_localhost():
    assert ip_allowed("10.20.100.55", "") is False      # 빈 값 = 차단
    assert ip_allowed("1.2.3.4", "   ") is False
    assert ip_allowed("10.25.2.16", "") is False        # 전역 예외 기본 없음 → 차단(계정별로만 허용)
    assert ip_allowed("127.0.0.1", "") is True          # localhost 만 항상 허용(서버 복구용)
    assert ip_allowed("::1", "") is True


def test_env_global_allow_optin(monkeypatch):
    # IP_ALWAYS_ALLOW env 를 설정했을 때만 전역 예외가 동작(기본은 계정별 제한 우회 안 함)
    monkeypatch.setenv("IP_ALWAYS_ALLOW", "10.25.2.16")
    assert ip_allowed("10.25.2.16", "1.2.3.4") is True
    monkeypatch.delenv("IP_ALWAYS_ALLOW", raising=False)
    assert ip_allowed("10.25.2.16", "1.2.3.4") is False   # env 없으면 계정 IP만


def test_exact_ip():
    assert ip_allowed("10.20.100.55", "10.20.100.55") is True
    assert ip_allowed("10.20.100.56", "10.20.100.55") is False


def test_cidr_not_matched_exact_only():
    # 완전 일치만 — 대역(CIDR)은 매칭되지 않는다
    assert ip_allowed("10.20.100.55", "10.20.100.0/24") is False
    assert ip_allowed("10.20.100.0", "10.20.100.0/24") is False   # 네트워크 주소도 CIDR 표기라 무시


def test_list_comma_and_newline():
    lst = "1.2.3.4, 10.20.100.7\n192.168.0.10"
    assert ip_allowed("10.20.100.7", lst) is True     # 정확히 등록된 IP만
    assert ip_allowed("192.168.0.10", lst) is True
    assert ip_allowed("10.20.100.8", lst) is False    # 인접 IP도 차단
    assert ip_allowed("8.8.8.8", lst) is False


def test_bad_client_ip_blocked():
    assert ip_allowed("not-an-ip", "10.20.100.5") is False


def test_ipv6_exact():
    assert ip_allowed("::1", "::1") is True
    assert ip_allowed("2001:db8::5", "2001:db8::5") is True
    assert ip_allowed("2001:db8::6", "2001:db8::5") is False
