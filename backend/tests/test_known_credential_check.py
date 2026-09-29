"""tests/test_known_credential_check.py — Known credential 검증 probe + 로더 (네트워크 없음)."""
import pytest

from probes.base import ProbeContext
from probes import credential_probe
from probes.config import ScanConfig
from probes.utils import credential_loader
from probes.utils.rate_limiter import RateLimiter, CompositeRateLimiter


class _DummySession:
    pass


def _ctx(cfg, points=None):
    return ProbeContext(
        target_url="http://target.example/login",
        session=_DummySession(),
        injection_points=points if points is not None else [
            {"url": "http://target.example/login", "method": "POST",
             "source": "form", "params": {"username": "x", "password": "y"},
             "csrf_fields": []},
        ],
        scan_config=cfg,
        rate_limiter=RateLimiter(0),
        auth_rate_limiter=CompositeRateLimiter(RateLimiter(0), RateLimiter(0)),
        scan_id="test-scan",
    )


# ── credential_loader ────────────────────────────────────────────────────────

def test_loader_caps_at_max_credentials(tmp_path):
    f = tmp_path / "creds.txt"
    # 2000줄 작성 → 최대 1000개까지만 로드
    f.write_text("\n".join(f"user{i}:pass{i}" for i in range(2000)))
    cfg = ScanConfig(max_auth_credentials=2000, auth_credential_file=str(f))
    # config 클램프는 from_env 에서만 적용되므로 로더 자체 하드캡(1000) 검증
    creds = credential_loader.load_credentials(cfg)
    assert len(creds) == 1000
    assert creds[0] == ("user0", "pass0")


def test_loader_respects_limit_below_file_size(tmp_path):
    f = tmp_path / "creds.txt"
    f.write_text("a:1\nb:2\nc:3\n# comment\n\nd:4\n")
    cfg = ScanConfig(max_auth_credentials=2, auth_credential_file=str(f))
    creds = credential_loader.load_credentials(cfg)
    assert creds == [("a", "1"), ("b", "2")]


def test_loader_no_sample_when_safe_bruteforce_disabled():
    # 파일 없음 + enable_safe_bruteforce=False → 빈 목록(기본 샘플 미사용)
    cfg = ScanConfig(max_auth_credentials=100, auth_credential_file="",
                     enable_safe_bruteforce=False)
    assert credential_loader.load_credentials(cfg) == []


def test_loader_sample_when_safe_bruteforce_enabled():
    cfg = ScanConfig(max_auth_credentials=100, auth_credential_file="",
                     enable_safe_bruteforce=True)
    creds = credential_loader.load_credentials(cfg)
    assert 0 < len(creds) <= 10        # 내장 샘플 최대 10개


def test_loader_zero_limit_returns_empty():
    cfg = ScanConfig(max_auth_credentials=0, enable_safe_bruteforce=True)
    assert credential_loader.load_credentials(cfg) == []


# ── CredentialProbe ──────────────────────────────────────────────────────────

def test_probe_disabled_by_default():
    assert credential_probe.PROBE.enabled_by_default is False
    assert credential_probe.PROBE.category == "credential"


@pytest.mark.asyncio
async def test_probe_noop_when_check_disabled(monkeypatch):
    called = {"posted": False}

    async def fake_post(session, url, data, timeout=8.0):
        called["posted"] = True
        return 200, "", {}

    monkeypatch.setattr(credential_probe, "_http_post", fake_post)
    cfg = ScanConfig(enable_known_credential_check=False, max_auth_credentials=10,
                     enable_safe_bruteforce=True)
    res = await credential_probe.PROBE.run(_ctx(cfg))
    assert res == []
    assert called["posted"] is False


@pytest.mark.asyncio
async def test_probe_success_creates_finding(monkeypatch, tmp_path):
    f = tmp_path / "creds.txt"
    f.write_text("admin:admin\n")

    async def fake_post(session, url, data, timeout=8.0):
        # 세션 쿠키 발급 → 성공
        return 200, "<html>Welcome to dashboard, logout here</html>", {}

    monkeypatch.setattr(credential_probe, "_http_post", fake_post)
    cfg = ScanConfig(enable_known_credential_check=True, max_auth_credentials=10,
                     max_auth_attempts_per_form=10, auth_credential_file=str(f))
    res = await credential_probe.PROBE.run(_ctx(cfg))
    vulns = [r for r in res if r.finding_type == "vulnerability"]
    assert vulns, "성공 시 finding 이 있어야 함"
    assert vulns[0].severity == "High"
    # 비밀번호 평문 미노출
    blob = " ".join(str(r.evidence) + r.reproduction + str(r.raw) for r in res)
    assert "admin" in blob          # username 은 노출될 수 있음
    # password 값이 평문으로 들어가지 않아야 함(마스킹: 'ad***' 형태)
    assert "password=admin" not in blob.replace("'", "")


@pytest.mark.asyncio
async def test_probe_failure_creates_good_or_noise(monkeypatch, tmp_path):
    f = tmp_path / "creds.txt"
    f.write_text("admin:admin\nroot:root\n")

    async def fake_post(session, url, data, timeout=8.0):
        return 200, "<html>Invalid username or password. Login failed.</html>", {}

    monkeypatch.setattr(credential_probe, "_http_post", fake_post)
    cfg = ScanConfig(enable_known_credential_check=True, max_auth_credentials=10,
                     max_auth_attempts_per_form=10, auth_credential_file=str(f))
    res = await credential_probe.PROBE.run(_ctx(cfg))
    assert all(r.finding_type != "vulnerability" for r in res)
    assert any(r.finding_type in ("good", "noise") for r in res)


@pytest.mark.asyncio
async def test_probe_stops_on_account_lock(monkeypatch, tmp_path):
    f = tmp_path / "creds.txt"
    f.write_text("\n".join(f"u{i}:p{i}" for i in range(20)))
    attempts = {"n": 0}

    async def fake_post(session, url, data, timeout=8.0):
        attempts["n"] += 1
        return 200, "<html>Too many attempts. Account locked out.</html>", {}

    monkeypatch.setattr(credential_probe, "_http_post", fake_post)
    cfg = ScanConfig(enable_known_credential_check=True, max_auth_credentials=20,
                     max_auth_attempts_per_form=20, auth_credential_file=str(f),
                     stop_on_account_lock_hint=True)
    res = await credential_probe.PROBE.run(_ctx(cfg))
    # 첫 잠금 감지 후 즉시 중단 → 1회만 시도
    assert attempts["n"] == 1
    assert any("lock" in str(r.tags).lower() or "lock" in r.title.lower() for r in res)
