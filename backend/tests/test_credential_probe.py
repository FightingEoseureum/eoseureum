"""tests/test_credential_probe.py — CredentialProbe 기본 비활성/무동작 검증 (네트워크 없음)."""
import pytest

from probes.base import ProbeContext
from probes import credential_probe
from probes.config import ScanConfig
from probes.utils.rate_limiter import RateLimiter


class _DummySession:
    pass


def _ctx(scan_config):
    return ProbeContext(
        target_url="http://target.example/login",
        session=_DummySession(),
        injection_points=[
            {"url": "http://target.example/login", "method": "POST",
             "source": "form", "params": {"username": "a", "password": "b"}},
        ],
        scan_config=scan_config,
        rate_limiter=RateLimiter(0),
        scan_id="test-scan",
    )


def test_disabled_by_default():
    assert credential_probe.PROBE.enabled_by_default is False
    assert credential_probe.PROBE.category == "credential"


@pytest.mark.asyncio
async def test_run_returns_empty_with_default_config():
    """기본 설정에서는 known credential 검증이 비활성 → 로그인 시도 없이 [] 반환."""
    cfg = ScanConfig()
    # 신규 정책: 기본은 enable_known_credential_check=False (자격증명 검증 미수행)
    assert cfg.enable_known_credential_check is False
    results = await credential_probe.PROBE.run(_ctx(cfg))
    assert results == []
