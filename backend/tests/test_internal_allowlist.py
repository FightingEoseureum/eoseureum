"""내부 대상 allowlist(SCAN_INTERNAL_ALLOW) — 인가한 내부 테스트 대상만 예외 허용 회귀."""
import proof_policy as pp


def test_internal_blocked_by_default(monkeypatch):
    monkeypatch.delenv("SCAN_INTERNAL_ALLOW", raising=False)
    assert pp.targets_internal("http://127.0.0.1:3000") is True
    assert pp.targets_internal("http://10.20.100.24:8080") is True


def test_allowlisted_internal_permitted(monkeypatch):
    monkeypatch.setenv("SCAN_INTERNAL_ALLOW", "127.0.0.1,10.20.100.24")
    assert pp.targets_internal("http://127.0.0.1:3000") is False
    assert pp.targets_internal("http://10.20.100.24:8080") is False


def test_non_allowlisted_internal_still_blocked(monkeypatch):
    monkeypatch.setenv("SCAN_INTERNAL_ALLOW", "127.0.0.1")
    assert pp.targets_internal("http://192.168.1.5") is True   # 목록에 없음 → 차단 유지


def test_cloud_metadata_never_allowlisted(monkeypatch):
    # 메타데이터는 allowlist 로도 예외 불가(SSRF 크리티컬)
    monkeypatch.setenv("SCAN_INTERNAL_ALLOW", "169.254.169.254,metadata")
    assert pp.targets_internal("http://169.254.169.254/") is True
    assert pp.targets_internal("http://metadata/") is True


def test_public_target_unaffected(monkeypatch):
    monkeypatch.delenv("SCAN_INTERNAL_ALLOW", raising=False)
    assert pp.targets_internal("http://demo.testfire.net") is False
