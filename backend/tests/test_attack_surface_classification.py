"""attack_surface 분류 + confidence_score 회귀 테스트."""
import finding_normalizer as fn


def _f(**kw):
    base = {
        "host": "target.example.com", "port": 80, "service": "HTTP",
        "judgment": "취약", "severity": "MEDIUM", "confidence": None,
        "probe_confirmed": None, "tool_source": None,
        "evidence_detail": "", "evidence_url": "http://target.example.com:80/",
    }
    base.update(kw)
    return base


def test_admin_200_login_form_is_attack_surface():
    """[1] HTTP 200 + 로그인 폼 관리자 페이지 → findings 아니라 attack_surface_items."""
    f = _f(title="관리자 페이지 인터넷 노출 (HTTP 200)", severity="HIGH",
           confidence="CONFIRMED", probe_confirmed=True,
           evidence_detail="HTTP 200, 로그인=있음",
           evidence_url="http://target.example.com:80/admin")
    assert fn.classify(f) == "attack_surface"
    out = fn.normalize([f])
    assert len(out["findings"]) == 0
    assert len(out["attack_surface_items"]) == 1
    assert out["summary"]["attack_surface_count"] == 1


def test_unauth_admin_function_is_vulnerability():
    """[2] 인증 없이 관리 기능 접근 가능 근거가 있을 때만 findings 로 승격."""
    f = _f(title="관리자 페이지 (HTTP 200)", severity="HIGH",
           confidence="CONFIRMED", probe_confirmed=True,
           evidence_detail="HTTP 200, 로그인=없음 — 사용자 목록/설정 조회 가능(무인증)",
           evidence_url="http://target.example.com:80/admin")
    assert fn.classify(f) == "vulnerability"


def test_manager_401_not_counted_as_vulnerability():
    """[3] /manager/html HTTP 401 은 취약점 카운트에 미포함."""
    f = _f(title="숨겨진 경로 발견: /manager/html (HTTP 401)", tool_source="ffuf",
           evidence_url="http://target.example.com:80/manager/html",
           evidence_detail="URL : http://target.example.com:80/manager/html\nStatus : 401")
    out = fn.normalize([f])
    assert out["summary"]["vulnerability_count"] == 0
    assert len(out["findings"]) == 0


def test_trace_real_call_confidence_ge_70():
    """[6] TRACE 실제 호출 성공 시 confidence_score >= 70."""
    f = _f(title="위험한 HTTP Method 활성화 (PUT/DELETE/TRACE)", severity="MEDIUM",
           confidence="CONFIRMED",
           evidence_detail="실제 동작 검증된 위험 메서드: TRACE — 실제 호출 시 정상 처리됨")
    assert fn.confidence_score(f) >= 70


def test_options_allow_only_low_confidence_not_promoted():
    """[7] OPTIONS Allow 만 있고 실제 호출 검증이 없으면 신뢰도 낮고 승격 근거 부족."""
    f = _f(title="위험한 HTTP Method 활성화 (PUT/DELETE/TRACE)", severity="MEDIUM",
           confidence=None,
           evidence_detail="서버 광고 메서드(Allow): GET, POST, PUT, DELETE")
    assert fn.confidence_score(f) <= 60


def test_env_file_content_exposed_is_vulnerability():
    """[9] .env 파일 내용이 실제 노출되면 findings."""
    f = _f(title="민감 파일 노출: /.env", severity="HIGH", tool_source="ffuf",
           confidence="CONFIRMED", probe_confirmed=True,
           evidence_detail="/.env 내용 노출: DB_PASSWORD=secret123 api_key=...",
           evidence_url="http://target.example.com:80/.env")
    assert fn.classify(f) == "vulnerability"


def test_login_screen_only_is_attack_surface():
    """[10] 로그인 화면만 발견되면 attack_surface."""
    f = _f(title="로그인 폼 발견", severity="LOW",
           evidence_detail="로그인 폼이 확인됨 (사용자/비밀번호 입력)",
           evidence_url="http://target.example.com:80/login")
    assert fn.classify(f) == "attack_surface"
    assert 50 <= fn.confidence_score(f, "attack_surface") <= 70


def test_swagger_is_attack_surface():
    """Swagger/OpenAPI 노출(민감정보 없음) → attack_surface."""
    f = _f(title="Swagger/OpenAPI 문서 노출", severity="MEDIUM",
           confidence="CONFIRMED", probe_confirmed=True,
           evidence_detail="swagger-ui 접근 가능, API 경로 목록 노출",
           evidence_url="http://target.example.com:80/swagger-ui/")
    assert fn.classify(f) == "attack_surface"


def test_summary_has_attack_surface_count_and_by_type():
    """summary 에 attack_surface_count 와 by_type 이 존재."""
    out = fn.normalize([
        _f(title="관리자 페이지 인터넷 노출 (HTTP 200)", confidence="CONFIRMED",
           probe_confirmed=True, evidence_detail="HTTP 200, 로그인=있음",
           evidence_url="http://target.example.com:80/admin"),
    ])
    assert "attack_surface_count" in out["summary"]
    assert out["summary"]["by_type"]["attack_surface"] == 1


def test_confidence_score_field_attached():
    """normalize 후 각 항목에 confidence_score(0~100)가 부여된다."""
    out = fn.normalize([
        _f(title="Clickjacking 취약점", severity="MEDIUM", confidence="CONFIRMED",
           probe_confirmed=True, evidence_screenshot="x.png",
           evidence_detail="iframe 실제 로드 확인"),
    ])
    f0 = out["findings"][0]
    assert "confidence_score" in f0
    assert 0 <= f0["confidence_score"] <= 100
    assert f0["confidence_score"] >= 90  # 스크린샷 실증
