"""오탐 수정 회귀 — 정적 에셋(SPA 빌드 JS 번들)을 특권/무인증 접근으로 오판하지 않는다.

배경: app.example.com 스캔에서 /_nuxt/pages/admin/api.<hash>.js (Nuxt 빌드 번들)가 경로에 'admin'을
포함하고 번들 안에 관리 UI 문자열이 있다는 이유로 '미인증 특권 콘텐츠 접근'·'Missing Function-Level
Auth' HIGH 오탐 2건이 발생했음. + SQLMap 미확인(MANUAL_REVIEW) 항목이 '취약' Low 로 오라벨됨.
"""
import authz_matrix as am
import false_positive_filter as fp
import finding_normalizer as fn
import active_probing as ap


# ── Fix 1a: authz_matrix.is_privileged 정적 에셋 제외 ──────────────────────────
def test_is_privileged_excludes_static_assets():
    assert am.is_privileged("http://app.example.com/_nuxt/pages/admin/api.83a4244f5a6a0e50c672.js") is False
    assert am.is_privileged("http://x/static/js/admin.chunk.js") is False
    assert am.is_privileged("http://x/assets/manage.css") is False
    assert am.is_privileged("http://x/_next/static/dashboard.js") is False
    # 진짜 관리/특권 경로는 여전히 특권
    assert am.is_privileged("http://x/admin/users") is True
    assert am.is_privileged("http://x/manage/status") is True


# ── Fix 1b: active_probing 특권 후보 정적 에셋 제외 정규식 ─────────────────────
def test_static_asset_regex_matches_build_bundles():
    assert ap._STATIC_ASSET_RE.search("/_nuxt/pages/admin/api.83a4244f5a6a0e50c672.js")
    assert ap._STATIC_ASSET_RE.search("/static/js/main.js")
    assert ap._STATIC_ASSET_RE.search("/assets/app.css")
    # 진짜 관리 경로(정적 아님)는 매칭 안 됨
    assert not ap._STATIC_ASSET_RE.search("/admin/users")
    assert not ap._STATIC_ASSET_RE.search("/manage/status")


# ── Fix 2: false_positive_filter 접근통제 finding 정적 에셋 억제 ───────────────
def test_fp_suppresses_access_control_on_static_asset():
    f = {"title": "미인증 특권 콘텐츠 접근 (CWE-306)", "type": "unauth_privileged_content",
         "url": "http://app.example.com/_nuxt/pages/admin/api.abc.js", "confidence": "CONFIRMED"}
    assert fp.assess(f)["suppress"] is True
    f2 = {"title": "인증 없이 관리/특권 기능 접근(Missing Function-Level Auth) 실증",
          "url": "http://x/_nuxt/pages/admin/api.abc.js", "confidence": "CONFIRMED"}
    assert fp.assess(f2)["suppress"] is True


def test_fp_keeps_access_control_on_real_path():
    # 진짜 관리 경로(정적 아님)에 대한 무인증 접근은 억제하지 않는다(정탐 보존)
    f = {"title": "미인증 특권 콘텐츠 접근", "type": "unauth_privileged_content",
         "url": "http://app.example.com/admin/users", "confidence": "CONFIRMED"}
    assert fp.assess(f).get("suppress") is not True


def test_fp_static_injection_still_suppressed():
    # 기존 A블록(인젝션 계열) 회귀 — 여전히 억제
    f = {"title": "SQL Injection", "family": "sqli", "url": "http://x/app.js", "confidence": "CONFIRMED"}
    assert fp.assess(f)["suppress"] is True


# ── Fix 3: SQLMap MANUAL_REVIEW → discovery(참고), 취약 승격 안 됨 ─────────────
def test_manual_review_sqli_forced_to_discovery():
    a = fn.normalize([{
        "title": "[참고] SQL 인젝션 가능성 — SQLMap 기본 검증에서 미확인",
        "cwe": "CWE-89", "severity": "Low", "confidence": "MANUAL_REVIEW",
        "probe_confirmed": False, "force_finding_type": "discovery",
        "evidence_detail": "SQLMap 검증했으나 injectable 미확인", "host": "x",
        "tool_source": "sqlmap",
    }])
    # 취약(findings)에 없어야 하고, discovery 에 참고로 있어야 함
    assert all("SQL 인젝션" not in f.get("title", "") for f in a["findings"])
    disc = [f for f in a["discovery_items"] if "SQL 인젝션" in f.get("title", "")]
    assert disc, "MANUAL_REVIEW SQLi 가 discovery 로 분류되지 않음"
    assert disc[0]["judgment"] == "참고"
