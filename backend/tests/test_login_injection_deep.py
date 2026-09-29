"""test_login_injection_deep.py — 로그인 우회/인젝션 심화 프로파일 검증.

- 인증 우회 payload 대폭 확대 + 비파괴(time-based/stacked/DML 없음)
- XSS payload 확대(여전히 alert 실증 시에만 CONFIRMED — 판정은 strict 유지)
- SQLMap technique 안전 검증(BEU만, T·S 임의 주입 차단)
- ffuf 10k 워드리스트 + env 오버라이드
- 주입지점/크롤 캡 env 게이트
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import active_probing as ap
import external_tools as et


# ── payload 확대 ─────────────────────────────────────────────────────────────
def test_auth_bypass_payloads_expanded():
    pls = ap._SQLI_AUTH_BYPASS_PAYLOADS
    assert len(pls) >= 30  # 9 → 30+ (10배 지향)
    # 모든 payload 는 (str, desc) 튜플
    assert all(isinstance(p, tuple) and len(p) == 2 for p in pls)


def test_auth_bypass_payloads_are_nondestructive():
    forbidden = ("sleep", "benchmark", "waitfor", "pg_sleep", "dbms_lock",
                 "drop ", "delete ", "update ", "insert ", "; ", "shutdown")
    for payload, _desc in ap._SQLI_AUTH_BYPASS_PAYLOADS:
        low = payload.lower()
        for bad in forbidden:
            assert bad not in low, f"파괴/지연 토큰 포함: {payload!r} ({bad})"


def test_xss_payloads_expanded():
    assert len(ap._XSS_PAYLOADS) >= 28  # 14 → 28+
    # 모든 payload 는 확증 마커를 포함(오탐 방지: alert 실증으로만 CONFIRMED)
    assert all(ap._XSS_CONFIRM_MSG in p for p in ap._XSS_PAYLOADS)


# ── SQLMap technique 안전 검증 ───────────────────────────────────────────────
def test_sqlmap_technique_beu_excludes_time_based(tmp_path):
    cmd = et._build_sqlmap_cmd(
        "sqlmap", "http://t/x?id=1", {"enum_dbs": False}, str(tmp_path),
        level=5, risk=1, technique="BEU", random_agent=False, tamper="",
    )
    joined = " ".join(cmd)
    assert "--technique=BEU" in joined
    assert "--level=5" in joined
    # time-based(T)/stacked(S) 미포함
    assert "T" not in cmd[cmd.index("--technique=BEU")].split("=")[1]


def test_sqlmap_technique_sanitized():
    # 임의 인자 주입 시도 → 허용 문자(BEUSTQ)만 남고 나머지 제거
    cmd = et._build_sqlmap_cmd(
        "sqlmap", "http://t/x?id=1", {"enum_dbs": False}, "/tmp",
        level=3, risk=1, technique="B; rm -rf /", random_agent=False, tamper="",
    )
    tech = [c for c in cmd if c.startswith("--technique=")]
    assert tech == ["--technique=B"]


def test_sqlmap_cmd_never_has_destructive_flags(tmp_path):
    cmd = et._build_sqlmap_cmd(
        "sqlmap", "http://t/x?id=1", {"enum_dbs": True}, str(tmp_path),
        level=5, risk=1, technique="BEU", random_agent=False, tamper="",
    )
    joined = " ".join(cmd)
    for bad in ("--dump", "--os-shell", "--os-pwn", "--file-read",
                "--file-write", "--sql-shell", "--passwords"):
        assert bad not in joined


# ── ffuf 10k 워드리스트 ──────────────────────────────────────────────────────
def test_ffuf_wordlist_prefers_10k():
    wl = et._wordlist_path()
    assert wl is not None
    assert wl.endswith("ffuf-10k.txt")
    with open(wl) as f:
        assert sum(1 for _ in f) >= 9000


def test_ffuf_wordlist_env_override(tmp_path, monkeypatch):
    custom = tmp_path / "my.txt"
    custom.write_text("admin\nlogin\n")
    monkeypatch.setenv("FFUF_WORDLIST", str(custom))
    assert et._wordlist_path() == str(custom)
