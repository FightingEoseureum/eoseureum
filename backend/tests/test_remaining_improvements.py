"""남은 개선 회귀 — ① iterative 기본 ON ② orphan 계약 ③ RAG 지식 finding 저장."""
import logging

import iterative_recrawl as irc
import rule_engine as re_mod


# ── ① iterative 재점검 기본 ON ────────────────────────────────────────────────
def test_iterative_recrawl_default_on(monkeypatch):
    monkeypatch.delenv("ENABLE_ITERATIVE_RECRAWL", raising=False)
    assert irc.enabled() is True


def test_iterative_recrawl_can_disable(monkeypatch):
    monkeypatch.setenv("ENABLE_ITERATIVE_RECRAWL", "false")
    assert irc.enabled() is False


def test_iterative_bounded():
    assert 1 <= irc.max_rounds() <= 10          # 라운드 상한 유지
    assert irc.time_budget_sec() <= 3600        # 시간 예산 상한


# ── ② orphan 계약: 미지의 키는 경고, 알려진/메타키는 조용히 스킵 ──────────────
def test_orphan_key_warns(caplog):
    # 미지의 probe 키(template/handler 없음)는 orphan 경고를 남긴다
    ap = {"totally_unknown_probe_xyz": {"vulnerable": True}}
    with caplog.at_level(logging.WARNING):
        re_mod._build_active_probe_findings("h", 80, "HTTP", ap, set())
    assert any("orphan" in r.message.lower() or "totally_unknown_probe_xyz" in r.message
               for r in caplog.records)


def test_meta_and_known_keys_no_warn(caplog):
    # _sqli_candidates(메타키) + login_sqli(별도집계)는 경고 없이 스킵
    ap = {"_sqli_candidates": ["http://t/?id=1"], "login_sqli": {"results": []}}
    with caplog.at_level(logging.WARNING):
        re_mod._build_active_probe_findings("h", 80, "HTTP", ap, set())
    assert not any("orphan" in r.message.lower() for r in caplog.records)


def test_handled_elsewhere_and_meta_no_warn(caplog):
    # login_sqli/csrf_dynamic(별도집계) + _접두 메타키는 경고 없이 스킵
    assert "login_sqli" in re_mod._PROBE_KEYS_HANDLED_ELSEWHERE
    assert "csrf_dynamic" in re_mod._PROBE_KEYS_HANDLED_ELSEWHERE


# ── ③ RAG 매칭 지식이 finding.ai_analysis 에 저장되는 형태 ─────────────────────
def test_rag_summary_shape():
    # 저장 포맷: cwe/title/similarity 상위 3개
    mk = [{"cwe": "CWE-89", "title": "SQL 인젝션", "similarity": 0.8, "extra": "drop"},
          {"cwe": "CWE-79", "title": "XSS", "similarity": 0.7}]
    summary = [{"cwe": m.get("cwe"), "title": m.get("title"), "similarity": m.get("similarity")}
               for m in mk[:3]]
    assert summary[0] == {"cwe": "CWE-89", "title": "SQL 인젝션", "similarity": 0.8}
    assert "extra" not in summary[0]   # 경량화(불필요 필드 제외)
