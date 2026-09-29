"""지식베이스 확장(cwe_mapping_ext) + 임베딩 CWE-exact 우선 결합 회귀."""
import security_rag as sr


def setup_function():
    sr.reset_cache()


def test_ext_entries_loaded():
    entries = sr._get_cache()["entries"]
    cwes = {e.get("cwe") for e in entries}
    # 신규 확장 클래스가 로드됐는지(대표 몇 개)
    for c in ("CWE-352", "CWE-78", "CWE-1336", "CWE-611", "CWE-502",
              "CWE-601", "CWE-347", "CWE-862", "CWE-693", "CWE-943"):
        assert c in cwes, f"{c} 누락"
    assert len(entries) >= 50


def test_keyword_cwe_exact_match():
    for title, cwe in [("사이트 간 요청 위조", "CWE-352"), ("운영체제 명령 주입", "CWE-78"),
                       ("안전하지 않은 역직렬화", "CWE-502"), ("미인증 쓰기 접근통제", "CWE-862")]:
        mk = sr.retrieve_knowledge({"title": title, "cwe": cwe, "owasp": ""}, [], []).get("matched_knowledge", [])
        assert mk and mk[0]["cwe"] == cwe, f"{cwe} 매칭 실패"


def test_semantic_prioritizes_cwe_exact(monkeypatch):
    # 임베딩 랭킹이 엉뚱해도 finding 의 CWE 정확매칭 엔트리가 최상단에 와야 함.
    import asyncio
    import security_embed as se

    # 가짜 임베딩: 모든 쿼리/엔트리를 동일 벡터로 → 랭킹이 무의미(최악) 상황 모사
    async def fake_embed(text, timeout=15.0):
        return [1.0, 0.0, 0.0]

    monkeypatch.setattr(se, "embed_enabled", lambda: True)
    monkeypatch.setattr(se, "embed_text", fake_embed)
    sr._ENTRY_VEC_CACHE.clear()

    f = {"title": "임의 취약점", "cwe": "CWE-352", "owasp": ""}
    mk = asyncio.run(
        sr.retrieve_knowledge_semantic(f, [], [])).get("matched_knowledge", [])
    assert mk and mk[0]["cwe"] == "CWE-352"   # 랭킹이 무의미해도 CWE-exact 가 최상단


def test_ext_entries_have_remediation():
    entries = {e.get("cwe"): e for e in sr._get_cache()["entries"]}
    for c in ("CWE-352", "CWE-78", "CWE-502"):
        assert entries[c].get("remediation"), f"{c} remediation 없음"
