"""test_embed_rag.py — 임베딩 RAG(코사인/랭킹/게이트/폴백) 검증(네트워크 없음)."""
import os, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import security_embed as se
import security_rag as sr


def test_cosine_basic():
    assert se.cosine([1, 0], [1, 0]) == pytest.approx(1.0)
    assert se.cosine([1, 0], [0, 1]) == pytest.approx(0.0)
    assert se.cosine([], [1]) == 0.0
    assert se.cosine([1, 2], [1]) == 0.0   # 차원 불일치


def test_rank_by_similarity_orders_and_threshold():
    q = [1.0, 0.0]
    vecs = [("a", [1.0, 0.0]), ("b", [0.9, 0.1]), ("c", [0.0, 1.0])]
    ranked = se.rank_by_similarity(q, vecs, top_k=3, threshold=0.25)
    ids = [r[0] for r in ranked]
    assert ids[0] == "a"          # 가장 유사
    assert "c" not in ids         # 직교 → threshold 미달 제외
    assert ranked[0][1] >= ranked[1][1]


def test_embed_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ENABLE_EMBED_RAG", raising=False)
    assert se.embed_enabled() is False
    assert se.embed_model() == "nomic-embed-text"


@pytest.mark.asyncio
async def test_semantic_falls_back_to_keyword_when_disabled(monkeypatch):
    monkeypatch.delenv("ENABLE_EMBED_RAG", raising=False)
    # 비활성 → 키워드 RAG 와 동일 결과(폴백)
    finding = {"title": "SQL Injection", "cwe": "CWE-89", "owasp": "A03"}
    out = await sr.retrieve_knowledge_semantic(finding)
    assert "matched_knowledge" in out


@pytest.mark.asyncio
async def test_semantic_falls_back_when_embed_fails(monkeypatch):
    monkeypatch.setenv("ENABLE_EMBED_RAG", "true")
    # 임베딩 호출이 None(서버 없음) → 키워드 폴백, 예외 없이 dict 반환
    async def _none(*a, **k):
        return None
    monkeypatch.setattr(se, "embed_text", _none)
    out = await sr.retrieve_knowledge_semantic({"title": "XSS", "cwe": "CWE-79"})
    assert "matched_knowledge" in out
