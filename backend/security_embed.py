"""
security_embed.py — 임베딩 기반 의미 검색 RAG (온프레미스 Ollama embeddings).

- 기본 비활성(ENABLE_EMBED_RAG=false). 활성 시 키워드 매칭 대신/보완으로 의미 검색.
- 임베딩 모델은 EMBED_MODEL(기본 nomic-embed-text) — 작은 모델은 CPU 에서도 동작,
  A6000 등 GPU 에서 가속/대형화 가능.
- HTTP 호출(embed_text)은 monkeypatch 가능. 실패/비활성 시 호출부가 키워드 RAG 로 폴백.

순수 함수(cosine, rank_by_similarity)는 네트워크 없이 테스트 가능.
"""
from __future__ import annotations

import math
import os

import aiohttp

_OLLAMA_BASE = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")


def embed_enabled() -> bool:
    return os.getenv("ENABLE_EMBED_RAG", "false").strip().lower() in ("1", "true", "yes", "on")


def embed_model() -> str:
    return os.getenv("EMBED_MODEL", "nomic-embed-text")


def cosine(a: list[float], b: list[float]) -> float:
    """두 벡터의 코사인 유사도(0~1 범위 가정, 음수도 가능). 차원 불일치/빈 벡터 → 0."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def rank_by_similarity(query_vec: list[float], entry_vecs: list[tuple],
                       top_k: int = 5, threshold: float = 0.25) -> list[tuple]:
    """entry_vecs = [(id, vec), ...] 를 query 와의 코사인 유사도로 정렬해 상위 top_k 반환.
    반환: [(id, score), ...] (score >= threshold 만)."""
    scored = []
    for eid, vec in (entry_vecs or []):
        s = cosine(query_vec, vec)
        if s >= threshold:
            scored.append((eid, s))
    scored.sort(key=lambda t: t[1], reverse=True)
    return scored[:top_k]


async def embed_text(text: str, timeout: float = 15.0) -> list[float] | None:
    """Ollama /api/embeddings 로 단일 텍스트 임베딩. 실패 시 None(호출부 폴백)."""
    if not text:
        return None
    url = f"{_OLLAMA_BASE.rstrip('/')}/api/embeddings"
    payload = {"model": embed_model(), "prompt": text[:4000]}
    try:
        to = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=to) as session:
            async with session.post(url, json=payload) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
                vec = data.get("embedding")
                return vec if isinstance(vec, list) and vec else None
    except Exception:
        return None
