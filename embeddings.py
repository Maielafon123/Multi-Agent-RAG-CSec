"""Embedding helpers with BGE query/passage prefixes."""

from __future__ import annotations

from functools import lru_cache

from sentence_transformers import SentenceTransformer

from config import EMBEDDING_MODEL


@lru_cache(maxsize=1)
def get_model() -> SentenceTransformer:
    return SentenceTransformer(EMBEDDING_MODEL)


def embed_documents(texts: list[str]) -> list[list[float]]:
    """Encode passages for upsert into Qdrant."""
    model = get_model()
    prefixed = [f"passage: {t}" for t in texts]
    vectors = model.encode(prefixed, normalize_embeddings=True, show_progress_bar=True)
    return [v.tolist() for v in vectors]


def embed_query(text: str) -> list[float]:
    """Encode a search query."""
    model = get_model()
    vector = model.encode(f"query: {text}", normalize_embeddings=True)
    return vector.tolist()
