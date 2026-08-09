"""Smoke-test Scanner and Critic search against Qdrant."""

from __future__ import annotations

from qdrant_client.http import models

from config import COLLECTION_EXPLOITS, COLLECTION_FALSE_POSITIVES
from embeddings import embed_query
from ingest_common import get_client

SAMPLE_QUERY = """
char *data;
data = (char *)malloc(10*sizeof(char));
strcpy(data, argv[1]);
"""


def search_exploits(code: str, cwe: str | None = None, limit: int = 3):
    """Scanner search: optionally filter by CWE from Router."""
    client = get_client()
    query_filter = None
    if cwe:
        query_filter = models.Filter(
            must=[models.FieldCondition(key="cwe", match=models.MatchValue(value=str(cwe)))]
        )

    return client.query_points(
        collection_name=COLLECTION_EXPLOITS,
        query=embed_query(code),
        query_filter=query_filter,
        limit=limit,
        with_payload=True,
    ).points


def search_false_positives(code: str, limit: int = 3):
    """Critic search: independent, no CWE filter from Router."""
    client = get_client()
    return client.query_points(
        collection_name=COLLECTION_FALSE_POSITIVES,
        query=embed_query(code),
        limit=limit,
        with_payload=True,
    ).points


def _print_hits(title: str, hits) -> None:
    print(f"\n=== {title} ===")
    if not hits:
        print("(no hits)")
        return
    for i, hit in enumerate(hits, 1):
        payload = hit.payload or {}
        snippet = (payload.get("code") or "").replace("\n", " ")[:120]
        print(
            f"{i}. score={hit.score:.4f} cwe={payload.get('cwe')} "
            f"file={payload.get('filename')}\n   {snippet}..."
        )


def main() -> None:
    client = get_client()
    for name in (COLLECTION_EXPLOITS, COLLECTION_FALSE_POSITIVES):
        info = client.get_collection(name)
        print(f"{name}: {info.points_count} points")

    exploit_hits = search_exploits(SAMPLE_QUERY)
    fp_hits = search_false_positives(SAMPLE_QUERY)
    _print_hits("Scanner /exploits", exploit_hits)
    _print_hits("Critic /false_positives", fp_hits)


if __name__ == "__main__":
    main()
