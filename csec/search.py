"""Поиск Сканера/Критика и smoke-test против Qdrant."""

from __future__ import annotations

from qdrant_client.http import models

from csec.config import COLLECTION_EXPLOITS, COLLECTION_FALSE_POSITIVES
from csec.embeddings import embed_query
from csec.ingest.common import get_client, normalize_cwe

# Пример запроса под MVP CWE23 (path traversal).
SAMPLE_QUERY = """
void badSink(char * data)
{
    ifstream inputFile;
    /* POTENTIAL FLAW: Possibly opening a file without validating the file name or path */
    inputFile.open((char *)data);
    inputFile.close();
}
"""


def search_exploits(code: str, cwe: str | None = None, limit: int = 3):
    """
    Поиск Сканера по коллекции exploits.

    Parameters
    ----------
    code:
        Фрагмент кода пользователя.
    cwe:
        Опциональный CWE от Router (``CWE-23`` / ``CWE23`` / ``23``).
        Если задан — ищем только внутри этой категории.
    limit:
        Сколько ближайших чанков вернуть.

    Returns
    -------
    Список hits Qdrant: score (cosine) + payload.
    """
    client = get_client()
    query_filter = None
    cwe_norm = normalize_cwe(cwe)
    if cwe_norm:
        query_filter = models.Filter(
            must=[models.FieldCondition(key="cwe", match=models.MatchValue(value=cwe_norm))]
        )

    return client.query_points(
        collection_name=COLLECTION_EXPLOITS,
        query=embed_query(code),
        query_filter=query_filter,
        limit=limit,
        with_payload=True,
    ).points


def search_false_positives(code: str, limit: int = 3):
    """
    Поиск Критика по коллекции false_positives.

    Намеренно без фильтра CWE от Router: проверка на FP должна быть независимой.

    Returns
    -------
    Список hits Qdrant: score (cosine) + payload.
    """
    client = get_client()
    return client.query_points(
        collection_name=COLLECTION_FALSE_POSITIVES,
        query=embed_query(code),
        limit=limit,
        with_payload=True,
    ).points


def _print_hits(title: str, hits) -> None:
    """Красиво напечатать top-k результаты поиска."""
    print(f"\n=== {title} ===")
    if not hits:
        print("(no hits)")
        return
    for i, hit in enumerate(hits, 1):
        payload = hit.payload or {}
        snippet = (payload.get("code") or "").replace("\n", " ")[:120]
        print(
            f"{i}. score={hit.score:.4f} cwe={payload.get('cwe')} "
            f"label={payload.get('label')} file={payload.get('filename')}\n"
            f"   {snippet}..."
        )


def main() -> None:
    """Smoke-test: размеры коллекций + параллельный по смыслу поиск Scanner/Critic."""
    client = get_client()
    for name in (COLLECTION_EXPLOITS, COLLECTION_FALSE_POSITIVES):
        info = client.get_collection(name)
        print(f"{name}: {info.points_count} points")

    exploit_hits = search_exploits(SAMPLE_QUERY, cwe="CWE-23")
    fp_hits = search_false_positives(SAMPLE_QUERY)
    _print_hits("Scanner /exploits (filter CWE23)", exploit_hits)
    _print_hits("Critic /false_positives", fp_hits)


if __name__ == "__main__":
    main()
