"""Создание коллекций Qdrant для Сканера (exploits) и Критика (false_positives)."""

from qdrant_client import QdrantClient
from qdrant_client.http import models

from csec.config import (
    COLLECTION_EXPLOITS,
    COLLECTION_FALSE_POSITIVES,
    QDRANT_HOST,
    QDRANT_PORT,
    VECTOR_SIZE,
)


def ensure_collection(client: QdrantClient, name: str) -> None:
    """
    Создать коллекцию, если её ещё нет.

    Векторы: размер VECTOR_SIZE, метрика cosine.
    Индекс по payload ``cwe`` нужен фильтру Сканера.
    """
    existing = {c.name for c in client.get_collections().collections}
    if name in existing:
        print(f"[skip] collection already exists: {name}")
        return

    client.create_collection(
        collection_name=name,
        vectors_config=models.VectorParams(
            size=VECTOR_SIZE,
            distance=models.Distance.COSINE,
        ),
    )
    # Ускоряет и стабилизирует filter по CWE при поиске Scanner.
    client.create_payload_index(
        collection_name=name,
        field_name="cwe",
        field_schema=models.PayloadSchemaType.KEYWORD,
    )
    print(f"[ok] created collection: {name}")


def main() -> None:
    """Создать обе коллекции MVP и вывести ссылку на dashboard."""
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
    ensure_collection(client, COLLECTION_EXPLOITS)
    ensure_collection(client, COLLECTION_FALSE_POSITIVES)
    print("Done. Dashboard: http://localhost:6333/dashboard")


if __name__ == "__main__":
    main()
