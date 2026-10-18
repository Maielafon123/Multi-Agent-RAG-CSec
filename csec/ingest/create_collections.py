"""Создание коллекций Qdrant для Сканера (exploits) и Критика (false_positives)."""

import argparse

from qdrant_client import QdrantClient
from qdrant_client.http import models

from csec.config import (
    COLLECTION_EXPLOITS,
    COLLECTION_FALSE_POSITIVES,
    QDRANT_HOST,
    QDRANT_PORT,
    VECTOR_SIZE,
)


PAYLOAD_INDEXES = {
    "cwe": models.PayloadSchemaType.KEYWORD,
    "document_id": models.PayloadSchemaType.KEYWORD,
    "function_id": models.PayloadSchemaType.KEYWORD,
    "project_id": models.PayloadSchemaType.KEYWORD,
    "source_dataset": models.PayloadSchemaType.KEYWORD,
    "split": models.PayloadSchemaType.KEYWORD,
}


def ensure_collection(client: QdrantClient, name: str, recreate: bool = False) -> None:
    """
    Создать коллекцию, если её ещё нет.

    Векторы: размер VECTOR_SIZE, метрика cosine.
    Индекс по payload ``cwe`` нужен фильтру Сканера.
    """
    existing = {c.name for c in client.get_collections().collections}
    if recreate and name in existing:
        client.delete_collection(name)
        existing.remove(name)
        print(f"[deleted] collection: {name}")

    if name in existing:
        print(f"[skip] collection already exists: {name}")
    else:
        client.create_collection(
            collection_name=name,
            vectors_config=models.VectorParams(
                size=VECTOR_SIZE,
                distance=models.Distance.COSINE,
            ),
        )
        print(f"[ok] created collection: {name}")

    info = client.get_collection(name)
    existing_schema = set((info.payload_schema or {}).keys())
    for field_name, field_schema in PAYLOAD_INDEXES.items():
        if field_name in existing_schema:
            continue
        client.create_payload_index(
            collection_name=name,
            field_name=field_name,
            field_schema=field_schema,
        )
        print(f"[ok] payload index: {name}.{field_name}")


def main() -> None:
    """Создать обе коллекции MVP и вывести ссылку на dashboard."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--recreate",
        action="store_true",
        help="Удалить воспроизводимые локальные коллекции и создать их заново.",
    )
    args = parser.parse_args()
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
    ensure_collection(client, COLLECTION_EXPLOITS, recreate=args.recreate)
    ensure_collection(client, COLLECTION_FALSE_POSITIVES, recreate=args.recreate)
    print("Done. Dashboard: http://localhost:6333/dashboard")


if __name__ == "__main__":
    main()
