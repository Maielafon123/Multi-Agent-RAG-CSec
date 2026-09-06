"""Загрузка безопасных примеров (kind=good) в коллекцию false_positives — RAG Критика."""

from csec.config import COLLECTION_FALSE_POSITIVES, FP_SPLITTER
from csec.ingest.common import chunk_rows, load_dataset_rows, upsert_chunks


def main() -> None:
    """Прочитать good-строки, нарезать крупными чанками и upsert в false_positives."""
    rows = load_dataset_rows("good")
    print(f"Loaded {len(rows)} false-positive samples from {rows[0]['source'] if rows else 'dataset'}")
    chunks = chunk_rows(rows, FP_SPLITTER)
    print(f"Split into {len(chunks)} chunks (size=1024, overlap=256)")
    upsert_chunks(COLLECTION_FALSE_POSITIVES, chunks)


if __name__ == "__main__":
    main()
