"""Load Juliet `good` samples into Qdrant collection `false_positives` (Critic RAG)."""

from config import COLLECTION_FALSE_POSITIVES, FP_SPLITTER
from ingest_common import chunk_rows, load_juliet_rows, upsert_chunks


def main() -> None:
    rows = load_juliet_rows("good")
    print(f"Loaded {len(rows)} false-positive samples from Juliet")
    chunks = chunk_rows(rows, FP_SPLITTER)
    print(f"Split into {len(chunks)} chunks (size=1024, overlap=256)")
    upsert_chunks(COLLECTION_FALSE_POSITIVES, chunks)


if __name__ == "__main__":
    main()
