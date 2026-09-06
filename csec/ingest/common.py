"""Общие хелперы ingest: dataset.jsonl → чанки → Qdrant."""

from __future__ import annotations

import json
import re
from typing import Any, Literal
from uuid import uuid4

from qdrant_client import QdrantClient
from qdrant_client.http import models
from tqdm import tqdm

from csec.config import DATASET_PATH, MVP_CWES, MVP_MAX_SAMPLES, QDRANT_HOST, QDRANT_PORT
from csec.embeddings import embed_documents

# bad — уязвимый код (exploits); good — безопасный (false_positives). Хотя дату ты парсила
CodeKind = Literal["bad", "good"]
_CWE_RE = re.compile(r"CWE-?(\d+)", re.IGNORECASE)


def get_client() -> QdrantClient:
    """Клиент к локальному Qdrant."""
    return QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT) #Все в конфиге лежит


def normalize_cwe(value: str | None) -> str | None:
    """
    Привести метку CWE к виду ``CWE78``.

    Принимает варианты от Router/датасета: ``CWE-78``, ``CWE78``, ``78``.
    ``unknown`` / пустое значение → ``None`` (без фильтра). Лучше проверить)))) ибо я мог плохо сделать
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() == "unknown":
        return None
    match = _CWE_RE.search(text)
    if not match:
        return text
    return f"CWE{match.group(1)}"


def load_dataset_rows(kind: CodeKind) -> list[dict[str, Any]]:
    """
    Прочитать строки из ``data/dataset.jsonl`` нужного kind.

    Учитывает опциональные фильтры ``MVP_CWES`` и ``MVP_MAX_SAMPLES`` из config.
    """
    if not DATASET_PATH.exists():
        raise SystemExit(f"Dataset not found: {DATASET_PATH}")

    rows: list[dict[str, Any]] = []
    with DATASET_PATH.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if item.get("kind") != kind:
                continue

            cwe = normalize_cwe(item.get("cwe"))
            if cwe is None:
                continue
            if MVP_CWES:
                allowed = {normalize_cwe(x) for x in MVP_CWES}
                if cwe not in allowed:
                    continue

            code = (item.get("code") or "").strip()
            if not code:
                continue

            rows.append(
                {
                    "code": code,
                    "cwe": cwe,
                    "filename": item.get("filename", ""),
                    "function_name": item.get("function_name", ""),
                    "label": item.get("label", ""),
                    "source": "dataset.jsonl",
                    "kind": kind,
                }
            )
            if MVP_MAX_SAMPLES is not None and len(rows) >= MVP_MAX_SAMPLES:
                break

    return rows


def chunk_rows(rows: list[dict[str, Any]], splitter) -> list[dict[str, Any]]:
    """
    Разрезать код на чанки выбранным сплиттером.

    Метаданные строки (cwe, filename, label, …) копируются в каждый чанк.
    """
    chunks: list[dict[str, Any]] = []
    for row in rows:
        pieces = splitter.split_text(row["code"])
        for idx, piece in enumerate(pieces):
            chunks.append(
                {
                    "code": piece,
                    "cwe": row["cwe"],
                    "filename": row["filename"],
                    "function_name": row.get("function_name", ""),
                    "label": row.get("label", ""),
                    "source": row["source"],
                    "kind": row["kind"],
                    "chunk_index": idx,
                }
            )
    return chunks


def upsert_chunks(
    collection_name: str,
    chunks: list[dict[str, Any]],
    batch_size: int = 64,
) -> None:
    """
    Посчитать эмбеддинги чанков и записать их в коллекцию Qdrant.

    Каждая точка: vector + payload (code, cwe, filename, function_name, label, …).
    """
    if not chunks:
        raise SystemExit(f"No chunks to upsert into {collection_name}")

    client = get_client()
    texts = [c["code"] for c in chunks]

    print(f"Embedding {len(texts)} chunks for `{collection_name}`...")
    vectors = embed_documents(texts)

    print(f"Upserting into `{collection_name}`...")
    for start in tqdm(range(0, len(chunks), batch_size), desc="upsert"):
        batch_chunks = chunks[start : start + batch_size]
        batch_vectors = vectors[start : start + batch_size]
        points = [
            models.PointStruct(
                id=str(uuid4()),
                vector=vector,
                payload={
                    "code": chunk["code"],
                    "cwe": chunk["cwe"],
                    "filename": chunk["filename"],
                    "function_name": chunk["function_name"],
                    "label": chunk["label"],
                    "source": chunk["source"],
                    "kind": chunk["kind"],
                    "chunk_index": chunk["chunk_index"],
                },
            )
            for chunk, vector in zip(batch_chunks, batch_vectors)
        ]
        client.upsert(collection_name=collection_name, points=points)

    info = client.get_collection(collection_name)
    print(f"[ok] {collection_name}: {info.points_count} points")
