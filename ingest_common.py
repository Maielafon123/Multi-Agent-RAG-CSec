"""Shared ingest helpers for Juliet -> Qdrant."""

from __future__ import annotations

import re
from typing import Any, Literal
from uuid import uuid4

from datasets import load_dataset
from qdrant_client import QdrantClient
from qdrant_client.http import models
from tqdm import tqdm

from config import JULIET_DATASET, MVP_CWES, MVP_MAX_SAMPLES, QDRANT_HOST, QDRANT_PORT
from embeddings import embed_documents

CodeKind = Literal["bad", "good"]
_CWE_RE = re.compile(r"CWE(\d+)", re.IGNORECASE)


def get_client() -> QdrantClient:
    return QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)


def extract_cwe(filename: str) -> str | None:
    """HF `class` is a label id, not CWE — parse CWE from the path instead."""
    match = _CWE_RE.search(filename or "")
    return match.group(1) if match else None


def load_juliet_rows(kind: CodeKind) -> list[dict[str, Any]]:
    """Load Juliet rows and keep either vulnerable (bad) or safe (good) code."""
    ds = load_dataset(JULIET_DATASET, split="train")
    rows: list[dict[str, Any]] = []

    for item in ds:
        filename = item.get("filename", "")
        cwe = extract_cwe(filename)
        if cwe is None:
            continue
        if MVP_CWES and int(cwe) not in MVP_CWES:
            continue

        code = (item.get(kind) or "").strip()
        if not code:
            continue

        rows.append(
            {
                "code": code,
                "cwe": cwe,
                "filename": filename,
                "source": "juliet",
                "kind": kind,
            }
        )
        if len(rows) >= MVP_MAX_SAMPLES:
            break

    return rows

def chunk_rows(rows: list[dict[str, Any]], splitter) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    for row in rows:
        pieces = splitter.split_text(row["code"])
        for idx, piece in enumerate(pieces):
            chunks.append(
                {
                    "code": piece,
                    "cwe": row["cwe"],
                    "filename": row["filename"],
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
