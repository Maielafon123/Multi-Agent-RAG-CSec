"""Общие хелперы ingest: dataset.jsonl → чанки → Qdrant."""

from __future__ import annotations

import json
import hashlib
import re
from pathlib import PurePosixPath
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

from qdrant_client import QdrantClient
from qdrant_client.http import models
from tqdm import tqdm

from csec.config import (
    DATASET_PATH,
    METADATA_PATH,
    MVP_CWES,
    MVP_MAX_SAMPLES,
    QDRANT_HOST,
    QDRANT_PORT,
)
# bad — уязвимый код (exploits); good — безопасный (false_positives). Хотя дату ты парсила
CodeKind = Literal["bad", "good"]
_CWE_RE = re.compile(r"CWE-?(\d+)", re.IGNORECASE)
_JULIET_VARIANT_RE = re.compile(r"_[0-9]{2}[a-z]?$", re.IGNORECASE)


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


def normalize_code_for_id(code: str) -> str:
    """Нормализовать переносы и хвостовые пробелы для стабильного хэша кода."""
    lines = [line.rstrip() for line in code.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    return "\n".join(lines).strip()


def stable_id(prefix: str, *parts: object, length: int = 24) -> str:
    """Построить воспроизводимый идентификатор из содержимого, а не порядка загрузки."""
    raw = "\x1f".join(str(part or "") for part in parts)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:length]
    return f"{prefix}_{digest}"


def juliet_family_key(source_file: str, filename: str) -> str:
    """Получить семейство Juliet, объединяя связанные translation units и варианты."""
    source = source_file.replace("\\", "/").strip()
    stem = PurePosixPath(source or filename).stem
    return _JULIET_VARIANT_RE.sub("", stem).lower()


def _load_metadata_by_filename() -> dict[str, dict[str, Any]]:
    """Загрузить исходный путь Juliet для строк, оставшихся после очистки датасета."""
    if not METADATA_PATH.exists():
        return {}
    metadata: dict[str, dict[str, Any]] = {}
    with METADATA_PATH.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            filename = str(item.get("filename") or "")
            if filename:
                metadata[filename] = item
    return metadata


def enrich_row_identifiers(item: dict[str, Any], kind: CodeKind) -> dict[str, Any]:
    """Добавить стабильные document/function/project ID и происхождение строки."""
    code = normalize_code_for_id(str(item.get("code") or ""))
    filename = str(item.get("filename") or "")
    function_name = str(item.get("function_name") or "")
    source_dataset = str(item.get("source_dataset") or "juliet")
    source_file = str(item.get("source_file") or filename)
    family_key = juliet_family_key(source_file, filename)
    project_id = str(item.get("project_id") or stable_id("project", source_dataset, family_key))
    function_id = str(
        item.get("function_id")
        or stable_id("function", source_dataset, source_file, filename, function_name)
    )
    document_id = str(
        item.get("document_id")
        or stable_id("document", function_id, kind, code)
    )
    return {
        "document_id": document_id,
        "function_id": function_id,
        "project_id": project_id,
        "source_dataset": source_dataset,
        "source_file": source_file,
        "split": str(item.get("split") or "corpus"),
    }


def load_dataset_rows(kind: CodeKind) -> list[dict[str, Any]]:
    """
    Прочитать строки из ``data/dataset.jsonl`` нужного kind.

    Учитывает опциональные фильтры ``MVP_CWES`` и ``MVP_MAX_SAMPLES`` из config.
    """
    if not DATASET_PATH.exists():
        raise SystemExit(f"Dataset not found: {DATASET_PATH}")

    rows: list[dict[str, Any]] = []
    metadata_by_filename = _load_metadata_by_filename()
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

            code = normalize_code_for_id(item.get("code") or "")
            if not code:
                continue

            filename = str(item.get("filename") or "")
            metadata = metadata_by_filename.get(filename, {})
            enriched_item = {**metadata, **item, "code": code}
            identifiers = enrich_row_identifiers(enriched_item, kind)

            rows.append(
                {
                    "code": code,
                    "cwe": cwe,
                    "filename": filename,
                    "function_name": item.get("function_name", ""),
                    "label": item.get("label", ""),
                    "source": DATASET_PATH.name,
                    "kind": kind,
                    **identifiers,
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
                    "document_id": row["document_id"],
                    "function_id": row["function_id"],
                    "project_id": row["project_id"],
                    "source_dataset": row["source_dataset"],
                    "source_file": row["source_file"],
                    "split": row["split"],
                    "chunk_id": stable_id("chunk", row["document_id"], idx, piece),
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
    # Тяжёлую ML-зависимость загружаем только при реальном ingest, а не при
    # импорте ID/metadata-хелперов и unit-тестов.
    from csec.embeddings import embed_documents

    vectors = embed_documents(texts)

    print(f"Upserting into `{collection_name}`...")
    for start in tqdm(range(0, len(chunks), batch_size), desc="upsert"):
        batch_chunks = chunks[start : start + batch_size]
        batch_vectors = vectors[start : start + batch_size]
        points = [
            models.PointStruct(
                id=str(uuid5(NAMESPACE_URL, chunk["chunk_id"])),
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
                    "chunk_id": chunk["chunk_id"],
                    "document_id": chunk["document_id"],
                    "function_id": chunk["function_id"],
                    "project_id": chunk["project_id"],
                    "source_dataset": chunk["source_dataset"],
                    "source_file": chunk["source_file"],
                    "split": chunk["split"],
                },
            )
            for chunk, vector in zip(batch_chunks, batch_vectors)
        ]
        client.upsert(collection_name=collection_name, points=points)

    info = client.get_collection(collection_name)
    print(f"[ok] {collection_name}: {info.points_count} points")
