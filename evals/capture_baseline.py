"""Зафиксировать конфигурацию, данные, коллекции и последние метрики MVP."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from csec.config import (
    COLLECTION_EXPLOITS,
    COLLECTION_FALSE_POSITIVES,
    DATASET_PATH,
    EMBEDDING_MODEL,
    EXPLOIT_SPLITTER,
    FP_SPLITTER,
    VECTOR_SIZE,
)
from csec.ingest.common import get_client, load_dataset_rows

RESULTS_PATH = Path(__file__).resolve().parent / "results.jsonl"
OUT_PATH = Path(__file__).resolve().parent / "baseline_mvp_v1.json"


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _latest_results() -> dict:
    latest: dict[str, dict] = {}
    if not RESULTS_PATH.exists():
        return latest
    for line in RESULTS_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        component = str(record.get("component") or "")
        run_name = str(record.get("run_name") or "")
        key = f"{component}:{run_name}" if component and run_name else component or run_name or "unknown"
        latest[key] = record
    return {key: value.get("metrics", value.get("overall", value)) for key, value in latest.items()}


def _collection_counts() -> tuple[dict[str, int | None], str | None]:
    try:
        client = get_client()
        counts = {}
        for name in (COLLECTION_EXPLOITS, COLLECTION_FALSE_POSITIVES):
            counts[name] = client.get_collection(name).points_count
        return counts, None
    except Exception as exc:
        return {COLLECTION_EXPLOITS: None, COLLECTION_FALSE_POSITIVES: None}, str(exc)


def capture() -> dict:
    bad_rows = load_dataset_rows("bad")
    good_rows = load_dataset_rows("good")
    counts, qdrant_error = _collection_counts()
    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "git": {
            "commit": _git("rev-parse", "HEAD"),
            "short_commit": _git("rev-parse", "--short", "HEAD"),
            "branch": _git("branch", "--show-current"),
            "dirty": bool(_git("status", "--porcelain")),
        },
        "dataset": {
            "path": str(DATASET_PATH.relative_to(ROOT)),
            "sha256": _sha256(DATASET_PATH),
            "rows": len(bad_rows) + len(good_rows),
            "bad_rows": len(bad_rows),
            "good_rows": len(good_rows),
        },
        "retrieval": {
            "embedding_model": EMBEDDING_MODEL,
            "vector_size": VECTOR_SIZE,
            "distance": "cosine",
            "exploit_chunk_size": EXPLOIT_SPLITTER._chunk_size,
            "exploit_chunk_overlap": EXPLOIT_SPLITTER._chunk_overlap,
            "fp_chunk_size": FP_SPLITTER._chunk_size,
            "fp_chunk_overlap": FP_SPLITTER._chunk_overlap,
        },
        "qdrant": {"collections": counts, "error": qdrant_error},
        "latest_recorded_metrics": _latest_results(),
    }


def main() -> None:
    baseline = capture()
    OUT_PATH.write_text(json.dumps(baseline, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(baseline, ensure_ascii=False, indent=2))
    print(f"baseline -> {OUT_PATH}")


if __name__ == "__main__":
    main()
