"""Сравнение latency retrieval-слоя: CPU vs GPU (BGE embeddings + Qdrant).

Не трогает Ollama — Router/Synthesizer здесь не замеряются.
Запуск из корня проекта:
    python evals/benchmark_device.py
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from qdrant_client import QdrantClient
from qdrant_client.http import models
from sentence_transformers import SentenceTransformer

from csec.config import (
    COLLECTION_EXPLOITS,
    COLLECTION_FALSE_POSITIVES,
    EMBEDDING_MODEL,
    QDRANT_HOST,
    QDRANT_PORT,
)
from csec.ingest.common import normalize_cwe

CASES_PATH = Path(__file__).resolve().parent / "cases.jsonl"
WARMUP = 2
RUNS = 8


def load_sample_code(n: int = 3) -> list[str]:
    cases = [json.loads(line) for line in CASES_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [c["code"] for c in cases[:n]]


def bench_embed(model: SentenceTransformer, samples: list[str]) -> list[float]:
    times: list[float] = []
    for _ in range(WARMUP):
        for code in samples:
            model.encode(f"query: {code}", normalize_embeddings=True)

    for _ in range(RUNS):
        for code in samples:
            t0 = time.perf_counter()
            model.encode(f"query: {code}", normalize_embeddings=True)
            times.append(time.perf_counter() - t0)
    return times


def bench_retrieval(model: SentenceTransformer, client: QdrantClient, samples: list[str]) -> list[float]:
    times: list[float] = []
    for _ in range(WARMUP):
        for code in samples:
            _search_pair(model, client, code, "CWE78")

    for _ in range(RUNS):
        for code in samples:
            t0 = time.perf_counter()
            _search_pair(model, client, code, "CWE78")
            times.append(time.perf_counter() - t0)
    return times


def _search_pair(model: SentenceTransformer, client: QdrantClient, code: str, cwe: str) -> None:
    vector = model.encode(f"query: {code}", normalize_embeddings=True).tolist()
    cwe_norm = normalize_cwe(cwe)
    flt = None
    if cwe_norm:
        flt = models.Filter(must=[models.FieldCondition(key="cwe", match=models.MatchValue(value=cwe_norm))])
    client.query_points(collection_name=COLLECTION_EXPLOITS, query=vector, query_filter=flt, limit=3)
    client.query_points(collection_name=COLLECTION_FALSE_POSITIVES, query=vector, limit=3)


def summarize(label: str, times: list[float]) -> dict:
    return {
        "label": label,
        "n": len(times),
        "mean_ms": round(statistics.mean(times) * 1000, 2),
        "p50_ms": round(statistics.median(times) * 1000, 2),
        "min_ms": round(min(times) * 1000, 2),
        "max_ms": round(max(times) * 1000, 2),
    }


def main() -> None:
    import torch

    samples = load_sample_code()
    print(f"samples: {len(samples)}, warmup={WARMUP}, runs={RUNS} per sample")
    print(f"gpu: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'n/a'}")
    print(f"torch: {torch.__version__}\n")

    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)

    results: list[dict] = []
    for device in ("cpu", "cuda"):
        if device == "cuda" and not torch.cuda.is_available():
            continue
        print(f"=== {device.upper()} ===")
        model = SentenceTransformer(EMBEDDING_MODEL, device=device)

        embed_times = bench_embed(model, samples)
        retr_times = bench_retrieval(model, client, samples)

        embed_stat = summarize(f"{device} embed_query", embed_times)
        retr_stat = summarize(f"{device} scanner+critic", retr_times)
        results.extend([embed_stat, retr_stat])

        print(f"  embed_query:      mean {embed_stat['mean_ms']} ms  p50 {embed_stat['p50_ms']} ms")
        print(f"  scanner+critic:   mean {retr_stat['mean_ms']} ms  p50 {retr_stat['p50_ms']} ms")
        print()

        del model
        if device == "cuda":
            torch.cuda.empty_cache()

    if len(results) >= 4:
        cpu_embed = results[0]["mean_ms"]
        gpu_embed = results[2]["mean_ms"]
        cpu_retr = results[1]["mean_ms"]
        gpu_retr = results[3]["mean_ms"]
        print("=== CPU vs GPU (mean) ===")
        print(f"  embed_query:    {cpu_embed} ms -> {gpu_embed} ms  ({cpu_embed / gpu_embed:.2f}x)")
        print(f"  scanner+critic: {cpu_retr} ms -> {gpu_retr} ms  ({cpu_retr / gpu_retr:.2f}x)")
        print()
        print("Примечание: Router + Synthesizer (Ollama qwen2.5-coder:7b) здесь не замерялись.")
        print("На CPU они дают ~50-100 s/запрос и обычно доминируют над retrieval.")


if __name__ == "__main__":
    main()
