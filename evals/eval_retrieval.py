"""Честная оценка dual-retrieval по стабильным document/function ID.

Основные метрики: Recall@1/3/5, MRR@5 и nDCG@5. Совпадение CWE остаётся
диагностикой и не считается релевантностью документа.
"""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from csec.config import DATASET_PATH, EMBEDDING_MODEL, EXPLOIT_SPLITTER, FP_SPLITTER, MVP_MAX_SAMPLES
from csec.decider import EXPLOIT_SCORE_THRESHOLD, FP_SCORE_THRESHOLD, decide_from_hits
from csec.ingest.common import normalize_cwe

CASES_PATH = Path(__file__).resolve().parent / "cases.jsonl"
RESULTS_PATH = Path(__file__).resolve().parent / "results.jsonl"
DEFAULT_CUTOFFS = (1, 3, 5)


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def load_cases(path: Path = CASES_PATH) -> list[dict]:
    if not path.exists():
        raise SystemExit(f"Нет eval-набора: {path}. Сначала: python evals/build_cases.py")
    cases = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for case in cases:
        case.setdefault("relevant_document_ids", [])
        case.setdefault("relevant_function_ids", [])
    return cases


def _payload(hit: Any) -> dict:
    return getattr(hit, "payload", None) or {}


def hit_matches_cwe(hit: Any, expected_cwe: str) -> bool:
    """Диагностическое совпадение категории, не retrieval relevance."""
    return normalize_cwe(_payload(hit).get("cwe")) == normalize_cwe(expected_cwe)


def hit_relevance_id(hit: Any, case: dict) -> str | None:
    """Вернуть ID релевантного документа/функции для hit или None."""
    payload = _payload(hit)
    document_id = payload.get("document_id")
    function_id = payload.get("function_id")
    relevant_documents = set(case.get("relevant_document_ids") or [])
    relevant_functions = set(case.get("relevant_function_ids") or [])
    if relevant_documents and document_id in relevant_documents:
        return f"document:{document_id}"
    if not relevant_documents and relevant_functions and function_id in relevant_functions:
        return f"function:{function_id}"
    return None


def relevant_target_count(case: dict) -> int:
    documents = set(case.get("relevant_document_ids") or [])
    if documents:
        return len(documents)
    return len(set(case.get("relevant_function_ids") or []))


def relevance_at_ranks(hits: Iterable[Any], case: dict, k: int) -> list[int]:
    """Бинарная релевантность top-k без повторного учёта чанков одного документа."""
    relevance: list[int] = []
    seen_relevant: set[str] = set()
    for hit in list(hits)[:k]:
        identity = hit_relevance_id(hit, case)
        if identity is not None and identity not in seen_relevant:
            relevance.append(1)
            seen_relevant.add(identity)
        else:
            relevance.append(0)
    relevance.extend([0] * (k - len(relevance)))
    return relevance


def recall_at_k(hits: Iterable[Any], case: dict, k: int) -> float | None:
    total = relevant_target_count(case)
    if total == 0:
        return None
    return sum(relevance_at_ranks(hits, case, k)) / total


def reciprocal_rank_at_k(hits: Iterable[Any], case: dict, k: int) -> float | None:
    if relevant_target_count(case) == 0:
        return None
    for rank, rel in enumerate(relevance_at_ranks(hits, case, k), start=1):
        if rel:
            return 1.0 / rank
    return 0.0


def ndcg_at_k(hits: Iterable[Any], case: dict, k: int) -> float | None:
    total = relevant_target_count(case)
    if total == 0:
        return None
    relevance = relevance_at_ranks(hits, case, k)
    dcg = sum(rel / math.log2(rank + 1) for rank, rel in enumerate(relevance, start=1))
    ideal_count = min(total, k)
    idcg = sum(1.0 / math.log2(rank + 1) for rank in range(1, ideal_count + 1))
    return dcg / idcg if idcg else 0.0


def _mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _empty_retriever_bucket(cutoffs: tuple[int, ...]) -> dict:
    return {
        "n_annotated": 0,
        "n_unannotated": 0,
        "recall": {k: [] for k in cutoffs},
        "rr": [],
        "ndcg": [],
        "top1_scores": [],
        "cwe_hits": [],
    }


def _add_retrieval_result(bucket: dict, hits: list[Any], case: dict, cutoffs: tuple[int, ...]) -> None:
    if relevant_target_count(case) == 0:
        bucket["n_unannotated"] += 1
        return
    bucket["n_annotated"] += 1
    max_k = max(cutoffs)
    for k in cutoffs:
        value = recall_at_k(hits, case, k)
        if value is not None:
            bucket["recall"][k].append(value)
    bucket["rr"].append(reciprocal_rank_at_k(hits, case, max_k) or 0.0)
    bucket["ndcg"].append(ndcg_at_k(hits, case, max_k) or 0.0)
    if hits:
        bucket["top1_scores"].append(float(hits[0].score))
    bucket["cwe_hits"].append(
        float(any(hit_matches_cwe(hit, case["expected_cwe"]) for hit in hits[:max_k]))
    )


def _bucket_metrics(prefix: str, bucket: dict, cutoffs: tuple[int, ...]) -> dict[str, float | int | None]:
    max_k = max(cutoffs)
    result: dict[str, float | int | None] = {
        f"{prefix}_n_annotated": bucket["n_annotated"],
        f"{prefix}_n_unannotated": bucket["n_unannotated"],
        f"{prefix}_mrr_at_{max_k}": _mean(bucket["rr"]),
        f"{prefix}_ndcg_at_{max_k}": _mean(bucket["ndcg"]),
        f"{prefix}_mean_top1_cosine": _mean(bucket["top1_scores"]),
        f"{prefix}_cwe_hit_rate_at_{max_k}": _mean(bucket["cwe_hits"]),
    }
    for k in cutoffs:
        result[f"{prefix}_recall_at_{k}"] = _mean(bucket["recall"][k])
    return result


def evaluate(
    cases: list[dict],
    cutoffs: tuple[int, ...] = DEFAULT_CUTOFFS,
    use_cwe_filter: bool = True,
) -> dict:
    """Оценить Scanner на vulnerable, Critic на false-positive и общий Decider."""
    cutoffs = tuple(sorted(set(cutoffs)))
    if not cutoffs or cutoffs[0] < 1:
        raise ValueError("cutoffs must contain positive integers")
    max_k = max(cutoffs)
    # Retrieval тянет SentenceTransformer; отложенный импорт оставляет чистые
    # функции метрик быстрыми и пригодными для unit-тестов без загрузки модели.
    from csec.search import search_exploits, search_false_positives

    scanner = _empty_retriever_bucket(cutoffs)
    critic = _empty_retriever_bucket(cutoffs)
    decision_correct = 0
    details: list[dict] = []

    for case in cases:
        code = case["code"]
        expected_cwe = case["expected_cwe"]
        expected_decision = case["expected_decision"]
        cwe_arg = expected_cwe if use_cwe_filter else None
        exploit_hits = search_exploits(code, cwe=cwe_arg, limit=max_k)
        fp_hits = search_false_positives(code, limit=max_k)

        if expected_decision == "vulnerable":
            _add_retrieval_result(scanner, exploit_hits, case, cutoffs)
        elif expected_decision == "false_positive":
            _add_retrieval_result(critic, fp_hits, case, cutoffs)

        predicted = decide_from_hits(exploit_hits, fp_hits)
        decision_correct += int(predicted == expected_decision)
        details.append(
            {
                "id": case["id"],
                "expected_cwe": expected_cwe,
                "expected_decision": expected_decision,
                "predicted_decision": predicted,
                "scanner_top1": float(exploit_hits[0].score) if exploit_hits else None,
                "critic_top1": float(fp_hits[0].score) if fp_hits else None,
                "scanner_relevant_ranks": relevance_at_ranks(exploit_hits, case, max_k),
                "critic_relevant_ranks": relevance_at_ranks(fp_hits, case, max_k),
                "scanner_cwe_hit": any(hit_matches_cwe(h, expected_cwe) for h in exploit_hits),
                "critic_cwe_hit": any(hit_matches_cwe(h, expected_cwe) for h in fp_hits),
            }
        )

    metrics: dict[str, float | int | None] = {
        "n_cases": len(cases),
        "decision_accuracy": decision_correct / len(cases) if cases else None,
    }
    metrics.update(_bucket_metrics("scanner", scanner, cutoffs))
    metrics.update(_bucket_metrics("critic", critic, cutoffs))
    return {"metrics": metrics, "details": details}


def log_jsonl(record: dict, path: Path = RESULTS_PATH) -> None:
    path.parent.mkdir(exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def log_mlflow(record: dict) -> None:
    """Записать плоские параметры и метрики одного режима в MLflow."""
    import os

    os.environ.setdefault("MLFLOW_ALLOW_FILE_STORE", "true")
    try:
        import mlflow
    except ImportError:
        print("MLflow не установлен - tracking пропущен.")
        return

    mlflow.set_tracking_uri((ROOT / "mlruns").resolve().as_uri())
    mlflow.set_experiment("csec-rag-mvp")
    with mlflow.start_run(run_name=record["run_name"]):
        for key, value in record["params"].items():
            mlflow.log_param(key, value)
        for key, value in record["metrics"].items():
            if isinstance(value, (int, float)) and value is not None:
                mlflow.log_metric(key, float(value))
        mlflow.log_dict(record, "eval_record.json")


def _parse_cutoffs(raw: str) -> tuple[int, ...]:
    return tuple(sorted({int(value.strip()) for value in raw.split(",") if value.strip()}))


def main() -> None:
    parser = argparse.ArgumentParser(description="Document-level retrieval eval for dual-RAG")
    parser.add_argument("--cutoffs", default="1,3,5", help="Например: 1,3,5")
    parser.add_argument(
        "--mode", choices=("both", "with_filter", "without_filter"), default="both",
        help="Считать Scanner с CWE-фильтром, без фильтра или оба режима.",
    )
    parser.add_argument("--no-mlflow", action="store_true")
    args = parser.parse_args()

    cutoffs = _parse_cutoffs(args.cutoffs)
    cases = load_cases()
    print(f"cases: {len(cases)} from {CASES_PATH}")
    modes = []
    if args.mode in {"both", "with_filter"}:
        modes.append(("with_cwe_filter", True))
    if args.mode in {"both", "without_filter"}:
        modes.append(("without_cwe_filter", False))

    for mode_name, use_filter in modes:
        result = evaluate(cases, cutoffs=cutoffs, use_cwe_filter=use_filter)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "component": "retrieval_v2",
            "git_commit": _git_commit(),
            "run_name": f"retrieval_eval_{mode_name}",
            "params": {
                "embedding_model": EMBEDDING_MODEL,
                "dataset": DATASET_PATH.name,
                "exploit_chunk": f"{EXPLOIT_SPLITTER._chunk_size}/{EXPLOIT_SPLITTER._chunk_overlap}",
                "fp_chunk": f"{FP_SPLITTER._chunk_size}/{FP_SPLITTER._chunk_overlap}",
                "mvp_max_samples": MVP_MAX_SAMPLES,
                "cutoffs": ",".join(map(str, cutoffs)),
                "scanner_cwe_filter": use_filter,
                "relevance": "document_id_or_function_id",
                "fp_score_threshold": FP_SCORE_THRESHOLD,
                "exploit_score_threshold": EXPLOIT_SCORE_THRESHOLD,
            },
            "metrics": result["metrics"],
            "details": result["details"],
        }
        log_jsonl(record)
        print(f"\n[{mode_name}]\n{json.dumps(result['metrics'], ensure_ascii=False, indent=2)}")
        if not args.no_mlflow:
            log_mlflow(record)

    print(f"\nappended -> {RESULTS_PATH}")


if __name__ == "__main__":
    main()
