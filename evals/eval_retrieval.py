"""
Оценка retrieval-слоя: recall@k, top-1 cosine, грубый decision proxy.

Результаты пишутся в evals/results.jsonl.
Опционально логируются в MLflow, если пакет установлен и tracking доступен.
Faithfulness появится после Синтезатора — в схеме метрик уже зарезервировано поле.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from csec.config import (  # noqa: E402
    DATASET_PATH,
    EMBEDDING_MODEL,
    EXPLOIT_SPLITTER,
    FP_SPLITTER,
    MVP_MAX_SAMPLES,
)
from csec.decider import (  # noqa: E402
    EXPLOIT_SCORE_THRESHOLD,
    FP_SCORE_THRESHOLD,
    decide_from_hits,
)
from csec.ingest.common import normalize_cwe  # noqa: E402
from csec.search import search_exploits, search_false_positives  # noqa: E402

CASES_PATH = Path(__file__).resolve().parent / "cases.jsonl"
RESULTS_PATH = Path(__file__).resolve().parent / "results.jsonl"


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def load_cases(path: Path = CASES_PATH) -> list[dict]:
    if not path.exists():
        raise SystemExit(f"Нет eval-набора: {path}. Сначала: python evals/build_cases.py")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def hit_matches_cwe(hit, expected_cwe: str) -> bool:
    payload = hit.payload or {}
    return normalize_cwe(payload.get("cwe")) == normalize_cwe(expected_cwe)


def evaluate(cases: list[dict], k: int = 3, use_cwe_filter: bool = True) -> dict:
    scanner_hits = 0
    scanner_total = 0
    critic_hits = 0
    critic_total = 0
    decision_correct = 0
    scanner_top1_scores: list[float] = []
    critic_top1_scores: list[float] = []
    details: list[dict] = []

    for case in cases:
        code = case["code"]
        expected_cwe = case["expected_cwe"]
        expected_decision = case["expected_decision"]

        cwe_arg = expected_cwe if use_cwe_filter else None
        # Для vulnerable-кейсов фильтр по expected CWE имитирует идеальный Router.
        # Для FP тоже можно фильтровать Scanner, но Critic всегда без фильтра.
        exploit_hits = search_exploits(code, cwe=cwe_arg, limit=k)
        fp_hits = search_false_positives(code, limit=k)

        if expected_decision == "vulnerable":
            scanner_total += 1
            ok = any(hit_matches_cwe(h, expected_cwe) for h in exploit_hits)
            scanner_hits += int(ok)
            if exploit_hits:
                scanner_top1_scores.append(float(exploit_hits[0].score))
        elif expected_decision == "false_positive":
            critic_total += 1
            ok = any(hit_matches_cwe(h, expected_cwe) for h in fp_hits)
            critic_hits += int(ok)
            if fp_hits:
                critic_top1_scores.append(float(fp_hits[0].score))

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
                "scanner_cwe_hit": any(hit_matches_cwe(h, expected_cwe) for h in exploit_hits),
                "critic_cwe_hit": any(hit_matches_cwe(h, expected_cwe) for h in fp_hits),
            }
        )

    metrics = {
        "n_cases": len(cases),
        "k": k,
        "scanner_recall_at_k": (scanner_hits / scanner_total) if scanner_total else None,
        "critic_recall_at_k": (critic_hits / critic_total) if critic_total else None,
        "decision_accuracy": decision_correct / len(cases) if cases else None,
        "scanner_mean_top1_cosine": (
            sum(scanner_top1_scores) / len(scanner_top1_scores) if scanner_top1_scores else None
        ),
        "critic_mean_top1_cosine": (
            sum(critic_top1_scores) / len(critic_top1_scores) if critic_top1_scores else None
        ),
        # Зарезервировано под Синтезатор / RAGAS.
        "faithfulness": None,
        "router_accuracy": None,
    }
    return {"metrics": metrics, "details": details}


def log_jsonl(record: dict, path: Path = RESULTS_PATH) -> None:
    path.parent.mkdir(exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def log_mlflow(record: dict) -> None:
    """Пишет метрики в MLflow, если пакет есть. Иначе тихо пропускает."""
    import os

    # MLflow 3.x по умолчанию блокирует file store; для локального MVP оставляем mlruns/.
    os.environ.setdefault("MLFLOW_ALLOW_FILE_STORE", "true")

    try:
        import mlflow
    except ImportError:
        print("MLflow не установлен — пропускаю tracking (pip install mlflow).")
        return

    tracking_dir = (ROOT / "mlruns").resolve().as_uri()
    mlflow.set_tracking_uri(tracking_dir)
    mlflow.set_experiment("csec-rag-mvp")
    with mlflow.start_run(run_name=record.get("run_name", "retrieval_eval")):
        params = record.get("params", {})
        metrics = record.get("metrics", {})
        for key, value in params.items():
            mlflow.log_param(key, value)
        for key, value in metrics.items():
            if value is None:
                continue
            mlflow.log_metric(key, float(value))
        mlflow.log_dict(record, "eval_record.json")
    runs_url = (
        "http://127.0.0.1:5000/#/experiments/"
        f"{mlflow.get_experiment_by_name('csec-rag-mvp').experiment_id}/runs"
    )
    print(f"MLflow run logged -> {ROOT / 'mlruns'}")
    print(f"Открыть runs (Model training, не Traces): {runs_url}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Eval retrieval metrics for dual-RAG MVP")
    parser.add_argument("--k", type=int, default=3)
    parser.add_argument("--no-cwe-filter", action="store_true", help="Scanner без CWE-фильтра")
    parser.add_argument("--no-mlflow", action="store_true")
    args = parser.parse_args()

    cases = load_cases()
    print(f"cases: {len(cases)} from {CASES_PATH}")
    result = evaluate(cases, k=args.k, use_cwe_filter=not args.no_cwe_filter)

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "run_name": "retrieval_eval",
        "params": {
            "embedding_model": EMBEDDING_MODEL,
            "dataset": str(DATASET_PATH.name),
            "exploit_chunk": f"{EXPLOIT_SPLITTER._chunk_size}/{EXPLOIT_SPLITTER._chunk_overlap}",
            "fp_chunk": f"{FP_SPLITTER._chunk_size}/{FP_SPLITTER._chunk_overlap}",
            "mvp_max_samples": MVP_MAX_SAMPLES,
            "k": args.k,
            "scanner_cwe_filter": not args.no_cwe_filter,
            "fp_score_threshold": FP_SCORE_THRESHOLD,
            "exploit_score_threshold": EXPLOIT_SCORE_THRESHOLD,
        },
        "metrics": result["metrics"],
        "details": result["details"],
    }

    log_jsonl(record)
    print(json.dumps(result["metrics"], ensure_ascii=False, indent=2))
    print(f"appended -> {RESULTS_PATH}")

    if not args.no_mlflow:
        log_mlflow(record)


if __name__ == "__main__":
    main()
