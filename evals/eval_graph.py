"""End-to-end eval полного графа router_accuracy +
resolved accuracy + латентность всего пайплайна
Метрики:
  - grounding_rate
  - faithfulness_rate
  - fallback_rate
  - resolved_accuracy
  - inconclusive_rate
  - avg_cycle_latency_sec
"""

import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

os.environ.setdefault("MLFLOW_ALLOW_FILE_STORE", "true")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from graph import analyze_code

CASES_PATH = Path("evals/cases.jsonl")
RESULTS_PATH = Path("evals/results.jsonl")


def load_cases() -> list[dict]:
    with open(CASES_PATH, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def normalize_for_compare(cwe: str | None) -> str | None:
    """CWE-78 / CWE78 / 78 -> "78" — для сравнения без привязки к формату."""
    if not cwe:
        return None
    return cwe.replace("CWE", "").replace("-", "").strip()


def _empty_bucket() -> dict:
    return {
        "n": 0, "router_correct": 0, "router_total": 0,
        "resolved_correct": 0, "resolved_total": 0, "inconclusive": 0,
        "latencies": [],
    }


def _bucket_to_metrics(bucket: dict) -> dict:
    n = bucket["n"]
    return {
        "n_cases": n,
        "router_accuracy": (
            round(bucket["router_correct"] / bucket["router_total"], 4)
            if bucket["router_total"] else None
        ),
        "router_n": bucket["router_total"],
        "resolved_accuracy": (
            round(bucket["resolved_correct"] / bucket["resolved_total"], 4)
            if bucket["resolved_total"] else None
        ),
        "resolved_n": bucket["resolved_total"],
        "inconclusive_rate": round(bucket["inconclusive"] / n, 4) if n else None,
        "avg_total_latency_sec": (
            round(sum(bucket["latencies"]) / len(bucket["latencies"]), 2)
            if bucket["latencies"] else None
        ),
    }


def main() -> None:
    cases = load_cases()

    overall = _empty_bucket()
    by_cwe: dict[str, dict] = defaultdict(_empty_bucket)

    for i, case in enumerate(cases, start=1):
        code = case["code"]
        expected_decision = case.get("expected_decision")
        expected_cwe = case.get("expected_cwe")
        cwe_key = expected_cwe or "unknown"

        print(f"[{i}/{len(cases)}] {case.get('filename', '?')}...", end=" ", flush=True)

        start = time.time()
        final_state = analyze_code(code)
        elapsed = time.time() - start

        verdict = final_state.get("verdict")
        router_cwe = final_state.get("router_result", {}).get("primary_cwe")

        print(f"verdict={verdict} router_cwe={router_cwe} ({elapsed:.1f}s)")

        for bucket in (overall, by_cwe[cwe_key]):
            bucket["n"] += 1
            bucket["latencies"].append(elapsed)

            if expected_cwe is not None:
                bucket["router_total"] += 1
                if normalize_for_compare(router_cwe) == normalize_for_compare(expected_cwe):
                    bucket["router_correct"] += 1

            if verdict == "inconclusive":
                bucket["inconclusive"] += 1
            else:
                bucket["resolved_total"] += 1
                if verdict == expected_decision:
                    bucket["resolved_correct"] += 1

    metrics = {
        "component": "graph_e2e",
        "overall": _bucket_to_metrics(overall),
        "by_cwe": {cwe: _bucket_to_metrics(b) for cwe, b in sorted(by_cwe.items())},
    }

    print("\n" + json.dumps(metrics, indent=2, ensure_ascii=False))

    with open(RESULTS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(metrics, ensure_ascii=False) + "\n")
    print(f"\nappended -> {RESULTS_PATH}")

    if metrics["overall"]["router_accuracy"] is None:
        print(
            "\nПРИМЕЧАНИЕ: router_accuracy = None — ни у одного кейса нет "
            "поля 'expected_cwe'. Проверь схему build_cases.py."
        )

    try:
        import mlflow
        mlflow.set_experiment("csec-rag-mvp")
        with mlflow.start_run(run_name="graph-e2e-eval"):
            for key, value in metrics["overall"].items():
                if isinstance(value, (int, float)):
                    mlflow.log_metric(key, value)
            for cwe, m in metrics["by_cwe"].items():
                for key, value in m.items():
                    if isinstance(value, (int, float)):
                        mlflow.log_metric(f"{cwe}_{key}", value)
            mlflow.log_param("component", "graph_e2e")
        print("MLflow run logged")
    except ImportError:
        print("mlflow не установлен ")
    except Exception as exc:
        print(f"MLflow логирование не удалось {exc}")


if __name__ == "__main__":
    main()