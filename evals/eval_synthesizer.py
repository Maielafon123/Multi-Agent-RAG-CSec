"""Eval для Synthesizer: grounding, fallback rate, resolved accuracy, latency.

Метрики (без второй LLM-судьи — дёшево и честно для MVP):
  - grounding_rate: упоминает ли объяснение реальный CWE из топ-находки
    (простая проверка на подстроку, не даёт 100% гарантии, но ловит
    явные случаи, когда модель говорит не по делу)
  - fallback_rate: доля кейсов, где LLM не вернула валидный JSON и сработал
    шаблонный fallback (важно для надёжности в графе)
  - resolved_accuracy: среди кейсов, где вердикт НЕ inconclusive, доля
    совпадений с expected_decision (аналог decision_accuracy у Decider'а,
    но именно на finalized-вердикте после Synthesizer)
  - inconclusive_rate: как часто система уходит в "не уверена" — не плохо
    само по себе, но важно знать масштаб для интерпретации accuracy
  - avg_latency_sec: средняя задержка на кейс (Ollama на CPU — не быстро)

Результат пишется в evals/results.jsonl
"""

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from decider import decide_from_hits
from search_test import search_exploits, search_false_positives
from synthesizer import synthesize

CASES_PATH = Path("evals/cases.jsonl")
RESULTS_PATH = Path("evals/results.jsonl")


def load_cases() -> list[dict]:
    with open(CASES_PATH, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def check_grounding(result, top_exploit_cwe: str | None, top_fp_cwe: str | None) -> bool:
    """Упоминает ли отчёт реальный CWE из находок (грубая, но честная проверка)."""
    text = f"{result.summary} {result.explanation}".lower()
    for cwe in (top_exploit_cwe, top_fp_cwe):
        if cwe:
            # ищем и "CWE-134", и "CWE134" — модель пишет по-разному
            bare = cwe.replace("CWE", "").replace("-", "")
            if cwe.lower() in text or f"cwe-{bare}" in text or f"cwe{bare}" in text:
                return True
    return False


def main() -> None:
    cases = load_cases()

    fallback_count = 0
    grounded_count = 0
    resolved_correct = 0
    resolved_total = 0
    inconclusive_count = 0
    latencies = []

    for i, case in enumerate(cases, start=1):
        code = case["code"]
        expected = case.get("expected_decision")
        print(f"[{i}/{len(cases)}] {case.get('filename', '?')}...", end=" ", flush=True)

        exploit_hits = search_exploits(code, limit=3)
        fp_hits = search_false_positives(code, limit=3)
        verdict = decide_from_hits(exploit_hits, fp_hits)

        top_exploit_cwe = exploit_hits[0].payload.get("cwe") if exploit_hits else None
        top_fp_cwe = fp_hits[0].payload.get("cwe") if fp_hits else None

        start = time.time()
        result = synthesize(code, verdict, exploit_hits, fp_hits)
        elapsed = time.time() - start
        latencies.append(elapsed)

        print(f"verdict={verdict} ({elapsed:.1f}s)")

        if result.used_fallback:
            fallback_count += 1

        if check_grounding(result, top_exploit_cwe, top_fp_cwe):
            grounded_count += 1

        if verdict == "inconclusive":
            inconclusive_count += 1
        else:
            resolved_total += 1
            if verdict == expected:
                resolved_correct += 1

    n = len(cases)
    metrics = {
        "component": "synthesizer",
        "n_cases": n,
        "fallback_rate": round(fallback_count / n, 4),
        "grounding_rate": round(grounded_count / n, 4),
        "inconclusive_rate": round(inconclusive_count / n, 4),
        "resolved_accuracy": round(resolved_correct / resolved_total, 4) if resolved_total else None,
        "resolved_n": resolved_total,
        "avg_latency_sec": round(sum(latencies) / len(latencies), 2) if latencies else None,
    }

    print(json.dumps(metrics, indent=2, ensure_ascii=False))

    with open(RESULTS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(metrics, ensure_ascii=False) + "\n")
    print(f"\nappended -> {RESULTS_PATH}")

    try:
        import mlflow
        mlflow.set_experiment("csec-rag-mvp")
        with mlflow.start_run(run_name="synthesizer-eval"):
            for key, value in metrics.items():
                if isinstance(value, (int, float)):
                    mlflow.log_metric(key, value)
            mlflow.log_param("component", "synthesizer")
        print("MLflow run logged")
    except ImportError:
        print("mlflow не установлен — пропускаю логирование")
    except Exception as exc:
        print(f"MLflow логирование не удалось (не критично, метрики уже в results.jsonl): {exc}")


if __name__ == "__main__":
    main()