"""Eval для Synthesizer: grounding, faithfulness, fallback rate, resolved
accuracy, latency полного цикла.

Метрики:
  - grounding_rate: упоминает ли объяснение реальный CWE из топ-находки
  - faithfulness_rate: упоминает ли объяснение конкретные детали ИЗ РЕАЛЬНОГО НАЙДЕННОГО КОДА
  - fallback_rate: доля кейсов, где LLM не вернула валидный JSON
  - resolved_accuracy: среди кейсов где вердикт НЕ inconclusive доля
    совпадений с expected_decision
  - inconclusive_rate
  - avg_cycle_latency_sec: ПОЛНЫЙ цикл

Результат пишется в evals/results.jsonl
"""

import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path
import os
os.environ.setdefault("MLFLOW_ALLOW_FILE_STORE", "true")


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from decider import decide_from_hits
from search_test import search_exploits, search_false_positives
from synthesizer import synthesize

CASES_PATH = Path("evals/cases.jsonl")
RESULTS_PATH = Path("evals/results.jsonl")

_GENERIC_TOKENS = {
    "if", "for", "while", "switch", "return", "sizeof", "printf",
    "void", "int", "char", "struct", "else", "case", "break",
    "data", "null", "true", "false", "const", "static",
}
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\s*\(")
_IDENTIFIER_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{4,})\b")


def load_cases() -> list[dict]:
    with open(CASES_PATH, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def check_grounding(result, top_exploit_cwe: str | None, top_fp_cwe: str | None) -> bool:
    text = f"{result.summary} {result.explanation}".lower()
    for cwe in (top_exploit_cwe, top_fp_cwe):
        if cwe:
            bare = cwe.replace("CWE", "").replace("-", "")
            if cwe.lower() in text or f"cwe-{bare}" in text or f"cwe{bare}" in text:
                return True
    return False


def extract_identifiers(code_snippet: str) -> set[str]:
    calls = {t.lower() for t in _CALL_RE.findall(code_snippet or "") if t.lower() not in _GENERIC_TOKENS}
    identifiers = {t.lower() for t in _IDENTIFIER_RE.findall(code_snippet or "") if t.lower() not in _GENERIC_TOKENS}
    return calls | identifiers


def check_faithfulness(result, top_exploit_snippet: str, top_fp_snippet: str) -> bool | None:
    identifiers = extract_identifiers(top_exploit_snippet) | extract_identifiers(top_fp_snippet)
    if not identifiers:
        return None
    text = f"{result.summary} {result.explanation}".lower()
    return any(ident in text for ident in identifiers)


def _empty_bucket() -> dict:
    return {
        "n": 0, "fallback": 0, "grounded": 0,
        "faithful": 0, "faithful_evaluable": 0,
        "resolved_correct": 0, "resolved_total": 0, "inconclusive": 0,
        "cycle_latencies": [], "synth_latencies": [],
    }


def _bucket_to_metrics(bucket: dict) -> dict:
    n = bucket["n"]
    return {
        "n_cases": n,
        "fallback_rate": round(bucket["fallback"] / n, 4) if n else None,
        "grounding_rate": round(bucket["grounded"] / n, 4) if n else None,
        "faithfulness_rate": (
            round(bucket["faithful"] / bucket["faithful_evaluable"], 4)
            if bucket["faithful_evaluable"] else None
        ),
        "faithfulness_n": bucket["faithful_evaluable"],
        "inconclusive_rate": round(bucket["inconclusive"] / n, 4) if n else None,
        "resolved_accuracy": (
            round(bucket["resolved_correct"] / bucket["resolved_total"], 4)
            if bucket["resolved_total"] else None
        ),
        "resolved_n": bucket["resolved_total"],
        "avg_cycle_latency_sec": (
            round(sum(bucket["cycle_latencies"]) / len(bucket["cycle_latencies"]), 2)
            if bucket["cycle_latencies"] else None
        ),
        "avg_synth_only_latency_sec": (
            round(sum(bucket["synth_latencies"]) / len(bucket["synth_latencies"]), 2)
            if bucket["synth_latencies"] else None
        ),
    }


def main() -> None:
    cases = load_cases()

    overall = _empty_bucket()
    by_cwe: dict[str, dict] = defaultdict(_empty_bucket)

    for i, case in enumerate(cases, start=1):
        code = case["code"]
        expected = case.get("expected_decision")
        cwe_key = case.get("expected_cwe", "unknown")
        print(f"[{i}/{len(cases)}] {case.get('filename', '?')}...", end=" ", flush=True)

        cycle_start = time.time()
        exploit_hits = search_exploits(code, limit=3)
        fp_hits = search_false_positives(code, limit=3)
        verdict = decide_from_hits(exploit_hits, fp_hits)

        synth_start = time.time()
        result = synthesize(code, verdict, exploit_hits, fp_hits)
        synth_elapsed = time.time() - synth_start

        cycle_elapsed = time.time() - cycle_start

        top_exploit_cwe = exploit_hits[0].payload.get("cwe") if exploit_hits else None
        top_fp_cwe = fp_hits[0].payload.get("cwe") if fp_hits else None
        top_exploit_code = exploit_hits[0].payload.get("code") if exploit_hits else ""
        top_fp_code = fp_hits[0].payload.get("code") if fp_hits else ""

        grounded = check_grounding(result, top_exploit_cwe, top_fp_cwe)
        faithful = check_faithfulness(result, top_exploit_code, top_fp_code)

        print(f"verdict={verdict} grounded={grounded} faithful={faithful} "
              f"(cycle={cycle_elapsed:.1f}s, synth_only={synth_elapsed:.1f}s)")

        for bucket in (overall, by_cwe[cwe_key]):
            bucket["n"] += 1
            bucket["cycle_latencies"].append(cycle_elapsed)
            bucket["synth_latencies"].append(synth_elapsed)
            if result.used_fallback:
                bucket["fallback"] += 1
            if grounded:
                bucket["grounded"] += 1
            if faithful is not None:
                bucket["faithful_evaluable"] += 1
                if faithful:
                    bucket["faithful"] += 1
            if verdict == "inconclusive":
                bucket["inconclusive"] += 1
            else:
                bucket["resolved_total"] += 1
                if verdict == expected:
                    bucket["resolved_correct"] += 1

    metrics = {
        "component": "synthesizer",
        "overall": _bucket_to_metrics(overall),
        "by_cwe": {cwe: _bucket_to_metrics(b) for cwe, b in sorted(by_cwe.items())},
    }

    print("\n" + json.dumps(metrics, indent=2, ensure_ascii=False))

    with open(RESULTS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(metrics, ensure_ascii=False) + "\n")
    print(f"\nappended -> {RESULTS_PATH}")

    try:
        import mlflow
        mlflow.set_experiment("csec-rag-mvp")
        with mlflow.start_run(run_name="synthesizer-eval"):
            for key, value in metrics["overall"].items():
                if isinstance(value, (int, float)):
                    mlflow.log_metric(key, value)
            for cwe, m in metrics["by_cwe"].items():
                for key, value in m.items():
                    if isinstance(value, (int, float)):
                        mlflow.log_metric(f"{cwe}_{key}", value)
            mlflow.log_param("component", "synthesizer")
        print("MLflow run logged")
    except ImportError:
        print("mlflow не установлен")
    except Exception as exc:
        print(f"MLflow логирование не удалось {exc}")


if __name__ == "__main__":
    main()