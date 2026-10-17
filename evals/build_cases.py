"""Собрать фиксированный retrieval-eval из строк индексируемого датасета.

Этот набор предназначен для проверки механики метрик и baseline MVP. Он
намеренно содержит запросы из корпуса, поэтому ``check_leakage.py`` помечает
его как leaked. Честный frozen test должен состоять из независимых ручных или
внешних примеров с заполненными relevant_document_ids/function_ids.
"""

from __future__ import annotations

import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from csec.ingest.common import load_dataset_rows

OUT = Path(__file__).resolve().parent / "cases.jsonl"
RANDOM_SEED = 42


def is_source_only(filename: str) -> bool:
    """Исключить функции-источники без sink: отдельно они не содержат дефект."""
    name = filename.lower()
    return "source" in name and "sink" not in name


def _case_from_row(row: dict, expected_decision: str) -> dict:
    cwe = row["cwe"]
    suffix = "vuln" if expected_decision == "vulnerable" else "fp"
    return {
        "id": f"{cwe}_{suffix}_{row['filename']}",
        "code": row["code"],
        "expected_cwe": f"CWE-{cwe.replace('CWE', '')}",
        "expected_decision": expected_decision,
        "relevant_document_ids": [row["document_id"]],
        "relevant_function_ids": [row["function_id"]],
        "required_sink": None,
        "required_source": None,
        "split": "test",
        "source_dataset": row["source_dataset"],
        "project_id": row["project_id"],
        "filename": row["filename"],
        "label": row.get("label", ""),
        "description": f"corpus baseline {row['kind']} {cwe} / {row.get('label', '')}",
        "query_origin": "corpus_sample",
    }


def build_cases(samples_per_class: int = 2, seed: int = RANDOM_SEED) -> list[dict]:
    """Построить воспроизводимый набор по CWE и классу."""
    rng = random.Random(seed)
    rows = load_dataset_rows("bad") + load_dataset_rows("good")
    by_cwe: dict[str, dict[str, list[dict]]] = defaultdict(lambda: {"bad": [], "good": []})
    for row in rows:
        if is_source_only(row.get("filename", "")):
            continue
        by_cwe[row["cwe"]][row["kind"]].append(row)

    cases: list[dict] = []
    for cwe in sorted(by_cwe):
        bad_rows = rng.sample(by_cwe[cwe]["bad"], min(samples_per_class, len(by_cwe[cwe]["bad"])))
        good_rows = rng.sample(by_cwe[cwe]["good"], min(samples_per_class, len(by_cwe[cwe]["good"])))
        cases.extend(_case_from_row(row, "vulnerable") for row in bad_rows)
        cases.extend(_case_from_row(row, "false_positive") for row in good_rows)
    return cases


def main() -> None:
    cases = build_cases()
    OUT.parent.mkdir(exist_ok=True)
    with OUT.open("w", encoding="utf-8") as f:
        for case in cases:
            f.write(json.dumps(case, ensure_ascii=False) + "\n")

    print(f"wrote {len(cases)} cases -> {OUT}")
    print("decisions:", dict(Counter(c["expected_decision"] for c in cases)))
    print("cwes:", sorted({c["expected_cwe"] for c in cases}))
    print("warning: corpus_sample cases are expected to be reported as leakage")


if __name__ == "__main__":
    main()
