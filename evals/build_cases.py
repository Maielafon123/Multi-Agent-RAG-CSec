"""Собрать небольшой фиксированный eval-набор из dataset.jsonl."""

from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "data" / "dataset.jsonl"
OUT = Path(__file__).resolve().parent / "cases.jsonl"

random.seed(42)


def is_source_only(filename: str) -> bool:
    name = filename.lower()
    return "source" in name and "sink" not in name


def main() -> None:
    rows = [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_cwe: dict[str, dict[str, list]] = defaultdict(lambda: {"bad": [], "good": []})
    for row in rows:
        if is_source_only(row.get("filename", "")):
            continue
        by_cwe[row["cwe"]][row["kind"]].append(row)

    cases: list[dict] = []
    for cwe in sorted(by_cwe):
        expected = f"CWE-{cwe.replace('CWE', '')}"
        for row in random.sample(by_cwe[cwe]["bad"], min(2, len(by_cwe[cwe]["bad"]))):
            cases.append(
                {
                    "id": f"{cwe}_vuln_{row['filename']}",
                    "code": row["code"],
                    "expected_cwe": expected,
                    "expected_decision": "vulnerable",
                    "description": f"bad sample {cwe} / {row.get('label')}",
                    "filename": row["filename"],
                    "label": row.get("label", ""),
                }
            )
        for row in random.sample(by_cwe[cwe]["good"], min(2, len(by_cwe[cwe]["good"]))):
            cases.append(
                {
                    "id": f"{cwe}_fp_{row['filename']}",
                    "code": row["code"],
                    "expected_cwe": expected,
                    "expected_decision": "false_positive",
                    "description": f"good sample {cwe} / {row.get('label')}",
                    "filename": row["filename"],
                    "label": row.get("label", ""),
                }
            )

    OUT.parent.mkdir(exist_ok=True)
    with OUT.open("w", encoding="utf-8") as f:
        for case in cases:
            f.write(json.dumps(case, ensure_ascii=False) + "\n")

    print(f"wrote {len(cases)} cases -> {OUT}")
    print("decisions:", dict(Counter(c["expected_decision"] for c in cases)))
    print("cwes:", sorted({c["expected_cwe"] for c in cases}))


if __name__ == "__main__":
    main()
