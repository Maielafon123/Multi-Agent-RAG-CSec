#тестим рутер минимально (НЕ EVAL)

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from csec.router import route

DATASET_PATH = Path("data/dataset.jsonl")
SAMPLES_PER_CWE = 3
random.seed(42)


def is_source_only(filename: str) -> bool:
    # сорс онли функции пропускаем тк без парной синк уязвимости в чанке физически нет
    name = filename.lower()
    return "source" in name and "sink" not in name


def load_bad_samples() -> dict[str, list[dict]]:
    #Берём только kind=bad это то что Router реально должен распознавать как конкретную уязвимость
    by_cwe = defaultdict(list)
    skipped = 0
    with open(DATASET_PATH, encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            if row["kind"] != "bad":
                continue
            if is_source_only(row["filename"]):
                skipped += 1
                continue
            by_cwe[row["cwe"]].append(row)
    if skipped:
        print(f"(пропущено {skipped} source-only функция не подходят для проверки классификации)")
    return by_cwe


def main() -> None:
    by_cwe = load_bad_samples()
    correct = 0
    total = 0

    for cwe, rows in sorted(by_cwe.items()):
        sample = random.sample(rows, min(SAMPLES_PER_CWE, len(rows)))
        expected = f"CWE-{cwe.replace('CWE', '')}"
        print(f"\n{'=' * 60}\n{cwe} → ожидаем {expected}\n{'=' * 60}")

        for row in sample:
            result = route(row["code"])
            got = result.primary_cwe
            match = "ok" if got == expected else "not ok"

            print(f"{match} {row['filename']}")
            print(f"   expected={expected} got={got} conf={result.confidence:.2f} action={result.action}")
            if result.secondary_cwe:
                print(f"   secondary={result.secondary_cwe}")
            print(f"   reasoning: {result.reasoning}")

            total += 1
            if got == expected:
                correct += 1

    print(f"\n{'=' * 60}")
    print(f"Итого: {correct}/{total} совпадений ({correct / total * 100:.1f}%)")


if __name__ == "__main__":
    main()