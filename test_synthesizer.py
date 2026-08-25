"""тест на трезвость Синтезатора: прогоняет кейсы из evals/cases.jsonl
через полный путь Scanner Critic Decider Synthesizer и печатает отчёты.

Это НЕ eval 
"""

import json
from pathlib import Path

from decider import decide_from_hits
from search_test import search_exploits, search_false_positives
from synthesizer import synthesize

CASES_PATH = Path("evals/cases.jsonl")
SAMPLE_SIZE = 20  # сколько кейсов каждого типа брать (vulnerable / false_positive)


def load_cases() -> list[dict]:
    cases = []
    with open(CASES_PATH, encoding="utf-8") as f:
        for line in f:
            cases.append(json.loads(line))
    return cases


def main() -> None:
    cases = load_cases()

    # берём по несколько кейсов каждого ожидаемого типа, для разнообразия
    vulnerable_cases = [c for c in cases if c.get("expected_decision") == "vulnerable"][:SAMPLE_SIZE]
    fp_cases = [c for c in cases if c.get("expected_decision") == "false_positive"][:SAMPLE_SIZE]
    sample = vulnerable_cases + fp_cases

    verdict_counts = {"vulnerable": 0, "false_positive": 0, "inconclusive": 0}

    for case in sample:
        code = case["code"]
        print(f"\n{'=' * 70}")
        print(f"file={case.get('filename')} expected={case.get('expected_decision')}")
        print("=" * 70)

        exploit_hits = search_exploits(code, limit=3)
        fp_hits = search_false_positives(code, limit=3)
        verdict = decide_from_hits(exploit_hits, fp_hits)
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

        result = synthesize(code, verdict, exploit_hits, fp_hits)

        print(f"verdict={verdict} (fallback={result.used_fallback})")
        print(result.to_report_text())

    print(f"\n{'=' * 70}")
    print("Распределение вердиктов на выборке:", verdict_counts)
    if verdict_counts.get("inconclusive", 0) == 0:
        print(
            "\nПРИМЕЧАНИЕ: ни одного inconclusive не попалось в этой выборке — "
            "конфликтная ветка (самая важная часть промпта) сейчас НЕ проверена. "
            "Стоит либо взять больше кейсов, либо руками сконструировать пример "
            "с близкими score exploit/false_positive для отдельной проверки."
        )


if __name__ == "__main__":
    main()