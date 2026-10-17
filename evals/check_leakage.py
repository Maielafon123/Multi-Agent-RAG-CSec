"""Проверить пересечения eval-запросов с индексируемым корпусом.

Проверяются четыре уровня: нормализованный exact duplicate, near duplicate по
token shingles, та же функция и то же семейство Juliet (project_id).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from csec.ingest.common import load_dataset_rows, normalize_code_for_id

CASES_PATH = Path(__file__).resolve().parent / "cases.jsonl"
REPORT_PATH = Path(__file__).resolve().parent / "leakage_report.json"
TOKEN_RE = re.compile(r"[A-Za-z_]\w*|0x[0-9A-Fa-f]+|\d+|==|!=|<=|>=|&&|\|\||[-+*/%&|^<>]=?")


def normalized_code_hash(code: str) -> str:
    """Хэш кода после унификации пробелов; комментарии намеренно сохраняются."""
    compact = " ".join(normalize_code_for_id(code).split())
    return hashlib.sha256(compact.encode("utf-8")).hexdigest()


def token_shingles(code: str, width: int = 5) -> set[tuple[str, ...]]:
    tokens = TOKEN_RE.findall(code)
    if len(tokens) < width:
        return {tuple(tokens)} if tokens else set()
    return {tuple(tokens[i : i + width]) for i in range(len(tokens) - width + 1)}


def jaccard(left: set, right: set) -> float:
    if not left and not right:
        return 1.0
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def load_cases(path: Path = CASES_PATH) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def analyze_leakage(cases: list[dict], near_threshold: float = 0.85) -> dict:
    corpus = load_dataset_rows("bad") + load_dataset_rows("good")
    corpus_prepared = []
    exact_index: dict[str, list[dict]] = {}
    function_ids: set[str] = set()
    project_ids: set[str] = set()

    for row in corpus:
        code_hash = normalized_code_hash(row["code"])
        shingles = token_shingles(row["code"])
        prepared = {"row": row, "hash": code_hash, "shingles": shingles}
        corpus_prepared.append(prepared)
        exact_index.setdefault(code_hash, []).append(row)
        function_ids.add(row["function_id"])
        project_ids.add(row["project_id"])

    details = []
    for case in cases:
        case_hash = normalized_code_hash(case["code"])
        exact_rows = exact_index.get(case_hash, [])
        case_shingles = token_shingles(case["code"])
        best_score = 0.0
        best_row = None
        if not exact_rows:
            for prepared in corpus_prepared:
                score = jaccard(case_shingles, prepared["shingles"])
                if score > best_score:
                    best_score = score
                    best_row = prepared["row"]
        else:
            best_score = 1.0
            best_row = exact_rows[0]

        relevant_functions = set(case.get("relevant_function_ids") or [])
        case_project = case.get("project_id")
        detail = {
            "id": case["id"],
            "exact_duplicate": bool(exact_rows),
            "exact_matches": [row["document_id"] for row in exact_rows[:5]],
            "near_duplicate": best_score >= near_threshold,
            "best_jaccard": round(best_score, 4),
            "best_document_id": best_row.get("document_id") if best_row else None,
            "same_function": bool(relevant_functions & function_ids),
            "same_project": bool(case_project and case_project in project_ids),
            "query_origin": case.get("query_origin", "unknown"),
        }
        details.append(detail)

    summary = {
        "n_cases": len(cases),
        "corpus_documents": len(corpus),
        "near_threshold": near_threshold,
        "exact_duplicate_cases": sum(item["exact_duplicate"] for item in details),
        "near_duplicate_cases": sum(item["near_duplicate"] for item in details),
        "same_function_cases": sum(item["same_function"] for item in details),
        "same_project_cases": sum(item["same_project"] for item in details),
        "clean_cases": sum(
            not (item["exact_duplicate"] or item["near_duplicate"] or item["same_function"])
            for item in details
        ),
    }
    return {"summary": summary, "details": details}


def main() -> None:
    parser = argparse.ArgumentParser(description="Проверка leakage между corpus и eval")
    parser.add_argument("--cases", type=Path, default=CASES_PATH)
    parser.add_argument("--output", type=Path, default=REPORT_PATH)
    parser.add_argument("--near-threshold", type=float, default=0.85)
    parser.add_argument("--fail-on-leakage", action="store_true")
    args = parser.parse_args()

    report = analyze_leakage(load_cases(args.cases), args.near_threshold)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    print(f"report -> {args.output}")
    if args.fail_on_leakage and report["summary"]["clean_cases"] != report["summary"]["n_cases"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
