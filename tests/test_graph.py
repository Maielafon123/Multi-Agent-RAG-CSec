"""Ручная проверка полного графа на одном примере плюс структура графа в формате Mermaid можно добавить в ридми или хз
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from csec.graph import analyze_code, build_graph


def print_graph_structure() -> None:
    app = build_graph()
    mermaid_code = app.get_graph().draw_mermaid()

    output_path = "graph_structure.md"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# Структура графа\n\n")
        f.write("```mermaid\n")
        f.write(mermaid_code)
        f.write("```\n")

    print(f"Схема сохранена в {output_path}")


def run_sample() -> None:
    sample_code = """
    void run_command(char *user_input) {
        char cmd[256];
        sprintf(cmd, "ls %s", user_input);
        system(cmd);
    }
    """

    final_state = analyze_code(sample_code)

    print("\nRouter")
    print(json.dumps(final_state["router_result"], indent=2, ensure_ascii=False))

    print("\nVerdict (Decider)")
    print(final_state["verdict"])

    print("\nSynthesizer")
    print(json.dumps(final_state["synthesizer_result"], indent=2, ensure_ascii=False))

    print("\nОтчет для пользователя\n")
    print(final_state["report_text"])


if __name__ == "__main__":
    print_graph_structure()
    run_sample()