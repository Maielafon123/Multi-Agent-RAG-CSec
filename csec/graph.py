"""Полный граф: Router -> Scanner, Critic -> Decider -> Synthesizer

State-объект накапливает данные по мере прохождения графа. Fallback от
Router (no_match / low_confidence -> cwe_filter=None) не требует отдельной
ветки графа тк Scanner получает cwe=None и ищет без фильтра по всей базе,
дальше граф идёт по тому же единственному пути. Decider и Synthesizer
одинаково корректно работают и с фильтром, и без него.
"""

from __future__ import annotations

from typing import Any, Optional, TypedDict

from langgraph.graph import END, START, StateGraph

from csec.decider import decide_from_hits
from csec.router import route
from csec.search import search_exploits, search_false_positives
from csec.synthesizer import synthesize


class GraphState(TypedDict, total=False):
    user_code: str
    router_result: dict
    cwe_filter: Optional[str]
    exploit_hits: list[Any]
    fp_hits: list[Any]
    verdict: str
    synthesizer_result: dict
    report_text: str


#каждый узел графа просто вызывает уже готовую функцию и кладёт результат в нужные поля state 
def router_node(state: GraphState) -> dict:
    result = route(state["user_code"])
    return {
        "router_result": result.to_log_dict(),
        "cwe_filter": result.cwe_filter,  #none если no_match или low_confidence
    }


def scanner_node(state: GraphState) -> dict:
    hits = search_exploits(state["user_code"], cwe=state.get("cwe_filter"), limit=3)
    return {"exploit_hits": hits}


def critic_node(state: GraphState) -> dict:
    hits = search_false_positives(state["user_code"], limit=3)
    return {"fp_hits": hits}


def decider_node(state: GraphState) -> dict:
    verdict = decide_from_hits(state.get("exploit_hits", []), state.get("fp_hits", []))
    return {"verdict": verdict}


def synthesizer_node(state: GraphState) -> dict:
    result = synthesize(
        user_code=state["user_code"],
        verdict=state["verdict"],
        exploit_hits=state.get("exploit_hits", []),
        fp_hits=state.get("fp_hits", []),
    )
    return {
        "synthesizer_result": result.to_log_dict(),
        "report_text": result.to_report_text(),
    }


#сборка графа

def build_graph():
    graph = StateGraph(GraphState)

    graph.add_node("router", router_node)
    graph.add_node("scanner", scanner_node)
    graph.add_node("critic", critic_node)
    graph.add_node("decider", decider_node)
    graph.add_node("synthesizer", synthesizer_node)

    graph.add_edge(START, "router")

    #router разветвляется на два параллельных узла
    graph.add_edge("router", "scanner")
    graph.add_edge("router", "critic")

    #decider ждёт оба узла (scanner и critic)прежде чем выполниться (встроенное поведение тип)
    graph.add_edge("scanner", "decider")
    graph.add_edge("critic", "decider")

    graph.add_edge("decider", "synthesizer")
    graph.add_edge("synthesizer", END)

    return graph.compile()


def analyze_code(user_code: str) -> GraphState:
    #точка входа для внешнего кода
    app = build_graph()
    final_state = app.invoke({"user_code": user_code})
    return final_state


if __name__ == "__main__":
    print("lol")