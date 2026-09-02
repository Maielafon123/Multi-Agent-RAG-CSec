
from __future__ import annotations
from typing import Any
from graph import GraphState
from api.schemas import AnalyzeResponse, DebugInfo, HitInfo, Report, RouterInfo

# Сколько символов кода из hit отдаём в debug-ответе.
SNIPPET_MAX_LEN = 400


def hit_to_info(hit: Any) -> HitInfo:
    """
    Один hit из search_exploits / search_false_positives → HitInfo.

    Qdrant отдаёт объект с .score и .payload (dict с code, cwe, filename).
    """
    payload = getattr(hit, "payload", None) or {}
    code = payload.get("code") or ""
    snippet = code if len(code) <= SNIPPET_MAX_LEN else code[:SNIPPET_MAX_LEN]

    return HitInfo(
        score=float(getattr(hit, "score", 0.0)),
        cwe=payload.get("cwe"),
        filename=payload.get("filename"),
        code_snippet=snippet or None,
    )


def _report_from_state(state: GraphState) -> Report:
    synth = state.get("synthesizer_result") or {}
    return Report(
        summary=str(synth.get("summary") or ""),
        explanation=str(synth.get("explanation") or ""),
        recommendation=str(synth.get("recommendation") or ""),
    )


def _router_from_state(state: GraphState) -> RouterInfo:
    router = state.get("router_result") or {}
    confidence = router.get("confidence")
    return RouterInfo(
        primary_cwe=router.get("primary_cwe"),
        confidence=float(confidence) if confidence is not None else None,
        action=router.get("action"),
        cwe_filter=state.get("cwe_filter") or router.get("cwe_filter"),
    )


def state_to_response(
    state: GraphState,
    latency_sec: float,
    include_debug: bool = False,
) -> AnalyzeResponse:
    """
    Финальный state графа → ответ POST /analyze.

    Аналог твоего return {"Result": ..., "Probability": ...} в loan API,
    только полей больше и часть собирается из вложенных dict/state.
    """
    synth = state.get("synthesizer_result") or {}

    debug: DebugInfo | None = None
    if include_debug:
        debug = DebugInfo(
            scanner_hits=[hit_to_info(h) for h in state.get("exploit_hits") or []],
            critic_hits=[hit_to_info(h) for h in state.get("fp_hits") or []],
            synthesizer_used_fallback=bool(synth.get("used_fallback")),
        )

    return AnalyzeResponse(
        verdict=str(state.get("verdict") or "inconclusive"),
        report=_report_from_state(state),
        router=_router_from_state(state),
        latency_sec=round(float(latency_sec), 3),
        debug=debug,
    )
