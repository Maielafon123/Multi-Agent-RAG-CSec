"""FastAPI-обёртка над graph.analyze_code."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from api.deps import check_ollama, check_qdrant, require_ready
from api.schemas import AnalyzeRequest, AnalyzeResponse, HealthResponse, ReadyResponse
from api.serializers import state_to_response
from graph import build_graph


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Один раз при старте — как joblib.load("model.pkl") в loan API.
    app.state.graph = build_graph()
    yield


app = FastAPI(title="Multi-Agent RAG CSec", lifespan=lifespan)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.get("/health/ready", response_model=ReadyResponse)
def health_ready() -> ReadyResponse:
    qdrant_ok = check_qdrant()
    ollama_ok = check_ollama()
    return ReadyResponse(
        status="ready" if qdrant_ok and ollama_ok else "degraded",
        qdrant=qdrant_ok,
        ollama=ollama_ok,
    )


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest, _: None = Depends(require_ready)) -> AnalyzeResponse:
    started = time.perf_counter()
    state = app.state.graph.invoke({"user_code": req.code})
    latency = time.perf_counter() - started
    return state_to_response(state, latency, include_debug=req.include_debug)
