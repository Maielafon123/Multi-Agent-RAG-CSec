"""Проверки Qdrant и Ollama перед /analyze."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from fastapi import HTTPException
from qdrant_client import QdrantClient

from config import COLLECTION_EXPLOITS, QDRANT_HOST, QDRANT_PORT
from router import ROUTER_MODEL

OLLAMA_TAGS_URL = "http://127.0.0.1:11434/api/tags"
CHECK_TIMEOUT_SEC = 3


def check_qdrant() -> bool:
    """Ping Qdrant и наличие коллекции exploits."""
    try:
        client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT, timeout=CHECK_TIMEOUT_SEC)
        client.get_collection(COLLECTION_EXPLOITS)
        return True
    except Exception:
        return False


def check_ollama() -> bool:
    """Ollama доступна и содержит модель Router/Synthesizer."""
    try:
        req = urllib.request.Request(OLLAMA_TAGS_URL, method="GET")
        with urllib.request.urlopen(req, timeout=CHECK_TIMEOUT_SEC) as resp:
            data = json.loads(resp.read().decode())
        names = {m.get("name", "").split(":")[0] for m in data.get("models", [])}
        model_base = ROUTER_MODEL.split(":")[0]
        for m in data.get("models", []):
            name = m.get("name", "")
            if name == ROUTER_MODEL or name.startswith(f"{model_base}:"):
                return True
        return model_base in names
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return False


def require_ready() -> None:
    """503, если инфраструктура для пайплайна недоступна."""
    qdrant_ok = check_qdrant()
    ollama_ok = check_ollama()
    if qdrant_ok and ollama_ok:
        return
    parts = []
    if not qdrant_ok:
        parts.append("Qdrant unavailable")
    if not ollama_ok:
        parts.append(f"Ollama unavailable or model {ROUTER_MODEL} not pulled")
    raise HTTPException(status_code=503, detail="; ".join(parts))
