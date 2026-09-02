"""Streamlit UI для POST /analyze."""

from __future__ import annotations

import os

import requests
import streamlit as st

API_URL = os.getenv("CSEC_API_URL", "http://127.0.0.1:8000")

VERDICT_LABELS = {
    "vulnerable": "Уязвимость",
    "false_positive": "False positive",
    "inconclusive": "Неоднозначно",
}

VERDICT_COLORS = {
    "vulnerable": "red",
    "false_positive": "green",
    "inconclusive": "orange",
}

SAMPLE_CODE = """void run_command(char *user_input) {
    char cmd[256];
    sprintf(cmd, "ls %s", user_input);
    system(cmd);
}"""


def fetch_ready() -> dict | None:
    try:
        resp = requests.get(f"{API_URL}/health/ready", timeout=5)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        st.session_state["ready_error"] = str(exc)
        return None


st.set_page_config(page_title="Code Security Audit", layout="wide")
st.title("Multi-Agent RAG — аудит безопасности кода")

with st.sidebar:
    st.subheader("Backend")
    st.caption(f"API: `{API_URL}`")
    if st.button("Проверить /health/ready", use_container_width=True):
        st.session_state["ready"] = fetch_ready()

    ready = st.session_state.get("ready")
    if ready:
        st.write("Qdrant:", "ok" if ready.get("qdrant") else "нет")
        st.write("Ollama:", "ok" if ready.get("ollama") else "нет")
        st.write("Статус:", ready.get("status"))
    elif st.session_state.get("ready_error"):
        st.error(st.session_state["ready_error"])

    include_debug = st.checkbox("Показать hits (debug)", value=False)

    if st.button("Загрузить пример", use_container_width=True):
        st.session_state.code_input = SAMPLE_CODE

if "code_input" not in st.session_state:
    st.session_state.code_input = SAMPLE_CODE

code = st.text_area("Код для проверки", height=260, key="code_input")

if st.button("Анализировать", type="primary", use_container_width=True):
    if not code.strip():
        st.warning("Введите код.")
    else:
        with st.spinner("Анализ… (Router + Scanner/Critic + Decider + Synthesizer)"):
            try:
                resp = requests.post(
                    f"{API_URL}/analyze",
                    json={"code": code, "include_debug": include_debug},
                    timeout=300,
                )
                if resp.status_code == 503:
                    st.error(f"Backend недоступен: {resp.json().get('detail', resp.text)}")
                elif resp.status_code >= 400:
                    st.error(f"Ошибка API {resp.status_code}: {resp.text}")
                else:
                    st.session_state["result"] = resp.json()
            except requests.RequestException as exc:
                st.error(f"Не удалось связаться с API: {exc}")

result = st.session_state.get("result")
if result:
    verdict = result.get("verdict", "unknown")
    label = VERDICT_LABELS.get(verdict, verdict)
    color = VERDICT_COLORS.get(verdict, "gray")

    st.markdown(f"**Вердикт:** :{color}[{label}]")
    st.caption(f"Latency: {result.get('latency_sec')} s")

    router = result.get("router") or {}
    st.markdown(
        f"**Router:** `{router.get('primary_cwe')}` · "
        f"confidence={router.get('confidence')} · action={router.get('action')}"
    )

    report = result.get("report") or {}
    st.subheader("Отчёт")
    st.write(report.get("summary", ""))
    st.write(report.get("explanation", ""))
    if report.get("recommendation"):
        st.info(report.get("recommendation"))

    debug = result.get("debug")
    if debug:
        st.subheader("Debug")
        st.write("Synthesizer fallback:", debug.get("synthesizer_used_fallback"))
        left, right = st.columns(2)
        with left:
            st.markdown("**Scanner hits**")
            st.json(debug.get("scanner_hits", []))
        with right:
            st.markdown("**Critic hits**")
            st.json(debug.get("critic_hits", []))
