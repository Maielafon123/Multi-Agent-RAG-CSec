"""Синтезатор ревращает вердикт Decider'а и находки Scanner/Critic в отчёт.

Вход:
    - user_code: str — код, который анализировался
    - verdict: str — "vulnerable" | "false_positive" | "inconclusive"
      (уже посчитан через decider.decide_from_hits, Синтезатор не пересчитывает
      сам вердикт, только объясняет его пользователю)
    - exploit_hits: list — результат search_exploits() (Scanner)
    - fp_hits: list — результат search_false_positives() (Critic)

Явно обрабатывает конфликт когда Scanner нашёл эксплойт, а Critic нашёл похожий безопасный код (это случай "inconclusive" от
Decider) . Промпт НЕ пытается разрулить конфликт сам
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from langchain_ollama import ChatOllama

logger = logging.getLogger(__name__)

SYNTHESIZER_MODEL = "qwen2.5-coder:7b"

VERDICT_LABELS = {
    "vulnerable": "Уязвимость обнаружена",
    "false_positive": "Похоже на безопасный код",
    "inconclusive": "Неоднозначно — требуется проверка человеком",
}

SYNTHESIZER_SYSTEM_PROMPT = """Ты — синтезатор отчётов в системе аудита безопасности кода.

Тебе даны:
1. Код пользователя, который анализировался
2. Вердикт системы: vulnerable / false_positive / inconclusive (уже посчитан,
   ты его не пересчитываешь, только объясняешь)
3. Топ-находка Сканера (самый похожий известный эксплойт) с CWE и score схожести
4. Топ-находка Критика (самый похожий известный безопасный код) с score схожести

Твоя задача — написать короткий, понятный отчёт для человека, который прислал
код на проверку (не для разработчика системы). Объясни, ПОЧЕМУ вынесен именно
такой вердикт, опираясь на конкретные находки, а не абстрактно.

Правила по вердикту:
- vulnerable: объясни, на какой известный паттерн похож код, и что именно
  опасно на практике (какая операция, с каким риском).
- false_positive: объясни, почему код похож на уязвимый паттерн, но безопасен
  (что именно его защищает — проверка, санитизация, фиксированное значение и т.п.).
- inconclusive: это САМЫЙ ВАЖНЫЙ случай — Сканер и Критик оба нашли сильное
  сходство с противоположными примерами. НЕ выбирай сторону и не выдумывай
  уверенность, которой нет. Явно скажи, что автоматическая система не может
  однозначно классифицировать этот код, кратко опиши ОБА сходства (с чем
  похоже на опасное, с чем на безопасное) и порекомендуй ручную проверку.

ОБЯЗАТЕЛЬНО для explanation, при любом вердикте: назови КОНКРЕТНЫЙ элемент
из показанного кода — имя функции, имя переменной, или саму опасную операцию
(например "умножение data * data", "разыменование указателя ptr", "вызов
system()"). НЕДОСТАТОЧНО просто назвать категорию CWE в общих словах — нужна
привязка к конкретной строке/операции/идентификатору из реального кода, даже
если это простое арифметическое выражение, а не вызов функции.

Формат ответа — СТРОГО валидный JSON, без markdown-разметки, без текста вне JSON:
{"summary": "1-2 предложения, суть для пользователя", "explanation": "подробнее, 2-4 предложения, с явной ссылкой на конкретный элемент кода (функцию/переменную/операцию)", "recommendation": "что делать дальше"}
"""

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


@dataclass
class SynthesizerResult:
    verdict: str
    summary: str
    explanation: str
    recommendation: str
    cwe: str | None = None
    scanner_score: float | None = None
    critic_score: float | None = None
    used_fallback: bool = False
    raw_llm_output: str = ""

    def to_report_text(self) -> str:
        label = VERDICT_LABELS.get(self.verdict, self.verdict)
        lines = [f"**{label}**", "", self.summary, "", self.explanation]
        if self.recommendation:
            lines += ["", f"Рекомендация: {self.recommendation}"]
        return "\n".join(lines)

    def to_log_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "summary": self.summary,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "scanner_score": self.scanner_score,
            "critic_score": self.critic_score,
            "used_fallback": self.used_fallback,
        }


def _get_llm(model: str = SYNTHESIZER_MODEL) -> ChatOllama:
    return ChatOllama(model=model, temperature=0.2, format="json")


def _hit_summary(hit: Any) -> dict:
    if hit is None:
        return {}
    payload = getattr(hit, "payload", {}) or {}
    return {
        "score": round(float(getattr(hit, "score", 0.0)), 4),
        "cwe": payload.get("cwe"),
        "label": payload.get("label"),
        "filename": payload.get("filename"),
        "code_snippet": (payload.get("code") or "")[:400],
    }


def _extract_json(raw_text: str) -> dict | None:
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        pass
    match = _JSON_BLOCK_RE.search(raw_text)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return None


_FALLBACK_TEMPLATES = {
    "vulnerable": (
        "Обнаружено сходство с известным паттерном уязвимости.",
        "Код структурно похож на зарегистрированный эксплойт в базе знаний.",
        "Рекомендуется ручная проверка специалистом по безопасности.",
    ),
    "false_positive": (
        "Код похож на безопасный вариант известного паттерна.",
        "Найдено сильное сходство с проверенным, безопасным примером.",
        "Дополнительная проверка не обязательна, но не будет лишней.",
    ),
    "inconclusive": (
        "Система не может уверенно классифицировать этот код.",
        "Найдено сходство как с уязвимым, так и с безопасным примером — "
        "разница недостаточна для однозначного вывода.",
        "Настоятельно рекомендуется ручная проверка специалистом.",
    ),
}


def _fallback_result(verdict: str, reason: str, top_exploit: dict, top_fp: dict) -> SynthesizerResult:
    summary, explanation, recommendation = _FALLBACK_TEMPLATES.get(
        verdict, ("Не удалось сформировать отчёт.", reason, "Проверьте систему вручную.")
    )
    return SynthesizerResult(
        verdict=verdict, summary=summary, explanation=explanation,
        recommendation=recommendation, cwe=top_exploit.get("cwe"),
        scanner_score=top_exploit.get("score"), critic_score=top_fp.get("score"),
        used_fallback=True, raw_llm_output=reason,
    )


def synthesize(
    user_code: str,
    verdict: str,
    exploit_hits: list[Any],
    fp_hits: list[Any],
    model: str = SYNTHESIZER_MODEL,
) -> SynthesizerResult:
    top_exploit = _hit_summary(exploit_hits[0]) if exploit_hits else {}
    top_fp = _hit_summary(fp_hits[0]) if fp_hits else {}

    user_message = f"""Вердикт системы: {verdict}

Код пользователя:
```c
{user_code}
```

Топ-находка Сканера (похожий эксплойт):
{json.dumps(top_exploit, ensure_ascii=False, indent=2) if top_exploit else "нет находок"}

Топ-находка Критика (похожий безопасный код):
{json.dumps(top_fp, ensure_ascii=False, indent=2) if top_fp else "нет находок"}
"""

    try:
        llm = _get_llm(model)
        messages = [("system", SYNTHESIZER_SYSTEM_PROMPT), ("human", user_message)]
        response = llm.invoke(messages)
        raw = response.content
    except Exception as exc:  
        logger.warning("Synthesizer: LLM недоступна: %s", exc)
        return _fallback_result(verdict, f"LLM error: {exc}", top_exploit, top_fp)

    parsed = _extract_json(raw)
    if parsed is None:
        logger.warning("Synthesizer: невалидный JSON от модели: %r", raw[:300])
        return _fallback_result(verdict, "invalid JSON from LLM", top_exploit, top_fp)

    return SynthesizerResult(
        verdict=verdict,
        summary=str(parsed.get("summary", "")),
        explanation=str(parsed.get("explanation", "")),
        recommendation=str(parsed.get("recommendation", "")),
        cwe=top_exploit.get("cwe"),
        scanner_score=top_exploit.get("score"),
        critic_score=top_fp.get("score"),
        raw_llm_output=raw,
    )


if __name__ == "__main__":
    from csec.decider import decide_from_hits
    from csec.search import search_exploits, search_false_positives

    sample_code = """
    void run_command(char *user_input) {
        char cmd[256];
        sprintf(cmd, "ls %s", user_input);
        system(cmd);
    }
    """

    exploit_hits = search_exploits(sample_code, limit=3)
    fp_hits = search_false_positives(sample_code, limit=3)
    verdict = decide_from_hits(exploit_hits, fp_hits)

    result = synthesize(sample_code, verdict, exploit_hits, fp_hits)

    print(json.dumps(result.to_log_dict(), indent=2, ensure_ascii=False))
    print("\n ОТЧЁТ ДЛЯ ПОЛЬЗОВАТЕЛЯ\n")
    print(result.to_report_text())