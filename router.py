from __future__ import annotations
import json
import logging
import re
from dataclasses import dataclass, field
from langchain_ollama import ChatOllama

logger = logging.getLogger(__name__)

#как и договаривались
ROUTER_MODEL = "qwen2.5-coder:7b"
LOW_CONFIDENCE_THRESHOLD = 0.5

CWE_DESCRIPTIONS = {
    "CWE-78": "OS Command Injection — выполнение системных команд с непроверенным "
              "вводом (system, exec, spawn, popen и т.п.)",
    "CWE-134": "Uncontrolled Format String — непроверенный пользовательский ввод "
               "используется как форматная строка (printf, fprintf, syslog и т.п.)",
    "CWE-190": "Integer Overflow — арифметическая операция может выйти за границы "
               "диапазона целочисленного типа",
    "CWE-23": "Relative Path Traversal — путь к файлу строится из непроверенного "
              "ввода, позволяя выйти за пределы ожидаемой директории",
    "CWE-476": "NULL Pointer Dereference — указатель используется (разыменовывается) "
               "без предварительной проверки на NULL",
}

ROUTER_SYSTEM_PROMPT = f"""Ты — классификатор уязвимостей C/C++ кода для системы аудита безопасности.

Твоя задача: определить, к какой из следующих категорий CWE относится код. Смотри не
на отдельные ключевые слова, а на то, течёт ли непроверенный/внешний ввод в опасную операцию.

Категории:
{chr(10).join(f"- {cwe}: {desc}" for cwe, desc in CWE_DESCRIPTIONS.items())}

Правила:
1. Если код явно соответствует одной категории — укажи её в primary_cwe.
2. Если код одновременно похож сразу на несколько категорий — укажи основную в
   primary_cwe, остальные перечисли в secondary_cwe.
3. Если код не относится ни к одной из категорий (или это безопасный код без
   уязвимости из списка) — primary_cwe = "unknown".
4. confidence — твоя уверенность от 0 до 1. Если сомневаешься — не завышай её.
5. Отвечай СТРОГО валидным JSON, без markdown-разметки, без пояснений до или после JSON.

Формат ответа:
{{"primary_cwe": "CWE-78" | "CWE-134" | "CWE-190" | "CWE-23" | "CWE-476" | "unknown", "confidence": 0.0-1.0, "secondary_cwe": ["CWE-XX", ...], "reasoning": "одно короткое предложение"}}
"""

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


@dataclass
class RouterResult:
    primary_cwe: str
    confidence: float
    secondary_cwe: list[str] = field(default_factory=list)
    reasoning: str = ""
    action: str = "single_match"
    cwe_filter: str | None = None

    def to_log_dict(self) -> dict:
        return {
            "primary_cwe": self.primary_cwe,
            "confidence": self.confidence,
            "secondary_cwe": self.secondary_cwe,
            "action": self.action,
            "cwe_filter": self.cwe_filter,
            "reasoning": self.reasoning,
        }


def _get_llm(model: str = ROUTER_MODEL) -> ChatOllama:
    # temperature = 0 тк не нужна креативность, нужна стабильность
    return ChatOllama(model=model, temperature=0, format="json")


def _extract_json(raw_text: str) -> dict | None:
    #Достаёт JSON из ответа модели даже если она добавила лишний текст
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


def _decide(parsed: dict) -> RouterResult:
    primary = str(parsed.get("primary_cwe", "unknown")).strip()
    try:
        confidence = float(parsed.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    secondary = parsed.get("secondary_cwe") or []
    secondary = [s for s in secondary if s and str(s).lower() != "unknown"]
    reasoning = str(parsed.get("reasoning", ""))

    if primary.lower() == "unknown" or primary not in CWE_DESCRIPTIONS:
        return RouterResult(
            primary_cwe="unknown", confidence=confidence, secondary_cwe=secondary,
            reasoning=reasoning, action="no_match", cwe_filter=None,
        )

    if confidence < LOW_CONFIDENCE_THRESHOLD:
        return RouterResult(
            primary_cwe=primary, confidence=confidence, secondary_cwe=secondary,
            reasoning=reasoning, action="low_confidence", cwe_filter=None,
        )

    if secondary:
        return RouterResult(
            primary_cwe=primary, confidence=confidence, secondary_cwe=secondary,
            reasoning=reasoning, action="multi_label", cwe_filter=primary,
        )

    return RouterResult(
        primary_cwe=primary, confidence=confidence, secondary_cwe=[],
        reasoning=reasoning, action="single_match", cwe_filter=primary,
    )


def route(code: str, model: str = ROUTER_MODEL) -> RouterResult:
    #точка вхожа главная
    llm = _get_llm(model)
    messages = [
        ("system", ROUTER_SYSTEM_PROMPT),
        ("human", f"Код для анализа:\n```c\n{code}\n```"),
    ]
    response = llm.invoke(messages)
    raw = response.content

    parsed = _extract_json(raw)
    if parsed is None:
        logger.warning("Router: не удалось распарсить ответ модели: %r", raw[:300])
        return RouterResult(
            primary_cwe="unknown", confidence=0.0, action="parse_error", cwe_filter=None,
            reasoning="LLM вернул невалидный JSON",
        )

    return _decide(parsed)


if __name__ == "__main__":
    sample_code = """
    void run_command(char *user_input) {
        char cmd[256];
        sprintf(cmd, "ls %s", user_input);
        system(cmd);
    }
    """
    result = route(sample_code)
    print(json.dumps(result.to_log_dict(), indent=2, ensure_ascii=False))