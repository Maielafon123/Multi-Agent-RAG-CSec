"""Простой Decider по cosine scores Scanner/Critic (до появления LLM-синтеза)."""

from __future__ import annotations

from typing import Any

# Абсолютные пороги «есть сильный hit» (если второй поиск слабый).
FP_SCORE_THRESHOLD = 0.85
EXPLOIT_SCORE_THRESHOLD = 0.7
# Оба score выше — сравниваем относительно, даже если FP < 0.85.
BOTH_ACTIVE_THRESHOLD = 0.7
# Если оба сильные — кто выше хотя бы на этот margin, тот и побеждает.
SCORE_MARGIN = 0.02
# Разница меньше margin: при равенстве/победе Critic — false_positive (не inconclusive).
TIE_EPSILON = 1e-6


def decide_from_hits(exploit_hits: list[Any], fp_hits: list[Any]) -> str:
    """
    Вернуть вердикт: vulnerable | false_positive | inconclusive.

    В Juliet good/bad часто почти идентичны: top-1 Scanner и Critic ~0.82–0.84.
    Старый баг: асимметричные пороги (0.7 vs 0.85) → всегда vulnerable.
    Перекос после фикса: при diff < margin всегда inconclusive, даже когда
    Critic чуть выше — для безопасного кода это слишком пессимистично.
    """
    fp_score = float(fp_hits[0].score) if fp_hits else 0.0
    ex_score = float(exploit_hits[0].score) if exploit_hits else 0.0

    if exploit_hits and fp_hits:
        if ex_score >= BOTH_ACTIVE_THRESHOLD and fp_score >= BOTH_ACTIVE_THRESHOLD:
            if ex_score >= fp_score + SCORE_MARGIN:
                return "vulnerable"
            if fp_score >= ex_score - TIE_EPSILON:
                return "false_positive"
            return "inconclusive"

    fp_strong = bool(fp_hits) and fp_score > FP_SCORE_THRESHOLD
    ex_strong = bool(exploit_hits) and ex_score > EXPLOIT_SCORE_THRESHOLD

    if fp_strong:
        return "false_positive"
    if ex_strong:
        return "vulnerable"
    return "inconclusive"
