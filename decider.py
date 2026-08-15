"""Простой Decider по cosine scores Scanner/Critic (до появления LLM-синтеза)."""

from __future__ import annotations

from typing import Any

# Абсолютные пороги «есть сильный hit».
FP_SCORE_THRESHOLD = 0.85
EXPLOIT_SCORE_THRESHOLD = 0.7
# Если оба сильные — кто выше хотя бы на этот margin, тот и побеждает.
SCORE_MARGIN = 0.02


def decide_from_hits(exploit_hits: list[Any], fp_hits: list[Any]) -> str:
    """
    Вернуть вердикт: vulnerable | false_positive | inconclusive.

    В Juliet good/bad часто почти идентичны по sink-коду, поэтому одного
    абсолютного порога FP недостаточно — сравниваем scores между собой.
    """
    fp_score = float(fp_hits[0].score) if fp_hits else 0.0
    ex_score = float(exploit_hits[0].score) if exploit_hits else 0.0

    fp_strong = bool(fp_hits) and fp_score > FP_SCORE_THRESHOLD
    ex_strong = bool(exploit_hits) and ex_score > EXPLOIT_SCORE_THRESHOLD

    if fp_strong and ex_strong:
        if fp_score >= ex_score + SCORE_MARGIN:
            return "false_positive"
        if ex_score >= fp_score + SCORE_MARGIN:
            return "vulnerable"
        return "inconclusive"

    if fp_strong:
        return "false_positive"
    if ex_strong:
        return "vulnerable"
    return "inconclusive"
