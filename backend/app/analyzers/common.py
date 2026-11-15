"""Shared helpers for analyzers."""

import unicodedata

from app.schemas import Signal

MAX_EVIDENCE_CHARS = 200
MAX_EXPLANATION_CHARS = 600


def clean_text(text: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    """Make attacker-controlled text safe to display as evidence.

    Invisible and direction-changing characters (e.g. U+202E) are shown as visible codes so they
    cannot disguise the text, whitespace is collapsed, and length is capped.
    """
    visible = "".join(
        f"[U+{ord(ch):04X}]" if unicodedata.category(ch) in {"Cc", "Cf"} else ch for ch in text
    )
    visible = " ".join(visible.split())
    return visible if len(visible) <= limit else visible[: limit - 1] + "…"


def make_signal(
    id: str,
    category: str,
    title: str,
    points: int,
    explanation: str,
    evidence: str | None = None,
) -> Signal:
    return Signal(
        id=id,
        category=category,
        title=title,
        points=points,
        # Explanations may embed attacker-controlled values (domains, names): clean them too.
        explanation=clean_text(explanation, MAX_EXPLANATION_CHARS),
        evidence=clean_text(evidence) if evidence else None,
    )
