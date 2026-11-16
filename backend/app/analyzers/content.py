"""Content analyzer: what does the email ask the reader to do?

Looks for well-known social-engineering language in the subject and body, grouped into
explainable categories. These signals are deliberately WEAK: legitimate email also says
"update your payment information" or "urgent". Their value is in combination with technical
signals (sender, links, attachments), which Step 7's scoring builds on.

Text is normalized first (Unicode compatibility forms, invisible characters removed, case
folded) so that tricks like "pass<zero-width space>word" or full-width letters do not evade it.
English only.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser

from app.analyzers.common import make_signal
from app.parsing import ParsedEmail
from app.schemas import Signal

CATEGORY = "content"
MAX_SCAN_CHARS = 200_000  # social-engineering language appears near the top of a message
MAX_EXAMPLES = 3
# Wording alone can never make an email Suspicious (threshold 30): it is corroborating evidence.
MAX_CONTENT_POINTS = 25
_SPELLING_VARIANTS = (("e-mail", "email"), ("mail box", "mailbox"), ("log-in", "login"))
_SPACED_LETTERS = re.compile(r"\b(?:\w ){3,}\w\b")
NEGATION_WINDOW = 40  # characters before a match checked for "never", "not", ...
_NEGATION = re.compile(r"\b(?:never|not|no\s+one|nobody|don't|do\s+not|won't|will\s+not)\b")


@dataclass(frozen=True)
class _Rule:
    id: str
    title: str
    points: int
    explanation: str
    pattern: re.Pattern[str]


def _rx(*alternatives: str) -> re.Pattern[str]:
    return re.compile(r"\b(?:" + "|".join(alternatives) + r")\b")


_RULES = (
    _Rule(
        "credentials",
        "Asks you to verify an account or enter a password",
        15,
        "The email asks you to verify, confirm or update account, password or payment "
        "details, or warns that your account will be locked. This is how most credential "
        "phishing starts; real services rarely ask for this by email.",
        _rx(
            r"(?:verify|confirm|validate|update|reactivate|unlock|restore)\s+(?:your\s+)?"
            r"(?:account|identity|password|login|credentials|mailbox|email\s+account"
            r"|billing\s+(?:details|information)"
            r"|payment\s+(?:details|information|method)|bank(?:ing)?\s+details)",
            r"(?:enter|provide|re-?enter|submit)\s+your\s+(?:password|login|credentials|pin"
            r"|social\s+security|ssn|card\s+(?:number|details))",
            r"your\s+(?:account|mailbox|password|email\s+account)\s+(?:has\s+been|will\s+be|is"
            r"|from\s+being|could\s+be|may\s+be|might\s+be)"
            r"\s+(?:suspended|locked|disabled|deactivated|closed|compromised|restricted"
            r"|limited|expired|on\s+hold)",
            r"(?:mailbox|email\s+storage)\s+(?:is\s+)?(?:full|almost\s+full|over\s+quota"
            r"|quota\s+(?:has\s+been\s+|is\s+)?exceeded)",
            r"your\s+(?:\w+\s+){0,2}password\s+(?:has\s+expired|(?:expires|will\s+expire"
            r"|is\s+expiring)\s+(?:today|tonight|soon|now|in\s+\d+\s+hours?))",
        ),
    ),
    _Rule(
        "payment",
        "Payment or bank-detail request",
        15,
        "The email talks about wire transfers, gift cards, changed bank details or overdue "
        "payments. Invoice fraud and CEO fraud rely on exactly these requests.",
        _rx(
            r"wire\s+transfer",
            r"gift\s+cards?",
            r"(?:bank|banking|account|payment)\s+(?:details|information)\s+(?:have|has)\s+"
            r"(?:changed|been\s+(?:changed|updated))",
            r"new\s+bank\s+account",
            r"(?:change|update)\s+(?:of\s+)?(?:our\s+)?bank(?:ing)?\s+details",
            r"(?:overdue|outstanding|unpaid)\s+(?:invoice|payment|balance)",
            r"(?:bitcoin|btc|crypto(?:currency)?)\s+(?:wallet|address|payment)",
            r"pay\s+(?:the\s+|a\s+|your\s+)?(?:small\s+)?(?:redelivery|re-delivery|customs"
            r"|delivery|shipping|release)\s+fee",
            r"(?:update|change)\s+my\s+(?:direct\s+deposit|payroll|bank)"
            r"(?:\s+(?:details|information|account))?",
        ),
    ),
    _Rule(
        "secrecy",
        "Asks for secrecy or a quick favor",
        10,
        "The email asks you to keep something confidential, or opens with 'are you "
        "available?'. Fraudsters impersonating a manager use this to stop you from checking "
        "with anyone.",
        _rx(
            r"keep\s+(?:this|it)\s+(?:confidential|between\s+us|private|to\s+yourself)",
            r"do(?:n'?t|\s+not)\s+(?:tell|mention|discuss|share\s+this)",
            r"are\s+you\s+(?:available|free|around|at\s+your\s+desk|in\s+the\s+office)"
            r"(?:\s+(?:now|right\s+now))?(?=\s*\?)",  # only as a question
            r"(?:i\s+)?need\s+(?:a\s+)?(?:quick\s+|small\s+)?favou?r",
            r"discreet(?:ly)?",
        ),
    ),
    _Rule(
        "reward",
        "Promises a prize, refund or money",
        10,
        "The email says you have won something or are owed money. Unexpected rewards are a "
        "classic lure to get you to click or share details.",
        _rx(
            r"you\s+(?:have\s+)?won",
            r"claim\s+your\s+(?:\w+\s+){0,2}(?:prize|reward|refund|winnings)",
            r"(?:eligible|entitled)\s+(?:for|to)\s+(?:a\s+)?(?:refund|reward|compensation)",
            r"unclaimed\s+(?:funds|package|parcel|reward|prize)",
            r"lottery",
            r"inheritance",
        ),
    ),
    _Rule(
        "urgency",
        "Creates time pressure",
        5,
        "The email pushes you to act immediately. Pressure is used to stop people from "
        "thinking twice. Common in marketing too, so this is weak evidence on its own.",
        _rx(
            r"urgent(?:ly)?",
            r"immediately",
            r"within\s+(?:12|24|48|72)\s+hours",
            r"final\s+(?:notice|warning|reminder)",
            r"last\s+(?:chance|warning)",
            r"act\s+now",
            r"action\s+required",
            r"expires?\s+(?:today|soon|tonight)",
        ),
    ),
    _Rule(
        "generic_greeting",
        "Impersonal greeting",
        5,
        "The email opens with 'Dear customer' or similar instead of your name. Services you "
        "have an account with usually know your name.",
        _rx(
            r"dear\s+(?:customer|user|client|member|account\s+holder|valued\s+(?:customer"
            r"|member|user|client)|sir\s*(?:/|or)\s*madam)",
            r"hello\s+(?:user|customer)",
        ),
    ),
)


def message_text(parsed: ParsedEmail) -> str:
    """Normalized subject + plain-text body + visible HTML text (shared by wording analyzers)."""
    return normalize_text(
        # " . " keeps the subject and body as separate sentences after whitespace is collapsed.
        " . ".join((parsed.subject, parsed.text_body[:MAX_SCAN_CHARS], html_to_text(parsed)))
    )[: MAX_SCAN_CHARS * 2]


def analyze_content(parsed: ParsedEmail) -> list[Signal]:
    text = message_text(parsed)
    signals = []
    budget = MAX_CONTENT_POINTS  # rules are ordered by importance and share this budget
    for rule in _RULES:
        matches = list(
            dict.fromkeys(
                m.group(0) for m in rule.pattern.finditer(text) if not _negated(text, m.start())
            )
        )
        if matches:
            shown = ", ".join(f'"{m}"' for m in matches[:MAX_EXAMPLES])
            points = min(rule.points, budget)  # 0 once the budget is used up: shown as "Info"
            budget -= points
            signals.append(
                make_signal(
                    f"content.{rule.id}",
                    CATEGORY,
                    rule.title,
                    points,
                    rule.explanation,
                    f"Phrases found: {shown}",
                )
            )
    return signals


def _negated(text: str, start: int) -> bool:
    """True for advice like "we will never ask you to enter your password".

    Only the same sentence counts: "Do not reply. Enter your password" is not negated.
    """
    window = text[max(0, start - NEGATION_WINDOW) : start]
    sentence = re.split(r"[.!?;]", window)[-1]
    return bool(_NEGATION.search(sentence))


def normalize_text(text: str) -> str:
    """Compatibility-normalize, drop invisible characters, unify apostrophes, case-fold."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    text = text.replace(chr(0x2019), "'").replace(chr(0x2018), "'")
    text = " ".join(text.casefold().split())
    for variant, canonical in _SPELLING_VARIANTS:
        text = text.replace(variant, canonical)
    # Rejoin letter-spaced words ("v e r i f y" -> "verify"), a filter-evasion trick.
    return _SPACED_LETTERS.sub(lambda m: m.group(0).replace(" ", ""), text)


def html_to_text(parsed: ParsedEmail) -> str:
    """Visible text of the HTML body (script and style contents are skipped)."""
    extractor = _TextExtractor()
    try:
        extractor.feed(parsed.html_body[:MAX_SCAN_CHARS])
        extractor.close()
    except Exception:
        # HTMLParser is lenient; on a rare internal error, use the text collected so far.
        return " ".join(extractor.parts)
    return " ".join(extractor.parts)


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.parts.append(data)
