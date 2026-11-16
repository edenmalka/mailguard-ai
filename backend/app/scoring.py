"""Scoring engine: turns analyzer signals into a score, a verdict, attack patterns and advice.

Design goals, in order:
1. Explainable: the points shown on the card add up to the score (up to the 100 cap).
2. Robust to stacking: signals of the same kind are correlated, so each category can add at
   most a fixed budget. Signals beyond a budget are still shown, as 0-point "Info" rows.
3. Corroboration matters: when DIFFERENT kinds of evidence point to the same attack (for
   example a look-alike link AND a request for your password), a named attack pattern adds a
   bonus. It appears as its own row listing the signals that triggered it. Only the strongest
   pattern adds points; others are still named.
4. Honest: a low score from an incomplete analysis is "inconclusive", never "safe".
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from app.schemas import AttackPattern, Signal, Verdict

SUSPICIOUS_THRESHOLD = 30
MALICIOUS_THRESHOLD = 70

# Maximum points each kind of evidence can add (correlated evidence is not counted twice).
CATEGORY_BUDGETS: dict[str, int] = {
    "authentication": 40,
    "sender": 50,
    "links": 50,
    "attachments": 60,
    "content": 25,
    "structure": 10,
}

# Groups of signal ids used by the pattern rules.
DECEPTIVE_LINK_OR_SENDER = frozenset(
    {
        "link.lookalike",
        "link.text_mismatch",
        "link.userinfo",
        "link.ip_address",
        "sender.brand_impersonation",
        "sender.lookalike_domain",
        "sender.address_in_display_name",
        "auth.dmarc_fail",
    }
)
CREDENTIAL_CAPTURE = frozenset({"content.credentials", "link.form", "attachment.html_active"})
REPLY_REDIRECTION_OR_IMPERSONATION = frozenset(
    {
        "sender.reply_to_freemail",
        "sender.reply_to_mismatch",
        "sender.address_in_display_name",
        "sender.lookalike_domain",
        "sender.brand_impersonation",
        "auth.dmarc_fail",
    }
)
MONEY_OR_SECRECY = frozenset({"content.payment", "content.secrecy"})
# 0-point facts that are not risky alone but matter in combination.
CONTEXT_FACTS = frozenset({"sender.free_webmail"})
MALWARE_PAYLOAD = frozenset(
    {
        "attachment.executable",
        "attachment.archive_executable",
        "attachment.macro",
        "attachment.active_document",
        "link.dangerous_file",
        "link.script_scheme",
    }
)
SPOOFING_COMPANIONS = frozenset(
    {
        "sender.brand_impersonation",
        "sender.reply_to_freemail",
        "sender.reply_to_mismatch",
        "sender.address_in_display_name",
    }
)


@dataclass(frozen=True)
class _PatternRule:
    pattern: AttackPattern
    bonus: int
    # Returns the ids of the signals that triggered the rule, or an empty set if it did not.
    match: Callable[[set[str]], set[str]]


def _two_sided(first: frozenset[str], second: frozenset[str]) -> Callable[[set[str]], set[str]]:
    """Fires when one signal from `first` and a DIFFERENT signal from `second` are present."""

    def match(ids: set[str]) -> set[str]:
        a, b = ids & first, ids & second
        if a and b and (len(a | b) >= 2):
            return a | b
        return set()

    return match


def _malware(ids: set[str]) -> set[str]:
    payload = ids & MALWARE_PAYLOAD
    if not payload:
        return set()
    # A payload plus a disguise, a lure (any wording signal), or a deceptive sender/link.
    support = {
        i
        for i in ids
        if i in {"attachment.disguised", "attachment.encrypted_archive"}
        or i.startswith("content.")
        or i in DECEPTIVE_LINK_OR_SENDER
    }
    return payload | support if support else set()


_impersonation_and_money = _two_sided(REPLY_REDIRECTION_OR_IMPERSONATION, MONEY_OR_SECRECY)


def _payment_fraud(ids: set[str]) -> set[str]:
    triggers = _impersonation_and_money(ids)
    if triggers:
        return triggers
    # CEO fraud from a personal webmail account carrying the boss's name: no deception is
    # visible in the headers, so require an actual MONEY request (secrecy alone is not enough).
    if "sender.free_webmail" in ids and "content.payment" in ids:
        return {"sender.free_webmail", "content.payment"} | (ids & {"content.secrecy"})
    return set()


PATTERN_RULES: tuple[_PatternRule, ...] = (
    _PatternRule(
        AttackPattern(
            id="malware_delivery",
            name="Malware delivery",
            description="The email tries to get you to open a file or download that can run "
            "code on your computer.",
            advice="Do not open the attachment or download the file. Delete the email, or "
            "report it to your IT or security team.",
        ),
        20,
        _malware,
    ),
    _PatternRule(
        AttackPattern(
            id="credential_phishing",
            name="Credential phishing",
            description="The email uses a deceptive sender or link and asks for your password "
            "or account details, typically on a fake sign-in page.",
            advice="Do not enter your password or payment details. If you think the account "
            "issue is real, open the website yourself by typing its address.",
        ),
        20,
        _two_sided(
            DECEPTIVE_LINK_OR_SENDER | {"link.form", "attachment.html_active"}, CREDENTIAL_CAPTURE
        ),
    ),
    _PatternRule(
        AttackPattern(
            id="payment_fraud",
            name="Payment fraud (business email compromise)",
            description="The email impersonates someone or redirects replies, and asks for a "
            "payment, gift cards, changed bank details or secrecy.",
            advice="Do not send money or change bank details based on this email. Confirm by "
            "phone, using a number you already know, not one from the email.",
        ),
        20,
        _payment_fraud,
    ),
    _PatternRule(
        AttackPattern(
            id="sender_spoofing",
            name="Sender spoofing",
            description="The email fails its domain's anti-forgery check (DMARC) and also "
            "uses other identity tricks, so it is likely not from who it claims.",
            advice="Do not trust requests in this email. If it matters, contact the sender "
            "through a channel you already know.",
        ),
        15,
        _two_sided(frozenset({"auth.dmarc_fail"}), SPOOFING_COMPANIONS),
    ),
)

ADVICE_BY_VERDICT: dict[Verdict, str] = {
    Verdict.MALICIOUS: "Do not click links, open attachments or reply. Report the email as "
    "phishing and delete it.",
    Verdict.SUSPICIOUS: "Be careful. Before clicking, downloading or replying, confirm the "
    "request with the sender through a channel you already know.",
    Verdict.SAFE: "No significant risks found. Stay alert for unexpected requests for "
    "passwords, payments or downloads.",
    Verdict.INCONCLUSIVE: "MailGuard could not check everything in this email. Treat its "
    "links, attachments and requests with caution.",
}


@dataclass(frozen=True)
class ScoreResult:
    score: int
    verdict: Verdict
    signals: list[Signal]  # with points as actually counted, most significant first
    patterns: list[AttackPattern]
    recommendation: str


def score_signals(signals: list[Signal], fully_analyzed: bool) -> ScoreResult:
    budgeted = _apply_budgets(signals)
    # Patterns use what the analyzers FOUND (any risk signal), even if a budget later
    # reduced its points: the evidence still exists. Context facts (0 points) count too.
    ids = {s.id for s in signals if s.points > 0 or s.id in CONTEXT_FACTS}

    matched: list[tuple[_PatternRule, set[str]]] = []
    for rule in PATTERN_RULES:
        triggers = rule.match(ids)
        if triggers:
            matched.append((rule, triggers))
    matched.sort(key=lambda item: item[0].bonus, reverse=True)

    titles = {s.id: s.title for s in budgeted}
    pattern_signals = [
        _pattern_signal(rule, triggers, titles, counted=(index == 0))
        for index, (rule, triggers) in enumerate(matched)
    ]
    all_signals = budgeted + pattern_signals
    all_signals.sort(key=lambda s: (s.points, s.category == "pattern"), reverse=True)

    score = min(100, sum(s.points for s in all_signals))
    verdict = _verdict(score, fully_analyzed)
    patterns = [rule.pattern for rule, _ in matched]
    recommendation = (
        patterns[0].advice
        if patterns and verdict in {Verdict.MALICIOUS, Verdict.SUSPICIOUS}
        else ADVICE_BY_VERDICT[verdict]
    )
    return ScoreResult(score, verdict, all_signals, patterns, recommendation)


def _apply_budgets(signals: list[Signal]) -> list[Signal]:
    """Within each category, count the strongest signals first until its budget is used."""
    remaining = dict(CATEGORY_BUDGETS)
    result = []
    for signal in sorted(signals, key=lambda s: s.points, reverse=True):
        budget = remaining.get(signal.category, signal.points)
        points = min(signal.points, budget)
        if signal.category in remaining:
            remaining[signal.category] -= points
        result.append(
            signal if points == signal.points else signal.model_copy(update={"points": points})
        )
    return result


def _pattern_signal(
    rule: _PatternRule, triggers: set[str], titles: dict[str, str], counted: bool
) -> Signal:
    names = "; ".join(sorted(titles[i] for i in triggers if i in titles))
    return Signal(
        id=f"pattern.{rule.pattern.id}",
        category="pattern",
        title=f"Several findings point to {rule.pattern.name.lower()}",
        points=rule.bonus if counted else 0,
        explanation=f"{rule.pattern.description} Several independent findings agree, which is "
        "much stronger evidence than any one of them alone.",
        evidence=f"Based on: {names}",
    )


def _verdict(score: int, fully_analyzed: bool) -> Verdict:
    if score >= MALICIOUS_THRESHOLD:
        return Verdict.MALICIOUS
    if score >= SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE if fully_analyzed else Verdict.INCONCLUSIVE
