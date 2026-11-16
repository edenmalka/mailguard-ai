"""Request analyzer: does the email ask you to SEND a password or security code?

Legitimate organizations essentially never ask you to send a password, PIN, one-time code,
recovery code, security answer, card security code or social security number by email or text;
they say the opposite ("never share this code"). An explicit request to disclose one is
therefore strong evidence on its own, unlike general wording such as "update your payment
method". This is the one deliberate exception to "wording alone never makes an email
Suspicious", and it is narrowly defined:

  a disclosure verb (reply, send, email, text, forward, share, give, tell, include, "provide us",
  "we need") ... in the SAME sentence ... the reader's own secret ("your ... password",
  "the verification code sent to your phone", "the SMS code you received").

Requests are ignored when a negation directly governs the verb ("never send", "do not reply",
"we will never ask you to share"). A negation elsewhere in the sentence ("Don't delay, send your
password") does not cancel the request, so attackers cannot hide behind an unrelated "don't".

Known gaps (documented): a bare "code" without a qualifier ("tell me the code Google sent you"),
question forms ("what's the code?"), requests split across sentences without a verb next to the
secret, non-English text, and text inside images.
"""

from __future__ import annotations

import re

from app.analyzers.common import make_signal
from app.analyzers.content import message_text
from app.parsing import ParsedEmail
from app.schemas import Signal

CATEGORY = "request"
POINTS_SECRET_REQUEST = 40
MAX_EXAMPLES = 3

# The reader's secrets. "password reset/manager/policy..." are not secrets.
_PROTECTED_ITEM = (
    r"(?:(?:current|old|new|account|e-?mail|login|work|network|vpn|banking|online\s+banking)\s+)?"
    r"(?:password|passcode|passphrase|pin(?:\s+(?:code|number))?"
    r"|(?:one[- ]?time|verification|security|authentication|login|sign[- ]?in|2fa|mfa|otp|sms"
    r"|\d[- ]?digit|confirmation)\s+(?:pass)?codes?"
    r"|otp|recovery\s+codes?|backup\s+codes?|security\s+(?:questions?|answers?)"
    r"|social\s+security\s+number|ssn|cvv|cvc|card\s+security\s+code"
    r"|(?:full\s+)?(?:credit\s+|debit\s+)?card\s+(?:number|details))"
    r"(?![\w-])(?!\s+(?:reset|change|policy|policies|manager|requirements?|expir\w*|strength"
    r"|rules?|delivery|notifications?|of\s+(?:conduct|practice|ethics)))"
)
# Verbs that move a secret from the reader to the sender (any inflection).
_VERB = (
    r"(?:repl(?:y|ying|ies)|respond(?:ing)?|send(?:ing)?|e-?mail(?:ing)?|text(?:ing)?"
    r"|forward(?:ing)?|shar(?:e|ing)|giv(?:e|ing)|tell(?:ing)?|includ(?:e|ing)"
    r"|provide\s+(?:us|me)|(?:we|i)\s+(?:will\s+)?(?:need|require))"
)
# Words that start a NEW clause: in "tell your manager if anyone asks for your password", the
# password belongs to "anyone asks", not to "tell", so it is not a request to send it.
_CLAUSE_BREAK = (
    r"(?:if|when|whenever|unless|because|whether|who|anyone|anybody|someone|somebody|asking|asks)"
)
# Same sentence, bounded, and no new clause in between.
_SAME_SENTENCE = rf"(?:(?!\b{_CLAUSE_BREAK}\b)[^.!?;]){{0,120}}?"
_REQUEST = re.compile(
    rf"\b{_VERB}\b{_SAME_SENTENCE}\b(?:"
    # "...with your work email, current password" or "...the code sent to your phone"
    rf"your\s+(?:[\w-]+,?\s+){{0,4}}{_PROTECTED_ITEM}"
    rf"|(?:the|that|this|a|an)\s+(?:[\w-]+\s+){{0,2}}{_PROTECTED_ITEM}\s+(?:[\w-]+\s+){{0,3}}"
    rf"(?:(?:sent|texted|delivered)\s+(?:to\s+)?(?:you|your)\b|(?:you\s+)?(?:received|got)\b)"
    # "...with the following details: username, password"
    rf"|following\s+(?:[\w-]+\s+)?(?:details|information|info)?\s*:\s*"
    rf"(?:[\w-]+,?\s+(?:and\s+)?){{0,4}}{_PROTECTED_ITEM}"
    r")"
)
# A negation that directly governs the request verb: "never send", "do not reply",
# "will never ask you to share", "won't ever request that you email".
_GOVERNING_NEGATION = re.compile(
    # "n't" is attached to its verb (don't, won't, can't), so it has no leading word boundary.
    r"(?:\b(?:never|not|no\s+one\s+will)|n't)\s+(?:ever\s+)?"
    r"(?:(?:ask|request|require|expect)\s+(?:you\s+|that\s+you\s+)?(?:to\s+)?)?$"
)


# Codes meant to be passed on to others are not personal credentials.
_SHARED_ACCESS_CODE = re.compile(
    r"\b(?:meeting|zoom|webinar|conference|event|wi-?fi|wifi|guest|room|door|gate|parking"
    r"|locker|alarm)\s+(?:pass(?:code|word)|pin|code)\b"
)


# Request verbs that are also everyday nouns ("this email contains your PIN reminder", "your
# welcome email includes your login"). They count as a noun, not a request, when one of the two
# preceding words in the same clause is a determiner or possessive.
_NOUN_LIKE_VERBS = frozenset({"email", "e-mail", "text", "reply", "forward", "share"})
_DETERMINERS = frozenset(
    {
        "the", "this", "that", "these", "those", "a", "an", "your", "our", "my", "his", "her",
        "their", "its", "any", "each", "every", "no", "which", "whose",
    }
)  # fmt: skip
_CLAUSE_SPLIT = re.compile(r"[.!?;:,\-]")


def _verb_position(text: str, start: int, verb: str) -> bool:
    """False when a noun-like verb ("email", "text"...) is used as a noun."""
    if verb not in _NOUN_LIKE_VERBS:
        return True
    clause = _CLAUSE_SPLIT.split(text[max(0, start - 60) : start])[-1]
    return not any(word in _DETERMINERS for word in clause.split()[-2:])


def analyze_requests(parsed: ParsedEmail) -> list[Signal]:
    text = message_text(parsed)
    found = []
    for match in _REQUEST.finditer(text):
        before = text[max(0, match.start() - 60) : match.start()]
        verb = match.group(0).split()[0]
        if (
            _GOVERNING_NEGATION.search(before)
            or _SHARED_ACCESS_CODE.search(match.group(0))
            or not _verb_position(text, match.start(), verb)
        ):
            continue
        found.append(match.group(0))
    if not found:
        return []
    examples = "; ".join(f'"{phrase[:80]}"' for phrase in list(dict.fromkeys(found))[:MAX_EXAMPLES])
    return [
        make_signal(
            "request.secret_disclosure",
            CATEGORY,
            "Asks you to send a password or security code",
            POINTS_SECRET_REQUEST,
            "The email asks you to send a password, PIN, one-time code or similar secret by "
            "reply or message. Legitimate organizations never ask for these by email: anyone "
            "who has them can take over your account.",
            f"Request found: {examples}",
        )
    ]
