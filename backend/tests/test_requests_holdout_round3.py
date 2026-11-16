"""THIRD held-out set for the secret-disclosure request rule (final generalization check).

Written after the noun/verb fix and BEFORE running it. Focus: words that are both nouns and
verbs, greetings without punctuation, multi-sentence requests, and negation.

First run: 8/8 malicious detected, 2/8 benign falsely flagged. Both were fixed afterwards and
are disclosed here: (1) a BUG in the negation guard, which did not recognize contractions such
as "don't" (it now does; verified with independent contraction cases in test_requests.py), and
(2) "security code of conduct", a document name, now excluded. After these fixes this set is no
longer unseen.
"""

import pytest

from app.analyzers.requests import analyze_requests
from app.parsing import parse_email

MALICIOUS = [
    "Hi Dana reply to me with your current password so I can update the payroll system",
    "Quick favor. Text me your verification code when it arrives.",
    "IT notice: your account is being migrated. Email us your username and password today.",
    "Please share the one-time code sent to your phone with our support agent.",
    "We will need your online banking PIN to stop the fraudulent transfer.",
    "Before 5 pm, forward your recovery codes to this address.",
    "Our system lost your profile. Reply and include your social security number.",
    "Don't worry about the warning, just send your 2FA code here.",
]

BENIGN = [
    "This text contains your new PIN; keep it somewhere safe.",
    "Your reply with your updated shipping address has been received.",
    "Forward this email to your manager if you did not request a password change.",
    "Our email includes your one-time code and instructions to sign in.",
    "Please don't reply with your password or any verification code.",
    "Share your ideas for the new security code of conduct.",
    "The verification code we sent you expires in 10 minutes.",
    "Send the meeting PIN to the external guests before the call.",
]

# Filled in AFTER the first and only run of this file, with the measured results.
KNOWN_MISSES: dict[str, str] = {}
KNOWN_FALSE_POSITIVES: dict[str, str] = {}


def _flagged(text: str) -> bool:
    raw = f"From: a@example.com\r\nSubject: Hello\r\n\r\n{text}".encode()
    return any(s.id == "request.secret_disclosure" for s in analyze_requests(parse_email(raw)))


@pytest.mark.parametrize("text", MALICIOUS)
def test_round3_malicious_request_is_detected(text: str) -> None:
    if text in KNOWN_MISSES:
        pytest.xfail(KNOWN_MISSES[text])
    assert _flagged(text)


@pytest.mark.parametrize("text", BENIGN)
def test_round3_benign_text_is_not_flagged(text: str) -> None:
    if text in KNOWN_FALSE_POSITIVES:
        pytest.xfail(KNOWN_FALSE_POSITIVES[text])
    assert not _flagged(text)
