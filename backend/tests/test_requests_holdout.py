"""HELD-OUT cases for the secret-disclosure request rule.

Written BEFORE the final implementation was run, and not used during prototyping. Results are
reported as measured; cases the rule gets wrong are kept and marked as known misses or known
false positives instead of being tuned away.
"""

import pytest

from app.analyzers.requests import analyze_requests
from app.parsing import parse_email

MALICIOUS = [
    "Our records show a login problem. Please send us your Outlook password so we can fix it.",
    "Hi, it's me. I accidentally sent my verification code to your number, can you text me the "
    "code you just got?",
    "Reply to this message with your banking PIN and the one-time password from your bank.",
    "Please reply to this email. Include your username, current password and security answers.",
    "To complete the migration, we will need your network password. Reply with it below.",
    "Kindly forward the authentication code that was delivered to your phone.",
    "Share your 2FA backup codes with me so I can log in while you're away.",
    "Respond with your full card number, expiry date and CVV to release the payment.",
    "Don't delay - email us your login password today.",
    "Send your SSN and date of birth to confirm your tax refund.",
    "Please reply with the following details: username, password, phone number.",
    "Can you send me the sms code you received? I'm locked out.",
]

BENIGN = [
    "For your security, we will never ask you to reply with your password.",
    "Do not reply to this email with your PIN or any security code.",
    "Your one-time password is 551204. It expires in 5 minutes. Never share it.",
    "Reply STOP to unsubscribe from security code notifications.",
    "We sent a verification code to your phone. Enter it in the app to continue.",
    "Please send the password-protected spreadsheet to finance by Friday.",
    "Tell your manager if you notice anyone asking for your password.",
    "Share your screen and your meeting passcode with the guest speaker.",
    "If you need help with your PIN, reply to this email.",
    "Please include your employee ID and start date in your reply.",
    "Send your password reset link to the help desk if it expired.",
    "Your bank will never text you asking for your security code; don't share it with anyone.",
]

# First run (before any adjustment): 9/12 malicious detected, 2/12 benign falsely flagged.
# The two false positives ("tell your manager if anyone asks for your password", "your meeting
# passcode") and two misses (card number list, "following details:" list) led to general fixes
# (clause breaks, shared access codes, card numbers, list form), which were then measured on a
# second, fresh set (test_requests_holdout_round2.py). The remaining miss is accepted:
KNOWN_MISSES: dict[str, str] = {
    MALICIOUS[1]: "bare 'code' without a qualifier is not treated as a secret (too common: "
    "promo or discount codes); documented limitation",
}
KNOWN_FALSE_POSITIVES: dict[str, str] = {}


def _flagged(text: str) -> bool:
    raw = f"From: a@example.com\r\nSubject: Hello\r\n\r\n{text}".encode()
    return any(s.id == "request.secret_disclosure" for s in analyze_requests(parse_email(raw)))


@pytest.mark.parametrize("text", MALICIOUS)
def test_heldout_malicious_request_is_detected(text: str) -> None:
    if text in KNOWN_MISSES:
        pytest.xfail(KNOWN_MISSES[text])
    assert _flagged(text)


@pytest.mark.parametrize("text", BENIGN)
def test_heldout_benign_text_is_not_flagged(text: str) -> None:
    if text in KNOWN_FALSE_POSITIVES:
        pytest.xfail(KNOWN_FALSE_POSITIVES[text])
    assert not _flagged(text)
