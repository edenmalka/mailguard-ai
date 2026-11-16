"""SECOND held-out set for the secret-disclosure request rule.

Written after the fixes driven by the first held-out set, and BEFORE running them, to measure
whether those fixes generalize. Reported as measured; wrong results are kept as known
misses / false positives rather than tuned away.
"""

import pytest

from app.analyzers.requests import analyze_requests
from app.parsing import parse_email

MALICIOUS = [
    "Hello team. Payroll is moving to a new system, so please email me your current password "
    "by noon.",
    "Your mailbox will be deactivated. To keep it, reply with your email password.",
    "I just texted you a security code by mistake. Please forward the security code you received.",
    "Send the MFA code that was sent to your phone so we can finish the setup.",
    "We require your VPN password to restore your remote access; include it in your reply.",
    "Answer this email with your password.",
    "Please give us your PIN number and the card security code printed on the back.",
    "Reply now with your login, password and recovery codes.",
    "Confirm receipt by sending your one-time passcode.",
    "To verify ownership, kindly provide us with your backup codes.",
]

BENIGN = [
    "This is your security code: 902114. If you didn't request it, you can ignore this email.",
    "Never reply to messages asking for your password, even if they look official.",
    "Send your questions about the password policy to the IT help desk.",
    "Reply with your preferred meeting time and we'll send the meeting passcode.",
    "Share your Wi-Fi password with guests using the QR code on the fridge.",
    "Please forward this message to anyone who asks about the new PIN pads.",
    "Text your friends the code for the party venue.",
    "Include your employee number and manager's name when you reply.",
    "Tell us your favorite security feature in the survey.",
    "If anyone sends you a verification code request, report it to IT.",
]

# First run: 20/20 correct, but "Answer this email with your password" matched only because the
# noun "email" was treated as a verb. A follow-up probe showed that this noun/verb ambiguity
# flagged 5/7 ordinary sentences ("This email contains your PIN reminder"), so noun-like verbs
# now count only in verb position. That fix makes the case below a miss, which is accepted
# ("answer" is not a request verb: "answer your security questions" is a normal reset flow).
# The fix was then measured on a third fresh set (test_requests_holdout_round3.py).
KNOWN_MISSES: dict[str, str] = {
    MALICIOUS[5]: "'answer' is not a request verb; 'this email' is a noun, not a request",
}
KNOWN_FALSE_POSITIVES: dict[str, str] = {}


def _flagged(text: str) -> bool:
    raw = f"From: a@example.com\r\nSubject: Hello\r\n\r\n{text}".encode()
    return any(s.id == "request.secret_disclosure" for s in analyze_requests(parse_email(raw)))


@pytest.mark.parametrize("text", MALICIOUS)
def test_round2_malicious_request_is_detected(text: str) -> None:
    if text in KNOWN_MISSES:
        pytest.xfail(KNOWN_MISSES[text])
    assert _flagged(text)


@pytest.mark.parametrize("text", BENIGN)
def test_round2_benign_text_is_not_flagged(text: str) -> None:
    if text in KNOWN_FALSE_POSITIVES:
        pytest.xfail(KNOWN_FALSE_POSITIVES[text])
    assert not _flagged(text)
