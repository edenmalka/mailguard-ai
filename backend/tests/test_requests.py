"""Secret-disclosure request rule and the "credential theft by reply" pattern.

The prototype cases below were used while designing the rule ("seen"). Independent measurement
is in test_requests_holdout*.py (three rounds written before running).
"""

import pytest

from app.analyzers.requests import POINTS_SECRET_REQUEST, analyze_requests
from app.parsing import parse_email
from app.pipeline import analyze_email
from tests.corpus import email

GMAIL = frozenset({"mx.google.com"})

# The email that MailGuard missed in a live Gmail test (scored Low risk 0/100 before the fix).
GMAIL_TEST_BODY = (
    "Hello,\n\nWe are updating our employee access records this week.\n\n"
    "To prevent your account from being suspended, please reply directly to this email with "
    "your work email address, current password, and the latest verification code sent to your "
    "phone.\n\nPlease complete this today so your access is not interrupted.\n\nIT Support"
)


def _flagged(text: str) -> bool:
    raw = f"From: a@example.com\r\nSubject: Hello\r\n\r\n{text}".encode()
    return any(s.id == "request.secret_disclosure" for s in analyze_requests(parse_email(raw)))


@pytest.mark.parametrize(
    "text",
    [
        GMAIL_TEST_BODY,
        "Reply with your username and password to keep your mailbox active.",
        "Send me the verification code that was just texted to you.",
        "Please text me the 6-digit code you received.",
        "Kindly provide us your online banking PIN and card security code.",
        "Forward the one-time passcode sent to your mobile to complete verification.",
        "Email us your recovery codes so we can restore access.",
        "Confirm your identity by replying with your SSN and date of birth.",
        "Respond with your current and new password so IT can migrate your account.",
        # multi-sentence: the request is in a later sentence than the setup
        "We are moving to a new mail system. Please reply. Include your password and PIN.",
        # an unrelated negation must not cancel the request
        "Don't hesitate: reply with your password now.",
        "I can't log in, can you send me your 2FA code?",
    ],
)
def test_requests_to_send_a_secret_are_detected(text: str) -> None:
    assert _flagged(text)


@pytest.mark.parametrize(
    "text",
    [
        # negation that governs the request verb, including contractions
        "Your verification code is 482913. Do not share this code with anyone.",
        "We will never ask you to send your password or PIN by email.",
        "Never share your one-time code, even with our support team.",
        "We won't ever ask you to send your PIN.",
        "Our agents won't text you asking for your verification code.",
        "Staff doesn't need your password, so don't email it.",
        # the secret is mentioned, but not requested
        "If you forgot your password, reply to this email and we'll help you reset it.",
        "Enter the code sent to your phone on the sign-in page.",
        "Tell your manager if you notice anyone asking for your password.",
        "You will be asked to provide your current password when you change it in the portal.",
        # not a secret: password policies, resets, managers, shared access codes, documents
        "I'll send the password for the PDF in a separate email.",
        "Please send your password reset request through the IT portal.",
        "Give your team the password manager link.",
        "Share your screen and your meeting passcode with the guest speaker.",
        "Share your Wi-Fi password with guests using the QR code on the fridge.",
        "Share your ideas for the new security code of conduct.",
        # nouns that look like request verbs
        "This email contains your PIN reminder from the branch.",
        "Your welcome email includes your login and a link to set your password.",
        "This text message contains your verification code.",
        # ordinary requests without secrets
        "Reply with your availability for Tuesday.",
        "Share the discount code you received with a friend.",
    ],
)
def test_benign_mentions_are_not_flagged(text: str) -> None:
    assert not _flagged(text)


def test_signal_scores_and_explains() -> None:
    raw = b"From: a@example.com\r\n\r\nReply with your password."
    (signal,) = analyze_requests(parse_email(raw))
    assert signal.category == "request"
    assert signal.points == POINTS_SECRET_REQUEST
    assert "reply with your password" in (signal.evidence or "")


# --- pipeline: verdicts and the new attack pattern --------------------------------------------


def test_missed_gmail_test_email_is_now_malicious() -> None:
    raw = email(
        "test mailguard <mg-test-demo-sender@gmail.com>",
        subject="Employee account verification",
        text=GMAIL_TEST_BODY,
    )
    result = analyze_email(raw, GMAIL)
    assert result.verdict == "malicious"
    assert result.attack_patterns[0].id == "credential_theft_by_reply"
    ids = {s.id for s in result.signals}
    assert {"request.secret_disclosure", "content.credentials", "sender.free_webmail"} <= ids


def test_secret_request_alone_is_suspicious() -> None:
    raw = email(
        "IT Desk <it@corp.example.com>",
        subject="Access review",
        text="For the access review, please reply with your network password.",
    )
    result = analyze_email(raw, GMAIL)
    assert result.verdict == "suspicious"
    assert result.score == POINTS_SECRET_REQUEST
    assert result.attack_patterns == []  # no pressure or identity trick: no pattern bonus


@pytest.mark.parametrize(
    "text",
    [
        "Your one-time password is 551204. It expires in 5 minutes. Never share it.",
        "For your security, we will never ask you to reply with your password.",
    ],
)
def test_legitimate_security_emails_stay_low_risk(text: str) -> None:
    raw = email("Example Bank <alerts@examplebank.example>", subject="Security", text=text)
    assert analyze_email(raw, GMAIL).verdict == "safe"
