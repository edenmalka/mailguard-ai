"""Content analyzer tests: social-engineering language, negation, evasion, and false positives."""

import pytest

from app.analyzers.content import analyze_content, normalize_text
from app.parsing import parse_email

ZWSP = chr(0x200B)  # zero-width space, as a code point (no raw invisible characters)


def _ids(body: str, subject: str = "Hello", html: bool = False) -> set[str]:
    ctype = "text/html" if html else "text/plain"
    raw = (
        f"From: a@example.com\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\n"
        f"Content-Type: {ctype}; charset=utf-8\r\n\r\n{body}"
    ).encode()
    return {s.id for s in analyze_content(parse_email(raw))}


@pytest.mark.parametrize(
    ("text", "signal"),
    [
        ("Please verify your account to avoid interruption.", "content.credentials"),
        ("Confirm your password using the link below.", "content.credentials"),
        ("Update your payment information today.", "content.credentials"),
        ("Your mailbox has been suspended.", "content.credentials"),
        ("Your account will be locked in 24 hours.", "content.credentials"),
        ("Your mailbox is almost full.", "content.credentials"),
        ("Please process a wire transfer to our partner.", "content.payment"),
        ("Can you buy gift cards for the team?", "content.payment"),
        ("Our bank details have changed, use the new bank account.", "content.payment"),
        ("This is an overdue invoice reminder.", "content.payment"),
        ("Keep this confidential for now.", "content.secrecy"),
        ("Are you available? I need a quick favor.", "content.secrecy"),
        ("Congratulations, you have won!", "content.reward"),
        ("You are eligible for a refund.", "content.reward"),
        ("Respond within 24 hours.", "content.urgency"),
        ("FINAL NOTICE regarding your account.", "content.urgency"),
        ("Dear Customer, thank you.", "content.generic_greeting"),
        ("Dear Sir/Madam,", "content.generic_greeting"),
    ],
)
def test_social_engineering_phrases_are_detected(text: str, signal: str) -> None:
    assert signal in _ids(text)


def test_subject_and_html_body_are_both_checked() -> None:
    assert "content.urgency" in _ids("Hi", subject="Action required")
    assert "content.credentials" in _ids("<p>Please <b>verify your account</b></p>", html=True)


def test_script_and_style_text_is_ignored() -> None:
    html = "<style>.verify your account{}</style><script>var s='wire transfer'</script><p>Hi</p>"
    assert _ids(html, html=True) == set()


# --- evasion ---------------------------------------------------------------------------------


def test_invisible_characters_do_not_hide_phrases() -> None:
    assert "content.credentials" in _ids(f"Please ver{ZWSP}ify your acc{ZWSP}ount now.")


def test_full_width_letters_do_not_hide_phrases() -> None:
    full_width = "".join(chr(ord(c) + 0xFEE0) if c.isalpha() else c for c in "wire transfer")
    assert "content.payment" in _ids(f"Please send a {full_width} today.")


def test_normalize_text_unifies_case_whitespace_and_apostrophes() -> None:
    assert normalize_text(f"DON{chr(0x2019)}T\n\n  Tell") == "don't tell"


# --- false positives -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "We will never ask you to enter your password by email.",  # security advice (negated)
        "Please verify your email address to finish signing up.",  # normal sign-up email
        "Click here to reset your password if you requested it.",  # requested password reset
        "Your order has shipped and will arrive Tuesday.",
        "Invoice #1234 is attached for your records.",
        "Dear Maria, thanks for the meeting.",
        "Our summer sale ends Sunday. Shop now!",
        "Update your app to get the newest features.",
        "Do not reply to this message.",
        "Thanks for confirming your subscription.",
    ],
)
def test_ordinary_email_language_raises_nothing(text: str) -> None:
    assert _ids(text) == set()


def test_negation_only_applies_within_the_same_sentence() -> None:
    assert "content.credentials" in _ids("Do not reply. Enter your password here.")


def test_each_category_fires_once_with_example_phrases() -> None:
    raw = (
        b"From: a@example.com\r\nSubject: Urgent\r\n\r\n"
        b"Urgent: act now. Urgent! Immediately. Within 24 hours."
    )
    signals = analyze_content(parse_email(raw))
    assert [s.id for s in signals] == ["content.urgency"]
    assert signals[0].points == 5
    assert '"urgent"' in (signals[0].evidence or "")


def test_wording_alone_never_reaches_suspicious() -> None:
    """Every category at once still adds at most 25 points (Suspicious starts at 30)."""
    from app.analyzers.content import MAX_CONTENT_POINTS
    from app.pipeline import SUSPICIOUS_THRESHOLD

    body = (
        "Dear customer, urgent: verify your account. Wire transfer needed. "
        "Keep this confidential. You have won a prize."
    )
    raw = f"From: a@example.com\r\nSubject: Hi\r\n\r\n{body}".encode()
    signals = analyze_content(parse_email(raw))
    assert len(signals) == 6  # every category is still reported
    assert sum(s.points for s in signals) == MAX_CONTENT_POINTS < SUSPICIOUS_THRESHOLD
    assert [s.points for s in signals][-1] == 0  # past the budget: shown as "Info"


def test_legitimate_dunning_email_stays_low_risk() -> None:
    from app.pipeline import analyze_email

    raw = (
        b"Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\r\n"
        b"From: billing@example.com\r\nSubject: Overdue invoice\r\n\r\n"
        b"Your invoice is overdue. Please update your payment method. Action required."
    )
    result = analyze_email(raw, frozenset({"mx.google.com"}))
    assert result.verdict == "safe"
