"""Generate the synthetic demo emails in ../demo (one per verdict and attack pattern).

Run from backend/:  uv run python scripts/make_demo_emails.py

All content is synthetic and safe: reserved .example domains, clearly fake "mg-test-*" webmail
addresses, and attachments that only LOOK like dangerous files (e.g. "MZ" + zero bytes, which
cannot run). The Authentication-Results header is simulated, as Gmail would write it.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.corpus import email as build_email  # noqa: E402
from tests.helpers import FAKE_EXE, make_zip  # noqa: E402

DEMO_DIR = Path(__file__).resolve().parents[2] / "demo"


def email(*args, **kwargs) -> bytes:
    """Build a demo email with a deterministic MIME boundary, so regenerating gives
    byte-identical files (the stdlib picks boundaries at random)."""
    random.seed(0)  # noqa: S311 - not security-relevant, only MIME boundary text
    return build_email(*args, **kwargs)


DEMO_EMAILS: dict[str, bytes] = {
    "01_low_risk_newsletter.eml": email(
        "Example News <news@example.com>",
        subject="This week at Example",
        text="Hi! Here are this week's top stories.",
        html='<p>Top stories: <a href="https://u1.ct.sendgrid.net/ls/click?x">'
        "www.example.com/stories</a></p>",
    ),
    "02_credential_phishing.eml": email(
        "PayPal Support <service@paypal-secure.example>",
        reply_to="mg-test-paypal-help@gmail.com",
        subject="Your account has been limited",
        text="We noticed unusual activity. Verify your account within 24 hours.",
        html="<p>We noticed unusual activity. Verify your account within 24 hours.</p>"
        '<p><a href="https://paypa1-login.example/signin">https://www.paypal.com/signin</a></p>',
    ),
    "03_payment_fraud_ceo.eml": email(
        "Daniel Rosen <mg-test-ceo@gmail.com>",
        subject="Quick request",
        text="Are you available? I need a favor. Buy gift cards for a client and keep this "
        "confidential until I call you.",
    ),
    "04_malware_delivery.eml": email(
        "Billing <billing@vendor-invoices.example>",
        subject="Overdue invoice",
        text="URGENT: your overdue invoice is attached. Please pay immediately.",
        attachments=(("Invoice.zip", "application/zip", make_zip({"Invoice.pdf.exe": FAKE_EXE})),),
    ),
    "05_sender_spoofing.eml": email(
        "Example Bank Security <security@examplebank.example>",
        auth=("fail", "none", "fail"),
        reply_to="mg-test-bank-security@gmail.com",
        subject="Unusual sign-in",
        text="We need to discuss recent activity on your account. Please reply with a "
        "convenient time for a call.",
    ),
    "06_html_attachment_phishing.eml": email(
        "Payments <payments@remittance-notice.example>",
        subject="Remittance advice",
        text="Dear customer, verify your account to view the attached remittance.",
        attachments=(
            (
                "Remittance.htm",
                "text/html",
                b"<form action='https://collect.example/'><input type=password></form>",
            ),
        ),
    ),
    "08_credential_theft_by_reply.eml": email(
        "IT Support <mg-test-it-support@gmail.com>",
        subject="Employee account verification",
        text="Hello,\n\nWe are updating our employee access records this week.\n\n"
        "To prevent your account from being suspended, please reply directly to this email with "
        "your work email address, current password, and the latest verification code sent to "
        "your phone.\n\nPlease complete this today so your access is not interrupted.\n\n"
        "IT Support",
    ),
    "07_inconclusive_archive.eml": email(
        "Sara <sara@contractor.example>",
        subject="Files",
        text="The files are attached.",
        attachments=(("files.rar", "application/x-rar", b"Rar!\x1a\x07\x01\x00" + bytes(16)),),
    ),
}


def main() -> None:
    DEMO_DIR.mkdir(exist_ok=True)
    for name, raw in DEMO_EMAILS.items():
        (DEMO_DIR / name).write_bytes(raw)
        print(f"wrote demo/{name} ({len(raw)} bytes)")


if __name__ == "__main__":
    main()
