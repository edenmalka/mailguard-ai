"""Calibration DEVELOPMENT set: realistic labeled emails used to tune the scoring engine.

Tuning happened against these cases. Generalization is measured separately on the held-out
set (test_calibration_holdout.py), which was written before it was ever run.
"""

import pytest

from app.pipeline import analyze_email
from tests.corpus import FLAGGED, MALICIOUS, SAFE, SAFE_OR_SUSPICIOUS, Case, email
from tests.helpers import FAKE_EXE, PDF_CLEAN, PNG, make_zip

GMAIL = frozenset({"mx.google.com"})
OLE_MACRO = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(504) + "_VBA_PROJECT".encode("utf-16-le")

LEGITIMATE = [
    Case(
        "newsletter with tracking links",
        SAFE,
        email(
            "Example News <news@example.com>",
            subject="This week at Example",
            text="Top stories this week.",
            html='<p><a href="https://u1.ct.sendgrid.net/ls/click?x">www.example.com/stories</a></p>'
            '<p><a href="https://www.example.com/unsubscribe">Unsubscribe</a></p>',
        ),
    ),
    Case(
        "shipping notification",
        SAFE,
        email(
            "Example Shop <orders@example-shop.com>",
            subject="Your order is on the way",
            text="Your package is on the way. Track it: https://www.example-shop.com/track/123",
        ),
    ),
    Case(
        "bank statement ready",
        SAFE,
        email(
            "Example Bank <alerts@examplebank.com>",
            subject="Your statement is ready",
            text="Your monthly statement is ready. Sign in at https://www.examplebank.com to view it.",
        ),
    ),
    Case(
        "requested password reset",
        SAFE,
        email(
            "Accounts <no-reply@accounts.example.com>",
            subject="Reset your password",
            text="Reset your password: https://accounts.example.com/reset?t=abc. "
            "If you did not request this, please ignore this email.",
        ),
    ),
    Case(
        "real brand: payment method failed",
        SAFE,
        email(
            "Netflix <info@account.netflix.com>",
            subject="Update your payment method",
            text="We couldn't process your payment. Update your payment information at "
            "https://www.netflix.com/youraccount",
        ),
    ),
    Case(
        "colleague shares a PDF",
        SAFE,
        email(
            "Dana Levi <dana@corp.example.com>",
            subject="Q3 numbers",
            text="Hi, the Q3 report is attached. Let me know what you think.",
            attachments=(("Q3 Report.pdf", "application/pdf", PDF_CLEAN),),
        ),
    ),
    Case(
        "calendar invite",
        SAFE,
        email(
            "Calendar <calendar-notification@google.com>",
            subject="Invitation: Sync",
            text="You have been invited to Sync on Tuesday.",
            attachments=(("invite.ics", "text/calendar", b"BEGIN:VCALENDAR\nEND:VCALENDAR"),),
        ),
    ),
    Case(
        "marketing with shortener and urgency",
        SAFE,
        email(
            "Example Store <deals@example-store.com>",
            subject="48 hours only",
            text="Our sale ends soon, act now! https://bit.ly/3sale",
        ),
    ),
    Case(
        "small business replies via Gmail",
        SAFE_OR_SUSPICIOUS,
        email(
            "Rina's Bakery <orders@rinasbakery.example>",
            reply_to="mg-test-bakery@gmail.com",
            subject="Your order",
            text="Dear customer, your cake is ready for pickup.",
        ),
    ),
    Case(
        "IT password-expiry reminder",
        SAFE,
        email(
            "IT Service Desk <it@corp.example.com>",
            subject="Password reminder",
            text="Your password expires in 14 days. Change it in the company portal.",
        ),
    ),
    Case(
        "vendor invoice due in 30 days",
        SAFE,
        email(
            "Billing <billing@supplier.example>",
            subject="Invoice #881",
            text="Invoice #881 is attached. Payment is due in 30 days.",
            attachments=(("Invoice-881.pdf", "application/pdf", PDF_CLEAN),),
        ),
    ),
    Case(
        "mailing-list post failing DMARC",
        SAFE_OR_SUSPICIOUS,
        email(
            "Avi Cohen <avi@member.example>",
            auth=("softfail", "fail", "fail"),
            subject="[club] Meeting notes",
            text="Notes from tonight's meeting are below.",
        ),
    ),
    Case(
        "security alert from Google",
        SAFE,
        email(
            "Google <no-reply@accounts.google.com>",
            subject="Security alert",
            text="A new sign-in to your Google Account was detected. If this was you, you don't "
            "need to do anything.",
        ),
    ),
    Case(
        "tech newsletter with .xyz and many links",
        SAFE,
        email(
            "Dev Weekly <hello@devweekly.example>",
            subject="Issue 120",
            text="Links: https://abc.xyz https://www.example.com/a https://bit.ly/devlink",
        ),
    ),
    Case(
        "photos from a friend",
        SAFE,
        email(
            "Noa <mg-test-friend@gmail.com>",
            subject="Trip photos",
            text="Here are the photos!",
            attachments=(("trip.zip", "application/zip", make_zip({"a.jpg": PNG, "b.jpg": PNG})),),
        ),
    ),
]

PHISHING = [
    Case(
        "PayPal look-alike sender and link",
        MALICIOUS,
        email(
            "PayPal Support <service@paypal-secure.example>",
            reply_to="mg-test-paypal-help@gmail.com",
            subject="Account limited",
            text="Verify your account within 24 hours.",
            html='<p><a href="https://paypa1-login.example/signin">https://www.paypal.com/signin</a></p>',
        ),
    ),
    Case(
        "Microsoft 365 password expiry phish",
        MALICIOUS,
        email(
            "IT Helpdesk <it-support@helpdesk-mail.example>",
            subject="Password expiry",
            text="Your Microsoft 365 password expires today.",
            html="<p>Your Microsoft 365 password expires today. "
            '<a href="https://m365-portal.example/keep">https://login.microsoftonline.com</a></p>',
        ),
    ),
    Case(
        "CEO gift-card fraud from webmail",
        FLAGGED,
        email(
            "Michael Stern <mg-test-ceo@gmail.com>",
            subject="Quick request",
            text="Are you available? I need a favor. Buy gift cards for clients and keep this "
            "confidential.",
        ),
    ),
    Case(
        "supplier bank-detail change",
        FLAGGED,
        email(
            "Accounts <accounts@supplier.example>",
            reply_to="mg-test-supplier@outlook.com",
            subject="Updated bank details",
            text="Our bank details have changed. Please use the new bank account for invoice 554.",
        ),
    ),
    Case(
        "zip with disguised executable",
        MALICIOUS,
        email(
            "Billing <billing@random-vendor.example>",
            subject="Overdue invoice",
            text="URGENT: overdue invoice attached.",
            attachments=(
                ("Invoice.zip", "application/zip", make_zip({"Invoice.pdf.exe": FAKE_EXE})),
            ),
        ),
    ),
    Case(
        "macro document",
        FLAGGED,
        email(
            "Accounts <accounts@random-vendor.example>",
            subject="Invoice",
            text="Please review the attached invoice.",
            attachments=(("Invoice.doc", "application/msword", OLE_MACRO),),
        ),
    ),
    Case(
        "HTML attachment credential page",
        MALICIOUS,
        email(
            "Payments <payments@remit-notice.example>",
            subject="Remittance advice",
            text="Dear customer, verify your account to view the remittance.",
            attachments=(
                (
                    "Remittance.htm",
                    "text/html",
                    b"<form action='https://collect.example/'><input type=password></form>",
                ),
            ),
        ),
    ),
    Case(
        "bank spoof failing DMARC",
        MALICIOUS,
        email(
            "Example Bank <security@examplebank.com>",
            auth=("fail", "none", "fail"),
            reply_to="mg-test-bank-security@gmail.com",
            subject="Unusual activity",
            text="Confirm your identity to restore access.",
        ),
    ),
    Case(
        "parcel redelivery fee scam",
        MALICIOUS,
        email(
            "DHL Express <noreply@dhl-parcel-track.example>",
            subject="Delivery failed",
            text="Your parcel could not be delivered. Pay the redelivery fee here: "
            "https://dhl-redeliver.example/pay",
        ),
    ),
    Case(
        "QR-code phishing (image only)",
        FLAGGED,
        email(
            "Security <security@mail-notice.example>",
            subject="Action required",
            text="Scan the QR code to verify your account.",
            attachments=(("qr.png", "image/png", PNG),),
        ),
    ),
    Case(
        "mailbox suspension with IP link",
        FLAGGED,
        email(
            "Mail Admin <admin@mailbox-service.example>",
            subject="Mailbox suspended",
            text="Your mailbox will be suspended. Restore it: http://203.0.113.5/login",
        ),
    ),
    Case(
        "encrypted zip with password",
        FLAGGED,
        email(
            "Sara <sara@contractor.example>",
            subject="Documents",
            text="Documents attached. Password: 7731",
            attachments=(
                ("Docs.zip", "application/zip", make_zip({"docs.pdf": PDF_CLEAN}, encrypted=True)),
            ),
        ),
    ),
    Case(
        "Apple ID lock from webmail",
        MALICIOUS,
        email(
            "Apple Support <mg-test-apple-support@gmail.com>",
            subject="Your Apple ID has been locked",
            text="Your Apple ID has been locked. Unlock your account now.",
            html='<p><a href="https://apple-id-unlock.example/">https://appleid.apple.com</a></p>',
        ),
    ),
    Case(
        "gift cards with look-alike reply",
        MALICIOUS,
        email(
            "Finance Director <director@corp-finance.example>",
            reply_to="mg-test-finance-director@gmail.com",
            subject="Urgent",
            text="I need a favor, urgently. Purchase gift cards today and keep this confidential.",
        ),
    ),
    Case(
        "fake DocuSign",
        FLAGGED,
        email(
            "DocuSign <dse@docusign-mail.example>",
            subject="Please review the document",
            text="You have a document to review.",
            html='<p><a href="https://docs-review.example/view">REVIEW DOCUMENT</a></p>',
        ),
    ),
]

KNOWN_DEV_MISSES = {
    # Image-only QR phishing: MailGuard does not read images (documented limitation).
    "QR-code phishing (image only)",
}


@pytest.mark.parametrize("case", LEGITIMATE + PHISHING, ids=lambda c: c.name)
def test_dev_case(case: Case) -> None:
    if case.name in KNOWN_DEV_MISSES:
        pytest.xfail("known limitation")
    result = analyze_email(case.raw, GMAIL)
    assert result.verdict in case.expected, (
        result.score,
        [(s.id, s.points) for s in result.signals],
    )
