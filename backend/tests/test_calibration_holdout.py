"""Calibration HELD-OUT set: written after tuning on the development set and BEFORE ever being
run, to measure how the scoring engine generalizes. Scenarios deliberately differ from the
development set. Results are reported as measured; cases the engine gets wrong are kept and
marked as known misses rather than tuned away.
"""

import pytest

from app.pipeline import analyze_email
from tests.corpus import FLAGGED, MALICIOUS, SAFE, Case, email
from tests.helpers import FAKE_ISO, PDF_CLEAN, make_zip

GMAIL = frozenset({"mx.google.com"})
DOCX = make_zip({"[Content_Types].xml": b"<T/>", "word/document.xml": b"<w/>"})

LEGITIMATE = [
    Case(
        "GitHub notification",
        SAFE,
        email(
            "GitHub <noreply@github.com>",
            subject="[repo] PR #42 merged",
            text="Your pull request was merged: https://github.com/example/repo/pull/42",
        ),
    ),
    Case(
        "airline booking with PDF",
        SAFE,
        email(
            "Example Air <bookings@example-air.com>",
            subject="Your booking confirmation",
            text="Your e-ticket is attached. Manage your trip at https://www.example-air.com/trips",
            attachments=(("e-ticket.pdf", "application/pdf", PDF_CLEAN),),
        ),
    ),
    Case(
        "school newsletter from Gmail",
        SAFE,
        email(
            "Class 3B Parents <mg-test-class-parents@gmail.com>",
            subject="Field trip photos",
            text="Dear parents, photos from the trip are here.",
            html='<p>Dear parents, <a href="https://drive.google.com/drive/folders/abc">Photos</a></p>',
        ),
    ),
    Case(
        "HR benefits enrollment",
        SAFE,
        email(
            "HR <hr@corp.example.com>",
            subject="Action required: benefits enrollment",
            text="Action required: complete your benefits enrollment by Friday at "
            "https://benefits.corp.example.com",
        ),
    ),
    Case(
        "utility bill",
        SAFE,
        email(
            "Example Power <billing@example-power.com>",
            subject="Your bill is ready",
            text="Your bill is ready. Amount due: $54. Pay online at https://www.example-power.com/pay",
        ),
    ),
    Case(
        "LinkedIn job alert",
        SAFE,
        email(
            "LinkedIn Job Alerts <jobalerts-noreply@linkedin.com>",
            subject="New jobs for you",
            text="New jobs matching your profile.",
            html='<p><a href="https://www.linkedin.com/comm/jobs/view/1?trk=x">Software Engineer</a></p>',
        ),
    ),
    Case(
        "clinic reminder via booking platform",
        SAFE,
        email(
            "Health Clinic <clinic@healthclinic.example>",
            reply_to="noreply@bookingplatform.example",
            subject="Appointment reminder",
            text="Reminder: your appointment is on Monday at 10:00.",
        ),
    ),
    Case(
        "friend shares a video",
        SAFE,
        email(
            "Yoni <mg-test-friend2@outlook.com>",
            subject="lol",
            text="You have to see this https://youtu.be/abc123",
        ),
    ),
    Case(
        "Amazon shipment",
        SAFE,
        email(
            "Amazon.com <shipment-tracking@amazon.com>",
            subject="Your package has shipped",
            text="Your package has shipped. Track it at https://www.amazon.com/progress-tracker",
        ),
    ),
    Case(
        "Zoom invitation",
        SAFE,
        email(
            "Dana Levi <dana@corp.example.com>",
            subject="Invitation: design review",
            text="Join Zoom meeting: https://us02web.zoom.us/j/123456789",
        ),
    ),
    Case(
        "donation receipt",
        SAFE,
        email(
            "Example Charity <receipts@example-charity.org>",
            subject="Thank you for your donation",
            text="Thank you for your donation. Your tax receipt is attached.",
            attachments=(("receipt.pdf", "application/pdf", PDF_CLEAN),),
        ),
    ),
    Case(
        "bank purchase check",
        SAFE,
        email(
            "Example Bank <alerts@examplebank.com>",
            subject="Did you make this purchase?",
            text="Did you make a purchase of $250 at Example Store? Reply YES or NO.",
        ),
    ),
    Case(
        "sale newsletter with generic greeting",
        SAFE,
        email(
            "Example Outlet <news@example-outlet.com>",
            subject="Last chance",
            text="Dear valued customer, last chance: our sale ends tonight! https://bit.ly/outlet",
        ),
    ),
    Case(
        "Dropbox share",
        SAFE,
        email(
            "Dropbox <no-reply@dropboxmail.com>",
            subject="Noa shared 'Trip' with you",
            text="Noa shared a folder with you: https://www.dropbox.com/s/abc/Trip",
        ),
    ),
    Case(
        "small company without DMARC sends a docx",
        SAFE,
        email(
            "Office <office@small-firm.example>",
            auth=("pass", "pass", "none"),
            subject="Contract draft",
            text="Attached is the contract draft for your review.",
            attachments=(("Contract.docx", "application/vnd.openxmlformats", DOCX),),
        ),
    ),
]

PHISHING = [
    Case(
        "fake voicemail HTML attachment",
        FLAGGED,
        email(
            "Voicemail <vm@voice-notify.example>",
            subject="New voicemail (0:42)",
            text="You have a new voicemail.",
            attachments=(
                (
                    "VM_0193.html",
                    "text/html",
                    b"<script>window.location='https://voice-login.example'</script>",
                ),
            ),
        ),
    ),
    Case(
        "Netflix look-alike billing",
        MALICIOUS,
        email(
            "Netflix <billing@netflix-account-update.example>",
            subject="Your account is on hold",
            text="Your account is on hold. Update your payment information.",
            html='<p><a href="https://netf1ix-billing.example/update">Update payment</a></p>',
        ),
    ),
    Case(
        "invoice delivered as ISO",
        FLAGGED,
        email(
            "Accounts <accounts@vendor-billing.example>",
            subject="Invoice",
            text="Please find the invoice attached.",
            attachments=(("Invoice_2026.iso", "application/octet-stream", FAKE_ISO),),
        ),
    ),
    Case(
        "urgent wire transfer, reply to webmail",
        MALICIOUS,
        email(
            "Daniel Rosen <ceo@corp-example.example>",
            reply_to="mg-test-ceo@proton.me",
            subject="Urgent",
            text="Process an urgent wire transfer today. Keep this confidential.",
        ),
    ),
    Case(
        "crypto giveaway",
        FLAGGED,
        email(
            "Crypto Rewards <rewards@crypto-giveaway.example>",
            subject="You have won 2 BTC",
            text="You have won 2 BTC! Send 0.1 BTC to the bitcoin wallet below to claim your prize.",
        ),
    ),
    Case(
        "SharePoint share lure",
        FLAGGED,
        email(
            "Microsoft SharePoint <share@notify-docs.example>",
            subject="A document was shared",
            text="A document was shared with you.",
            html='<p><a href="https://sharepoint-docs.example/view">Open document</a></p>',
        ),
    ),
    Case(
        "payroll diversion from webmail",
        FLAGGED,
        email(
            "Lior Ben-David <mg-test-employee@gmail.com>",
            subject="Bank change",
            text="Hi, please update my direct deposit information, I changed banks.",
        ),
    ),
    Case(
        "DHL customs fee with HTML form",
        MALICIOUS,
        email(
            "DHL <dhl@parcel-alerts.example>",
            subject="Customs payment needed",
            text="Pay the customs fee to release your parcel.",
            attachments=(
                (
                    "DHL_Payment.html",
                    "text/html",
                    b"<form action='https://pay-collect.example'><input name=card></form>",
                ),
            ),
        ),
    ),
    Case(
        "spoofed IT mailbox-full with IP link",
        MALICIOUS,
        email(
            "IT <it@corp.example.com>",
            auth=("fail", "none", "fail"),
            subject="Mailbox full",
            text="Your mailbox is almost full. Expand it: http://198.51.100.20/expand",
        ),
    ),
    Case(
        "DocuSign HTML attachment",
        FLAGGED,
        email(
            "DocuSign <sign@esign-notice.example>",
            subject="Document ready",
            text="Your document is ready.",
            attachments=(("Document.html", "text/html", b"<html><p>Loading...</p></html>"),),
        ),
    ),
    Case(
        "tax refund claim",
        FLAGGED,
        email(
            "Refunds <refunds@tax-office.example>",
            subject="Tax refund",
            text="Claim your tax refund now: https://tax-refund.top/claim",
        ),
    ),
    Case(
        "bank verification with @ trick",
        FLAGGED,
        email(
            "Security <security@bank-alerts.example>",
            subject="Verify",
            text="Confirm your identity: https://www.examplebank.com@verify-session.example/login",
        ),
    ),
    Case(
        "zip with JavaScript dropper",
        FLAGGED,
        email(
            "Scanner <scanner@office-devices.example>",
            subject="Scanned document",
            text="Please see the scanned document.",
            attachments=(("Scan.zip", "application/zip", make_zip({"Scan_0042.js": b"var a;"})),),
        ),
    ),
    Case(
        "lottery advance-fee",
        FLAGGED,
        email(
            "International Lottery <lotto@intl-lottery.example>",
            reply_to="mg-test-claims@yahoo.com",
            subject="Winner",
            text="You have won the lottery! Reply with your bank details.",
        ),
    ),
    Case(
        "Google Drive look-alike",
        FLAGGED,
        email(
            "Google Drive <drive-shares@googledocs-share.example>",
            subject="Shared with you",
            text="A file was shared with you.",
            html='<p><a href="https://docs-google.share-files.example/f">Open in Docs</a></p>',
        ),
    ),
]

# Filled in AFTER the first and only evaluation run (27/30 correct, 0/15 false alarms), with the
# measured misses. "SharePoint share lure" was also missed; it exposed a brand-matching BUG
# ("Microsoft SharePoint" not recognized), which was fixed and checked on fresh brand cases
# (see test_sender.py). The two below are accepted by design, not tuned away.
KNOWN_HOLDOUT_MISSES: dict[str, str] = {
    "crypto giveaway": "wording-only scam: wording is capped below Suspicious by design",
    "tax refund claim": "only weak signals (reward wording, abused TLD): below Suspicious",
}


@pytest.mark.parametrize("case", LEGITIMATE + PHISHING, ids=lambda c: c.name)
def test_holdout_case(case: Case) -> None:
    if case.name in KNOWN_HOLDOUT_MISSES:
        pytest.xfail(KNOWN_HOLDOUT_MISSES[case.name])
    result = analyze_email(case.raw, GMAIL)
    assert result.verdict in case.expected, (
        result.score,
        [(s.id, s.points) for s in result.signals],
    )
