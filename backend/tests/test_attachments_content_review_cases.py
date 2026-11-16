"""Review cases for the attachment and content analyzers, from an independent edge-case review.

Written BEFORE running the analyzers, in two rounds, to check generalization beyond the cases
used during development. The first round drove fixes (e-invoice PDFs, hex-encoded PDF names,
missed phrasings); the second round showed that adding phrases caused false positives, which
led to narrowing rules instead of adding more. Kept here as regression tests.
"""

import pytest

from app.analyzers.attachments import analyze_attachments
from app.analyzers.content import analyze_content
from app.analyzers.links import analyze_links
from app.parsing import parse_email
from tests.helpers import FAKE_EXE, OLE_HEADER, PDF_CLEAN, PNG, email_with_attachments, make_zip

OOXML_DECK = make_zip({"[Content_Types].xml": b"<Types/>", "ppt/presentation.xml": b"<p/>"})
OOXML_DOC = make_zip({"[Content_Types].xml": b"<T/>", "word/document.xml": b"<w/>"})

LEGITIMATE_ATTACHMENTS = [
    ("Dotted file name", ("Q3 Report v1.2.pdf", "application/pdf", PDF_CLEAN)),
    ("PowerPoint deck", ("deck.pptx", "application/vnd.openxmlformats", OOXML_DECK)),
    ("Calendar invite", ("invite.ics", "text/calendar", b"BEGIN:VCALENDAR\nEND:VCALENDAR")),
    ("Contact card", ("contact.vcf", "text/vcard", b"BEGIN:VCARD\nEND:VCARD")),
    ("Outlook .msg", ("forwarded.msg", "application/vnd.ms-outlook", OLE_HEADER)),
    ("winmail.dat", ("winmail.dat", "application/ms-tnef", b"\x78\x9f\x3e\x22" + bytes(32))),
    ("Inline logo", ("image001.png", "image/png", PNG)),
    (
        "PDF linking to own bank",
        ("s.pdf", "application/pdf", b"%PDF-1.4\n<</URI (https://www.example-bank.com/login)>>"),
    ),
    (
        "E-invoice PDF with embedded XML",
        ("inv.pdf", "application/pdf", b"%PDF-1.7\n<</Type /Filespec /F (factur-x.xml)>>"),
    ),
    (
        "Apple Pages document",
        ("l.pages", "application/zip", make_zip({"Index/Document.iwa": b"x", "p.jpg": PNG})),
    ),
    ("Uppercase JPG", ("IMG_2041.JPG", "image/jpeg", b"\xff\xd8\xff\xe0" + bytes(16))),
    ("Google Docs export", ("Notes.docx", "application/vnd.openxmlformats", OOXML_DOC)),
    (
        "Zip of photos and a PDF",
        ("trip.zip", "application/zip", make_zip({"a.jpg": PNG, "it.pdf": PDF_CLEAN})),
    ),
]

MALICIOUS_ATTACHMENTS = [
    (
        "Double extension .pdf.htm with form",
        (
            "Invoice.pdf.htm",
            "text/html",
            b"<form action='https://x.example/'><input type=password>",
        ),
        {"attachment.html_active"},
    ),
    (
        "SHTML with JS redirect",
        (
            "doc.shtml",
            "text/html",
            b"<script>window.location.replace('https://x.example')</script>",
        ),
        {"attachment.html_active"},
    ),
    (
        "Raw disk .img",
        ("photos.img", "application/octet-stream", bytes(64)),
        {"attachment.executable"},
    ),
    (
        "Excel add-in .xll",
        ("tool.xll", "application/octet-stream", FAKE_EXE),
        {"attachment.executable"},
    ),
    (
        "Program without extension",
        ("document", "application/octet-stream", FAKE_EXE),
        {"attachment.executable", "attachment.disguised"},
    ),
    (
        "Shortcut with decoy ext in zip",
        ("scan.zip", "application/zip", make_zip({"scan.pdf.lnk": b"L\x00\x00\x00"})),
        {"attachment.archive_executable", "attachment.disguised"},
    ),
    (
        "PDF with only hex-obfuscated /JavaScript",
        ("doc.pdf", "application/pdf", b"%PDF-1.7\n<</OpenAction <</S /J#61vaScript>>>>"),
        {"attachment.active_document"},
    ),
    (
        "PDF embedding a program",
        ("doc.pdf", "application/pdf", b"%PDF-1.7\n<</Type /Filespec /F (update.exe)>>"),
        {"attachment.active_document"},
    ),
    (
        "HTML attachment linking to look-alike",
        ("view.html", "text/html", b"<a href='https://micros0ft-login.example/'>Open</a>"),
        {"attachment.html", "link.lookalike"},
    ),
    (
        "Java archive",
        ("update.jar", "application/java-archive", b"PK\x03\x04"),
        {"attachment.executable"},
    ),
    (
        "VBS with decoy ext in zip",
        ("pay.zip", "application/zip", make_zip({"invoice.pdf.vbs": b"x"})),
        {"attachment.archive_executable", "attachment.disguised"},
    ),
    (
        "Trailing dot",
        ("invoice.exe.", "application/octet-stream", FAKE_EXE),
        {"attachment.executable"},
    ),
    (
        "Uppercase .EXE",
        ("SETUP.EXE", "application/octet-stream", FAKE_EXE),
        {"attachment.executable"},
    ),
    (
        "HTA application",
        ("view.hta", "application/hta", b"<script>x</script>"),
        {"attachment.executable"},
    ),
]

LEGITIMATE_TEXT = [
    "Your verification code is 482913. It expires in 10 minutes.",
    "Security alert: a new sign-in to your account was detected. If this was you, ignore this.",
    "Your payment of $12.99 was received. Thank you!",
    "Please confirm your attendance by Friday.",
    "Reminder: your subscription renews on March 3.",
    "We've updated our privacy policy.",
    "If you did not request this, please ignore this email.",
    "Don't miss our spring collection.",
    "Hi team, the quarterly numbers are attached. Let me know if you have questions.",
    "Free shipping and no delivery fee on orders over $50!",
    "Your password expires in 14 days. You can change it in the company portal.",
    "Reminder from HR: update your direct deposit details in Workday before Friday.",
    "Customs fees are included at checkout.",
    "Grades this term: A B C D F scale explained.",
    "J R R Tolkien fans meetup on Friday.",
    "Your package was delivered to the front door.",
    "Call us at 1 8 0 0 5 5 5 0 1 0 0 any time.",
    "Are you free on Tuesday for a call about the roadmap",
]

PHISHING_TEXT = [
    ("Kindly verify your identity to continue using our services.", {"content.credentials"}),
    ("Your Microsoft 365 password expires today. Keep it here.", {"content.credentials"}),
    ("Re-validate your mailbox now or lose access.", {"content.credentials"}),
    (
        "Are you available? I need you to purchase Apple gift cards for clients.",
        {"content.secrecy", "content.payment"},
    ),
    ("Your package could not be delivered. Pay the redelivery fee of $1.99.", {"content.payment"}),
    ("Please update my direct deposit information before the next payroll.", {"content.payment"}),
    ("This is your last warning before account termination.", {"content.urgency"}),
    ("Please v e r i f y your account now.", {"content.credentials"}),
    ("Your e-mail account will be deactivated today.", {"content.credentials"}),
    ("Confirm your billing details to avoid suspension.", {"content.credentials"}),
    ("Hey, are you free right now? need a favor.", {"content.secrecy"}),
    ("Claim your tax refund now.", {"content.reward"}),
    ("Your mail box quota has been exceeded.", {"content.credentials"}),
]


def _signals(attachments=(), body: str = "See attached.") -> set[str]:
    parsed = parse_email(email_with_attachments(list(attachments), body))
    attachment_analysis = analyze_attachments(parsed)
    ids = {s.id for s in attachment_analysis.signals}
    ids |= {s.id for s in analyze_links(parsed, attachment_analysis.urls).signals}
    ids |= {s.id for s in analyze_content(parsed)}
    return ids


@pytest.mark.parametrize(
    ("description", "attachment"),
    LEGITIMATE_ATTACHMENTS,
    ids=[c[0] for c in LEGITIMATE_ATTACHMENTS],
)
def test_legitimate_attachment_is_not_flagged(description: str, attachment) -> None:
    assert _signals([attachment]) == set()


@pytest.mark.parametrize(
    ("description", "attachment", "expected"),
    MALICIOUS_ATTACHMENTS,
    ids=[c[0] for c in MALICIOUS_ATTACHMENTS],
)
def test_malicious_attachment_is_detected(description: str, attachment, expected) -> None:
    assert expected <= _signals([attachment])


@pytest.mark.parametrize("text", LEGITIMATE_TEXT)
def test_legitimate_text_is_not_flagged(text: str) -> None:
    assert _signals(body=text) == set()


@pytest.mark.parametrize(("text", "expected"), PHISHING_TEXT, ids=[c[0] for c in PHISHING_TEXT])
def test_phishing_text_is_detected(text: str, expected: set[str]) -> None:
    assert expected <= _signals(body=text)


@pytest.mark.xfail(
    strict=True,
    reason="Known limitation: 'new account details' also appears in legitimate sign-up emails, "
    "so it is not matched. Phrase lists cannot separate these; see README limitations.",
)
def test_known_miss_payment_to_new_account_details() -> None:
    assert "content.payment" in _signals(body="Send the payment to the new account details below.")
