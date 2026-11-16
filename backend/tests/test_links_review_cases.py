"""Review cases for the link analyzer, from an independent edge-case review.

These were written BEFORE running the analyzer, to check generalization beyond the
cases used during development. Several initially failed and drove fixes (security
gateway rewrites, redirects, file-name link text, brand-as-subdomain, Windows link
schemes, browser-tolerated malformed URLs). Kept here as regression tests.
"""

import pytest

from app.analyzers.links import analyze_links
from app.parsing import parse_email

LEGITIMATE = [
    (
        "Outlook Safe Links rewrite",
        '<a href="https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.example.com%2F&data=x">www.example.com</a>',
    ),
    (
        "Proofpoint URL Defense rewrite",
        '<a href="https://urldefense.com/v3/__https://www.example.com/__;!!abc">https://www.example.com</a>',
    ),
    (
        "Mimecast rewrite",
        '<a href="https://protect-eu.mimecast.com/s/AbCd?domain=example.com">www.example.com</a>',
    ),
    (
        "Google redirect to same site",
        '<a href="https://www.google.com/url?q=https://www.example.com/">www.example.com</a>',
    ),
    (
        "Download link named report.zip",
        '<a href="https://drive.google.com/file/d/abc/view">report.zip</a>',
    ),
    (
        "Video named intro.mov",
        '<a href="https://www.dropbox.com/s/abc/intro.mov?dl=0">intro.mov</a>',
    ),
    ("Product name ASP.NET", '<a href="https://learn.microsoft.com/aspnet">ASP.NET</a>'),
    ("Product name Socket.IO", '<a href="https://socket.io/docs">Socket.IO</a>'),
    (
        "Script name setup.py",
        '<a href="https://github.com/example/repo/blob/main/setup.py">setup.py</a>',
    ),
    ("Medium @user path", '<a href="https://medium.com/@someone/post-1">Read on Medium</a>'),
    (
        "Email address as link text",
        '<a href="https://example.zendesk.com/hc">support@example.com</a>',
    ),
    ("Uppercase scheme", '<a href="HTTPS://WWW.EXAMPLE.COM/">www.example.com</a>'),
    ("Brand official subdomain", '<a href="https://www.paypal.com/myaccount">Log in to PayPal</a>'),
    (
        "Amazon SES tracking",
        '<a href="https://abc.r.us-east-1.awstrack.me/L0/https:%2F%2Fwww.example.com">www.example.com</a>',
    ),
    (
        "Facebook share link with embedded URL",
        '<a href="https://www.facebook.com/sharer/sharer.php?u=https%3A%2F%2Fwww.example.com%2Fpost">Share</a>',
    ),
    (
        "Tracking param pointing to own site",
        '<a href="https://www.example.com/go?redirect=https://www.example.com/sale">Shop the sale</a>',
    ),
    ("Google Docs link", '<a href="https://docs.google.com/document/d/abc/edit">Project plan</a>'),
    (
        "Calendar response",
        '<a href="https://calendar.google.com/calendar/event?action=RESPOND&eid=x">Yes</a>',
    ),
    (
        "Zoom meeting",
        '<a href="https://us02web.zoom.us/j/123456789">https://us02web.zoom.us/j/123456789</a>',
    ),
    ("Phone number as text", '<a href="tel:+18005550100">1.800.555.0100</a>'),
    ("Version number as text", '<a href="https://example.com/changelog">v2.5.1</a>'),
    ("Abbreviation U.S.", '<a href="https://example.com/us">U.S.</a>'),
    ("Capitalized own domain", '<a href="https://www.example.com/">Example.com</a>'),
    (
        "GitHub repo of a brand",
        '<a href="https://github.com/apple/swift">github.com/apple/swift</a>',
    ),
    ("Amazon jobs site", '<a href="https://www.amazon.jobs/en/">Amazon jobs</a>'),
    ("PayPal.me link", '<a href="https://paypal.me/someone">paypal.me/someone</a>'),
    ("Apple App Store", '<a href="https://apps.apple.com/app/id1">Download on the App Store</a>'),
    (
        "Brand word inside unrelated path",
        '<a href="https://news.example.com/paypal-earnings">Read</a>',
    ),
    ("Image file name text", '<a href="https://cdn.example.com/x/photo.jpg">photo.jpg</a>'),
]

PHISHING = [
    (
        "Google open redirect to look-alike",
        '<a href="https://www.google.com/url?q=https://paypa1.example/login">Sign in</a>',
        ["link.lookalike"],
    ),
    (
        "Brand as subdomain label of unrelated domain",
        '<a href="https://paypal.account-verify.example/">Sign in</a>',
        ["link.lookalike"],
    ),
    (
        "Brand label then com-something",
        '<a href="https://paypal.com-login.example/">Sign in</a>',
        ["link.lookalike"],
    ),
    ("Single-slash scheme", '<a href="http:/192.0.2.5/login">Sign in</a>', ["link.ip_address"]),
    (
        "No-slash scheme",
        '<a href="https:evil.example/">https://www.paypal.com</a>',
        ["link.text_mismatch"],
    ),
    (
        "Zero-width char in link text",
        '<a href="https://evil.example/">pay\u200bpal.com</a>',
        ["link.text_mismatch"],
    ),
    (
        "Full-width dot in host",
        '<a href="https://paypa1\uff0ecom/">Sign in</a>',
        ["link.lookalike"],
    ),
    (
        "Executable via query parameter",
        '<a href="https://dl.example.net/get.php?file=invoice.exe">Invoice</a>',
        ["link.dangerous_file"],
    ),
    (
        "ms-msdt protocol handler",
        '<a href="ms-msdt:/id PCWDiagnostic">Fix</a>',
        ["link.script_scheme"],
    ),
    (
        "file:// UNC share",
        '<a href="file://198.51.100.9/share/doc.lnk">Document</a>',
        ["link.script_scheme"],
    ),
    (
        "search-ms protocol",
        '<a href="search-ms:query=invoice&crumb=location:\\\\evil.example">Open</a>',
        ["link.script_scheme"],
    ),
    ("Hex IP with path", '<a href="http://0xC0A80001/login">x</a>', ["link.ip_address"]),
    (
        "Safe Links wrapping a look-alike",
        '<a href="https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpaypa1.example%2F">Sign in</a>',
        ["link.lookalike"],
    ),
    (
        "Microsoft login domain as subdomain",
        '<a href="https://login.microsoftonline.com.session-check.example/">Sign in</a>',
        ["link.lookalike"],
    ),
    (
        "Homoglyph + extra word in sender-style domain",
        '<a href="https://micros0ft-support.example/">Help</a>',
        ["link.lookalike"],
    ),
    (
        "Brand text, shortener destination",
        '<a href="https://bit.ly/3xYz">paypal.com</a>',
        ["link.shortener", "link.text_mismatch"],
    ),
    (
        "Uppercase brand domain as text",
        '<a href="https://evil.example/">PAYPAL.COM</a>',
        ["link.text_mismatch"],
    ),
    (
        "Mixed-case brand domain as text",
        '<a href="https://evil.example/">PayPal.com</a>',
        ["link.text_mismatch"],
    ),
    (
        "Percent-encoded dot in host",
        '<a href="https://paypa1%2Ecom/">Sign in</a>',
        ["link.lookalike"],
    ),
    ("Leading newline in href", '<a href="\nhttps://198.51.100.4/">Open</a>', ["link.ip_address"]),
    (
        "Open redirect to IP via 'url' param",
        '<a href="https://www.example.com/r?url=http%3A%2F%2F203.0.113.8%2Flogin">Open</a>',
        ["link.ip_address"],
    ),
    (
        "Redirect to executable",
        '<a href="https://www.google.com/url?q=https://dl.example.net/Invoice.pdf.exe">Invoice</a>',
        ["link.dangerous_file"],
    ),
    (
        "Brand as subdomain on real-world style TLD",
        '<a href="https://dhl.parcel-redelivery.example/">Track</a>',
        ["link.lookalike"],
    ),
]


def _signals(html: str) -> set[str]:
    raw = (
        "From: a@example.com\r\nMIME-Version: 1.0\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n\r\n{html}"
    ).encode()
    return {s.id for s in analyze_links(parse_email(raw)).signals}


@pytest.mark.parametrize(("description", "html"), LEGITIMATE, ids=[c[0] for c in LEGITIMATE])
def test_legitimate_link_is_not_flagged(description: str, html: str) -> None:
    assert _signals(html) == set()


@pytest.mark.parametrize(
    ("description", "html", "expected"), PHISHING, ids=[c[0] for c in PHISHING]
)
def test_phishing_link_is_detected(description: str, html: str, expected: list[str]) -> None:
    assert set(expected) <= _signals(html)
