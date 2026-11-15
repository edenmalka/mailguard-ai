"""End-to-end tests: fixtures through the pipeline and through the signed HTTP API."""

import time

import pytest

from app.analyzers.urls import MAX_LINKS
from app.parsing import MAX_TEXT_CHARS
from app.pipeline import (
    LIMIT_MALFORMED,
    LIMIT_NO_AUTH,
    LIMIT_NO_SENDER,
    LIMIT_PARTIAL_CONTENT,
    LIMIT_UNINSPECTED_ATTACHMENTS,
    analyze_email,
)
from tests.conftest import encode_message
from tests.helpers import GMAIL, load_fixture


def _ids(result) -> set[str]:
    return {s.id for s in result.signals}


def test_legitimate_newsletter_is_safe() -> None:
    result = analyze_email(load_fixture("legit_newsletter.eml"), GMAIL)
    assert result.verdict == "safe"
    assert result.score == 0
    assert result.authentication is not None and result.authentication.source == "reported"


def test_authenticated_lookalike_phish_is_malicious() -> None:
    # Passes SPF/DKIM/DMARC for its own look-alike domain: authentication alone would miss it.
    result = analyze_email(load_fixture("phish_paypal_lookalike.eml"), GMAIL)
    assert result.verdict == "malicious"
    assert {
        "sender.lookalike_domain",
        "sender.brand_impersonation",
        "sender.reply_to_freemail",
    } <= _ids(result)
    assert result.authentication is not None and result.authentication.dmarc == "pass"


def test_spoofed_brand_failing_dmarc_is_malicious() -> None:
    result = analyze_email(load_fixture("spoofed_dmarc_fail.eml"), GMAIL)
    assert result.verdict == "malicious"
    assert {"auth.dmarc_fail", "auth.spf_fail", "sender.reply_to_freemail"} <= _ids(result)


def test_forged_auth_header_is_suspicious_not_safe() -> None:
    result = analyze_email(load_fixture("forged_auth_header.eml"), GMAIL)
    assert result.verdict in {"suspicious", "malicious"}
    assert "auth.dmarc_fail" in _ids(result)


def test_brand_name_on_free_webmail_is_flagged() -> None:
    result = analyze_email(load_fixture("encoded_headers.eml"), GMAIL)
    assert "sender.brand_impersonation" in _ids(result)


def test_malformed_message_produces_a_result() -> None:
    result = analyze_email(load_fixture("malformed.eml"), GMAIL)
    assert {"sender.missing", "structure.malformed", "auth.unavailable"} <= _ids(result)


# --- Never "safe" when the analysis was incomplete -------------------------------------------


def test_malformed_message_is_inconclusive_not_safe() -> None:
    result = analyze_email(load_fixture("malformed.eml"), GMAIL)
    assert result.score < 30
    assert result.verdict == "inconclusive"
    assert LIMIT_NO_SENDER in result.limitations
    assert LIMIT_MALFORMED in result.limitations
    assert "cannot call it low risk" in result.summary


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x00\xff\xfe garbage",
        b"no headers at all, just text",
        b"From:\r\n\r\n",
        b"From: <>\r\n\r\n",
        b"Subject: hi\r\n\r\nno sender",
        b"From: a@example.com\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nbroken",
    ],
)
def test_unparseable_or_partial_messages_are_never_safe(raw: bytes) -> None:
    assert analyze_email(raw, GMAIL).verdict != "safe"


def test_missing_authentication_is_disclosed_but_not_penalized() -> None:
    result = analyze_email(load_fixture("untrusted_auth_only.eml"), GMAIL)
    assert result.score == 0
    assert result.verdict == "safe"
    assert result.limitations == [LIMIT_NO_AUTH]
    assert "could not be completed" in result.summary


def test_fully_analyzed_clean_message_has_no_limitations() -> None:
    result = analyze_email(load_fixture("legit_newsletter.eml"), GMAIL)
    assert result.limitations == []


# --- Resource limits against slow-parsing ("make the scanner time out") emails ---------------


@pytest.mark.parametrize("header", ["From", "Reply-To", "To", "Cc"])
def test_huge_address_lists_are_analyzed_quickly(header: str) -> None:
    addresses = ", ".join(f"user{i}@example.com" for i in range(50_000))
    raw = f"From: a@example.com\r\n{header}: {addresses}\r\n\r\nhi".encode()
    start = time.perf_counter()
    result = analyze_email(raw, GMAIL)
    assert time.perf_counter() - start < 3  # was ~36 s before the header-size cap
    assert result.verdict != "safe"  # oversized header is a structural defect


def test_analysis_makes_no_network_calls(monkeypatch) -> None:
    """Analysis must work fully offline (no DNS, no downloads of suffix lists, etc.)."""
    import socket

    def blocked(*args, **kwargs):
        raise AssertionError("network access attempted during analysis")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    for fixture in ("phish_paypal_lookalike.eml", "spoofed_dmarc_fail.eml", "malformed.eml"):
        analyze_email(load_fixture(fixture), GMAIL)


def test_signals_are_sorted_most_serious_first() -> None:
    result = analyze_email(load_fixture("phish_paypal_lookalike.eml"), GMAIL)
    points = [s.points for s in result.signals]
    assert points == sorted(points, reverse=True)


@pytest.mark.parametrize(
    "fixture",
    [
        "legit_newsletter.eml",
        "phish_paypal_lookalike.eml",
        "spoofed_dmarc_fail.eml",
        "forged_auth_header.eml",
        "untrusted_auth_only.eml",
        "encoded_headers.eml",
        "malformed.eml",
        "phish_link_tricks.eml",
        "newsletter_tracking_links.eml",
    ],
)
def test_every_fixture_works_through_the_signed_api(post_signed, fixture: str) -> None:
    response = post_signed({"raw_message": encode_message(load_fixture(fixture))})
    assert response.status_code == 200
    body = response.json()
    assert 0 <= body["score"] <= 100
    assert body["authentication"]["source"] in {"reported", "unavailable"}
    assert all(s["category"] for s in body["signals"])


# --- Links (Step 5) ------------------------------------------------------------------------


def _html_message(html: str) -> bytes:
    return (
        "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\r\n"
        "From: a@example.com\r\nMIME-Version: 1.0\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n\r\n{html}"
    ).encode()


def test_link_phishing_fixture_is_malicious_despite_passing_authentication() -> None:
    result = analyze_email(load_fixture("phish_link_tricks.eml"), GMAIL)
    assert result.verdict == "malicious"
    assert result.authentication is not None and result.authentication.dmarc == "pass"
    assert any(s.category == "links" for s in result.signals)


def test_newsletter_with_tracking_links_is_low_risk() -> None:
    result = analyze_email(load_fixture("newsletter_tracking_links.eml"), GMAIL)
    assert result.verdict == "safe"
    assert result.score == 0
    assert result.limitations == []


def test_too_many_links_is_inconclusive_not_safe() -> None:
    # An attacker could hide one bad link after hundreds of harmless ones.
    html = "".join(f'<a href="https://example.com/{i}">x</a>' for i in range(MAX_LINKS + 10))
    result = analyze_email(_html_message(html), GMAIL)
    assert result.verdict == "inconclusive"
    assert LIMIT_PARTIAL_CONTENT in result.limitations


def test_oversized_body_is_inconclusive_not_safe() -> None:
    result = analyze_email(_html_message("<p>" + "a" * (MAX_TEXT_CHARS + 10) + "</p>"), GMAIL)
    assert result.verdict == "inconclusive"
    assert LIMIT_PARTIAL_CONTENT in result.limitations


@pytest.mark.parametrize(
    "html",
    [
        "<" * 1_900_000,
        "<a href='x" * 190_000,
        "".join(f'<a href="https://h{i}.example/">www.h{i}.example</a>' for i in range(40_000)),
        "&#x41;" * 300_000,
    ],
)
def test_worst_case_html_is_analyzed_quickly(html: str) -> None:
    start = time.perf_counter()
    analyze_email(_html_message(html), GMAIL)
    assert time.perf_counter() - start < 5


# --- Attachments and content (Step 6) --------------------------------------------------------

from tests.helpers import (  # noqa: E402
    FAKE_EXE,
    PDF_CLEAN,
    email_with_attachments,
    make_zip,
)


def _with_auth(raw: bytes) -> bytes:
    return b"Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\r\n" + raw


def test_ordinary_invoice_email_is_low_risk() -> None:
    raw = _with_auth(
        email_with_attachments(
            [("Invoice-1042.pdf", "application/pdf", PDF_CLEAN)],
            body="Hi Maria, invoice #1042 for October is attached. Thanks!",
        )
    )
    result = analyze_email(raw, GMAIL)
    assert result.verdict == "safe"
    assert result.score == 0


def test_link_inside_pdf_attachment_is_analyzed() -> None:
    pdf = b"%PDF-1.4\n<</A <</S /URI /URI (https://paypa1-login.example/x)>>>>\n"
    result = analyze_email(
        _with_auth(email_with_attachments([("a.pdf", "application/pdf", pdf)])), GMAIL
    )
    lookalike = next(s for s in result.signals if s.id == "link.lookalike")
    assert "found inside an attachment" in (lookalike.evidence or "")


def test_uninspectable_archive_is_inconclusive_not_safe() -> None:
    rar = b"Rar!\x1a\x07\x01\x00" + bytes(16)
    result = analyze_email(_with_auth(email_with_attachments([("files.rar", "x/y", rar)])), GMAIL)
    assert result.score < 30
    assert result.verdict == "inconclusive"
    assert any(limit.startswith(LIMIT_UNINSPECTED_ATTACHMENTS) for limit in result.limitations)


def test_malware_delivery_email_is_malicious() -> None:
    raw = _with_auth(
        email_with_attachments(
            [("Invoice.zip", "application/zip", make_zip({"Invoice.pdf.exe": FAKE_EXE}))],
            body="URGENT: overdue invoice attached. Pay immediately.",
        )
    )
    result = analyze_email(raw, GMAIL)
    assert result.verdict == "malicious"


@pytest.mark.parametrize(
    "attachment",
    [
        (
            "many-links.pdf",
            "application/pdf",
            b"%PDF-1.4\n" + b"".join(b"/URI (https://h%d.example/)\n" % i for i in range(60_000)),
        ),
        ("many-files.zip", "application/zip", make_zip({f"f{i}.txt": b"" for i in range(30_000)})),
        ("big.html", "text/html", b"<html>" + b"<a href='https://x.example/'>x</a>" * 40_000),
        ("big.bin", "application/octet-stream", bytes(1_400_000)),
    ],
)
def test_worst_case_attachments_are_analyzed_quickly(attachment) -> None:
    raw = email_with_attachments([attachment])[: 2 * 1024 * 1024]
    start = time.perf_counter()
    analyze_email(raw, GMAIL)
    assert time.perf_counter() - start < 5


def test_worst_case_content_text_is_analyzed_quickly() -> None:
    body = "verify your account wire transfer urgent " * 40_000
    start = time.perf_counter()
    analyze_email(_with_auth(email_with_attachments([], body=body)), GMAIL)
    assert time.perf_counter() - start < 5
