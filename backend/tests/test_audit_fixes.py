"""Regression tests for the findings of the independent security audit (2026-11-16).

Each test reproduces the original problem (it failed before the fix) and checks the corrected
behavior, plus the legitimate cases the fix must not break. IDs match the audit report:
H = high, M = medium, L = low severity; "X" = additional findings.
"""

import time

import pytest

from app.analyzers import attachments as attachments_module
from app.analyzers.attachments import analyze_attachments
from app.analyzers.brands import BRANDS
from app.analyzers.domains import find_lookalike, registrable_domain
from app.analyzers.file_types import sniff
from app.analyzers.link_data import RISKY_TLDS
from app.analyzers.links import analyze_links
from app.analyzers.sender import analyze_sender, claimed_brand
from app.parsing import MAX_HEADERS, parse_email
from app.pipeline import analyze_email
from tests.corpus import email
from tests.helpers import FAKE_EXE, FAKE_LNK, PDF_JS, email_with_attachments, make_zip

GMAIL = frozenset({"mx.google.com"})
AUTH = "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\r\n"


def _html_email(html: str, sender: str = "Shop <news@mg-test-shop.com>") -> bytes:
    return (
        f"{AUTH}From: {sender}\r\nMIME-Version: 1.0\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n\r\n{html}"
    ).encode()


def _link_ids(html: str) -> set[str]:
    return {s.id for s in analyze_links(parse_email(_html_email(html))).signals}


def _attachment_ids(files: list[tuple[str | None, str, bytes]]) -> set[str]:
    return {s.id for s in analyze_attachments(parse_email(email_with_attachments(files))).signals}


# --- H1: a decoy "[Content_Types].xml" no longer hides programs inside a ZIP ------------------


@pytest.mark.parametrize(
    "files",
    [
        {"[Content_Types].xml": b"<Types/>", "invoice.exe": FAKE_EXE},
        {"[Content_Types].xml": b"x", "Invoice.pdf.lnk": FAKE_LNK},
    ],
)
def test_h1_office_marker_does_not_hide_programs_in_zip(files: dict[str, bytes]) -> None:
    ids = _attachment_ids([("invoice.zip", "application/zip", make_zip(files))])
    assert "attachment.archive_executable" in ids  # was: no signal at all, verdict "safe"


def test_h1_office_marker_does_not_hide_encryption() -> None:
    archive = make_zip({"[Content_Types].xml": b"x", "doc.js": b"x"}, encrypted=True)
    ids = _attachment_ids([("files.zip", "application/zip", archive)])
    assert {"attachment.encrypted_archive", "attachment.archive_executable"} <= ids


def test_h1_real_office_documents_stay_clean_and_macros_are_still_found() -> None:
    docx = make_zip(
        {
            "[Content_Types].xml": b"<Types/>",
            "word/document.xml": b"<w/>",
            "word/media/image1.png": b"png",
            "word/embeddings/oleObject1.bin": b"ole",
        }
    )
    docm = make_zip({"[Content_Types].xml": b"<Types/>", "word/vbaProject.bin": b"vba"})
    assert _attachment_ids([("report.docx", "application/octet-stream", docx)]) == set()
    assert _attachment_ids([("report.docm", "application/octet-stream", docm)]) == {
        "attachment.macro"
    }


# --- M1: very long host names no longer make analysis take tens of seconds -------------------


@pytest.mark.parametrize(
    "html",
    [
        # 500 links whose host has a 2,000-character label: took 35 s before the fix.
        "".join(f'<a href="https://{"q" * 2000}{i}.com/">x</a>' for i in range(500)),
        # 500 links that each nest three long-host URLs: took 32 s before the fix.
        "".join(
            f'<a href="https://r{i}.example/?a='
            + "".join(f"https://{'w' * 600}{k}.com/" for k in range(3))
            + '">x</a>'
            for i in range(500)
        ),
    ],
)
def test_m1_long_host_names_are_analyzed_quickly(html: str) -> None:
    start = time.perf_counter()
    analyze_email(_html_email(html), GMAIL)
    assert time.perf_counter() - start < 3


def test_m1_typo_detection_is_unchanged_by_the_length_shortcut() -> None:
    assert find_lookalike("paypall.example").technique == "typo"  # one extra character
    assert find_lookalike("micosoft.example").technique == "typo"  # one missing character
    assert find_lookalike("paypallllll.example") is None  # too different to be a typo


# --- L1: header floods are cut off and reported ----------------------------------------------


@pytest.mark.parametrize("header", ["From", "Reply-To", "To", "X-Pad"])
def test_l1_header_floods_are_analyzed_quickly_and_never_safe(header: str) -> None:
    line = f"{header}: a@b.example\r\n".encode()
    raw = b"From: a@example.com\r\n" + line * (2_000_000 // len(line)) + b"\r\nhi"
    start = time.perf_counter()
    result = analyze_email(raw, GMAIL)
    assert time.perf_counter() - start < 3  # was up to 9 s (From) before the header cap
    assert result.verdict != "safe"
    assert "TooManyHeaders" in parse_email(raw).defects


def test_l1_realistic_header_counts_are_unaffected() -> None:
    received = "".join(f"Received: from relay{i}.example by mx.example\r\n" for i in range(300))
    raw = f"{AUTH}{received}From: a@example.com\r\nSubject: hi\r\n\r\nhello".encode()
    assert 300 < MAX_HEADERS
    assert parse_email(raw).defects == []
    assert analyze_email(raw, GMAIL).verdict == "safe"


# --- M2: decoy URLs no longer make a text/link mismatch look legitimate -----------------------


@pytest.mark.parametrize(
    "html",
    [
        # Attacker-made pages on google.com hosts, with a decoy brand URL appended.
        '<a href="https://sites.google.com/view/acct?r=https://www.paypal.com/">paypal.com</a>',
        '<a href="https://docs.google.com/forms/d/e/x/viewform?u=https://www.paypal.com">'
        "www.paypal.com</a>",
        # A real redirector, but the decoy is not the parameter the redirector follows.
        '<a href="https://www.google.com/url?x=https://www.paypal.com&q=https://evil.example.net/">'
        "paypal.com</a>",
        '<a href="https://eur01.safelinks.protection.outlook.com/?x=https%3A%2F%2Fwww.paypal.com'
        '&url=https%3A%2F%2Fevil.example.net%2F">paypal.com</a>',
    ],
)
def test_m2_decoy_urls_do_not_hide_a_mismatch(html: str) -> None:
    assert "link.text_mismatch" in _link_ids(html)  # was: no signal at all


@pytest.mark.parametrize(
    "html",
    [
        '<a href="https://www.google.com/url?q=https://www.example.com/">www.example.com</a>',
        '<a href="https://www.google.com/url?url=https://www.example.com/&sa=t">example.com</a>',
        '<a href="https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.example.com'
        '%2F&data=x">www.example.com</a>',
        '<a href="https://urldefense.com/v3/__https://www.example.com/__;!!abc">'
        "https://www.example.com</a>",
        '<a href="https://linkprotect.cudasvc.com/url?a=https%3a%2f%2fwww.example.com%2f&c=E">'
        "www.example.com</a>",
    ],
)
def test_m2_genuine_gateway_rewrites_still_match(html: str) -> None:
    assert "link.text_mismatch" not in _link_ids(html)


# --- M3: a brand's own country domains are not look-alikes -----------------------------------


@pytest.mark.parametrize(
    "domain", ["amazon.com.au", "email.amazon.com.au", "amazon.com.br", "paypal.com.au"]
)
def test_m3_regional_brand_domains_are_not_lookalikes(domain: str) -> None:
    assert find_lookalike(domain) is None  # was: "subdomain" look-alike of amazon.com/paypal.com


def test_m3_regional_amazon_order_email_is_low_risk() -> None:
    raw = email(
        "Amazon.com.au <auto-confirm@amazon.com.au>",
        subject="Your order",
        text="Thanks for your order. Track it at https://www.amazon.com.au/orders",
    )
    result = analyze_email(raw, GMAIL)
    assert (result.score, result.verdict) == (0, "safe")  # was 60, suspicious


@pytest.mark.parametrize(
    "domain",
    ["paypal.com.evil.example", "amazon.com.au.evil.example", "mail.dhl.com.track.test"],
)
def test_m3_brand_domains_used_as_subdomains_are_still_caught(domain: str) -> None:
    assert find_lookalike(domain).technique == "subdomain"


def test_brand_domains_are_registrable_domains() -> None:
    """A brand domain outside the public-suffix list (e.g. amazon.com.be, whose registrable part
    is "com.be") would turn "com" into a brand name and flag unrelated domains."""
    for brand in BRANDS:
        for domain in brand.domains:
            assert registrable_domain(domain) == domain, (brand.name, domain)


# --- M4: common brand display names are recognized -------------------------------------------


@pytest.mark.parametrize(
    ("name", "brand"),
    [
        ("Amazon.com", "Amazon"),
        ("amazon.co.uk", "Amazon"),
        ("Amazon Prime", "Amazon"),
        ("DHL Express", "DHL"),
        ("FedEx Delivery", "FedEx"),
        ("Wells Fargo Online", "Wells Fargo"),
        ("Wells Fargo Bank", "Wells Fargo"),
        ("Pay Pal", "PayPal"),
        ("Pay Pal Support", "PayPal"),
        ("P a y P a l", "PayPal"),
        ("Netflix.com Billing", "Netflix"),
    ],
)
def test_m4_brand_display_names_are_recognized(name: str, brand: str) -> None:
    found = claimed_brand(name)  # each was None before the fix
    assert found is not None and found.name == brand


@pytest.mark.parametrize(
    "name",
    [
        "Prime",  # a product word alone is not the brand
        "Prime Fitness",
        "Express Dry Cleaning",
        "Apple Bank",  # "bank" is a companion of Wells Fargo only
        "DHL Parcel",  # DHL Parcel mails from its own domains
        "Socket.IO",
        "John.Smith",
        "Pay Day Loans",
    ],
)
def test_m4_ordinary_names_are_still_not_brand_claims(name: str) -> None:
    assert claimed_brand(name) is None


@pytest.mark.parametrize(
    "sender",
    [
        "Amazon.com <shipment-tracking@amazon.com>",
        "Amazon.com.au <auto-confirm@amazon.com.au>",
        "PayPal <service@paypal.co.uk>",
        "PayPal <service@paypal.com.au>",
        "DHL Express <noreply@dhl.com>",
    ],
)
def test_m4_brand_display_name_from_official_domain_is_fine(sender: str) -> None:
    raw = email(sender, text="Your package shipped.")
    assert {s.id for s in analyze_sender(parse_email(raw)) if s.points} == set()


# --- L2: one brand's own domains are not a text/link mismatch --------------------------------


def test_l2_same_brand_domains_are_not_a_mismatch() -> None:
    html = '<a href="https://outlook.live.com/mail/">Outlook.com</a>'
    assert "link.text_mismatch" not in _link_ids(html)  # was 30 points, suspicious


def test_l2_different_brands_are_still_a_mismatch() -> None:
    html = '<a href="https://outlook.live.com/mail/">paypal.com</a>'
    assert "link.text_mismatch" in _link_ids(html)


# --- L3: wording beyond the 25-point cap still counts as pattern evidence --------------------


def test_l3_more_wording_evidence_does_not_hide_the_attack_pattern() -> None:
    text = (
        "I need a quick favor. Keep this confidential. Please handle the wire transfer urgently "
        "and send me your verification code."
    )
    result = analyze_email(email("Dana <dana@partner-firm.example>", text=text), GMAIL)
    assert "credential_theft_by_reply" in [p.id for p in result.attack_patterns]  # was: none
    content = [s for s in result.signals if s.category == "content"]
    assert sum(s.points for s in content) <= 25  # the wording cap itself is unchanged
    assert result.score == sum(s.points for s in result.signals)  # rows still add up


# --- L4: attachments are checked completely, or reported as not fully checked ----------------


def test_l4_pdf_script_after_the_first_megabyte_is_found() -> None:
    pdf = b"%PDF-1.7\n%" + b"A" * 1_100_000 + b"\n" + PDF_JS[len(b"%PDF-1.7\n") :]
    ids = _attachment_ids([("doc.pdf", "application/pdf", pdf)])
    assert "attachment.active_document" in ids  # was: not found, no limitation shown


def test_l4_files_beyond_the_scan_limit_are_reported(monkeypatch) -> None:
    monkeypatch.setattr(attachments_module, "MAX_SCAN_BYTES", 1000)
    raw = email_with_attachments([("doc.pdf", "application/pdf", b"%PDF-1.7\n" + bytes(5000))])
    analysis = analyze_attachments(parse_email(raw))
    assert any("only the first" in item for item in analysis.uninspected)


def test_l4_full_size_attachments_are_analyzed_quickly() -> None:
    hostile_pdf = b"%PDF-1.7\n" + b"#41/URI (https://h.example/)" * 50_000  # ~1.4 MB
    raw = email_with_attachments([("big.pdf", "application/pdf", hostile_pdf)])
    start = time.perf_counter()
    analyze_email(raw[: 2 * 1024 * 1024], GMAIL)
    assert time.perf_counter() - start < 3


# --- L5: structure defects inside nested parts are reported ----------------------------------


def test_l5_unclosed_nested_multipart_is_reported() -> None:
    raw = (
        f"{AUTH}From: a@example.com\r\nMIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="outer"\r\n\r\n'
        "--outer\r\n"
        'Content-Type: multipart/alternative; boundary="inner"\r\n\r\n'
        "--inner\r\nContent-Type: text/plain\r\n\r\nHello\r\n"
        "--outer--\r\n"
    ).encode()
    assert "CloseBoundaryNotFoundDefect" in parse_email(raw).defects
    assert analyze_email(raw, GMAIL).verdict == "inconclusive"  # was "safe"


def test_l5_well_formed_nested_multipart_has_no_defects() -> None:
    raw = email(
        "a@example.com",
        text="Hello",
        html="<p>Hello</p>",
        attachments=(("notes.txt", "text/plain", b"notes"),),
    )
    assert parse_email(raw).defects == []


# --- X1: plain XML files are not web pages ----------------------------------------------------


def test_x1_xml_invoice_is_not_a_web_page() -> None:
    xml = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n<Invoice xmlns="urn:oasis:names:specification:'
        b'ubl:schema:xsd:Invoice-2"><ID>42</ID><htmlDescription>x</htmlDescription></Invoice>'
    )
    assert sniff(xml) is None
    assert _attachment_ids([("invoice.xml", "application/xml", xml)]) == set()  # was +15


@pytest.mark.parametrize(
    "data",
    [
        b'<?xml version="1.0"?>\n<!-- Created with an editor -->\n<svg xmlns="x"><script/></svg>',
        b'<?xml version="1.0"?>\n<!DOCTYPE html>\n<html xmlns="http://www.w3.org/1999/xhtml">',
    ],
)
def test_x1_svg_and_xhtml_with_xml_prolog_are_still_web_pages(data: bytes) -> None:
    assert sniff(data) == "html"


# --- X2: major email platforms' click tracking is not a mismatch -----------------------------


@pytest.mark.parametrize("host", ["go.pardot.com", "links.iterable.com", "click.pstmrk.it"])
def test_x2_marketing_click_tracking_is_not_a_mismatch(host: str) -> None:
    html = f'<a href="https://{host}/c/abc123">www.mg-test-shop.com</a>'
    assert "link.text_mismatch" not in _link_ids(html)  # was 30 points, suspicious


# --- X3: sender domains that put the exact brand name on a different ending ------------------


# Built from the rule's own list of abused endings instead of naming specific real domains.
_ABUSED_ENDINGS = sorted(RISKY_TLDS)


@pytest.mark.parametrize("brand_label", ["paypal", "netflix", "microsoft"])
def test_x3_exact_brand_name_on_abused_endings_is_a_lookalike(brand_label: str) -> None:
    for ending in _ABUSED_ENDINGS:
        found = find_lookalike(f"{brand_label}.{ending}")  # each was None before the fix
        assert found is not None and found.technique == "tld", ending


def test_x3_brand_name_glued_to_com_is_a_lookalike() -> None:
    found = find_lookalike("paypalcom.example")  # was None before the fix
    assert found is not None and found.technique == "combo"


@pytest.mark.parametrize("domain", ["amazon.ca", "amazon.fr", "paypal.me"])
def test_x3_brand_country_domains_are_not_flagged(domain: str) -> None:
    assert find_lookalike(domain) is None


def test_x3_dictionary_word_brands_on_abused_endings_are_not_flagged() -> None:
    # "office", "live", "meta", "outlook" are ordinary words: only look-alike characters count.
    for label in ("office", "live", "meta", "outlook"):
        for ending in _ABUSED_ENDINGS:
            assert find_lookalike(f"{label}.{ending}") is None, (label, ending)
