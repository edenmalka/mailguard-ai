"""Parser tests: encoded content, missing headers, malformed input, and resource limits."""

import pytest

from app.parsing import MAX_PARTS, MAX_TEXT_CHARS, parse_email
from tests.helpers import load_fixture, make_email


def test_basic_fields_are_extracted() -> None:
    parsed = parse_email(load_fixture("legit_newsletter.eml"))
    assert parsed.sender is not None
    assert parsed.sender.display_name == "Example News"
    assert parsed.sender.address == "news@example.com"
    assert parsed.sender.domain == "example.com"
    assert parsed.reply_to[0].domain == "help.example.com"
    assert parsed.return_path is not None and parsed.return_path.domain == "mail.example.com"
    assert parsed.subject == "Your weekly digest"
    assert "top stories" in parsed.text_body
    assert parsed.defects == []


def test_authentication_results_keep_top_to_bottom_order() -> None:
    parsed = parse_email(load_fixture("forged_auth_header.eml"))
    assert len(parsed.authentication_results) == 2
    assert "dmarc=fail" in parsed.authentication_results[0]
    assert "dmarc=pass" in parsed.authentication_results[1]


def test_arc_authentication_results_are_not_mixed_in() -> None:
    parsed = parse_email(load_fixture("legit_newsletter.eml"))
    assert len(parsed.authentication_results) == 1


def test_encoded_words_and_transfer_encodings_are_decoded() -> None:
    parsed = parse_email(load_fixture("encoded_headers.eml"))
    assert parsed.sender is not None
    assert parsed.sender.display_name == "PayPal Security"  # base64 encoded-word
    assert parsed.subject == "Accès suspendu"  # quoted-printable ISO-8859-1 encoded-word
    assert "Votre accès est suspendu." in parsed.text_body  # QP body, ISO-8859-1
    assert "<p>Votre accès est suspendu.</p>" in parsed.html_body  # base64 body, UTF-8


def test_raw_utf8_headers_are_decoded_and_domain_normalized() -> None:
    raw = 'From: "Bücher Team" <a@Bücher.example>\r\n\r\nhi'.encode()
    parsed = parse_email(raw)
    assert parsed.sender is not None
    assert parsed.sender.display_name == "Bücher Team"
    assert parsed.sender.domain == "xn--bcher-kva.example"


def test_invalid_utf8_in_headers_does_not_crash() -> None:
    parsed = parse_email(b"From: a@example.com\r\nSubject: bad \xff\xfe bytes\r\n\r\nhi")
    assert "bad" in parsed.subject


def test_malformed_message_is_handled() -> None:
    parsed = parse_email(load_fixture("malformed.eml"))
    assert parsed.sender is None
    assert parsed.from_header_count == 0
    assert "Body in an unknown charset." in parsed.text_body  # unknown charset -> fallback
    assert parsed.attachments and parsed.attachments[0].filename == "invoice.pdf"
    assert parsed.defects  # unclosed boundary and bad base64 are recorded, not raised


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x00\xff\xfe garbage",
        b"no headers at all, just text",
        b"From:\r\n\r\n",
        b"From: <>\r\n\r\n",
        b'From: "unterminated <a@example.com\r\n\r\n',
        b"Content-Type: multipart/mixed\r\n\r\nmissing boundary parameter",
    ],
)
def test_hostile_inputs_never_raise(raw: bytes) -> None:
    parsed = parse_email(raw)
    assert parsed.text_body is not None


def test_multiple_from_headers_are_counted() -> None:
    parsed = parse_email(make_email("From: a@example.com", "From: b@example.net"))
    assert parsed.from_header_count == 2
    assert [a.address for a in parsed.from_addresses] == ["a@example.com", "b@example.net"]


def test_part_count_is_limited() -> None:
    parts = "".join(
        f"--b\r\nContent-Type: text/plain\r\n\r\npart {i}\r\n" for i in range(MAX_PARTS + 50)
    )
    raw = f"Content-Type: multipart/mixed; boundary=b\r\n\r\n{parts}--b--\r\n".encode()
    parsed = parse_email(raw)
    assert "TooManyParts" in parsed.defects


def test_deeply_nested_multipart_does_not_crash() -> None:
    depth = 1500
    opening = "".join(
        f"--b{i}\r\nContent-Type: multipart/mixed; boundary=b{i + 1}\r\n\r\n" for i in range(depth)
    )
    raw = f"Content-Type: multipart/mixed; boundary=b0\r\n\r\n{opening}".encode()
    parse_email(raw)  # must return, whatever defects it records


def test_oversized_address_header_is_cut_at_an_address_boundary() -> None:
    addresses = ", ".join(f"user{i}@example.com" for i in range(5_000))
    parsed = parse_email(f"From: a@example.com\r\nReply-To: {addresses}\r\n\r\nhi".encode())
    assert "OversizedAddressHeader" in parsed.defects
    assert 0 < len(parsed.reply_to) < 5_000
    assert all(a.domain == "example.com" for a in parsed.reply_to)  # no half-cut address


def test_text_body_size_is_limited() -> None:
    parsed = parse_email(make_email("From: a@example.com", body="x" * (MAX_TEXT_CHARS + 1000)))
    assert len(parsed.text_body) == MAX_TEXT_CHARS
