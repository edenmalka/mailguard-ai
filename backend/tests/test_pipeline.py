"""End-to-end tests: fixtures through the pipeline and through the signed HTTP API."""

import time

import pytest

from app.pipeline import LIMIT_MALFORMED, LIMIT_NO_AUTH, LIMIT_NO_SENDER, analyze_email
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
    ],
)
def test_every_fixture_works_through_the_signed_api(post_signed, fixture: str) -> None:
    response = post_signed({"raw_message": encode_message(load_fixture(fixture))})
    assert response.status_code == 200
    body = response.json()
    assert 0 <= body["score"] <= 100
    assert body["authentication"]["source"] in {"reported", "unavailable"}
    assert all(s["category"] for s in body["signals"])
