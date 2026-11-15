"""Sender identity analyzer and domain helper tests."""

import pytest

from app.analyzers.common import clean_text
from app.analyzers.domains import find_lookalike, levenshtein, registrable_domain, skeleton
from app.analyzers.sender import analyze_sender, claimed_brand
from app.parsing import parse_email
from tests.helpers import load_fixture, make_email


def _ids(raw: bytes) -> set[str]:
    return {s.id for s in analyze_sender(parse_email(raw))}


# --- domain helpers --------------------------------------------------------------------------


def test_registrable_domain_handles_multi_part_suffixes() -> None:
    assert registrable_domain("mail.paypal.com") == "paypal.com"
    assert registrable_domain("shop.bbc.co.uk") == "bbc.co.uk"
    assert registrable_domain("host.example.test") == "host.example.test"  # no known suffix


def test_skeleton_and_levenshtein() -> None:
    assert skeleton("paypa1") == skeleton("paypal")
    assert skeleton("rnicrosoft") == skeleton("microsoft")
    assert levenshtein("paypall", "paypal") == 1
    assert levenshtein("kitten", "sitting") == 3


@pytest.mark.parametrize(
    ("domain", "brand", "technique"),
    [
        ("paypa1.com", "PayPal", "homoglyph"),
        ("rnicrosoft.com", "Microsoft", "homoglyph"),
        ("paypall.com", "PayPal", "typo"),
        ("micosoft.com", "Microsoft", "typo"),
        ("paypal-secure.com", "PayPal", "combo"),
        ("secure-paypal.net", "PayPal", "combo"),
        ("paypalsupport.com", "PayPal", "combo"),
        ("paypal.com.account-verify.net", "PayPal", "subdomain"),
        ("mail.dhl.com.parcel-track.test", "DHL", "subdomain"),
    ],
)
def test_lookalike_domains_are_detected(domain: str, brand: str, technique: str) -> None:
    found = find_lookalike(domain)
    assert found is not None
    assert (found.brand.name, found.technique) == (brand, technique)


@pytest.mark.parametrize(
    "domain",
    [
        "paypal.com",
        "mail.paypal.com",
        "microsoft.com",
        "example.com",
        "apply.com",  # one letter from "apple", but too short and common to call a typo
        "offices.com",  # "office" is a dictionary word
        "live-music.example",
        "applebees.com",
    ],
)
def test_legitimate_domains_are_not_lookalikes(domain: str) -> None:
    assert find_lookalike(domain) is None


# --- display name ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "brand"),
    [
        ("PayPal", "PayPal"),
        ("PayPal Support", "PayPal"),
        ("Microsoft account team", "Microsoft"),
        ("Apple ID", "Apple"),
        ("Office365 Admin", "Microsoft"),
        ("Wells Fargo", "Wells Fargo"),
        ("PayPaI Security", "PayPal"),  # capital I instead of l
    ],
)
def test_brand_claims_are_recognized(name: str, brand: str) -> None:
    found = claimed_brand(name)
    assert found is not None and found.name == brand


@pytest.mark.parametrize("name", ["Big Apple Pizza", "Jane Doe", "", "Amazonian Plants Co"])
def test_ordinary_names_are_not_brand_claims(name: str) -> None:
    assert claimed_brand(name) is None


def test_brand_name_from_official_domain_is_fine() -> None:
    assert _ids(make_email('From: "PayPal" <service@paypal.com>')) == set()


def test_brand_name_from_other_domain_is_flagged() -> None:
    assert "sender.brand_impersonation" in _ids(
        make_email('From: "PayPal Support" <help@example.com>')
    )


def test_brand_name_from_brands_own_free_webmail_is_flagged() -> None:
    # Anyone can register a Gmail account called "Google Support".
    assert "sender.brand_impersonation" in _ids(
        make_email('From: "Google Support" <mg-test-google-support@gmail.com>')
    )


def test_email_address_in_display_name() -> None:
    raw = make_email('From: "security@paypal.com" <attacker@example.net>')
    assert "sender.address_in_display_name" in _ids(raw)
    same = make_email('From: "news@example.com" <news@mail.example.com>')
    assert "sender.address_in_display_name" not in _ids(same)


def test_hidden_direction_characters_are_flagged_and_made_visible() -> None:
    raw = 'From: "Invoice \u202efdp.exe" <a@example.com>\r\n\r\nhi'.encode()
    signals = analyze_sender(parse_email(raw))
    hidden = next(s for s in signals if s.id == "sender.hidden_characters")
    assert "U+202E" in (hidden.evidence or "")
    assert "\u202e" not in hidden.model_dump_json()


def test_punycode_domain_is_flagged() -> None:
    raw = 'From: "Shop" <a@bücher.example>\r\n\r\nhi'.encode()
    assert "sender.punycode_domain" in _ids(raw)


# --- From header problems --------------------------------------------------------------------


def test_missing_sender() -> None:
    assert "sender.missing" in _ids(make_email("To: a@example.com"))


def test_multiple_from_headers() -> None:
    raw = make_email("From: a@example.com", "From: b@example.net")
    assert "sender.multiple_from" in _ids(raw)


# --- Reply-To --------------------------------------------------------------------------------


def test_reply_to_same_organization_is_fine() -> None:
    assert _ids(load_fixture("legit_newsletter.eml")) == set()


def test_reply_to_other_organization() -> None:
    raw = make_email("From: a@example.com", "Reply-To: b@example.net")
    assert _ids(raw) == {"sender.reply_to_mismatch"}


def test_reply_to_free_webmail() -> None:
    raw = make_email("From: billing@example.com", "Reply-To: mg-test-billing@gmail.com")
    assert _ids(raw) == {"sender.reply_to_freemail"}


def test_freemail_to_freemail_is_only_a_mismatch() -> None:
    raw = make_email("From: mg-test-a@gmail.com", "Reply-To: mg-test-a@yahoo.com")
    assert _ids(raw) == {"sender.reply_to_mismatch"}


# --- evidence safety -------------------------------------------------------------------------


def test_clean_text_truncates_and_reveals_control_characters() -> None:
    assert clean_text("a\u200bb") == "a[U+200B]b"
    assert clean_text("x" * 500).endswith("…")
    assert len(clean_text("x" * 500)) == 200
