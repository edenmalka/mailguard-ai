"""Link analyzer tests: each signal fires on its trick and stays quiet on legitimate patterns."""

import pytest

from app.analyzers.links import analyze_links
from app.parsing import parse_email
from tests.helpers import load_fixture


def _analyze_html(html: str, sender: str = "a@example.com"):
    raw = (
        f"From: {sender}\r\nMIME-Version: 1.0\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n\r\n{html}"
    ).encode()
    return analyze_links(parse_email(raw))


def _ids(html: str) -> set[str]:
    return {s.id for s in _analyze_html(html).signals}


@pytest.mark.parametrize(
    ("html", "signal"),
    [
        ('<a href="https://evil.example/">https://www.paypal.com</a>', "link.text_mismatch"),
        ('<a href="https://evil.example/">Go to www.mybank.com now</a>', "link.text_mismatch"),
        ('<a href="https://paypa1.com/">Log in</a>', "link.lookalike"),
        ('<a href="https://paypa1-login.top/">Log in</a>', "link.lookalike"),
        ('<a href="https://paypal.com.secure-check.example/">x</a>', "link.lookalike"),
        ('<a href="https://www.paypal.com@evil.example/">x</a>', "link.userinfo"),
        ('<a href="https://files.example.net/invoice.pdf.exe">x</a>', "link.dangerous_file"),
        ('<a href="https://files.example.net/update.JS?x=1">x</a>', "link.dangerous_file"),
        ('<form action="https://collect.example/"><input type=password></form>', "link.form"),
        ("<form><input type=password></form>", "link.form"),
        ('<a href="http://192.0.2.7/login">x</a>', "link.ip_address"),
        ('<a href="http://3232235777/">x</a>', "link.ip_address"),
        ('<a href="javascript:void(0)">x</a>', "link.script_scheme"),
        ('<a href="data:text/html;base64,PGgxPkhpPC9oMT4=">x</a>', "link.script_scheme"),
        ('<a href="https://bit.ly/abc">x</a>', "link.shortener"),
        ('<a href="https://xn--bcher-kva.example/">x</a>', "link.punycode"),
        ('<a href="https://login.example.top/">x</a>', "link.risky_tld"),
        ('<a href="https://invoice.zip/">invoice</a>', "link.risky_tld"),
    ],
)
def test_each_trick_is_detected(html: str, signal: str) -> None:
    assert signal in _ids(html)


@pytest.mark.parametrize(
    "html",
    [
        '<a href="https://www.example.com/x">www.example.com</a>',
        '<a href="https://shop.example.com/">https://example.com</a>',  # same organization
        '<a href="https://u1.ct.sendgrid.net/ls/click?x">www.example.com</a>',  # tracking
        '<a href="https://www.paypal.com/signin">https://www.paypal.com/signin</a>',
        '<a href="mailto:a@example.com">a@example.com</a>',
        '<a href="tel:+15550100">Call us</a>',
        '<a href="/relative">Relative</a>',
        '<a href="https://example.com/files/report.pdf">report.pdf</a>',
        '<img src="http://192.0.2.7/pixel.gif">',  # images are not clickable links
        '<a href="https://1password.com/">1password.com</a>',
    ],
)
def test_legitimate_links_raise_no_signals(html: str) -> None:
    assert _ids(html) == set()


def test_one_signal_per_problem_type_with_counted_examples() -> None:
    html = "".join(f'<a href="https://bit.ly/{i}">x</a>' for i in range(5))
    signals = _analyze_html(html).signals
    assert [s.id for s in signals] == ["link.shortener"]
    assert signals[0].points == 10
    evidence = signals[0].evidence or ""
    assert evidence.startswith("5 link(s):")
    assert "and 2 more" in evidence


def test_examples_are_defanged() -> None:
    signal = _analyze_html('<a href="https://evil.example/">https://www.paypal.com</a>').signals[0]
    assert "hxxps://evil[.]example/" in (signal.evidence or "")
    assert "https://evil.example" not in (signal.evidence or "")


def test_form_destination_is_also_checked() -> None:
    ids = _ids('<form action="http://192.0.2.9/collect"><input type=password></form>')
    assert {"link.form", "link.ip_address"} <= ids


def test_lookalike_signal_names_the_brand() -> None:
    signals = _analyze_html('<a href="https://paypa1.com/">Log in</a>').signals
    lookalike = next(s for s in signals if s.id == "link.lookalike")
    assert lookalike.title == "Link imitates PayPal"


def test_phishing_fixture_triggers_the_expected_signals() -> None:
    result = analyze_links(parse_email(load_fixture("phish_link_tricks.eml")))
    assert {s.id for s in result.signals} >= {
        "link.text_mismatch",
        "link.lookalike",
        "link.form",
        "link.ip_address",
        "link.userinfo",
        "link.dangerous_file",
        "link.shortener",
        "link.risky_tld",
    }


def test_newsletter_with_tracking_links_is_clean() -> None:
    result = analyze_links(parse_email(load_fixture("newsletter_tracking_links.eml")))
    assert result.signals == []
    assert result.link_count >= 5
    assert not result.truncated
