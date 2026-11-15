"""URL extraction and normalization tests: links are judged by where a browser would go."""

import pytest

from app.analyzers.urls import (
    MAX_LINKS,
    defang,
    domain_shown_in_text,
    extract_links,
    ip_host_kind,
    parse_link,
)
from app.parsing import parse_email


def _html_email(html: str, text: str | None = None) -> bytes:
    if text is None:
        return (
            "From: a@example.com\r\nMIME-Version: 1.0\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n\r\n{html}"
        ).encode()
    return (
        "From: a@example.com\r\nMIME-Version: 1.0\r\n"
        'Content-Type: multipart/alternative; boundary="b"\r\n\r\n'
        f"--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{text}\r\n"
        f"--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}\r\n--b--\r\n"
    ).encode()


def _links(html: str, text: str | None = None):
    return extract_links(parse_email(_html_email(html, text))).links


# --- normalization: what the browser really does --------------------------------------------


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://Example.COM/path", "example.com"),
        ("https://www.paypal.com@evil.example/login", "evil.example"),  # user-info trick
        ("https:\\\\evil.example\\path", "evil.example"),  # backslashes act as slashes
        ("https://ev\til.exa\nmple/", "evil.example"),  # browsers drop tabs/newlines
        ("//evil.example/x", "evil.example"),  # scheme-relative
        ("www.evil.example/x", "www.evil.example"),
        ("https://%65vil.example/", "evil.example"),  # percent-encoded host
        ("https://bücher.example/", "xn--bcher-kva.example"),  # international domain
        ("https://evil.example:8443/", "evil.example"),
        ("https://[2001:db8::1]/", "2001:db8::1"),
    ],
)
def test_hosts_are_normalized_like_a_browser(url: str, host: str) -> None:
    link = parse_link(url)
    assert link is not None and link.host == host


def test_userinfo_is_detected() -> None:
    link = parse_link("https://paypal.com@evil.example/")
    assert link is not None and link.has_userinfo


@pytest.mark.parametrize("url", ["https://[::1/", "http://", "https://exa mple.com/"])
def test_malformed_urls_do_not_raise(url: str) -> None:
    parse_link(url)


def test_relative_links_are_ignored_but_non_web_schemes_are_kept() -> None:
    assert parse_link("/relative/path") is None
    js = parse_link("JavaScript:alert(1)")
    assert js is not None and js.scheme == "javascript" and js.host == ""


@pytest.mark.parametrize(
    ("host", "kind"),
    [
        ("192.0.2.1", "ip"),
        ("2001:db8::1", "ip"),
        ("3232235777", "obfuscated_ip"),  # decimal form of 192.168.1.1
        ("0x7f.1", "obfuscated_ip"),
        ("010.0.0.1", "obfuscated_ip"),  # octal-looking form
        ("example.com", None),
        ("1password.com", None),
    ],
)
def test_ip_host_kind(host: str, kind: str | None) -> None:
    assert ip_host_kind(host) == kind


@pytest.mark.parametrize(
    ("text", "domain"),
    [
        ("paypal.com", "paypal.com"),
        ("https://www.paypal.com/signin", "paypal.com"),
        ("Go to www.example.com now", "example.com"),
        ("Sign in", None),
        ("Invoice.pdf", None),  # .pdf is not a domain ending
        ("version 1.2.3", None),
    ],
)
def test_domain_shown_in_text(text: str, domain: str | None) -> None:
    assert domain_shown_in_text(text) == domain


def test_defang_makes_urls_unclickable() -> None:
    assert defang("https://evil.example/a.b") == "hxxps://evil[.]example/a[.]b"
    assert len(defang("https://example.com/" + "a" * 500)) < 120


# --- extraction from HTML and text ----------------------------------------------------------


def test_html_links_keep_their_visible_text() -> None:
    links = _links('<a href="https://evil.example/">https://<b>paypal</b>.com</a>')
    assert links[0].host == "evil.example"
    assert links[0].text == "https://paypal.com"


def test_html_entities_are_decoded_like_a_browser() -> None:
    links = _links('<a href="https&#x3a;//evil&#x2e;example/p">x</a>')
    assert links[0].host == "evil.example"


def test_unclosed_and_nested_anchors_are_still_found() -> None:
    links = _links('<a href="https://a.example/">one <a href="https://b.example/">two')
    assert {link.host for link in links} == {"a.example", "b.example"}


def test_forms_and_image_maps_are_found() -> None:
    links = _links(
        '<form action="https://collect.example/pw"></form><form></form>'
        '<map><area href="https://area.example/"></map>'
    )
    sources = sorted((link.source, link.host) for link in links)
    assert sources == [
        ("html_form", ""),
        ("html_form", "collect.example"),
        ("html_link", "area.example"),
    ]


def test_plain_text_urls_are_found_without_trailing_punctuation() -> None:
    links = _links("<p>hi</p>", text="Visit https://evil.example/login. Or www.other.example!")
    assert {(link.source, link.url) for link in links if link.source == "text"} == {
        ("text", "https://evil.example/login"),
        ("text", "http://www.other.example"),  # bare "www." links get a scheme added
    }


def test_link_count_is_capped() -> None:
    html = "".join(f'<a href="https://h{i}.example/">x</a>' for i in range(MAX_LINKS + 100))
    result = extract_links(parse_email(_html_email(html)))
    assert len(result.links) == MAX_LINKS
    assert result.truncated


@pytest.mark.parametrize(
    "html",
    ["<" * 5000, "<a href='x" * 2000, "<a href=>", "<form action>", "&#xffffffff;", "\x00<a>"],
)
def test_hostile_html_never_raises(html: str) -> None:
    extract_links(parse_email(_html_email(html)))
