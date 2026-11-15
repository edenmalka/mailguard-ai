"""Link analyzer: where would a click in this email really take the user?

Each kind of problem produces at most one signal (with a count and up to three examples),
so many links of the same kind do not inflate the score. Examples are "defanged"
(hxxps://evil[.]example) so they cannot be clicked from the verdict card.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import parse_qsl

from app.analyzers.common import make_signal
from app.analyzers.domains import Lookalike, find_lookalike, registrable_domain, same_organization
from app.analyzers.link_data import (
    DANGEROUS_EXTENSIONS,
    OPAQUE_REWRITER_DOMAINS,
    REWRITER_HOSTS,
    RISKY_TLDS,
    SCRIPT_SCHEMES,
    SHORTENER_DOMAINS,
    TRACKING_DOMAINS,
)
from app.analyzers.urls import (
    Link,
    defang,
    domain_shown_in_text,
    embedded_urls,
    extract_links,
    ip_host_kind,
    parse_link,
)
from app.parsing import ParsedEmail
from app.schemas import Signal

CATEGORY = "links"
MAX_EXAMPLES = 3

POINTS_TEXT_MISMATCH = 30
POINTS_LOOKALIKE = 30
POINTS_USERINFO = 25
POINTS_DANGEROUS_FILE = 25
POINTS_FORM = 25
POINTS_IP_HOST = 20
POINTS_SCRIPT_SCHEME = 20
POINTS_SHORTENER = 10
POINTS_PUNYCODE = 10
POINTS_RISKY_TLD = 10


@dataclass(frozen=True)
class LinkAnalysis:
    signals: list[Signal]
    link_count: int
    truncated: bool  # not every link could be checked


def analyze_links(parsed: ParsedEmail, extra_urls: Sequence[str] = ()) -> LinkAnalysis:
    """Check links in the email body and `extra_urls` (URLs found inside attachments)."""
    extraction = extract_links(parsed, extra_urls)
    findings: dict[str, list[str]] = {}
    lookalikes: list[Lookalike] = []

    def note(kind: str, example: str) -> None:
        findings.setdefault(kind, []).append(example)

    for link in extraction.links:
        if link.source == "html_form":
            note("form", defang(link.url) if link.url else "(submits to an unknown page)")
            # Where the form sends data matters too (e.g. a password posted to an IP address).
        if link.scheme in SCRIPT_SCHEMES:
            note("script", f"{link.scheme}: link")
            continue
        if link.scheme not in {"http", "https"} or not link.host:
            continue  # mailto:, tel:, cid:, relative links, unparseable URLs
        _check_web_link(link, note, lookalikes)
        # URLs nested inside this one (redirects, security-gateway rewrites) are where the
        # user may really end up, so they get the same checks (except the text comparison).
        for inner_url in embedded_urls(link.url):
            inner = parse_link(inner_url, None, "embedded")
            if inner is not None and inner.host:
                _check_web_link(inner, note, lookalikes, via=link.host)

    signals = [build(findings[kind]) for kind, build in _BUILDERS.items() if kind in findings]
    if lookalikes and "lookalike" in findings:
        signals = [s for s in signals if s.id != "link.lookalike"]
        signals.append(_lookalike_signal(lookalikes, findings["lookalike"]))
    return LinkAnalysis(signals, len(extraction.links), extraction.truncated)


def _is_rewriter(host: str) -> bool:
    return any(host == h or host.endswith("." + h) for h in REWRITER_HOSTS)


def _text_matches_destination(text_domain: str, link: Link) -> bool:
    """True if the domain shown in the link text is where the link (effectively) goes."""
    if same_organization(text_domain, link.host):
        return True
    registered = registrable_domain(link.host)
    if registered in TRACKING_DOMAINS or registered in OPAQUE_REWRITER_DOMAINS:
        return True  # legitimate click tracking / opaque security gateway
    if _is_rewriter(link.host):
        # Safe Links, URL Defense, google.com/url: compare with the wrapped destination.
        return any(
            same_organization(text_domain, inner.host)
            for inner in (parse_link(u, None, "embedded") for u in embedded_urls(link.url))
            if inner is not None
        )
    return False


def _check_web_link(
    link: Link,
    note: Callable[[str, str], None],
    lookalikes: list[Lookalike],
    via: str | None = None,
) -> None:
    shown = defang(link.url) + (f" (hidden inside a link to {defang(via)})" if via else "")
    if link.source == "attachment":
        shown += " (found inside an attachment)"
    host = link.host
    registered = registrable_domain(host)

    if link.text:
        text_domain = domain_shown_in_text(link.text)
        if text_domain and not _text_matches_destination(text_domain, link):
            note("mismatch", f'Text shows "{defang(text_domain)}", link goes to {shown}')

    ip_kind = ip_host_kind(host)
    if ip_kind:
        note("ip", shown + (" (disguised IP address)" if ip_kind == "obfuscated_ip" else ""))
    if link.has_userinfo:
        note("userinfo", shown)

    lookalike = find_lookalike(host) if not ip_kind else None
    if lookalike:
        lookalikes.append(lookalike)
        note("lookalike", f"{shown} imitates {lookalike.official_domain}")
    elif any(label.startswith("xn--") for label in host.split(".")):
        note("punycode", shown)

    if registered in SHORTENER_DOMAINS:
        note("shortener", shown)
    if host.rsplit(".", 1)[-1] in RISKY_TLDS:
        note("risky_tld", shown)
    if _downloads_program(link):
        note("dangerous_file", shown)


def _downloads_program(link: Link) -> bool:
    """File name in the path, or in a query value such as download.php?file=invoice.exe."""
    candidates = [link.path] + [value for _, value in parse_qsl(link.query)]
    for candidate in candidates:
        name = candidate.rsplit("/", 1)[-1].lower()
        if "." in name and name.rsplit(".", 1)[-1] in DANGEROUS_EXTENSIONS:
            return True
    return False


def _evidence(examples: list[str]) -> str:
    unique = list(dict.fromkeys(examples))
    shown = "; ".join(unique[:MAX_EXAMPLES])
    more = len(unique) - MAX_EXAMPLES
    return f"{len(unique)} link(s): {shown}" + (f"; and {more} more" if more > 0 else "")


def _builder(id: str, title: str, points: int, explanation: str):
    def build(examples: list[str]) -> Signal:
        return make_signal(f"link.{id}", CATEGORY, title, points, explanation, _evidence(examples))

    return build


def _lookalike_signal(lookalikes: list[Lookalike], examples: list[str]) -> Signal:
    brand = lookalikes[0].brand.name
    return make_signal(
        "link.lookalike",
        CATEGORY,
        f"Link imitates {brand}",
        POINTS_LOOKALIKE,
        f"A link points to a website made to look like {brand}'s. Fake sign-in pages on "
        "look-alike domains are the most common way passwords are stolen.",
        _evidence(examples),
    )


_BUILDERS = {
    "mismatch": _builder(
        "text_mismatch",
        "Link text hides the real destination",
        POINTS_TEXT_MISMATCH,
        "A link displays one web address but actually leads to a different one. This is the "
        "classic phishing trick for making a fake site look trustworthy.",
    ),
    "lookalike": _builder("lookalike", "Link imitates a known brand", POINTS_LOOKALIKE, ""),
    "userinfo": _builder(
        "userinfo",
        "Link uses a disguised address",
        POINTS_USERINFO,
        "A link contains an '@' that makes the start of the address look like a trusted site, "
        "while the browser actually goes to the part after the '@'.",
    ),
    "dangerous_file": _builder(
        "dangerous_file",
        "Link downloads a program",
        POINTS_DANGEROUS_FILE,
        "A link points directly to a file that can run code on your computer (for example .exe "
        "or .js). Legitimate senders rarely link to programs in email.",
    ),
    "form": _builder(
        "form",
        "Email contains a form",
        POINTS_FORM,
        "The email contains a form that can send typed information (such as a password) "
        "straight to a server. Legitimate services ask you to sign in on their website instead.",
    ),
    "ip": _builder(
        "ip_address",
        "Link goes to a bare IP address",
        POINTS_IP_HOST,
        "A link uses a numeric server address instead of a website name. Real companies use "
        "domain names; numeric addresses are typical of throwaway attack servers.",
    ),
    "script": _builder(
        "script_scheme",
        "Link runs code or opens a local program",
        POINTS_SCRIPT_SCHEME,
        "A link uses a special type (such as 'javascript:', 'data:', 'file:' or 'ms-msdt:') "
        "that can run code, show a hidden page, open files from another computer, or launch "
        "Windows tools, instead of opening a normal website.",
    ),
    "shortener": _builder(
        "shortener",
        "Link hides its destination behind a URL shortener",
        POINTS_SHORTENER,
        "A link uses a URL-shortening service, so you cannot see where it really goes before "
        "clicking. Common in both marketing and phishing.",
    ),
    "punycode": _builder(
        "punycode",
        "Link uses an international domain",
        POINTS_PUNYCODE,
        "A link's domain contains non-Latin characters (shown as 'xn--'). Legitimate in many "
        "languages, but also used to imitate familiar names.",
    ),
    "risky_tld": _builder(
        "risky_tld",
        "Link uses a frequently abused domain ending",
        POINTS_RISKY_TLD,
        "A link's domain ends in an extension that is cheap and frequently used for scams "
        "(for example .top, .xyz, or .zip, which looks like a file name).",
    ),
}
