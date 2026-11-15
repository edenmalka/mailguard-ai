"""Link extraction and URL normalization. Offline string processing only: links are never visited.

Hosts are normalized the way browsers interpret them, so we judge where a click would really go:
- tabs/newlines inside URLs are removed, "\\" is treated as "/", and any number of slashes
  after "http:" is accepted ("http:/host", "https:host"), as browsers do,
- "//host" means https, and "https://paypal.com@evil.example/" really goes to evil.example,
- percent-encoded and international hosts are decoded and converted to punycode.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

from app.analyzers.brands import BRANDS
from app.analyzers.domains import has_public_suffix, normalize_domain, registrable_label
from app.analyzers.link_data import FILE_LIKE_TLDS
from app.parsing import ParsedEmail

MAX_LINKS = 500
MAX_LINK_TEXT_CHARS = 300
MAX_URL_CHARS = 2048
MAX_EMBEDDED_URLS = 3

_SCHEME = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*):")
_TEXT_URL = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'()\[\]{}]+")
_TRAILING_PUNCTUATION = ".,;:!?"
_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}")
# A domain shown as link text: "paypal.com", "www.paypal.com/login", "https://paypal.com".
_DOMAIN_TEXT = re.compile(
    r"(?P<scheme>https?://)?(?P<www>www\.)?(?P<domain>[\w-]+(?:\.[\w-]+)+)"
    r"(?::\d+)?(?P<path>[/?#]\S*)?"
)
_DOMAIN_IN_SENTENCE = re.compile(r"(?i)(?:https?://|\bwww\.)([\w-]+(?:\.[\w-]+)+)")
# A URL nested inside another URL (redirect parameters, security-gateway rewrites).
_EMBEDDED_URL = re.compile(r"(?i)https?://[^\s&\"'<>]+")
_URL_START = re.compile(r"(?i)https?://")


@dataclass(frozen=True)
class Link:
    url: str  # as found, without whitespace, capped length
    scheme: str  # lower-case, e.g. "https", "mailto", "javascript"; "" if relative
    host: str  # normalized host ("" if none)
    path: str
    query: str
    has_userinfo: bool  # "user@host" form, used to disguise the real host
    text: str | None  # visible link text (HTML links only), invisible characters removed
    source: str  # "html_link" | "html_form" | "text" | "embedded"


@dataclass(frozen=True)
class LinkExtraction:
    links: list[Link]
    truncated: bool  # more links existed than MAX_LINKS


def extract_links(parsed: ParsedEmail) -> LinkExtraction:
    collector = _HtmlLinkCollector()
    try:
        collector.feed(parsed.html_body)
        collector.close()
    except Exception:  # HTMLParser is lenient; keep whatever was collected
        collector.flush_open_anchors()

    found = list(collector.found)
    truncated = collector.overflow
    for match in _TEXT_URL.finditer(parsed.text_body):
        if len(found) >= MAX_LINKS:
            truncated = True
            break
        found.append((match.group(0).rstrip(_TRAILING_PUNCTUATION), None, "text"))

    links: list[Link] = []
    seen: set[tuple[str, str | None, str]] = set()
    for raw_url, text, source in found:
        key = (raw_url, text, source)
        if key in seen:
            continue
        seen.add(key)
        link = parse_link(raw_url, text, source)
        if link is not None:
            links.append(link)
    return LinkExtraction(links, truncated)


def parse_link(raw_url: str, text: str | None = None, source: str = "text") -> Link | None:
    """Normalize one URL. Returns None for relative links (no scheme), except forms."""
    url = "".join(ch for ch in raw_url if ch not in "\t\r\n").strip()[:MAX_URL_CHARS]
    if url.lower().startswith("www."):
        url = "http://" + url
    elif url.startswith("//"):
        url = "https:" + url
    text = _clean_link_text(text)

    match = _SCHEME.match(url)
    if not match:
        if source == "html_form":
            return Link(url, "", "", "", "", False, text, source)  # posts to "this page"
        return None
    scheme = match.group(1).lower()
    if scheme not in {"http", "https"}:
        return Link(url, scheme, "", "", "", False, text, source)

    # Browsers accept "http:/host", "http:\\host" and "https:host": normalize the slashes.
    rest = url[match.end() :].lstrip("/\\")
    normalized = f"{scheme}://{rest}".replace("\\", "/")
    try:
        parts = urlsplit(normalized)
        host = parts.hostname or ""
        path, query = parts.path, parts.query
        has_userinfo = "@" in parts.netloc
    except ValueError:  # e.g. malformed IPv6 literal
        host, path, query, has_userinfo = "", "", "", False
    host = normalize_domain(unquote(host))
    return Link(url, scheme, host, path, query, has_userinfo, text, source)


def embedded_urls(url: str) -> list[str]:
    """Absolute URLs nested inside a URL, e.g. the target of ?q=https://... or a gateway rewrite."""
    decoded = unquote(unquote(url))  # gateways often encode the inner URL once or twice
    found = []
    # Search from every "http(s)://" after the start: a greedy single pass would swallow the
    # inner URL as part of the outer one.
    for start in _URL_START.finditer(decoded, 1):
        match = _EMBEDDED_URL.match(decoded, start.start())
        if match is None:
            continue
        inner = match.group(0).split("__;")[0].rstrip("_")  # Proofpoint v3 delimiters
        found.append(inner)
        if len(found) >= MAX_EMBEDDED_URLS:
            break
    return found


def ip_host_kind(host: str) -> str | None:
    """'ip' for a plain IP address, 'obfuscated_ip' for forms like 3232235777 or 0x7f.1."""
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        pass
    if _NUMERIC_HOST.fullmatch(host):
        return "obfuscated_ip"  # browsers still treat these as IP addresses
    return None


def domain_shown_in_text(text: str) -> str | None:
    """The domain a link's visible text presents, if the text looks like a web address.

    A bare word such as "report.zip", "setup.py" or "ASP.NET" is treated as a file or product
    name, not an address, unless it has "http(s)://", "www." or a path.
    """
    text = text.strip()
    full = _DOMAIN_TEXT.fullmatch(text)
    if full:
        candidate = full.group("domain")
        is_bare = not (full.group("scheme") or full.group("www") or full.group("path"))
        tld = candidate.rsplit(".", 1)[-1]
        if is_bare and tld.lower() in FILE_LIKE_TLDS:
            return None
        # "ASP.NET", "Socket.IO" are product names; but "PAYPAL.COM" is a brand address.
        if is_bare and not tld.islower() and not _names_known_brand(candidate):
            return None
    else:
        sentence = _DOMAIN_IN_SENTENCE.search(text)
        if not sentence:
            return None
        candidate = sentence.group(1)
    domain = normalize_domain(candidate)
    return domain if has_public_suffix(domain) else None


def _names_known_brand(candidate: str) -> bool:
    label = registrable_label(normalize_domain(candidate))
    return any(
        label == registrable_label(official) for brand in BRANDS for official in brand.domains
    )


def defang(url: str, limit: int = 80) -> str:
    """Make a URL non-clickable for display: hxxps://evil[.]example/path."""
    shown = url if len(url) <= limit else url[: limit - 1] + "…"
    if shown.lower().startswith("http"):
        shown = "hxxp" + shown[4:]
    return shown.replace(".", "[.]")


def _clean_link_text(text: str | None) -> str | None:
    """Collapse whitespace and drop invisible characters (e.g. zero-width spaces), which
    attackers insert so that "pay<zero-width>pal.com" is not recognized as an address."""
    if not text:
        return None
    visible = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return " ".join(visible.split())[:MAX_LINK_TEXT_CHARS] or None


class _HtmlLinkCollector(HTMLParser):
    """Collects <a>/<area> links with their visible text, and <form> targets."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)  # decodes &#x2e; etc. like a browser
        self.found: list[tuple[str, str | None, str]] = []
        self.overflow = False
        self._open_anchors: list[tuple[str, list[str]]] = []

    def _add(self, url: str, text: str | None, source: str) -> None:
        if len(self.found) >= MAX_LINKS:
            self.overflow = True
            return
        self.found.append((url, text, source))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value for name, value in attrs if value is not None}
        if tag == "a" and values.get("href"):
            self._open_anchors.append((values["href"], []))
        elif tag == "area" and values.get("href"):
            self._add(values["href"], None, "html_link")
        elif tag == "form":
            self._add(values.get("action", ""), None, "html_form")

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._open_anchors:
            href, parts = self._open_anchors.pop()
            self._add(href, "".join(parts), "html_link")

    def handle_data(self, data: str) -> None:
        for _, parts in self._open_anchors:
            if sum(len(p) for p in parts) < MAX_LINK_TEXT_CHARS:
                parts.append(data[:MAX_LINK_TEXT_CHARS])

    def close(self) -> None:
        super().close()
        self.flush_open_anchors()

    def flush_open_anchors(self) -> None:
        while self._open_anchors:  # unclosed <a> tags still count as links
            href, parts = self._open_anchors.pop()
            self._add(href, "".join(parts), "html_link")
