"""Safe MIME parsing: turns untrusted raw email bytes into a plain `ParsedEmail` object.

This is the only module that touches raw MIME. Analyzers work on `ParsedEmail`, so every
parsing edge case (encoded headers, broken structure, unknown charsets) is handled here once.

Design rules:
- Never raise on bad input. Problems are recorded in `ParsedEmail.defects` instead.
- Bound the work: limits on number of MIME parts and on decoded text size.
- Decode RFC 2047 encoded headers (e.g. "=?UTF-8?B?...?=") so analyzers see real text.
"""

from __future__ import annotations

import email.utils
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser

from app.analyzers.domains import normalize_domain

MAX_PARTS = 200
MAX_TEXT_CHARS = 1_000_000  # per body type; raw messages are capped at 2 MB anyway
MAX_HEADER_CHARS = 10_000
# Python's address parser slows down sharply on huge address lists (seconds for tens of
# thousands of addresses), which an attacker could use to make analysis time out. Real
# address headers are far shorter, so longer ones are cut at an address boundary first.
MAX_ADDRESS_HEADER_CHARS = 2_000
ADDRESS_HEADERS = frozenset(
    {"from", "sender", "reply-to", "to", "cc", "bcc", "return-path"}
    | {"resent-from", "resent-sender", "resent-to", "resent-cc", "resent-bcc"}
)


@dataclass(frozen=True)
class EmailAddress:
    display_name: str
    address: str  # "local@domain" as written, domain lower-cased
    domain: str  # normalized (lower-case, IDNA/punycode); "" if missing


@dataclass(frozen=True)
class Attachment:
    filename: str | None  # base name only (any path is removed); None if the part has none
    content_type: str  # as DECLARED by the sender: untrusted
    size: int
    data: bytes = field(default=b"", repr=False, compare=False)  # decoded content


@dataclass
class ParsedEmail:
    headers: list[tuple[str, str]] = field(default_factory=list)  # decoded, original order
    from_addresses: list[EmailAddress] = field(default_factory=list)
    from_header_count: int = 0
    reply_to: list[EmailAddress] = field(default_factory=list)
    return_path: EmailAddress | None = None
    subject: str = ""
    authentication_results: list[str] = field(default_factory=list)  # topmost first
    text_body: str = ""
    html_body: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    body_truncated: bool = False  # True if text/HTML beyond MAX_TEXT_CHARS was not kept
    defects: list[str] = field(default_factory=list)

    @property
    def sender(self) -> EmailAddress | None:
        """The (first) From address, or None if there is no usable one."""
        return self.from_addresses[0] if self.from_addresses else None


def parse_email(raw: bytes) -> ParsedEmail:
    parsed = ParsedEmail()
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # the stdlib parser is lenient; this is a last-resort guard
        parsed.defects.append(f"UnparseableMessage:{type(exc).__name__}")
        return parsed

    parsed.defects.extend(type(d).__name__ for d in message.defects)
    _read_headers(message, parsed)
    _read_parts(message, parsed)
    parsed.defects = sorted(set(parsed.defects))
    return parsed


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------


def _read_headers(message: EmailMessage, parsed: ParsedEmail) -> None:
    for name, raw_value in message.raw_items():
        raw_value = _restore_utf8(raw_value)
        lname = name.lower()
        raw_value = _limit_header(lname, raw_value, parsed)
        value = _decode_header(message, name, raw_value, parsed)
        parsed.headers.append((name, value))

        if lname == "from":
            parsed.from_header_count += 1
            parsed.from_addresses.extend(_parse_addresses(message, name, raw_value, parsed))
        elif lname == "reply-to":
            parsed.reply_to.extend(_parse_addresses(message, name, raw_value, parsed))
        elif lname == "return-path" and parsed.return_path is None:
            addresses = _parse_addresses(message, name, raw_value, parsed)
            parsed.return_path = addresses[0] if addresses else None
        elif lname == "subject" and not parsed.subject:
            parsed.subject = value
        elif lname == "authentication-results":
            parsed.authentication_results.append(value)


def _limit_header(lname: str, raw_value: str, parsed: ParsedEmail) -> str:
    """Cut oversized headers BEFORE parsing, so parsing time stays bounded."""
    if lname in ADDRESS_HEADERS and len(raw_value) > MAX_ADDRESS_HEADER_CHARS:
        parsed.defects.append("OversizedAddressHeader")
        cut = raw_value[:MAX_ADDRESS_HEADER_CHARS]
        return cut[: cut.rfind(",")] if "," in cut else cut
    if len(raw_value) > MAX_HEADER_CHARS:
        parsed.defects.append("OversizedHeader")
        return raw_value[:MAX_HEADER_CHARS]
    return raw_value


def _restore_utf8(value: str) -> str:
    """Raw 8-bit header bytes arrive as surrogate escapes; turn valid UTF-8 back into text."""
    if not any("\udc80" <= ch <= "\udcff" for ch in value):
        return value
    return value.encode("utf-8", "surrogateescape").decode("utf-8", errors="replace")


def _decode_header(message: EmailMessage, name: str, raw_value: str, parsed: ParsedEmail) -> str:
    """Decode encoded words and unfold. Falls back to the raw text if decoding fails."""
    try:
        value = str(message.policy.header_fetch_parse(name, raw_value))
    except Exception:
        parsed.defects.append("UndecodableHeader")
        value = raw_value
    value = " ".join(value.split())  # unfold and collapse whitespace
    return value[:MAX_HEADER_CHARS]


def _parse_addresses(
    message: EmailMessage, name: str, raw_value: str, parsed: ParsedEmail
) -> list[EmailAddress]:
    try:
        header = message.policy.header_fetch_parse(name, raw_value)
        if hasattr(header, "addresses"):
            addresses = [
                _make_address(a.display_name, a.username, a.domain) for a in header.addresses
            ]
        else:
            # Some headers (e.g. Return-Path) are not parsed as address lists by the stdlib.
            addresses = _fallback_addresses(raw_value)
    except Exception:
        parsed.defects.append("UnparseableAddressHeader")
        addresses = _fallback_addresses(raw_value)
    return [a for a in addresses if a.address or a.display_name]


def _fallback_addresses(raw_value: str) -> list[EmailAddress]:
    addresses = []
    for display_name, addr in email.utils.getaddresses([raw_value]):
        local, _, domain = addr.rpartition("@")
        addresses.append(_make_address(display_name, local or addr, domain))
    return addresses


def _make_address(display_name: str, username: str, domain: str) -> EmailAddress:
    display_name = " ".join((display_name or "").split())[:MAX_HEADER_CHARS]
    domain_text = (domain or "").strip().lower()
    address = f"{username}@{domain_text}" if username and domain_text else (username or "")
    return EmailAddress(
        display_name=display_name,
        address=address,
        domain=normalize_domain(domain_text),
    )


# ---------------------------------------------------------------------------
# Body parts
# ---------------------------------------------------------------------------


def _read_parts(message: EmailMessage, parsed: ParsedEmail) -> None:
    text_parts: list[str] = []
    html_parts: list[str] = []
    try:
        for index, part in enumerate(message.walk()):
            if index >= MAX_PARTS:
                parsed.defects.append("TooManyParts")
                break
            if part.is_multipart():
                continue
            _read_leaf_part(part, parsed, text_parts, html_parts)
    except RecursionError:
        parsed.defects.append("NestingTooDeep")

    text_body = "".join(text_parts)
    html_body = "".join(html_parts)
    parsed.body_truncated = len(text_body) > MAX_TEXT_CHARS or len(html_body) > MAX_TEXT_CHARS
    parsed.text_body = text_body[:MAX_TEXT_CHARS]
    parsed.html_body = html_body[:MAX_TEXT_CHARS]


def _read_leaf_part(
    part: Message, parsed: ParsedEmail, text_parts: list[str], html_parts: list[str]
) -> None:
    content_type = part.get_content_type()
    try:
        filename = part.get_filename()
        disposition = part.get_content_disposition()
    except Exception:
        parsed.defects.append("UnreadablePartHeaders")
        filename, disposition = None, None

    is_body_text = content_type in {"text/plain", "text/html"}
    # Anything that is not body text is treated as an attachment, even without a filename or
    # an "attachment" label: otherwise a program sent as an unnamed part would go unseen.
    if filename or disposition == "attachment" or not is_body_text:
        payload = _payload_bytes(part, parsed)
        name = _base_name(filename) if filename else None
        parsed.attachments.append(Attachment(name, content_type, len(payload), payload))
        return

    if content_type == "text/plain":
        text_parts.append(_decode_text(part, parsed))
    else:
        html_parts.append(_decode_text(part, parsed))


def _base_name(filename: str) -> str:
    """Drop any directory part ("../../x.exe" -> "x.exe"); keep the name otherwise as sent."""
    name = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
    return name[:MAX_HEADER_CHARS] or filename[:MAX_HEADER_CHARS]


def _payload_bytes(part: Message, parsed: ParsedEmail) -> bytes:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        parsed.defects.append("UndecodablePayload")
        return b""
    return payload if isinstance(payload, bytes) else b""


def _decode_text(part: Message, parsed: ParsedEmail) -> str:
    """Decode a text part using its declared charset; never fail on bad or unknown charsets."""
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except Exception:
        parsed.defects.append("UndecodableTextPart")
    return _payload_bytes(part, parsed).decode("utf-8", errors="replace")
