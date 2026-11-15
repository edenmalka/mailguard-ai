"""Helpers for building synthetic test emails."""

from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
GMAIL = frozenset({"mx.google.com"})


def load_fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def make_email(*header_lines: str, body: str = "Hello.") -> bytes:
    """Build a minimal RFC 822 message from header lines like 'From: a@example.com'."""
    headers = "\r\n".join(header_lines)
    return f"{headers}\r\nMIME-Version: 1.0\r\n\r\n{body}\r\n".encode()


def gmail_auth(spf: str = "pass", dkim: str = "pass", dmarc: str = "pass") -> str:
    return (
        f"Authentication-Results: mx.google.com; dkim={dkim} header.i=@example.com; "
        f"spf={spf} smtp.mailfrom=a@example.com; dmarc={dmarc} header.from=example.com"
    )
