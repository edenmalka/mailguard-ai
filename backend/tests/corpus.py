"""Labeled synthetic emails for calibrating and evaluating the scoring engine.

Each case lists the ACCEPTABLE verdicts. Genuinely ambiguous cases accept two verdicts. All
content is synthetic: reserved domains (example.*, .test) or obviously fake look-alikes; real
brand domains appear only as legitimate senders or as the brand being imitated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from email.message import EmailMessage
from email.policy import SMTP

SAFE = frozenset({"safe"})
FLAGGED = frozenset({"suspicious", "malicious"})
MALICIOUS = frozenset({"malicious"})
SAFE_OR_SUSPICIOUS = frozenset({"safe", "suspicious"})


@dataclass(frozen=True)
class Case:
    name: str
    expected: frozenset[str]
    raw: bytes = field(repr=False)


def email(
    sender: str,
    *,
    subject: str = "Hello",
    text: str = "Hello.",
    html: str | None = None,
    reply_to: str | None = None,
    auth: tuple[str, str, str] | None = ("pass", "pass", "pass"),
    attachments: tuple[tuple[str, str, bytes], ...] = (),
) -> bytes:
    """Build a realistic MIME email. `auth` is Gmail's (spf, dkim, dmarc) or None."""
    message = EmailMessage()
    message["From"] = sender
    message["To"] = "reader@example.org"
    message["Subject"] = subject
    if reply_to:
        message["Reply-To"] = reply_to
    message.set_content(text)
    if html is not None:
        message.add_alternative(html, subtype="html")
    for filename, content_type, data in attachments:
        maintype, subtype = content_type.split("/", 1)
        message.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    raw = message.as_bytes(policy=SMTP)
    if auth is None:
        return raw
    spf, dkim, dmarc = auth
    header = (
        f"Authentication-Results: mx.google.com; dkim={dkim} header.i=@x; "
        f"spf={spf} smtp.mailfrom=x; dmarc={dmarc} header.from=x\r\n"
    )
    return header.encode() + raw
