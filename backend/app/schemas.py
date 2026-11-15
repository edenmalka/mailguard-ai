"""Request and response models: the contract between the add-on and the backend."""

import base64
import binascii
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class AnalyzeRequest(BaseModel):
    # Reject unexpected fields instead of silently ignoring them.
    model_config = ConfigDict(extra="forbid")

    # The full RFC 822 email (headers + body), base64url-encoded by the add-on.
    raw_message: str = Field(min_length=1)


class Verdict(StrEnum):
    SAFE = "safe"  # low risk: no significant signals in a fully analyzed message
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    # Low score, but the message could not be fully analyzed (e.g. malformed, no sender).
    # Never reported as "safe": absence of evidence from a partial analysis proves little.
    INCONCLUSIVE = "inconclusive"


class Signal(BaseModel):
    """One piece of evidence. Points are 0 for purely informational findings."""

    id: str
    category: str
    title: str
    points: int = Field(ge=0)
    explanation: str
    evidence: str | None = None


class AuthSource(StrEnum):
    # Results written by a mail server we trust (Gmail), read from the message headers.
    # MailGuard did not re-run the checks itself.
    REPORTED = "reported"
    # Reserved for checks MailGuard performs itself (e.g. DKIM signature verification).
    VERIFIED = "verified"
    # No trustworthy results were available.
    UNAVAILABLE = "unavailable"


class AuthenticationSummary(BaseModel):
    """SPF/DKIM/DMARC outcome and, crucially, where it came from."""

    source: AuthSource
    reported_by: str | None = None  # e.g. "mx.google.com"
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"


class AnalyzeResponse(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    summary: str
    signals: list[Signal]
    authentication: AuthenticationSummary | None = None
    # Plain-language notes on what could not be checked for this message.
    limitations: list[str] = Field(default_factory=list)


def decode_raw_message(encoded: str) -> bytes:
    """Strictly decode base64url. Raises ValueError on any invalid character or padding."""
    try:
        return base64.b64decode(encoded, altchars=b"-_", validate=True)
    except binascii.Error as exc:
        raise ValueError("raw_message is not valid base64url") from exc
