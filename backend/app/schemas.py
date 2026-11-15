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
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Signal(BaseModel):
    """One piece of evidence that contributed to the score."""

    id: str
    title: str
    points: int
    explanation: str
    evidence: str | None = None


class AnalyzeResponse(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    summary: str
    signals: list[Signal]


def decode_raw_message(encoded: str) -> bytes:
    """Strictly decode base64url. Raises ValueError on any invalid character or padding."""
    try:
        return base64.b64decode(encoded, altchars=b"-_", validate=True)
    except binascii.Error as exc:
        raise ValueError("raw_message is not valid base64url") from exc
