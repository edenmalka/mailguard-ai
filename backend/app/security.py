"""Request authentication using HMAC-SHA256 signatures.

The Gmail add-on and the backend share a secret. For every request the add-on sends:
  X-MailGuard-Timestamp: current Unix time in seconds
  X-MailGuard-Signature: hex(HMAC_SHA256(secret, "<timestamp>." + body))

The backend recomputes the signature and compares it in constant time. Including the
timestamp in the signed data limits how long a captured request can be replayed.
"""

import hashlib
import hmac
import time

TIMESTAMP_HEADER = "X-MailGuard-Timestamp"
SIGNATURE_HEADER = "X-MailGuard-Signature"


def compute_signature(secret: bytes, timestamp: str, body: bytes) -> str:
    message = timestamp.encode("ascii") + b"." + body
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify_signature(
    secret: bytes,
    timestamp: str | None,
    signature: str | None,
    body: bytes,
    max_age_seconds: int,
    now: float | None = None,
) -> bool:
    """Return True only if the signature is valid and the timestamp is fresh."""
    if not timestamp or not signature:
        return False
    if not timestamp.isascii() or not timestamp.isdigit():
        return False

    current = time.time() if now is None else now
    if abs(current - int(timestamp)) > max_age_seconds:
        return False

    expected = compute_signature(secret, timestamp, body)
    # compare_digest takes the same time whether the first or last character differs,
    # so an attacker cannot guess the signature one character at a time.
    return hmac.compare_digest(expected, signature.lower())
