"""Unit tests for HMAC signature verification."""

from app.security import compute_signature, verify_signature

SECRET = b"unit-test-secret-value-32-chars-min"
BODY = b'{"raw_message":"abc"}'
NOW = 1_700_000_000
MAX_AGE = 300


def _verify(**overrides) -> bool:
    ts = str(NOW)
    args = {
        "secret": SECRET,
        "timestamp": ts,
        "signature": compute_signature(SECRET, ts, BODY),
        "body": BODY,
        "max_age_seconds": MAX_AGE,
        "now": NOW,
    }
    args.update(overrides)
    return verify_signature(**args)


def test_valid_signature_is_accepted() -> None:
    assert _verify() is True


def test_wrong_secret_is_rejected() -> None:
    bad = compute_signature(b"some-other-secret-value-32-chars!!", str(NOW), BODY)
    assert _verify(signature=bad) is False


def test_tampered_body_is_rejected() -> None:
    assert _verify(body=b'{"raw_message":"evil"}') is False


def test_old_timestamp_is_rejected() -> None:
    assert _verify(now=NOW + MAX_AGE + 1) is False


def test_future_timestamp_is_rejected() -> None:
    assert _verify(now=NOW - MAX_AGE - 1) is False


def test_timestamp_at_edge_of_window_is_accepted() -> None:
    assert _verify(now=NOW + MAX_AGE) is True


def test_missing_or_malformed_headers_are_rejected() -> None:
    assert _verify(timestamp=None) is False
    assert _verify(signature=None) is False
    assert _verify(timestamp="") is False
    assert _verify(timestamp="12.5") is False
    assert _verify(timestamp="-1") is False
    assert _verify(timestamp="١٢٣") is False  # non-ASCII digits


def test_oversized_or_non_ascii_values_are_rejected_without_errors() -> None:
    # Found in the final review: these used to raise inside verify_signature (HTTP 500).
    assert _verify(timestamp="1" * 4301) is False  # beyond Python's int() digit limit
    assert _verify(timestamp="1" * 13) is False
    assert _verify(signature="\xe9" * 64) is False  # non-ASCII: compare_digest would raise
    assert _verify(signature="a" * 63) is False
    assert _verify(signature="z" * 64) is False
