"""Authentication analyzer tests: trust model, missing results, and scoring rules."""

from app.analyzers.authentication import analyze_authentication
from app.parsing import parse_email
from app.schemas import AuthSource
from tests.helpers import GMAIL, gmail_auth, load_fixture, make_email


def _analyze(raw: bytes):
    return analyze_authentication(parse_email(raw), GMAIL)


def _ids(analysis) -> set[str]:
    return {s.id for s in analysis.signals}


def test_all_pass_is_reported_by_gmail_with_zero_points() -> None:
    result = _analyze(load_fixture("legit_newsletter.eml"))
    assert result.summary.source is AuthSource.REPORTED
    assert result.summary.reported_by == "mx.google.com"
    assert (result.summary.spf, result.summary.dkim, result.summary.dmarc) == (
        "pass",
        "pass",
        "pass",
    )
    assert _ids(result) == {"auth.all_pass"}
    assert sum(s.points for s in result.signals) == 0


def test_missing_results_are_not_treated_as_failure() -> None:
    result = _analyze(make_email("From: a@example.com"))
    assert result.summary.source is AuthSource.UNAVAILABLE
    assert result.summary.dmarc == "unknown"
    assert _ids(result) == {"auth.unavailable"}
    assert sum(s.points for s in result.signals) == 0


def test_untrusted_receiver_results_are_ignored() -> None:
    result = _analyze(load_fixture("untrusted_auth_only.eml"))
    assert result.summary.source is AuthSource.UNAVAILABLE
    assert result.summary.spf == "unknown"  # the forged "spf=pass" is not believed
    assert "Ignored 1" in (result.signals[0].evidence or "")


def test_forged_header_below_gmails_is_ignored() -> None:
    # The attacker added "dmarc=pass" lower down; only Gmail's topmost header counts.
    result = _analyze(load_fixture("forged_auth_header.eml"))
    assert result.summary.dmarc == "fail"
    assert result.summary.spf == "softfail"
    assert {"auth.dmarc_fail", "auth.spf_softfail"} <= _ids(result)


def test_spoofed_header_from_attacker_above_is_not_trusted() -> None:
    # If the topmost header is not from a trusted receiver, nothing is trusted.
    raw = make_email(
        "Authentication-Results: evil.test; spf=pass; dkim=pass; dmarc=pass",
        gmail_auth(dmarc="fail"),
        "From: a@example.com",
    )
    assert _analyze(raw).summary.source is AuthSource.UNAVAILABLE


def test_dmarc_fail_scores_and_explains() -> None:
    result = _analyze(load_fixture("spoofed_dmarc_fail.eml"))
    by_id = {s.id: s for s in result.signals}
    assert by_id["auth.dmarc_fail"].points == 35
    assert "microsoft.com" in by_id["auth.dmarc_fail"].explanation
    assert "reported by mx.google.com" in (by_id["auth.dmarc_fail"].evidence or "")
    assert "auth.spf_fail" in by_id


def test_spf_failure_is_not_penalized_when_dmarc_passes() -> None:
    # Typical of forwarded mail: SPF breaks, DKIM keeps DMARC passing.
    result = _analyze(make_email(gmail_auth(spf="fail", dkim="pass", dmarc="pass")))
    assert sum(s.points for s in result.signals) == 0


def test_dkim_fail_and_no_dmarc_policy() -> None:
    result = _analyze(make_email(gmail_auth(spf="none", dkim="fail", dmarc="none")))
    assert {"auth.dkim_fail", "auth.no_dmarc"} == _ids(result)


def test_one_passing_dkim_signature_is_enough() -> None:
    raw = make_email(
        "Authentication-Results: mx.google.com; dkim=fail header.d=x.example; "
        "dkim=pass header.d=example.com; spf=pass; dmarc=pass header.from=example.com"
    )
    assert _analyze(raw).summary.dkim == "pass"


def test_trusted_ids_are_configurable() -> None:
    raw = make_email("Authentication-Results: mx.corp.example; spf=pass; dkim=pass; dmarc=fail")
    parsed = parse_email(raw)
    assert analyze_authentication(parsed, GMAIL).summary.source is AuthSource.UNAVAILABLE
    custom = analyze_authentication(parsed, frozenset({"mx.corp.example"}))
    assert custom.summary.dmarc == "fail"
