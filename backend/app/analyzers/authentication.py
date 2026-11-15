"""Email authentication analyzer: SPF, DKIM and DMARC.

What these checks mean, in short:
- SPF:   was the message sent from a server the sender's domain allows?
- DKIM:  is the message cryptographically signed by a domain, and unmodified?
- DMARC: does the domain in the visible From address pass SPF or DKIM *for that same domain*,
         and what does the domain owner want done if it does not?

Trust model: MailGuard does not re-run these checks. It reads the results Gmail recorded when it
received the message. Senders can include their own fake "Authentication-Results" headers, so
only the TOPMOST such header is considered (Gmail adds it above everything the sender wrote), and
only if it was written by a trusted receiver (default: mx.google.com). Results are therefore
labeled "reported" (by Gmail), never "verified" (by MailGuard).

Missing results are not treated as failure: they produce a 0-point informational signal.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.auth_results import AuthResultsHeader, parse_authentication_results
from app.analyzers.common import make_signal
from app.parsing import ParsedEmail
from app.schemas import AuthenticationSummary, AuthSource, Signal

CATEGORY = "authentication"

POINTS_DMARC_FAIL = 35
POINTS_SPF_FAIL = 15
POINTS_SPF_SOFTFAIL = 8
POINTS_DKIM_FAIL = 15
POINTS_NO_DMARC_POLICY = 5


@dataclass(frozen=True)
class AuthenticationAnalysis:
    summary: AuthenticationSummary
    signals: list[Signal]


def select_trusted_header(
    parsed: ParsedEmail, trusted_authserv_ids: frozenset[str]
) -> AuthResultsHeader | None:
    """Return the topmost Authentication-Results header if a trusted receiver wrote it."""
    if not parsed.authentication_results:
        return None
    top = parse_authentication_results(parsed.authentication_results[0])
    if top is not None and top.authserv_id in trusted_authserv_ids:
        return top
    return None


def _overall(header: AuthResultsHeader, method: str) -> str:
    """Combine multiple results for one method (e.g. several DKIM signatures)."""
    results = [r.result for r in header.for_method(method)]
    if not results:
        return "none"
    if "pass" in results:
        return "pass"  # one valid DKIM signature is enough
    for outcome in ("fail", "softfail", "permerror", "temperror", "neutral", "policy"):
        if outcome in results:
            return outcome
    return results[0]


def analyze_authentication(
    parsed: ParsedEmail, trusted_authserv_ids: frozenset[str]
) -> AuthenticationAnalysis:
    header = select_trusted_header(parsed, trusted_authserv_ids)
    if header is None:
        return _unavailable(parsed)

    spf, dkim, dmarc = (_overall(header, m) for m in ("spf", "dkim", "dmarc"))
    summary = AuthenticationSummary(
        source=AuthSource.REPORTED, reported_by=header.authserv_id, spf=spf, dkim=dkim, dmarc=dmarc
    )
    from_domain = _from_domain(header, parsed)
    reported = f"reported by {header.authserv_id}"
    signals: list[Signal] = []

    if dmarc == "fail":
        signals.append(
            make_signal(
                "auth.dmarc_fail",
                CATEGORY,
                "Sender failed DMARC",
                POINTS_DMARC_FAIL,
                f"The message claims to come from {from_domain or 'a domain'}, but it did not pass "
                "that domain's own anti-spoofing policy (DMARC). The sender may be impersonating "
                "this domain.",
                f"spf={spf}, dkim={dkim}, dmarc={dmarc} ({reported})",
            )
        )

    # When DMARC passes, an individual SPF or DKIM failure is expected in some legitimate
    # cases (e.g. forwarding breaks SPF), so it adds no points.
    if dmarc != "pass":
        if spf == "fail":
            signals.append(
                make_signal(
                    "auth.spf_fail",
                    CATEGORY,
                    "Sent from an unauthorized server (SPF fail)",
                    POINTS_SPF_FAIL,
                    "The sending server is not on the list of servers allowed to send email "
                    "for the sender's domain.",
                    f"spf={spf} ({reported})",
                )
            )
        elif spf == "softfail":
            signals.append(
                make_signal(
                    "auth.spf_softfail",
                    CATEGORY,
                    "Sending server not clearly authorized (SPF softfail)",
                    POINTS_SPF_SOFTFAIL,
                    "The sender's domain says this server is probably not allowed to send its "
                    "email.",
                    f"spf={spf} ({reported})",
                )
            )
        if dkim == "fail":
            signals.append(
                make_signal(
                    "auth.dkim_fail",
                    CATEGORY,
                    "Invalid digital signature (DKIM fail)",
                    POINTS_DKIM_FAIL,
                    "The message carries a digital signature that does not match. It may have "
                    "been altered or forged.",
                    f"dkim={dkim} ({reported})",
                )
            )
        if dmarc == "none":
            signals.append(
                make_signal(
                    "auth.no_dmarc",
                    CATEGORY,
                    "Sender's domain has no anti-spoofing policy",
                    POINTS_NO_DMARC_POLICY,
                    "The sender's domain does not publish a DMARC policy, so receivers cannot "
                    "reliably detect messages that spoof it. Common for small domains; weak "
                    "evidence on its own.",
                    f"dmarc={dmarc} ({reported})",
                )
            )

    if spf == "pass" and dkim == "pass" and dmarc == "pass":
        signals.append(
            make_signal(
                "auth.all_pass",
                CATEGORY,
                "Sender authentication passed",
                0,
                f"Gmail confirmed the message really comes from {from_domain or 'the sender'}'s "
                "domain. This proves who sent it, not that the sender is trustworthy: attackers "
                "can authenticate their own look-alike domains.",
                f"spf=pass, dkim=pass, dmarc=pass ({reported})",
            )
        )

    return AuthenticationAnalysis(summary, signals)


def _unavailable(parsed: ParsedEmail) -> AuthenticationAnalysis:
    ignored = len(parsed.authentication_results)
    evidence = (
        f"Ignored {ignored} Authentication-Results header(s) not written by a trusted mail "
        "server; senders can forge these."
        if ignored
        else "No Authentication-Results header present."
    )
    signal = make_signal(
        "auth.unavailable",
        CATEGORY,
        "Sender authentication could not be confirmed",
        0,
        "No authentication results from a trusted mail server were found. This is normal for "
        "some internal or forwarded mail and is not, by itself, a sign of phishing.",
        evidence,
    )
    return AuthenticationAnalysis(AuthenticationSummary(source=AuthSource.UNAVAILABLE), [signal])


def _from_domain(header: AuthResultsHeader, parsed: ParsedEmail) -> str:
    for result in header.for_method("dmarc"):
        if result.properties.get("header.from"):
            return result.properties["header.from"].lower()
    return parsed.sender.domain if parsed.sender else ""
