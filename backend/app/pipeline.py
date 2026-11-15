"""Analysis pipeline: parse once, run every analyzer, combine the evidence into a result.

Scoring here is deliberately simple and provisional (sum of points, capped at 100).
Step 7 replaces it with weighted scoring, combination rules and attack-pattern labels.

A low score only means "low risk" when the message was fully analyzed. If the message is
malformed, has no usable sender, was too large to check completely, or has attachments that
could not be inspected, the verdict is "inconclusive" instead of "safe".
"""

from app.analyzers.attachments import analyze_attachments
from app.analyzers.authentication import analyze_authentication
from app.analyzers.content import analyze_content
from app.analyzers.links import analyze_links
from app.analyzers.sender import analyze_sender
from app.analyzers.structure import analyze_structure
from app.parsing import ParsedEmail, parse_email
from app.schemas import AnalyzeResponse, AuthSource, Signal, Verdict

SUSPICIOUS_THRESHOLD = 30
MALICIOUS_THRESHOLD = 70

LIMIT_NO_SENDER = "The message has no valid sender address, so the sender could not be checked."
LIMIT_MALFORMED = (
    "The message structure is malformed, so some of its content may not have been analyzed."
)
LIMIT_NO_AUTH = (
    "Sender authentication results (SPF, DKIM, DMARC) from Gmail were not available, so the "
    "sender's identity could not be confirmed."
)
LIMIT_PARTIAL_CONTENT = (
    "The email is very large, so only its first part and first links were checked; links "
    "further down were not analyzed."
)
LIMIT_UNINSPECTED_ATTACHMENTS = (
    "Some attachments could not be inspected (for example password-protected or RAR/7z "
    "archives), so their contents were not checked: "
)


def analyze_email(raw: bytes, trusted_authserv_ids: frozenset[str]) -> AnalyzeResponse:
    parsed = parse_email(raw)
    auth = analyze_authentication(parsed, trusted_authserv_ids)
    attachments = analyze_attachments(parsed)
    links = analyze_links(parsed, extra_urls=attachments.urls)  # incl. URLs inside files
    signals = [
        *auth.signals,
        *analyze_sender(parsed),
        *links.signals,
        *attachments.signals,
        *analyze_content(parsed),
        *analyze_structure(parsed),
    ]
    signals.sort(key=lambda s: s.points, reverse=True)

    partial_content = parsed.body_truncated or links.truncated
    limitations = _limitations(parsed, auth.summary.source, partial_content)
    if attachments.uninspected:
        limitations.append(LIMIT_UNINSPECTED_ATTACHMENTS + "; ".join(attachments.uninspected[:3]))
    fully_analyzed = (
        parsed.sender is not None
        and not parsed.defects
        and not partial_content
        and not attachments.uninspected
    )

    score = min(100, sum(s.points for s in signals))
    verdict = _verdict(score, fully_analyzed)
    return AnalyzeResponse(
        score=score,
        verdict=verdict,
        summary=_summary(verdict, signals, limitations),
        signals=signals,
        authentication=auth.summary,
        limitations=limitations,
    )


def _limitations(parsed: ParsedEmail, auth_source: AuthSource, partial_content: bool) -> list[str]:
    limitations = []
    if parsed.sender is None:
        limitations.append(LIMIT_NO_SENDER)
    if parsed.defects:
        limitations.append(LIMIT_MALFORMED)
    if auth_source is AuthSource.UNAVAILABLE:
        limitations.append(LIMIT_NO_AUTH)
    if partial_content:
        limitations.append(LIMIT_PARTIAL_CONTENT)
    return limitations


def _verdict(score: int, fully_analyzed: bool) -> Verdict:
    if score >= MALICIOUS_THRESHOLD:
        return Verdict.MALICIOUS
    if score >= SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE if fully_analyzed else Verdict.INCONCLUSIVE


def _summary(verdict: Verdict, signals: list[Signal], limitations: list[str]) -> str:
    risky = [s for s in signals if s.points > 0]
    if verdict is Verdict.INCONCLUSIVE:
        return (
            "This email could not be fully analyzed, so MailGuard cannot call it low risk. "
            "Treat links, attachments and requests in it with caution."
        )
    if verdict is Verdict.SAFE:
        if risky:
            return f"Low risk. Minor finding: {risky[0].title}."
        if limitations:
            return "No risk signals found, but some checks could not be completed."
        return "No risk signals found in any of the checks."
    return f"{len(risky)} risk signal(s) found. Most serious: {risky[0].title}."
