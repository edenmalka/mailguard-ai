"""Offline command-line analyzer: run MailGuard on .eml files without the add-on or a server.

Usage (from backend/):
    uv run python -m app.cli ../demo/02_credential_phishing.eml
    uv run python -m app.cli --json some.eml

Uses exactly the same pipeline as the /analyze endpoint. No network access, no secrets.
Useful for reviewers, for demos without Gmail, and for analyzing samples safely.

Note: Authentication-Results headers are trusted only if the topmost one was written by
mx.google.com, exactly as in production. Emails saved from Gmail ("Show original" ->
"Download original") therefore keep their real authentication results.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.config import Settings
from app.pipeline import analyze_email
from app.schemas import AnalyzeResponse

# Same default limit as the API (no secret is needed, so the default is read, not Settings()).
MAX_MESSAGE_BYTES: int = Settings.model_fields["max_message_bytes"].default
TRUSTED_AUTHSERV_IDS = frozenset({"mx.google.com"})
VERDICT_LABELS = {
    "safe": "LOW RISK",
    "suspicious": "SUSPICIOUS",
    "malicious": "MALICIOUS",
    "inconclusive": "INCONCLUSIVE",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze .eml files with MailGuard (offline).")
    parser.add_argument("files", nargs="+", type=Path, help="raw RFC 822 email files (.eml)")
    parser.add_argument("--json", action="store_true", help="print the raw API response as JSON")
    args = parser.parse_args(argv)

    exit_code = 0
    for path in args.files:
        try:
            # Check the size BEFORE reading, so a huge file is never loaded into memory.
            if path.stat().st_size > MAX_MESSAGE_BYTES:
                print(
                    f"{path}: larger than {MAX_MESSAGE_BYTES} bytes, not analyzed", file=sys.stderr
                )
                exit_code = 2
                continue
            raw = path.read_bytes()
        except OSError as exc:
            print(f"{path}: cannot read file ({exc.strerror})", file=sys.stderr)
            exit_code = 2
            continue
        result = analyze_email(raw, TRUSTED_AUTHSERV_IDS)
        print(result.model_dump_json(indent=2) if args.json else render(path.name, result))
    return exit_code


def render(name: str, result: AnalyzeResponse) -> str:
    """A plain-text version of the Gmail card."""
    lines = [
        f"=== {name}",
        f"Verdict: {VERDICT_LABELS[result.verdict]}   Score: {result.score}/100",
    ]
    if result.attack_patterns:
        lines.append(f"Looks like: {result.attack_patterns[0].name}")
    lines.append(f"Summary: {result.summary}")
    lines.append(f"What to do: {result.recommendation}")
    risky = [s for s in result.signals if s.points > 0]
    lines.append("Why:" if risky else "Why: no risk signals were found.")
    lines += [f"  +{s.points:<3} {s.title}" for s in risky]
    if result.authentication:
        auth = result.authentication
        if auth.source == "reported":
            lines.append(
                f"Authentication: SPF {auth.spf}, DKIM {auth.dkim}, DMARC {auth.dmarc} "
                f"(reported by {auth.reported_by})"
            )
        else:
            lines.append("Authentication: not available")
    lines += [f"Limit: {text}" for text in result.limitations]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
