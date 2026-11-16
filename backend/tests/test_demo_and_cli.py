"""Demo emails (../demo) and the offline command-line analyzer."""

import json
from pathlib import Path

import pytest

from app.cli import main
from app.pipeline import analyze_email
from scripts.make_demo_emails import DEMO_DIR, DEMO_EMAILS

GMAIL = frozenset({"mx.google.com"})

EXPECTED = {
    "01_low_risk_newsletter.eml": ("safe", None),
    "02_credential_phishing.eml": ("malicious", "credential_phishing"),
    "03_payment_fraud_ceo.eml": ("suspicious", "payment_fraud"),
    "04_malware_delivery.eml": ("malicious", "malware_delivery"),
    "05_sender_spoofing.eml": ("malicious", "sender_spoofing"),
    "06_html_attachment_phishing.eml": ("malicious", "credential_phishing"),
    "07_inconclusive_archive.eml": ("inconclusive", None),
    "08_credential_theft_by_reply.eml": ("malicious", "credential_theft_by_reply"),
}


def test_every_demo_email_has_an_expectation() -> None:
    assert set(EXPECTED) == set(DEMO_EMAILS)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_demo_file_matches_generator(name: str) -> None:
    """The committed .eml files must be exactly what the generator produces (no drift)."""
    assert (DEMO_DIR / name).read_bytes() == DEMO_EMAILS[name]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_demo_email_verdict_and_pattern(name: str) -> None:
    verdict, pattern = EXPECTED[name]
    result = analyze_email((DEMO_DIR / name).read_bytes(), GMAIL)
    assert result.verdict == verdict
    top_pattern = result.attack_patterns[0].id if result.attack_patterns else None
    assert top_pattern == pattern


def test_cli_prints_a_readable_report(capsys) -> None:
    assert main([str(DEMO_DIR / "02_credential_phishing.eml")]) == 0
    out = capsys.readouterr().out
    assert "Verdict: MALICIOUS" in out
    assert "Looks like: Credential phishing" in out
    assert "What to do:" in out


def test_cli_json_output_matches_the_api_schema(capsys) -> None:
    assert main(["--json", str(DEMO_DIR / "07_inconclusive_archive.eml")]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "inconclusive"
    assert data["limitations"]


def test_cli_rejects_missing_and_oversized_files(tmp_path: Path, capsys) -> None:
    big = tmp_path / "big.eml"
    big.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    assert main([str(tmp_path / "missing.eml"), str(big)]) == 2
    err = capsys.readouterr().err
    assert "cannot read file" in err
    assert "not analyzed" in err
