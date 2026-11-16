"""Scoring engine tests: budgets, explainability invariant, patterns, verdicts, advice."""

import pytest

from app.schemas import Signal, Verdict
from app.scoring import (
    ADVICE_BY_VERDICT,
    CATEGORY_BUDGETS,
    MALICIOUS_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    score_signals,
)


def sig(id: str, points: int, category: str | None = None) -> Signal:
    return Signal(
        id=id,
        category=category
        or {"auth": "authentication", "link": "links", "attachment": "attachments"}.get(
            id.split(".")[0], id.split(".")[0]
        ),
        title=id,
        points=points,
        explanation="x",
    )


def _ids(result) -> set[str]:
    return {s.id for s in result.signals}


# --- explainability --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "signals",
    [
        [sig("link.lookalike", 30), sig("content.credentials", 15), sig("content.urgency", 5)],
        [sig(f"link.x{i}", 25) for i in range(6)],
        [sig("attachment.executable", 40), sig("attachment.disguised", 35)],
        [sig("sender.reply_to_freemail", 25), sig("content.payment", 15)],
    ],
)
def test_card_rows_add_up_to_the_score(signals) -> None:
    result = score_signals(signals, fully_analyzed=True)
    total = sum(s.points for s in result.signals)
    assert result.score == min(100, total)


def test_category_budget_limits_stacking_but_keeps_every_signal_visible() -> None:
    signals = [sig(f"link.x{i}", 20) for i in range(5)]  # 100 points of link evidence
    result = score_signals(signals, fully_analyzed=True)
    assert result.score == CATEGORY_BUDGETS["links"]
    assert len(result.signals) == 5  # all still reported
    assert sorted(s.points for s in result.signals) == [0, 0, 10, 20, 20]


def test_strongest_signals_are_counted_first_within_a_budget() -> None:
    result = score_signals(
        [sig("attachment.small", 15), sig("attachment.big", 40), sig("attachment.mid", 35)], True
    )
    points = {s.id: s.points for s in result.signals}
    assert points == {"attachment.big": 40, "attachment.mid": 20, "attachment.small": 0}


# --- attack patterns -------------------------------------------------------------------------


def test_credential_phishing_needs_deception_and_capture() -> None:
    result = score_signals([sig("link.lookalike", 30), sig("content.credentials", 15)], True)
    assert [p.id for p in result.patterns] == ["credential_phishing"]
    bonus = next(s for s in result.signals if s.id == "pattern.credential_phishing")
    assert bonus.points == 20
    assert "link.lookalike" in (bonus.evidence or "") and "content.credentials" in (
        bonus.evidence or ""
    )


@pytest.mark.parametrize(
    "signals",
    [
        [sig("link.lookalike", 30)],  # deception without a request
        [sig("content.credentials", 15)],  # request without deception
        [sig("link.form", 25)],  # a single signal cannot corroborate itself
        [sig("content.payment", 15), sig("content.secrecy", 10)],  # wording only
    ],
)
def test_patterns_require_independent_evidence(signals) -> None:
    assert score_signals(signals, True).patterns == []


def test_payment_fraud_from_free_webmail_requires_a_money_request() -> None:
    webmail = sig("sender.free_webmail", 0)
    with_money = score_signals([webmail, sig("content.payment", 15)], True)
    secrecy_only = score_signals([webmail, sig("content.secrecy", 10)], True)
    assert [p.id for p in with_money.patterns] == ["payment_fraud"]
    assert secrecy_only.patterns == []


def test_malware_pattern_needs_payload_plus_support() -> None:
    assert score_signals([sig("attachment.executable", 40)], True).patterns == []
    disguised = score_signals(
        [sig("attachment.executable", 40), sig("attachment.disguised", 35)], True
    )
    assert [p.id for p in disguised.patterns] == ["malware_delivery"]


def test_only_the_strongest_pattern_adds_points() -> None:
    result = score_signals(
        [
            sig("auth.dmarc_fail", 35),
            sig("sender.reply_to_freemail", 25),
            sig("content.payment", 15),
            sig("content.credentials", 15),
        ],
        True,
    )
    assert len(result.patterns) >= 2
    bonuses = [s.points for s in result.signals if s.category == "pattern"]
    assert sum(1 for b in bonuses if b > 0) == 1


def test_patterns_still_use_evidence_whose_points_were_budgeted_away() -> None:
    # Links budget is 50: lookalike (30) + userinfo (20 of 25) use it up, so the form gets 0
    # points. The form is still real evidence of credential capture, so the pattern fires.
    signals = [sig("link.lookalike", 30), sig("link.userinfo", 25), sig("link.form", 25)]
    result = score_signals(signals, True)
    form = next(s for s in result.signals if s.id == "link.form")
    assert form.points == 0
    assert [p.id for p in result.patterns] == ["credential_phishing"]


# --- verdicts and advice ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("points", "fully", "verdict"),
    [
        (0, True, Verdict.SAFE),
        (SUSPICIOUS_THRESHOLD - 1, True, Verdict.SAFE),
        (SUSPICIOUS_THRESHOLD - 1, False, Verdict.INCONCLUSIVE),
        (SUSPICIOUS_THRESHOLD, False, Verdict.SUSPICIOUS),
        (MALICIOUS_THRESHOLD - 1, True, Verdict.SUSPICIOUS),
    ],
)
def test_verdict_thresholds(points: int, fully: bool, verdict: Verdict) -> None:
    signals = [sig("structure.x", points, category="other")] if points else []
    assert score_signals(signals, fully).verdict is verdict


def test_malicious_threshold() -> None:
    result = score_signals([sig("attachment.a", 40), sig("link.b", 30)], True)
    assert result.score == MALICIOUS_THRESHOLD
    assert result.verdict is Verdict.MALICIOUS


def test_recommendation_uses_pattern_advice_when_flagged() -> None:
    result = score_signals([sig("link.lookalike", 30), sig("content.credentials", 15)], True)
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.recommendation == result.patterns[0].advice


def test_recommendation_for_clean_email_uses_verdict_advice() -> None:
    assert score_signals([], True).recommendation == ADVICE_BY_VERDICT[Verdict.SAFE]
