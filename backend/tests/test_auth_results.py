"""Tests for the Authentication-Results header parser."""

from app.analyzers.auth_results import parse_authentication_results, strip_comments

GMAIL_HEADER = (
    "mx.google.com; dkim=pass header.i=@example.com header.s=s1 header.b=AbC; "
    "spf=pass (google.com: domain of a@example.com designates 192.0.2.1 as permitted sender) "
    "smtp.mailfrom=a@example.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com"
)


def test_parses_gmail_header() -> None:
    header = parse_authentication_results(GMAIL_HEADER)
    assert header is not None
    assert header.authserv_id == "mx.google.com"
    assert [(r.method, r.result) for r in header.results] == [
        ("dkim", "pass"),
        ("spf", "pass"),
        ("dmarc", "pass"),
    ]
    assert header.for_method("dmarc")[0].properties["header.from"] == "example.com"


def test_comments_cannot_inject_results() -> None:
    # A semicolon and "dmarc=pass" inside a comment must not become a real result.
    header = parse_authentication_results(
        "mx.google.com; spf=fail (fake; dmarc=pass (nested)) smtp.mailfrom=a@example.com"
    )
    assert header is not None
    assert [(r.method, r.result) for r in header.results] == [("spf", "fail")]


def test_strip_comments_respects_quotes_and_nesting() -> None:
    assert strip_comments('a (b (c) d) "e (f)" g') == 'a  "e (f)" g'


def test_authserv_id_version_and_case_are_normalized() -> None:
    header = parse_authentication_results("MX.Google.COM 1; SPF=PASS")
    assert header is not None
    assert header.authserv_id == "mx.google.com"
    assert header.results[0].method == "spf" and header.results[0].result == "pass"


def test_none_means_no_results() -> None:
    header = parse_authentication_results("mx.google.com; none")
    assert header is not None and header.results == []


def test_multiple_dkim_results_are_kept() -> None:
    header = parse_authentication_results(
        "mx.google.com; dkim=fail header.d=a.example; dkim=pass header.d=b.example"
    )
    assert header is not None
    assert [r.result for r in header.for_method("dkim")] == ["fail", "pass"]


def test_garbage_is_rejected_or_ignored() -> None:
    assert parse_authentication_results("") is None
    assert parse_authentication_results(";;;") is None
    assert parse_authentication_results("<script>; spf=pass") is None
    header = parse_authentication_results("mx.google.com; spf=<b>pass</b>; =fail; dkim")
    assert header is not None and header.results == []
