"""Parser for the Authentication-Results header (RFC 8601).

Example (as written by Gmail):
  mx.google.com; dkim=pass header.i=@example.com header.s=s1;
     spf=pass (google.com: domain of a@example.com designates ...) smtp.mailfrom=a@example.com;
     dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com

Structure: "<authserv-id> [version]; <method>=<result> <prop>=<value> ...; ..."
Comments in parentheses carry no meaning and are removed first.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_TOKEN = re.compile(r"^[a-z0-9._-]+$")


@dataclass(frozen=True)
class AuthResult:
    method: str  # "spf", "dkim", "dmarc", ...
    result: str  # "pass", "fail", "softfail", "none", ...
    properties: dict[str, str] = field(default_factory=dict)  # e.g. {"header.from": "x.com"}


@dataclass(frozen=True)
class AuthResultsHeader:
    authserv_id: str  # who wrote the header, e.g. "mx.google.com"
    results: list[AuthResult]

    def for_method(self, method: str) -> list[AuthResult]:
        return [r for r in self.results if r.method == method]


def strip_comments(value: str) -> str:
    """Remove (possibly nested) parenthesized comments, respecting quoted strings."""
    out: list[str] = []
    depth = 0
    in_quotes = False
    escaped = False
    for ch in value:
        if escaped:
            escaped = False
            if depth == 0:
                out.append(ch)
            continue
        if ch == "\\":
            escaped = True
            if depth == 0:
                out.append(ch)
            continue
        if ch == '"' and depth == 0:
            in_quotes = not in_quotes
        elif not in_quotes and ch == "(":
            depth += 1
            continue
        elif not in_quotes and ch == ")" and depth > 0:
            depth -= 1
            continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


def parse_authentication_results(value: str) -> AuthResultsHeader | None:
    """Parse one header value. Returns None if it has no recognizable authserv-id."""
    parts = [p.strip() for p in strip_comments(value).split(";")]
    if not parts or not parts[0]:
        return None

    authserv_id = parts[0].split()[0].lower()
    if not _TOKEN.match(authserv_id):
        return None

    results: list[AuthResult] = []
    for part in parts[1:]:
        tokens = part.split()
        if not tokens or "=" not in tokens[0]:
            continue  # includes the literal "none" (no checks were performed)
        method, _, result = tokens[0].partition("=")
        method = method.split("/")[0].lower()  # drop optional method version, e.g. "dkim/1"
        result = result.lower()
        if not (_TOKEN.match(method) and _TOKEN.match(result)):
            continue
        properties = {}
        for token in tokens[1:]:
            key, sep, prop_value = token.partition("=")
            if sep and key:
                properties[key.lower()] = prop_value.strip('"')
        results.append(AuthResult(method, result, properties))

    return AuthResultsHeader(authserv_id, results)
