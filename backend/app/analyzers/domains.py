"""Domain helpers: normalization, registrable domains, and lookalike detection.

All work is offline. The public-suffix list comes from tldextract's bundled snapshot,
so the backend never makes network calls while analyzing an email.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

import tldextract

from app.analyzers.brands import BRANDS, GENERIC_WORDS, Brand

# suffix_list_urls=() -> never download; use the bundled public-suffix snapshot.
_extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Characters attackers swap for look-alikes. Applied to both sides of a comparison.
_CONFUSABLE_SEQUENCES = (("rn", "m"), ("vv", "w"), ("cl", "d"))
# Official labels that are ordinary words: typo/extra-word matching would flag innocent
# domains (offices.com, live-music.com), so only look-alike characters are checked for them.
_DICTIONARY_LABELS = frozenset({"office", "live", "meta", "outlook"})
_MIN_TYPO_LABEL_LENGTH = 6

_CONFUSABLE_CHARS = str.maketrans(
    {"0": "o", "1": "l", "i": "l", "|": "l", "3": "e", "5": "s", "$": "s", "@": "a", "4": "a"}
)


def normalize_domain(domain: str) -> str:
    """Lower-case, strip dots/brackets, and convert Unicode domains to punycode (xn--)."""
    domain = domain.strip().strip("[]").rstrip(".").lower()
    if domain and not domain.isascii():
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            pass  # keep as-is; still flagged as non-ASCII by the sender analyzer
    return domain


def registrable_domain(domain: str) -> str:
    """The part of a domain an organization registers, e.g. mail.paypal.com -> paypal.com.

    Falls back to the full domain when there is no known public suffix (e.g. ".test").
    """
    if not domain:
        return ""
    return _extractor(domain).top_domain_under_public_suffix or domain


def registrable_label(domain: str) -> str:
    """The name part of the registrable domain, e.g. mail.paypal.co.uk -> paypal."""
    if not domain:
        return ""
    return _extractor(domain).domain or domain


def same_organization(domain_a: str, domain_b: str) -> bool:
    return bool(domain_a) and registrable_domain(domain_a) == registrable_domain(domain_b)


def skeleton(text: str) -> str:
    """Collapse look-alike characters so 'paypa1' and 'paypal' compare equal."""
    text = unicodedata.normalize("NFKC", text).casefold()
    for sequence, replacement in _CONFUSABLE_SEQUENCES:
        text = text.replace(sequence, replacement)
    return text.translate(_CONFUSABLE_CHARS)


def levenshtein(a: str, b: str) -> int:
    """Edit distance: how many single-character changes turn `a` into `b`."""
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            current.append(
                min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (char_a != char_b))
            )
        previous = current
    return previous[-1]


def official_brand_for(domain: str) -> Brand | None:
    """Return the brand if `domain` is (a subdomain of) one of its official domains."""
    registered = registrable_domain(domain)
    for brand in BRANDS:
        if registered in brand.domains:
            return brand
    return None


@dataclass(frozen=True)
class Lookalike:
    brand: Brand
    official_domain: str
    technique: str  # "homoglyph" | "typo" | "combo" | "subdomain"


def find_lookalike(domain: str) -> Lookalike | None:
    """Detect a domain imitating a known brand. Official brand domains never match."""
    if not domain or official_brand_for(domain) is not None:
        return None

    label = registrable_label(domain)
    for brand in BRANDS:
        for official in sorted(brand.domains):
            official_label = registrable_label(official)

            # paypal.com.account-verify.net, mail.dhl.com.track.test: a brand domain used as
            # subdomain labels of an unrelated domain, so the start of the name looks official.
            if f".{official}." in f".{domain}":
                return Lookalike(brand, official, "subdomain")

            # paypa1.com, rnicrosoft.com: different characters that look the same.
            if label != official_label and skeleton(label) == skeleton(official_label):
                return Lookalike(brand, official, "homoglyph")

            if official_label in _DICTIONARY_LABELS:
                continue

            # paypall.com, micosoft.com: one or two typing mistakes away.
            max_distance = 2 if len(official_label) >= 9 else 1
            if (
                len(official_label) >= _MIN_TYPO_LABEL_LENGTH
                and 0 < levenshtein(label, official_label) <= max_distance
            ):
                return Lookalike(brand, official, "typo")

            # paypal-secure.com, paypalsupport.com: brand name plus a generic word.
            parts = label.split("-")
            if len(parts) > 1 and official_label in parts:
                return Lookalike(brand, official, "combo")
            if label.startswith(official_label) and label[len(official_label) :] in GENERIC_WORDS:
                return Lookalike(brand, official, "combo")
    return None
