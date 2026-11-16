"""Domain helpers: normalization, registrable domains, and lookalike detection.

All work is offline. The public-suffix list comes from tldextract's bundled snapshot,
so the backend never makes network calls while analyzing an email.
"""

from __future__ import annotations

import ipaddress
import unicodedata
from dataclasses import dataclass

import tldextract

from app.analyzers.brands import BRANDS, GENERIC_WORDS, Brand
from app.analyzers.link_data import RISKY_TLDS

# suffix_list_urls=() -> never download; use the bundled public-suffix snapshot.
_extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Characters attackers swap for look-alikes. Applied to both sides of a comparison.
_CONFUSABLE_SEQUENCES = (("rn", "m"), ("vv", "w"), ("cl", "d"))
# Official labels that are ordinary words: typo/extra-word matching would flag innocent
# domains (offices.com, live-music.com), so only look-alike characters are checked for them.
_DICTIONARY_LABELS = frozenset({"office", "live", "meta", "outlook"})
_MIN_TYPO_LABEL_LENGTH = 6
# Domain endings written as part of the name: "paypalcom" reads as "paypal.com".
_TLD_WORDS = frozenset({"com", "net", "org"})

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

    For unknown endings (e.g. ".test", internal names) the last two labels are used, so
    a.corp.test and b.corp.test still count as one organization. IP addresses are kept whole.
    """
    if not domain:
        return ""
    registered = _extractor(domain).top_domain_under_public_suffix
    if registered:
        return registered
    if _is_ip_address(domain):
        return domain
    return ".".join(domain.split(".")[-2:])


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def registrable_label(domain: str) -> str:
    """The name part of the registrable domain, e.g. mail.paypal.co.uk -> paypal."""
    registered = registrable_domain(domain)
    if not registered or _is_ip_address(registered):
        return registered
    suffix = _extractor(domain).suffix
    name = registered[: -len(suffix) - 1] if suffix and registered.endswith("." + suffix) else ""
    return name or registered.split(".")[0]


def has_public_suffix(domain: str) -> bool:
    """True if the domain ends in a known public suffix (e.g. .com, .co.uk)."""
    return bool(domain) and bool(_extractor(domain).suffix)


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
    registered = registrable_domain(domain)
    # Labels in front of the registrable domain, e.g. "paypal" in paypal.account-verify.example.
    prefix = domain[: -len(registered)].rstrip(".") if domain.endswith("." + registered) else ""
    prefix_parts = {skeleton(p) for lbl in prefix.split(".") if lbl for p in lbl.split("-")}

    tld = domain.rsplit(".", 1)[-1]

    for brand in BRANDS:
        for official in sorted(brand.domains):
            official_label = registrable_label(official)

            # paypal.com.account-verify.example, mail.dhl.com.track.test: a brand domain used as
            # subdomain labels of an unrelated domain, so the start of the name looks official.
            # Only the labels BEFORE the registrable domain count: in email.amazon.com.au the
            # "amazon.com" is part of the registrable domain itself, not a disguise.
            if prefix and f".{official}." in f".{prefix}.":
                return Lookalike(brand, official, "subdomain")
            # paypal.account-verify.example, paypal.com-login.example: brand name as a
            # subdomain label in front of an unrelated registrable domain.
            if official_label not in _DICTIONARY_LABELS and skeleton(official_label) in (
                prefix_parts
            ):
                return Lookalike(brand, official, "subdomain")

            # paypa1.example, rnicrosoft.example: different characters that look the same.
            if label != official_label and skeleton(label) == skeleton(official_label):
                return Lookalike(brand, official, "homoglyph")

            if official_label in _DICTIONARY_LABELS:
                continue

            # "paypal" + ".top": the exact brand name on a cheap, frequently abused ending.
            # Brands do not run their mail or sign-in pages there. (Other endings, such as
            # amazon.ca, are often the brand's own country sites, so they are not flagged.)
            if label == official_label and tld in RISKY_TLDS:
                return Lookalike(brand, official, "tld")

            # paypall.example, micosoft.example: one or two typing mistakes away.
            max_distance = 2 if len(official_label) >= 9 else 1
            if (
                len(official_label) >= _MIN_TYPO_LABEL_LENGTH
                # Edit distance is at least the length difference. Checking that first is exact
                # and keeps very long (attacker-made) host names from costing seconds each.
                and abs(len(label) - len(official_label)) <= max_distance
                and 0 < levenshtein(label, official_label) <= max_distance
            ):
                return Lookalike(brand, official, "typo")

            # paypal-secure.example, paypa1-login.example, paypalsupport.example: brand name
            # (possibly with look-alike characters) plus other words.
            official_skeleton = skeleton(official_label)
            parts = label.split("-")
            if len(parts) > 1 and official_skeleton in {skeleton(p) for p in parts}:
                return Lookalike(brand, official, "combo")
            # paypalsupport.example, paypalcom.example ("paypal.com" without the dot).
            rest = label[len(official_label) :]
            if label.startswith(official_label) and (rest in GENERIC_WORDS or rest in _TLD_WORDS):
                return Lookalike(brand, official, "combo")
    return None
