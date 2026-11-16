"""Sender identity analyzer: is the sender pretending to be someone else?

Checks (all based on headers the attacker controls, compared against each other):
- Missing or multiple From addresses.
- Display name claims a well-known brand, but the address is not that brand's domain.
- Display name contains an email address different from the real one.
- Sender domain imitates a brand domain (look-alike characters, typos, extra words, subdomain).
- Internationalized (punycode) sender domain.
- Invisible or text-direction characters hidden in the display name.
- Replies are redirected to a different organization, especially a free webmail account.
"""

from __future__ import annotations

import re
import unicodedata

from app.analyzers.brands import BRANDS, FREE_EMAIL_DOMAINS, GENERIC_WORDS, Brand
from app.analyzers.common import make_signal
from app.analyzers.domains import (
    find_lookalike,
    official_brand_for,
    registrable_domain,
    same_organization,
    skeleton,
)
from app.parsing import EmailAddress, ParsedEmail
from app.schemas import Signal

CATEGORY = "sender"

POINTS_NO_SENDER = 10
POINTS_MULTIPLE_FROM = 20
POINTS_BRAND_IMPERSONATION = 30
POINTS_ADDRESS_IN_DISPLAY_NAME = 25
POINTS_LOOKALIKE_DOMAIN = 30
POINTS_PUNYCODE_DOMAIN = 15
POINTS_HIDDEN_CHARACTERS = 15
POINTS_REPLY_TO_MISMATCH = 15
POINTS_REPLY_TO_FREEMAIL = 25

_EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
_WORD = re.compile(r"[^\W_]+")
# Bidirectional overrides/isolates and zero-width characters: used to disguise text.
_HIDDEN_CHARS = frozenset(
    chr(cp)
    for cp in (
        *range(0x200B, 0x2010),  # zero-width space/joiners, LTR/RTL marks
        *range(0x202A, 0x202F),  # bidi embeddings and overrides (e.g. U+202E)
        *range(0x2066, 0x206A),  # bidi isolates
        0xFEFF,  # zero-width no-break space
        0x00AD,  # soft hyphen
    )
)


def analyze_sender(parsed: ParsedEmail) -> list[Signal]:
    signals: list[Signal] = []
    sender = parsed.sender

    if sender is None or not sender.domain:
        signals.append(
            make_signal(
                "sender.missing",
                CATEGORY,
                "No valid sender address",
                POINTS_NO_SENDER,
                "The message has no usable From address, so the sender cannot be identified.",
                f"From headers found: {parsed.from_header_count}",
            )
        )
    if parsed.from_header_count > 1 or len(parsed.from_addresses) > 1:
        signals.append(
            make_signal(
                "sender.multiple_from",
                CATEGORY,
                "Multiple sender addresses",
                POINTS_MULTIPLE_FROM,
                "Email should have exactly one From address. Several can make different programs "
                "show different senders, a known spoofing trick.",
                ", ".join(a.address for a in parsed.from_addresses[:5]),
            )
        )
    if sender is None:
        return signals

    signals.extend(_display_name_signals(sender))
    if sender.domain:
        signals.extend(_domain_signals(sender))
        signals.extend(_reply_to_signals(sender, parsed.reply_to))
        if registrable_domain(sender.domain) in FREE_EMAIL_DOMAINS:
            # A fact, not a risk: normal for personal mail. The scoring engine only uses it in
            # combination (a free webmail sender asking for money is classic CEO fraud).
            signals.append(
                make_signal(
                    "sender.free_webmail",
                    CATEGORY,
                    "Sent from a free webmail account",
                    0,
                    "The sender uses a free email service such as Gmail or Outlook.com. That is "
                    "normal for personal mail, but notable when the email asks for money or "
                    "claims to come from a company or manager.",
                    sender.address,
                )
            )
    return signals


# ---------------------------------------------------------------------------
# Display name
# ---------------------------------------------------------------------------


def _display_name_signals(sender: EmailAddress) -> list[Signal]:
    signals: list[Signal] = []
    name = sender.display_name

    hidden = sorted({f"U+{ord(ch):04X}" for ch in name if ch in _HIDDEN_CHARS})
    if hidden:
        signals.append(
            make_signal(
                "sender.hidden_characters",
                CATEGORY,
                "Hidden characters in sender name",
                POINTS_HIDDEN_CHARACTERS,
                "The sender name contains invisible or text-direction characters, which can make "
                "it display differently from what it really says.",
                f"{', '.join(hidden)} in display name",
            )
        )

    brand = claimed_brand(name)
    # A free webmail address (e.g. "Google Support" <mg-test-x@gmail.com>) is never the brand itself,
    # even when the brand operates that webmail service.
    from_brand = official_brand_for(sender.domain)
    is_freemail = registrable_domain(sender.domain) in FREE_EMAIL_DOMAINS
    if brand is not None and (from_brand is not brand or is_freemail):
        signals.append(
            make_signal(
                "sender.brand_impersonation",
                CATEGORY,
                f"Sender name claims to be {brand.name}",
                POINTS_BRAND_IMPERSONATION,
                f"The sender calls itself {brand.name}, but the email address is not from an "
                f"official {brand.name} domain.",
                f'"{name}" <{sender.address}>',
            )
        )

    embedded = _EMAIL_IN_TEXT.search(name)
    if embedded and not same_organization(embedded.group(1).lower(), sender.domain):
        signals.append(
            make_signal(
                "sender.address_in_display_name",
                CATEGORY,
                "Sender name shows a different email address",
                POINTS_ADDRESS_IN_DISPLAY_NAME,
                "The sender name contains an email address that differs from the real sending "
                "address. Many mail apps show only the name, hiding the real address.",
                f'Name shows "{embedded.group(0)}", real address is {sender.address}',
            )
        )
    return signals


def claimed_brand(display_name: str) -> Brand | None:
    """Return a brand if the display name presents itself as that brand.

    "PayPal", "PayPal Support", "Microsoft account team" -> brand.
    "Big Apple Pizza" -> None (other words make it a different business).
    """
    normalized = unicodedata.normalize("NFKC", display_name).casefold()
    normalized = "".join(ch for ch in normalized if ch not in _HIDDEN_CHARS)
    words = _WORD.findall(normalized)
    if not words or len(words) > 6:
        return None
    joined = skeleton("".join(words))
    for brand in BRANDS:
        brand_keys = {skeleton(k) for k in brand.keywords}
        for keyword in brand.keywords:
            key = skeleton(keyword)
            matching = [w for w in words if skeleton(w) == key]
            # Other words may be generic ("Support"), numbers ("365"), or the same brand's
            # products ("Microsoft SharePoint", "Apple iCloud").
            others = [w for w in words if skeleton(w) != key]
            if matching and all(
                w in GENERIC_WORDS or w.isdigit() or skeleton(w) in brand_keys for w in others
            ):
                return brand
            # Multi-word brands written together or apart: "Wells Fargo" -> "wellsfargo".
            if len(key) > 6 and joined == key:
                return brand
    return None


# ---------------------------------------------------------------------------
# Sender domain
# ---------------------------------------------------------------------------


def _domain_signals(sender: EmailAddress) -> list[Signal]:
    lookalike = find_lookalike(sender.domain)
    if lookalike is not None:
        techniques = {
            "homoglyph": "uses look-alike characters",
            "typo": "is a near-misspelling",
            "combo": "adds extra words to the brand name",
            "subdomain": "hides the real domain name at the start of a different domain",
        }
        return [
            make_signal(
                "sender.lookalike_domain",
                CATEGORY,
                f"Sender domain imitates {lookalike.brand.name}",
                POINTS_LOOKALIKE_DOMAIN,
                f"The sender's domain {techniques[lookalike.technique]} of "
                f"{lookalike.official_domain}, a common way to impersonate {lookalike.brand.name}.",
                f"{sender.domain} vs official {lookalike.official_domain} ({lookalike.technique})",
            )
        ]

    if any(label.startswith("xn--") for label in sender.domain.split(".")):
        return [
            make_signal(
                "sender.punycode_domain",
                CATEGORY,
                "Sender domain uses international characters",
                POINTS_PUNYCODE_DOMAIN,
                "The sender's domain contains non-Latin characters (shown as 'xn--'). These are "
                "legitimate in many languages but are also used to mimic familiar names.",
                sender.domain,
            )
        ]
    return []


# ---------------------------------------------------------------------------
# Reply-To
# ---------------------------------------------------------------------------


def _reply_to_signals(sender: EmailAddress, reply_to: list[EmailAddress]) -> list[Signal]:
    for target in reply_to:
        if not target.domain or same_organization(target.domain, sender.domain):
            continue
        to_freemail = registrable_domain(target.domain) in FREE_EMAIL_DOMAINS
        sender_freemail = registrable_domain(sender.domain) in FREE_EMAIL_DOMAINS
        if to_freemail and not sender_freemail:
            return [
                make_signal(
                    "sender.reply_to_freemail",
                    CATEGORY,
                    "Replies go to a free webmail account",
                    POINTS_REPLY_TO_FREEMAIL,
                    "The message is sent from one organization, but your reply would go to a "
                    "personal webmail address. This is typical of invoice and CEO-fraud scams.",
                    f"From {sender.address}, Reply-To {target.address}",
                )
            ]
        return [
            make_signal(
                "sender.reply_to_mismatch",
                CATEGORY,
                "Replies go to a different organization",
                POINTS_REPLY_TO_MISMATCH,
                "Your reply would go to a different domain than the one that sent the message.",
                f"From {sender.address}, Reply-To {target.address}",
            )
        ]
    return []
