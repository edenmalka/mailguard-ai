"""Frequently impersonated brands and their official sending domains.

A small, curated list keeps false positives low and the logic explainable. Domains are
registrable domains (subdomains like mail.paypal.com are covered automatically).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str  # shown to the user
    keywords: frozenset[str]  # words that identify the brand in a display name
    domains: frozenset[str]  # official registrable domains


def _brand(name: str, keywords: set[str], domains: set[str]) -> Brand:
    return Brand(name, frozenset(keywords), frozenset(domains))


BRANDS: tuple[Brand, ...] = (
    _brand("PayPal", {"paypal"}, {"paypal.com", "paypal.me"}),
    _brand(
        "Microsoft",
        {"microsoft", "office365", "outlook", "onedrive", "sharepoint"},
        {"microsoft.com", "outlook.com", "live.com", "office.com", "microsoftonline.com"},
    ),
    _brand("Apple", {"apple", "icloud"}, {"apple.com", "icloud.com"}),
    _brand(
        "Google", {"google", "gmail"}, {"google.com", "gmail.com", "googlemail.com", "youtube.com"}
    ),
    _brand("Amazon", {"amazon"}, {"amazon.com", "amazon.co.uk", "amazon.de"}),
    _brand("Netflix", {"netflix"}, {"netflix.com"}),
    _brand("DHL", {"dhl"}, {"dhl.com", "dhl.de"}),
    _brand("FedEx", {"fedex"}, {"fedex.com"}),
    _brand("DocuSign", {"docusign"}, {"docusign.com", "docusign.net"}),
    _brand("LinkedIn", {"linkedin"}, {"linkedin.com"}),
    _brand("Facebook", {"facebook", "meta"}, {"facebook.com", "facebookmail.com", "meta.com"}),
    _brand("Instagram", {"instagram"}, {"instagram.com", "mail.instagram.com"}),
    _brand("Dropbox", {"dropbox"}, {"dropbox.com", "dropboxmail.com"}),
    _brand("Coinbase", {"coinbase"}, {"coinbase.com"}),
    _brand("Wells Fargo", {"wellsfargo"}, {"wellsfargo.com"}),
)

# Words that commonly accompany a brand in phishing display names and domains
# ("PayPal Support", "paypal-secure.com"). A display name made only of a brand keyword
# plus these words is treated as claiming to be that brand.
GENERIC_WORDS: frozenset[str] = frozenset(
    {
        "account", "accounts", "admin", "alert", "alerts", "billing", "care", "center",
        "centre", "customer", "desk", "help", "helpdesk", "id", "inc", "info", "llc", "login",
        "ltd", "mail", "no", "noreply", "notification", "notifications", "official", "online",
        "payment", "payments", "reply", "secure", "security", "service", "services", "signin",
        "support", "team", "the", "update", "verify", "verification",
    }
)  # fmt: skip

FREE_EMAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
        "aol.com", "icloud.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net",
        "mail.com", "yandex.com", "zoho.com",
    }
)  # fmt: skip
