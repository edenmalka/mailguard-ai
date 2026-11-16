"""Reference lists used by the link analyzer. Small and curated, so results stay explainable."""

# URL shorteners hide the real destination until the user clicks.
SHORTENER_DOMAINS: frozenset[str] = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
        "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "v.gd", "bl.ink",
    }
)  # fmt: skip

# Click-tracking domains used by legitimate email services. Newsletters routinely show the
# real address as link text while the link itself goes through one of these, so a text/link
# mismatch involving them is expected and not flagged.
TRACKING_DOMAINS: frozenset[str] = frozenset(
    {
        "sendgrid.net", "list-manage.com", "mcsv.net", "mailchimp.com", "mailgun.org",
        "mandrillapp.com", "hubspotlinks.com", "hubspot.com", "exct.net", "rs6.net",
        "createsend.com", "cmail19.com", "cmail20.com", "awstrack.me", "klclick.com",
        "klaviyo.com", "sparkpostmail.com", "spmailtechn.com", "substack.com", "mlsend.com",
        "convertkit-mail.com", "beehiiv.com", "pardot.com", "iterable.com", "eloqua.com",
        "customeriomail.com", "pstmrk.it", "mjt.lu",
    }
)  # fmt: skip

# Top-level domains that are cheap or frequently abused for phishing, plus ".zip"/".mov",
# which look like file names ("invoice.zip") but are real web addresses.
RISKY_TLDS: frozenset[str] = frozenset(
    {
        "zip", "mov", "top", "xyz", "click", "icu", "tk", "ml", "ga", "cf", "gq", "rest",
        "cam", "sbs", "cfd", "buzz", "monster", "quest", "lol",
    }
)  # fmt: skip

# File types that can run code when opened.
DANGEROUS_EXTENSIONS: frozenset[str] = frozenset(
    {
        "exe", "scr", "bat", "cmd", "msi", "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta",
        "ps1", "jar", "lnk", "iso", "img", "vhd", "vhdx", "apk", "appx", "msix", "reg",
        "cpl", "dll",
    }
)  # fmt: skip

# Link schemes that run code, embed whole pages, open local/network files, or launch Windows
# programs (e.g. ms-msdt: was used by the "Follina" exploit, search-ms: by malware droppers).
SCRIPT_SCHEMES: frozenset[str] = frozenset(
    {"javascript", "vbscript", "data", "file", "ms-msdt", "search-ms", "search", "ms-officecmd"}
)

# Security gateways that wrap the real destination inside their own link; the wrapped
# destination is what the user effectively visits. Host -> the query parameter(s) holding the
# destination, or () when it is written in the path (Proofpoint v3: /v3/__https://dest__;...).
REWRITER_HOSTS: dict[str, tuple[str, ...]] = {
    "safelinks.protection.outlook.com": ("url",),  # Microsoft Defender Safe Links
    "urldefense.com": (),  # Proofpoint URL Defense (v3)
    "urldefense.proofpoint.com": ("u",),  # Proofpoint URL Defense (v2, encoded: not decoded)
    "linkprotect.cudasvc.com": ("a",),  # Barracuda Link Protection
}
# Redirectors at one path only. Other pages on these hosts can be made by anyone (Google Sites,
# Google Forms), so a URL inside THOSE links is not where the click goes.
# Host -> (path, destination query parameters).
REDIRECT_PATHS: dict[str, tuple[str, tuple[str, ...]]] = {
    "google.com": ("/url", ("q", "url")),
    "www.google.com": ("/url", ("q", "url")),
}

# Gateways whose links are opaque (destination not visible): exempt from text/link mismatch.
OPAQUE_REWRITER_DOMAINS: frozenset[str] = frozenset({"mimecast.com"})

# Top-level domains that are also common file extensions ("report.zip", "setup.py",
# "README.md", "logo.ai"). A bare word like this in link text is treated as a file name.
FILE_LIKE_TLDS: frozenset[str] = frozenset(
    {"zip", "mov", "py", "sh", "md", "rs", "pl", "ai", "app", "ms", "cc", "so", "pm", "ps"}
)
