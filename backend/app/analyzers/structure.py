"""Structure analyzer: reports messages the parser found to be malformed.

Malformed structure is weak evidence on its own (some legitimate mailers are sloppy), but
broken MIME is also used to make security tools and mail clients disagree about content.
"""

from app.analyzers.common import make_signal
from app.parsing import ParsedEmail
from app.schemas import Signal

CATEGORY = "structure"
POINTS_MALFORMED = 5


def analyze_structure(parsed: ParsedEmail) -> list[Signal]:
    if not parsed.defects:
        return []
    return [
        make_signal(
            "structure.malformed",
            CATEGORY,
            "Message structure is malformed",
            POINTS_MALFORMED,
            "The email does not follow the standard format. This can be sloppy software, or an "
            "attempt to confuse mail clients and security filters.",
            ", ".join(parsed.defects[:5]),
        )
    ]
