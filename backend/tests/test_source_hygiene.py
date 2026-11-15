"""Guard against "Trojan Source": invisible or direction-changing characters in project files.

Such characters can make code display differently from how it runs. Tests that need them
must write escapes like "\\u202e" instead of the raw character.
"""

import unicodedata
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKED_DIRS = ("backend/app", "backend/tests", "addon")
CHECKED_SUFFIXES = {".py", ".gs", ".json", ".eml", ".toml", ".md"}


def _is_invisible(ch: str) -> bool:
    return unicodedata.category(ch) == "Cf" or ch == chr(0xAD)  # soft hyphen


def test_no_invisible_characters_in_source_files() -> None:
    offenders = []
    for directory in CHECKED_DIRS:
        for path in (REPO_ROOT / directory).rglob("*"):
            if path.suffix not in CHECKED_SUFFIXES or "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for number, line in enumerate(text.splitlines(), start=1):
                if any(_is_invisible(ch) for ch in line):
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}")
    assert offenders == []
