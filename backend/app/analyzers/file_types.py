"""File-type knowledge: real type from content ("magic bytes") and risky extensions.

The declared Content-Type and the file name are chosen by the sender; the first bytes of the
file are what the operating system actually acts on. Comparing them reveals disguised files.
"""

from __future__ import annotations

from app.analyzers.link_data import DANGEROUS_EXTENSIONS

# Files that run code, or containers/shortcuts that lead to code, when opened on Windows/macOS.
EXECUTABLE_EXTENSIONS: frozenset[str] = DANGEROUS_EXTENSIONS | frozenset(
    {
        "com", "pif", "application", "gadget", "msp", "scf", "url", "library-ms",
        "settingcontent-ms", "chm", "hlp", "one", "xll", "wsc", "sct", "inf", "cab", "dmg",
        "pkg", "command",
    }
)  # fmt: skip

# Office formats that can contain macros.
MACRO_EXTENSIONS: frozenset[str] = frozenset(
    {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppsm", "sldm"}
)
OLE_OFFICE_EXTENSIONS: frozenset[str] = frozenset({"doc", "dot", "xls", "xlt", "ppt", "pps"})

# Ordinary document/image types attackers use as the "visible" part of a double extension.
DECOY_EXTENSIONS: frozenset[str] = frozenset(
    {
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "odt",
        "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4", "wav", "zip",
    }
)  # fmt: skip

ARCHIVE_EXTENSIONS: frozenset[str] = frozenset(
    {"zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "arj", "ace", "lzh", "z"}
)
HTML_EXTENSIONS: frozenset[str] = frozenset({"htm", "html", "shtml", "xhtml", "svg", "mht"})


def extension(filename: str | None) -> str:
    """Lower-case last extension, e.g. 'Invoice.PDF.exe' -> 'exe'; '' if none."""
    if not filename or "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].strip().lower()


def extensions(filename: str | None) -> list[str]:
    """All extensions, e.g. 'invoice.pdf.exe' -> ['pdf', 'exe']."""
    if not filename:
        return []
    return [part.strip().lower() for part in filename.split(".")[1:] if part.strip()]


def sniff(data: bytes) -> str | None:
    """Identify the real file type from its first bytes. Returns a short kind name or None."""
    head = data[:16]
    if head.startswith(b"MZ"):
        return "windows_executable"
    if head.startswith(b"\x7fELF"):
        return "linux_executable"
    if head[:4] in {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}:
        return "macos_executable"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "windows_shortcut"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"  # legacy Office (.doc/.xls), MSI, and some other containers
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if any(data[offset : offset + 5] == b"CD001" for offset in (0x8001, 0x8801, 0x9001)):
        return "disk_image"
    if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8")):
        return "image"
    if _looks_like_html(data):
        return "html"
    return None


def _looks_like_html(data: bytes) -> bool:
    start = data[:512].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    return start.startswith((b"<!doctype html", b"<html", b"<script", b"<svg", b"<?xml"))


# Real types that run code no matter what the name says.
EXECUTABLE_KINDS: frozenset[str] = frozenset(
    {"windows_executable", "linux_executable", "macos_executable", "windows_shortcut"}
)

# Which real types are consistent with which extensions (used to spot disguised files).
EXPECTED_KINDS: dict[str, frozenset[str]] = {
    "pdf": frozenset({"pdf"}),
    "docx": frozenset({"zip"}),
    "xlsx": frozenset({"zip"}),
    "pptx": frozenset({"zip"}),
    "zip": frozenset({"zip"}),
    "doc": frozenset({"ole", "rtf"}),  # .doc files are often really RTF
    "xls": frozenset({"ole"}),
    "ppt": frozenset({"ole"}),
    "jpg": frozenset({"image"}),
    "jpeg": frozenset({"image"}),
    "png": frozenset({"image"}),
    "gif": frozenset({"image"}),
    "txt": frozenset(),  # plain text has no magic bytes; only executables are a mismatch
    "csv": frozenset(),
}
