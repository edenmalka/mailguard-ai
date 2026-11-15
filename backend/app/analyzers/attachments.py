"""Attachment analyzer: what are the attached files really, and can they run code?

Safety rules for handling untrusted files:
- Files are never executed, opened in an application, or extracted.
- ZIP archives are inspected by reading only their file list (central directory), which does
  not decompress anything, so "zip bombs" cannot exhaust memory or CPU.
- Content checks are simple byte searches with bounded input sizes.
- Formats we cannot inspect (encrypted archives, RAR, 7z, nested archives) are reported as
  limitations instead of being silently treated as clean.
"""

from __future__ import annotations

import io
import re
import unicodedata
import zipfile
from dataclasses import dataclass, field

from app.analyzers.common import make_signal
from app.analyzers.file_types import (
    ARCHIVE_EXTENSIONS,
    DECOY_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    EXECUTABLE_KINDS,
    HTML_EXTENSIONS,
    MACRO_EXTENSIONS,
    OLE_OFFICE_EXTENSIONS,
    extensions,
    sniff,
)
from app.analyzers.urls import html_link_urls
from app.parsing import Attachment, ParsedEmail
from app.schemas import Signal

CATEGORY = "attachments"
MAX_ATTACHMENTS = 50
MAX_ZIP_ENTRIES = 1000
MAX_URLS_PER_FILE = 50
MAX_SCAN_BYTES = 1_000_000
MAX_EXAMPLES = 3

POINTS_EXECUTABLE = 40
POINTS_DISGUISED = 35
POINTS_ARCHIVE_EXECUTABLE = 35
POINTS_MACRO = 30
POINTS_HTML_ACTIVE = 30
POINTS_HTML = 15
POINTS_ACTIVE_DOCUMENT = 25
POINTS_ENCRYPTED_ARCHIVE = 20
POINTS_ENCRYPTED_ARCHIVE_WITH_PASSWORD = 30

_PASSWORD_IN_BODY = re.compile(r"(?i)\b(password|passcode|pass\s*code|pwd|kennwort)\b\s*(is|:|=)")
_HTML_ACTIVE = re.compile(
    rb"(?i)<script|<form|type\s*=\s*[\"']?password|http-equiv\s*=\s*[\"']?refresh"
    rb"|window\.location|location\.(href|replace)|atob\s*\(|document\.write|\.submit\s*\("
)
_PDF_ACTIVE = re.compile(rb"/(JavaScript|JS|Launch|RichMedia)(?![A-Za-z])")
_PDF_FILE_NAME = re.compile(rb"/(?:UF|F)\s*\(([^)\r\n]{1,256})\)")
_PDF_HEX_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
_PDF_URI = re.compile(rb"/URI\s*\(([^)\r\n]{1,2048})\)")
_RAW_URL = re.compile(rb"https?://[^\s\"'<>()\\]{3,2048}")
_RTF_OBJECT = re.compile(rb"\\object|\\objdata|\\objupdate")
_OLE_MACRO_MARKER = "_VBA_PROJECT".encode("utf-16-le")


@dataclass
class AttachmentAnalysis:
    signals: list[Signal]
    urls: list[str] = field(default_factory=list)  # found inside files, for the link analyzer
    uninspected: list[str] = field(default_factory=list)  # files whose contents were not checked


@dataclass
class _Findings:
    examples: dict[str, list[str]] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    uninspected: list[str] = field(default_factory=list)

    def note(self, kind: str, example: str) -> None:
        self.examples.setdefault(kind, []).append(example)


def analyze_attachments(parsed: ParsedEmail) -> AttachmentAnalysis:
    findings = _Findings()
    password_in_body = bool(
        _PASSWORD_IN_BODY.search(parsed.text_body) or _PASSWORD_IN_BODY.search(parsed.html_body)
    )
    for index, attachment in enumerate(parsed.attachments):
        if index >= MAX_ATTACHMENTS:
            findings.uninspected.append(f"{len(parsed.attachments) - index} more attachment(s)")
            break
        _inspect(attachment, findings)

    if "html_active" in findings.examples:  # one web-page signal: the more serious one
        findings.examples.pop("html", None)
    signals = [
        build(findings.examples[kind], password_in_body)
        for kind, build in _BUILDERS.items()
        if kind in findings.examples
    ]
    return AttachmentAnalysis(signals, findings.urls, findings.uninspected)


# ---------------------------------------------------------------------------
# Per-file inspection
# ---------------------------------------------------------------------------


def _inspect(attachment: Attachment, findings: _Findings) -> None:
    name = attachment.filename or f"(unnamed {attachment.content_type} file)"
    exts = extensions(attachment.filename)
    ext = exts[-1] if exts else ""
    data = attachment.data
    kind = sniff(data)

    # Disguises: hidden characters, double extensions, and names that lie about the content.
    if attachment.filename and any(unicodedata.category(ch) == "Cf" for ch in attachment.filename):
        findings.note("disguised", f"{name}: hidden characters change how the name is displayed")
    elif len(exts) >= 2 and exts[-2] in DECOY_EXTENSIONS and ext in EXECUTABLE_EXTENSIONS:
        findings.note("disguised", f"{name}: looks like .{exts[-2]} but is .{ext}")
    if kind in EXECUTABLE_KINDS and ext not in EXECUTABLE_EXTENSIONS:
        findings.note("disguised", f"{name}: named .{ext or '(none)'} but is a {_label(kind)}")
    elif ext in {"pdf", "jpg", "jpeg", "png", "gif", "txt"} and kind in {"html", "zip", "ole"}:
        findings.note("disguised", f"{name}: named .{ext} but is really {_label(kind)}")

    if ext in EXECUTABLE_EXTENSIONS or kind in EXECUTABLE_KINDS or kind == "disk_image":
        findings.note("executable", f"{name} ({_label(kind) if kind else '.' + ext + ' file'})")

    if kind == "zip":
        _inspect_zip(name, ext, data, findings)
    elif kind in {"rar", "7z", "gzip"} or (ext in ARCHIVE_EXTENSIONS and kind is None):
        findings.uninspected.append(f"{name} ({kind or ext} archive)")

    if ext in MACRO_EXTENSIONS:
        findings.note("macro", f"{name} (macro-enabled Office format)")
    elif kind == "ole" and (ext in OLE_OFFICE_EXTENSIONS or not ext):
        if _OLE_MACRO_MARKER in data[: MAX_SCAN_BYTES * 2]:
            findings.note("macro", f"{name} (contains a VBA macro project)")

    if kind == "pdf":
        _inspect_pdf(name, data, findings)
    elif kind == "rtf" and _RTF_OBJECT.search(data[:MAX_SCAN_BYTES]):
        findings.note("active_document", f"{name}: RTF with embedded objects")

    if ext in HTML_EXTENSIONS or kind == "html" or attachment.content_type == "text/html":
        _inspect_html(name, data, findings)


def _inspect_zip(name: str, ext: str, data: bytes, findings: _Findings) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()  # reads the file list only; nothing is decompressed
    except Exception:  # corrupt or deliberately malformed archive
        findings.uninspected.append(f"{name} (damaged archive)")
        return

    names = [entry.filename for entry in entries[:MAX_ZIP_ENTRIES]]
    if len(entries) > MAX_ZIP_ENTRIES:
        findings.uninspected.append(f"{name} (more than {MAX_ZIP_ENTRIES} files inside)")

    is_office = "[Content_Types].xml" in names
    if is_office:
        if any(n.lower().endswith("vbaproject.bin") for n in names):
            findings.note("macro", f"{name} (contains a VBA macro project)")
        return

    if any(entry.flag_bits & 0x1 for entry in entries):
        findings.note("encrypted", name)
        findings.uninspected.append(f"{name} (password-protected archive)")

    for inner in names:
        base = inner.rsplit("/", 1)[-1]
        inner_exts = extensions(base)
        inner_ext = inner_exts[-1] if inner_exts else ""
        if inner_ext in EXECUTABLE_EXTENSIONS or inner_ext in MACRO_EXTENSIONS:
            findings.note("archive_executable", f"{name} contains {base}")
        # Disguises count wherever the file is, including inside an archive.
        if any(unicodedata.category(ch) == "Cf" for ch in base):
            findings.note("disguised", f"{base} in {name}: hidden characters in the name")
        elif (
            len(inner_exts) >= 2
            and inner_exts[-2] in DECOY_EXTENSIONS
            and inner_ext in EXECUTABLE_EXTENSIONS
        ):
            findings.note("disguised", f"{base} in {name}: looks like .{inner_exts[-2]}")
        elif inner_ext in ARCHIVE_EXTENSIONS:
            findings.uninspected.append(f"{base} (archive inside {name})")


def _inspect_pdf(name: str, data: bytes, findings: _Findings) -> None:
    # PDF readers decode "#xx" in names, so "/J#61vaScript" means "/JavaScript".
    sample = _PDF_HEX_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), data[:MAX_SCAN_BYTES])
    active = sorted({m.group(1).decode() for m in _PDF_ACTIVE.finditer(sample)})
    if active:
        findings.note("active_document", f"{name}: PDF with {', '.join(active)}")
    # Embedded files are normal (e.g. XML in e-invoices); embedded PROGRAMS are not.
    for match in _PDF_FILE_NAME.finditer(sample):
        embedded = match.group(1).decode("latin-1").strip()
        if extensions(embedded)[-1:] and extensions(embedded)[-1] in EXECUTABLE_EXTENSIONS:
            findings.note("active_document", f"{name}: PDF contains the program {embedded}")
    for match in _PDF_URI.finditer(sample):
        if len(findings.urls) >= MAX_URLS_PER_FILE:
            break
        findings.urls.append(match.group(1).decode("latin-1").strip())


def _inspect_html(name: str, data: bytes, findings: _Findings) -> None:
    sample = data[:MAX_SCAN_BYTES]
    kind = "html_active" if _HTML_ACTIVE.search(sample) else "html"
    findings.note(kind, name)
    text = sample.decode("utf-8", errors="replace")
    urls = html_link_urls(text)
    urls += [m.group(0).decode("latin-1") for m in _RAW_URL.finditer(sample)]  # e.g. in scripts
    for url in dict.fromkeys(urls):
        if len(findings.urls) >= MAX_URLS_PER_FILE:
            break
        findings.urls.append(url)


def _label(kind: str | None) -> str:
    return {
        "windows_executable": "Windows program",
        "linux_executable": "Linux program",
        "macos_executable": "macOS program",
        "windows_shortcut": "Windows shortcut",
        "disk_image": "disk image",
        "html": "a web page",
        "zip": "a ZIP archive",
        "ole": "an Office/installer container",
    }.get(kind or "", kind or "unknown file")


# ---------------------------------------------------------------------------
# Signals (one per problem type)
# ---------------------------------------------------------------------------


def _evidence(examples: list[str]) -> str:
    unique = list(dict.fromkeys(examples))
    shown = "; ".join(unique[:MAX_EXAMPLES])
    more = len(unique) - MAX_EXAMPLES
    return f"{len(unique)} file(s): {shown}" + (f"; and {more} more" if more > 0 else "")


def _builder(id: str, title: str, points: int, explanation: str):
    def build(examples: list[str], _password_in_body: bool) -> Signal:
        return make_signal(
            f"attachment.{id}", CATEGORY, title, points, explanation, _evidence(examples)
        )

    return build


def _encrypted_signal(examples: list[str], password_in_body: bool) -> Signal:
    if password_in_body:
        return make_signal(
            "attachment.encrypted_archive",
            CATEGORY,
            "Password-protected archive, password in the email",
            POINTS_ENCRYPTED_ARCHIVE_WITH_PASSWORD,
            "The attachment is locked with a password that is given in the email itself. This "
            "protects nothing; it is a common trick to stop security scanners from looking "
            "inside, used to deliver malware.",
            _evidence(examples),
        )
    return make_signal(
        "attachment.encrypted_archive",
        CATEGORY,
        "Password-protected archive",
        POINTS_ENCRYPTED_ARCHIVE,
        "The attachment is a locked archive, so neither MailGuard nor other scanners can see "
        "what is inside. Be careful if a password arrives separately.",
        _evidence(examples),
    )


_BUILDERS = {
    "executable": _builder(
        "executable",
        "Attachment can run code",
        POINTS_EXECUTABLE,
        "An attached file is a program, script, shortcut or disk image. Opening it can install "
        "malware. Legitimate senders almost never email programs.",
    ),
    "disguised": _builder(
        "disguised",
        "Attachment is disguised",
        POINTS_DISGUISED,
        "An attached file pretends to be a different type than it really is (for example "
        "'invoice.pdf.exe', or a 'PDF' that is actually a program). Disguises are a strong "
        "sign of malicious intent.",
    ),
    "archive_executable": _builder(
        "archive_executable",
        "Archive contains a program",
        POINTS_ARCHIVE_EXECUTABLE,
        "An attached archive (such as a .zip) contains a program, script or macro document. "
        "Archives are often used to sneak programs past email filters.",
    ),
    "macro": _builder(
        "macro",
        "Office document with macros",
        POINTS_MACRO,
        "An attached Office document contains macros: small programs that run inside Word or "
        "Excel. Never click 'Enable content' on documents you did not expect.",
    ),
    "html_active": _builder(
        "html",
        "Web page attachment with active content",
        POINTS_HTML_ACTIVE,
        "An attached web page (.html/.svg) contains scripts, forms or redirects. Opened in a "
        "browser, it can show a fake sign-in page that never appears as a link in the email.",
    ),
    "html": _builder(
        "html",
        "Web page attachment",
        POINTS_HTML,
        "An attached file is a web page (.html/.svg). These open in your browser and are a "
        "common way to deliver fake sign-in pages.",
    ),
    "active_document": _builder(
        "active_document",
        "Document with active content",
        POINTS_ACTIVE_DOCUMENT,
        "An attached PDF or RTF document contains scripts, launch actions or embedded files, "
        "which ordinary documents do not need.",
    ),
    "encrypted": _encrypted_signal,
}
