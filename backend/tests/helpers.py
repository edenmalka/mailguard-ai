"""Helpers for building synthetic test emails."""

from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
GMAIL = frozenset({"mx.google.com"})


def load_fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def make_email(*header_lines: str, body: str = "Hello.") -> bytes:
    """Build a minimal RFC 822 message from header lines like 'From: a@example.com'."""
    headers = "\r\n".join(header_lines)
    return f"{headers}\r\nMIME-Version: 1.0\r\n\r\n{body}\r\n".encode()


def gmail_auth(spf: str = "pass", dkim: str = "pass", dmarc: str = "pass") -> str:
    return (
        f"Authentication-Results: mx.google.com; dkim={dkim} header.i=@example.com; "
        f"spf={spf} smtp.mailfrom=a@example.com; dmarc={dmarc} header.from=example.com"
    )


# --- Attachment test payloads: harmless byte patterns that only LOOK like each format --------
FAKE_EXE = b"MZ" + bytes(62) + b"This is not a real program"
FAKE_LNK = b"L\x00\x00\x00\x01\x14\x02\x00" + bytes(64)
OLE_HEADER = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(504)
OLE_WITH_MACRO = OLE_HEADER + "_VBA_PROJECT".encode("utf-16-le") + bytes(32)
FAKE_ISO = bytes(0x8001) + b"CD001" + bytes(64)
PDF_CLEAN = b"%PDF-1.4\n1 0 obj <</Type /Catalog /OpenAction [3 0 R /Fit]>> endobj\n%%EOF"
PDF_JS = b"%PDF-1.7\n1 0 obj <</OpenAction <</S /JavaScript /JS (app.alert(1))>>>> endobj\n"
PNG = b"\x89PNG\r\n\x1a\n" + bytes(32)


def make_zip(files: dict[str, bytes], encrypted: bool = False) -> bytes:
    """Build a ZIP in memory. `encrypted` only sets the 'encrypted' flag (enough for detection)."""
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(zipfile.ZipInfo(name), data)
    raw = bytearray(buffer.getvalue())
    if encrypted:
        # zipfile cannot write encrypted archives and clears the flag, so set the
        # "encrypted" bit (bit 0 of the general-purpose flags) in every header directly.
        for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            start = raw.find(signature)
            while start != -1:
                raw[start + flag_offset] |= 0x1
                start = raw.find(signature, start + 4)
    return bytes(raw)


def email_with_attachments(
    attachments: list[tuple[str | None, str, bytes]],
    body: str = "Please see the attached file.",
    sender: str = "a@example.com",
) -> bytes:
    """Build a multipart email; each attachment is (filename or None, content_type, data)."""
    import base64

    parts = [f"--mix\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n"]
    for filename, content_type, data in attachments:
        disposition = ""
        if filename is not None:
            disposition = (
                f"Content-Disposition: attachment; filename*=utf-8''{_quote(filename)}\r\n"
            )
        encoded = base64.encodebytes(data).decode("ascii")
        parts.append(
            f"--mix\r\nContent-Type: {content_type}\r\n{disposition}"
            f"Content-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
        )
    return (
        f"From: {sender}\r\nMIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="mix"\r\n\r\n' + "".join(parts) + "--mix--\r\n"
    ).encode()


def _quote(filename: str) -> str:
    from urllib.parse import quote

    return quote(filename, safe="")
