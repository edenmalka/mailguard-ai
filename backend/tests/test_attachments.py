"""Attachment analyzer tests: real file types, disguises, archives, macros, active documents."""

import time
import zipfile

import pytest

from app.analyzers.attachments import analyze_attachments
from app.analyzers.file_types import sniff
from app.parsing import parse_email
from tests.helpers import (
    FAKE_EXE,
    FAKE_ISO,
    FAKE_LNK,
    OLE_HEADER,
    OLE_WITH_MACRO,
    PDF_CLEAN,
    PDF_JS,
    PNG,
    email_with_attachments,
    make_zip,
)

RLO = chr(0x202E)  # right-to-left override, written as a code point (no raw invisible chars)


def _analyze(attachments, body: str = "See attached."):
    return analyze_attachments(parse_email(email_with_attachments(attachments, body)))


def _ids(attachments, body: str = "See attached.") -> set[str]:
    return {s.id for s in _analyze(attachments, body).signals}


# --- file type detection ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "kind"),
    [
        (FAKE_EXE, "windows_executable"),
        (b"\x7fELF" + bytes(16), "linux_executable"),
        (FAKE_LNK, "windows_shortcut"),
        (FAKE_ISO, "disk_image"),
        (OLE_HEADER, "ole"),
        (PDF_CLEAN, "pdf"),
        (make_zip({"a.txt": b"x"}), "zip"),
        (b"Rar!\x1a\x07\x01\x00", "rar"),
        (PNG, "image"),
        (b"\xef\xbb\xbf  <!DOCTYPE html><html>", "html"),
        (b"plain text", None),
        (b"", None),
    ],
)
def test_sniff_identifies_real_type(data: bytes, kind: str | None) -> None:
    assert sniff(data) == kind


# --- dangerous files -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "ctype", "data"),
    [
        ("setup.exe", "application/octet-stream", FAKE_EXE),
        ("invoice.js", "application/javascript", b"var x = 1;"),
        ("document.lnk", "application/octet-stream", FAKE_LNK),
        ("scan.iso", "application/octet-stream", FAKE_ISO),
        ("notes.one", "application/octet-stream", b"onenote"),
        ("run.ps1", "text/plain", b"Write-Host hi"),
    ],
)
def test_programs_scripts_and_disk_images_are_flagged(name: str, ctype: str, data: bytes) -> None:
    assert "attachment.executable" in _ids([(name, ctype, data)])


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("invoice.pdf.exe", FAKE_EXE),  # double extension
        ("invoice.pdf          .exe", FAKE_EXE),  # padded with spaces
        ("invoice.pdf", FAKE_EXE),  # name says PDF, content is a program
        (f"invoice{RLO}fdp.exe", FAKE_EXE),  # right-to-left override: shows as "invoiceexe.pdf"
        ("photo.jpg", b"<html><script>location.href='x'</script></html>"),  # web page as image
    ],
)
def test_disguised_files_are_flagged(name: str, data: bytes) -> None:
    assert "attachment.disguised" in _ids([(name, "application/pdf", data)])


def test_hidden_characters_are_shown_as_codes_in_evidence() -> None:
    signal = next(
        s
        for s in _analyze([(f"invoice{RLO}fdp.exe", "application/pdf", FAKE_EXE)]).signals
        if s.id == "attachment.disguised"
    )
    assert "[U+202E]" in (signal.evidence or "")
    assert RLO not in signal.model_dump_json()


def test_unnamed_part_is_still_inspected() -> None:
    # No filename and no "attachment" label: previously such parts were ignored entirely.
    assert "attachment.executable" in _ids([(None, "application/octet-stream", FAKE_EXE)])


def test_path_in_filename_is_reduced_to_the_name() -> None:
    parsed = parse_email(email_with_attachments([("../../evil.exe", "x/y", FAKE_EXE)]))
    assert parsed.attachments[0].filename == "evil.exe"


# --- archives ----------------------------------------------------------------------------------


def test_archive_containing_program_is_flagged() -> None:
    archive = make_zip({"docs/readme.txt": b"hi", "docs/invoice.pdf.exe": FAKE_EXE})
    analysis = _analyze([("invoice.zip", "application/zip", archive)])
    signal = next(s for s in analysis.signals if s.id == "attachment.archive_executable")
    assert "invoice.pdf.exe" in (signal.evidence or "")


def test_archive_with_ordinary_files_is_clean() -> None:
    archive = make_zip({"report.pdf": PDF_CLEAN, "photo.png": PNG})
    analysis = _analyze([("photos.zip", "application/zip", archive)])
    assert analysis.signals == []
    assert analysis.uninspected == []


def test_encrypted_archive_is_flagged_and_reported_as_uninspected() -> None:
    archive = make_zip({"invoice.pdf": PDF_CLEAN}, encrypted=True)
    analysis = _analyze([("invoice.zip", "application/zip", archive)])
    signal = next(s for s in analysis.signals if s.id == "attachment.encrypted_archive")
    assert signal.points == 20
    assert any("password-protected" in u for u in analysis.uninspected)


def test_encrypted_archive_with_password_in_body_scores_higher() -> None:
    archive = make_zip({"invoice.pdf": PDF_CLEAN}, encrypted=True)
    analysis = _analyze([("invoice.zip", "application/zip", archive)], body="Password: 4821")
    signal = next(s for s in analysis.signals if s.id == "attachment.encrypted_archive")
    assert signal.points == 30


@pytest.mark.parametrize(
    ("name", "data"),
    [("files.rar", b"Rar!\x1a\x07\x01\x00" + bytes(16)), ("files.7z", b"7z\xbc\xaf\x27\x1c")],
)
def test_archives_we_cannot_read_are_reported(name: str, data: bytes) -> None:
    analysis = _analyze([(name, "application/octet-stream", data)])
    assert analysis.uninspected


def test_nested_archive_is_reported_as_uninspected() -> None:
    inner = make_zip({"evil.exe": FAKE_EXE})
    analysis = _analyze([("outer.zip", "application/zip", make_zip({"inner.zip": inner}))])
    assert any("inner.zip" in u for u in analysis.uninspected)


def test_corrupt_archive_does_not_crash() -> None:
    analysis = _analyze([("broken.zip", "application/zip", b"PK\x03\x04" + bytes(30))])
    assert analysis.uninspected


def test_zip_bomb_is_never_decompressed(monkeypatch) -> None:
    """Only the file list is read; decompressing anything would fail this test."""

    bomb = make_zip({f"zeros{i}.bin": bytes(5_000_000) for i in range(4)})  # 20 MB unpacked

    def refuse(*args, **kwargs):
        raise AssertionError("archive content was decompressed")

    # Patched only after building the test archive (writing a ZIP also uses ZipFile.open).
    monkeypatch.setattr(zipfile.ZipFile, "open", refuse)
    monkeypatch.setattr(zipfile.ZipFile, "read", refuse)
    start = time.perf_counter()
    _analyze([("bomb.zip", "application/zip", bomb)])
    assert time.perf_counter() - start < 2


# --- Office documents --------------------------------------------------------------------------


def test_macro_enabled_extension_is_flagged() -> None:
    assert "attachment.macro" in _ids([("budget.xlsm", "application/octet-stream", b"PK")])


def test_macros_inside_a_docx_named_file_are_flagged() -> None:
    doc = make_zip({"[Content_Types].xml": b"<Types/>", "word/vbaProject.bin": b"vba"})
    ids = _ids([("report.docx", "application/octet-stream", doc)])
    assert "attachment.macro" in ids
    assert "attachment.archive_executable" not in ids  # Office files are not treated as archives


def test_legacy_office_file_with_macro_project_is_flagged() -> None:
    assert "attachment.macro" in _ids([("invoice.doc", "application/msword", OLE_WITH_MACRO)])


def test_ordinary_office_files_are_clean() -> None:
    docx = make_zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>"})
    assert _ids([("report.docx", "application/octet-stream", docx)]) == set()
    assert _ids([("old.doc", "application/msword", OLE_HEADER)]) == set()


# --- PDF, RTF and HTML -------------------------------------------------------------------------


def test_pdf_with_javascript_is_flagged() -> None:
    assert "attachment.active_document" in _ids([("doc.pdf", "application/pdf", PDF_JS)])


def test_ordinary_pdf_is_clean() -> None:
    assert _ids([("doc.pdf", "application/pdf", PDF_CLEAN)]) == set()


def test_rtf_with_embedded_object_is_flagged() -> None:
    rtf = b"{\\rtf1 {\\object\\objemb {\\objdata 0105000002000000}}}"
    assert "attachment.active_document" in _ids([("doc.rtf", "application/rtf", rtf)])


def test_links_inside_pdf_and_html_attachments_are_collected() -> None:
    pdf = b"%PDF-1.4\n<</A <</S /URI /URI (https://paypa1-login.example/x)>>>>\n"
    html = b"<html><a href='https://evil.example/login'>Sign in</a></html>"
    analysis = _analyze([("a.pdf", "application/pdf", pdf), ("b.html", "text/html", html)])
    assert "https://paypa1-login.example/x" in analysis.urls
    assert "https://evil.example/login" in analysis.urls


@pytest.mark.parametrize(
    "html",
    [
        b"<html><form action='https://x.example'><input type='password'></form></html>",
        b"<html><script>window.location='https://evil.example'</script></html>",
        b"<html><meta http-equiv='refresh' content='0;url=https://evil.example'></html>",
        b"<svg xmlns='http://www.w3.org/2000/svg'><script>atob('aGk=')</script></svg>",
    ],
)
def test_active_web_page_attachments(html: bytes) -> None:
    analysis = _analyze([("receipt.html", "text/html", html)])
    signal = next(s for s in analysis.signals if s.id == "attachment.html_active")
    assert signal.points == 30


def test_plain_web_page_attachment_scores_lower() -> None:
    analysis = _analyze([("receipt.htm", "text/html", b"<html><p>Thanks</p></html>")])
    assert [(s.id, s.points) for s in analysis.signals] == [("attachment.html", 15)]


# --- legitimate attachments ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "ctype", "data"),
    [
        ("photo.png", "image/png", PNG),
        ("report.pdf", "application/pdf", PDF_CLEAN),
        ("data.csv", "text/csv", b"a,b\n1,2\n"),
        ("invite.ics", "text/calendar", b"BEGIN:VCALENDAR\nEND:VCALENDAR"),
        ("notes.txt", "text/plain", b"hello"),
        (None, "image/jpeg", b"\xff\xd8\xff\xe0" + bytes(16)),  # inline image without a name
    ],
)
def test_ordinary_attachments_raise_nothing(name, ctype: str, data: bytes) -> None:
    analysis = _analyze([(name, ctype, data)])
    assert analysis.signals == []
    assert analysis.uninspected == []


def test_one_signal_per_problem_type() -> None:
    files = [(f"tool{i}.exe", "application/octet-stream", FAKE_EXE) for i in range(5)]
    signals = _analyze(files).signals
    assert [s.id for s in signals] == ["attachment.executable"]
    assert "and 2 more" in (signals[0].evidence or "")


def test_disguised_file_inside_archive_is_flagged_as_disguised() -> None:
    archive = make_zip({"Invoice.pdf.exe": FAKE_EXE, f"scan{RLO}gpj.scr": FAKE_EXE})
    ids = _ids([("Invoice.zip", "application/zip", archive)])
    assert {"attachment.archive_executable", "attachment.disguised"} <= ids
