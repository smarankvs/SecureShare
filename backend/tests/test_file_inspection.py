import io
import zipfile

import pytest

from app.services.file_inspection import UnsupportedFileTypeError, resolve_final_mime, verify_header

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde" + b"\x00" * 64
PDF = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\x00" * 64 + b"\xff\xd9"
EXE = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 200


def make_docx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        zf.writestr("_rels/.rels", "<Relationships/>")
        zf.writestr("word/document.xml", "<w:document/>")
    return buf.getvalue()


def make_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("payload.txt", "hello")
    return buf.getvalue()


@pytest.mark.parametrize("data,mime", [(PNG, "image/png"), (PDF, "application/pdf"), (JPEG, "image/jpeg")])
def test_allowed_types(data, mime, tmp_path):
    assert verify_header(data) == mime
    p = tmp_path / "x"
    p.write_bytes(data)
    assert resolve_final_mime(p, mime) == mime


def test_executable_rejected_regardless_of_extension():
    with pytest.raises(UnsupportedFileTypeError):
        verify_header(EXE)


def test_docx_confirmed_structurally(tmp_path):
    data = make_docx()
    provisional = verify_header(data)
    p = tmp_path / "x"
    p.write_bytes(data)
    assert resolve_final_mime(p, provisional) == (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )


def test_plain_zip_rejected(tmp_path):
    data = make_zip()
    provisional = verify_header(data)  # provisionally allowed as ZIP …
    p = tmp_path / "x"
    p.write_bytes(data)
    with pytest.raises(UnsupportedFileTypeError):  # … but not an OOXML document
        resolve_final_mime(p, provisional)
