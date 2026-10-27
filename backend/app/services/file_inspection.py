"""
Content-based file type inspection using libmagic (python-magic).

The client-supplied filename extension and ``Content-Type`` header are
ignored: only the real file signature ("magic bytes") decides whether a
file is accepted.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

import magic

# Detected MIME type → canonical MIME type stored in the DB.
ALLOWED_MIME_TYPES: dict[str, str] = {
    "application/pdf": "application/pdf",
    "image/png": "image/png",
    "image/jpeg": "image/jpeg",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation":
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

# OOXML containers are ZIP archives; libmagic can fall back to generic ZIP
# when the identifying entries are not in the sniffed prefix.
_OOXML_MARKERS = {
    "word/": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xl/": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "ppt/": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}
_ZIP_GENERIC = {"application/zip", "application/octet-stream"}


class UnsupportedFileTypeError(Exception):
    def __init__(self, detected: str):
        super().__init__(f"File content type '{detected}' is not permitted")
        self.detected = detected


def sniff_mime(head: bytes) -> str:
    """Return the MIME type libmagic detects from the file's leading bytes."""
    return magic.from_buffer(head, mime=True)


def verify_header(head: bytes) -> str:
    """
    Fast pre-check on the first bytes of the stream (before anything is
    written to disk). Returns the detected MIME type or raises.

    A generic ZIP is provisionally accepted here so that OOXML files can be
    confirmed structurally by :func:`resolve_final_mime` once quarantined.
    """
    detected = sniff_mime(head)
    if detected in ALLOWED_MIME_TYPES:
        return detected
    if head.startswith(b"PK\x03\x04") and detected in _ZIP_GENERIC:
        return "application/zip"
    raise UnsupportedFileTypeError(detected)


def resolve_final_mime(path: Path, provisional: str) -> str:
    """
    Final, authoritative type decision on the fully quarantined file.
    Re-runs libmagic on the full file and confirms ZIP-based OOXML structure.
    """
    detected = magic.from_file(str(path), mime=True)
    if detected in ALLOWED_MIME_TYPES and detected != "application/zip":
        if provisional != "application/zip" and detected != provisional:
            raise UnsupportedFileTypeError(detected)
        return ALLOWED_MIME_TYPES[detected]

    if provisional == "application/zip" or detected in _ZIP_GENERIC:
        ooxml = _detect_ooxml(path)
        if ooxml:
            return ooxml
    raise UnsupportedFileTypeError(detected)


def _detect_ooxml(path: Path) -> str | None:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return None
    if "[Content_Types].xml" not in names:
        return None
    for prefix, mime in _OOXML_MARKERS.items():
        if any(n.startswith(prefix) for n in names):
            return mime
    return None
