import io
import os
import re
import uuid
import zipfile
from typing import Tuple
from app.core.config import settings
from app.core.exceptions import (
    BadRequestException,
    FileTooLargeException,
    UnsupportedMediaTypeException
)

# Magic Byte Signatures for allowed MIME types
PDF_SIGNATURE = b"%PDF-"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
JPEG_SIGNATURE = b"\xff\xd8\xff"
ZIP_SIGNATURE = b"\x50\x4b\x03\x04"  # Base signature for docx (OpenXML ZIP)

MIME_TYPE_MAPPINGS = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
}


def sanitize_filename(filename: str) -> str:
    """
    Sanitize the user-provided filename to mitigate Path Traversal,
    Null Byte Injection, and Command Injection attacks.
    """
    if not filename:
        raise BadRequestException("Original filename cannot be empty.")

    # Remove null bytes
    sanitized = filename.replace("\x00", "")

    # Strip directory paths (both Unix and Windows style)
    sanitized = os.path.basename(sanitized)
    sanitized = sanitized.replace("\\", "/").split("/")[-1]

    # Remove path traversal sequences
    sanitized = re.sub(r"\.\.+", ".", sanitized)

    # Allow only alphanumeric, dashes, underscores, and dots
    sanitized = re.sub(r"[^a-zA-Z0-9.\-_ ]", "_", sanitized)

    # Trim whitespace and trailing dots
    sanitized = sanitized.strip().strip(".")

    if not sanitized:
        sanitized = "unnamed_file"

    # Truncate filename length to safe limit
    if len(sanitized) > 200:
        base, ext = os.path.splitext(sanitized)
        sanitized = base[:190] + ext

    return sanitized


def validate_file_extension(filename: str) -> str:
    """
    Extract and validate file extension against the strict allowlist:
    [.pdf, .png, .jpg, .jpeg, .docx].
    """
    _, ext = os.path.splitext(filename)
    ext_lower = ext.lower().strip()

    if not ext_lower or ext_lower not in settings.ALLOWED_EXTENSIONS:
        raise UnsupportedMediaTypeException(
            f"File extension '{ext_lower}' is not allowed. "
            f"Permitted extensions: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        )

    return ext_lower


def validate_file_size(size_bytes: int) -> None:
    """
    Enforce hard 25 MB payload limit.
    """
    if size_bytes <= 0:
        raise BadRequestException("File payload cannot be empty (0 bytes).")

    if size_bytes > settings.MAX_FILE_SIZE_BYTES:
        max_mb = settings.MAX_FILE_SIZE_BYTES / (1024 * 1024)
        raise FileTooLargeException(
            f"Uploaded file exceeds maximum allowed size of {max_mb:.0f} MB."
        )


def validate_content_signature(file_content: bytes, extension: str) -> str:
    """
    Inspect magic bytes (file signature) to detect MIME type spoofing.
    Never trust user-supplied Content-Type headers or file extensions alone.
    """
    content_len = len(file_content)
    if content_len < 4:
        raise BadRequestException("File content is too small to be a valid file.")

    if extension == ".pdf":
        if not file_content.startswith(PDF_SIGNATURE):
            raise BadRequestException("File signature verification failed: not a valid PDF file.")
        return "application/pdf"

    elif extension == ".png":
        if not file_content.startswith(PNG_SIGNATURE):
            raise BadRequestException("File signature verification failed: not a valid PNG image.")
        return "image/png"

    elif extension in [".jpg", ".jpeg"]:
        if not file_content.startswith(JPEG_SIGNATURE):
            raise BadRequestException("File signature verification failed: not a valid JPEG image.")
        return "image/jpeg"

    elif extension == ".docx":
        if not file_content.startswith(ZIP_SIGNATURE):
            raise BadRequestException("File signature verification failed: not a valid DOCX container.")

        # Deep inspect DOCX archive to verify OpenXML structure and avoid arbitrary ZIP execution
        try:
            with zipfile.ZipFile(io.BytesIO(file_content)) as zf:
                namelist = zf.namelist()
                has_content_types = "[Content_Types].xml" in namelist
                has_word_dir = any(name.startswith("word/") for name in namelist)
                if not (has_content_types and has_word_dir):
                    raise BadRequestException("File signature verification failed: corrupt or spoofed DOCX file.")
        except zipfile.BadZipFile:
            raise BadRequestException("Invalid DOCX format: archive corrupted.")
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

    raise UnsupportedMediaTypeException(f"Unsupported file format for extension: {extension}")


def generate_uuid_filename(extension: str) -> str:
    """
    Generate an unpredictable UUID v4 based filename.
    Example: 7c12d5ab-b0b2-45e3-96e2-28df330ebcb8.pdf
    Ensures user-controlled filenames are never stored on filesystem or cloud storage.
    """
    random_uuid = uuid.uuid4()
    return f"{random_uuid}{extension}"


def validate_and_prepare_file(filename: str, file_content: bytes) -> Tuple[str, str, str, str, int]:
    """
    Orchestrates the entire security validation pipeline:
    1. Size validation (<= 25 MB)
    2. Filename sanitization
    3. Extension validation
    4. Magic bytes MIME verification
    5. UUID blob filename generation

    Returns:
        (sanitized_name, extension, validated_mime, uuid_blob_name, file_size)
    """
    file_size = len(file_content)
    validate_file_size(file_size)

    sanitized_name = sanitize_filename(filename)
    extension = validate_file_extension(sanitized_name)
    validated_mime = validate_content_signature(file_content, extension)
    uuid_blob_name = generate_uuid_filename(extension)

    return sanitized_name, extension, validated_mime, uuid_blob_name, file_size
