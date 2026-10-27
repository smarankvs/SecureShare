"""
Ephemeral quarantine storage.

Uploaded bytes are written to an isolated, owner-only directory under a
random UUID filename. The user-supplied filename never touches the
filesystem. Files live only for the duration of the request: the
:func:`quarantine_file` context manager guarantees secure removal on every
exit path (clean, infected, error).
"""
from __future__ import annotations

import hashlib
import logging
import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings

logger = logging.getLogger("secureshare.quarantine")


class FileTooLargeError(Exception):
    pass


@dataclass
class QuarantinedFile:
    path: Path
    size: int = 0
    sha256: str = ""

    def read_bytes(self) -> bytes:
        return self.path.read_bytes()


def _ensure_quarantine_dir() -> Path:
    qdir = settings.QUARANTINE_DIR
    qdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(qdir, 0o700)
    return qdir


def purge(path: Path) -> None:
    """Overwrite (best-effort) and unlink a quarantined file."""
    try:
        size = path.stat().st_size
        with open(path, "r+b", buffering=0) as fh:
            fh.write(b"\x00" * min(size, 32 * 1024 * 1024))
            fh.flush()
            os.fsync(fh.fileno())
    except FileNotFoundError:
        return
    except OSError as exc:  # pragma: no cover - best effort
        logger.warning("Quarantine overwrite failed for %s: %s", path.name, exc)
    try:
        path.unlink()
    except FileNotFoundError:
        pass


@contextmanager
def quarantine_file() -> Iterator[QuarantinedFile]:
    """Reserve a quarantine slot (random UUID name, 0600) and always purge it."""
    qdir = _ensure_quarantine_dir()
    path = qdir / f"{uuid.uuid4().hex}.quarantine"
    # O_EXCL: never follow/overwrite an existing path; O_NOFOLLOW where available.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    os.close(os.open(path, flags, 0o600))
    qf = QuarantinedFile(path=path)
    try:
        yield qf
    finally:
        purge(path)


def write_stream(qf: QuarantinedFile, first_chunk: bytes, chunks: Iterator[bytes], limit: int) -> None:
    """
    Stream bytes into the quarantine file while enforcing the size limit and
    computing the SHA-256 digest on the fly. Aborts as soon as ``limit`` is
    exceeded.
    """
    hasher = hashlib.sha256()
    total = 0
    with open(qf.path, "wb", buffering=0) as fh:
        for chunk in _chain(first_chunk, chunks):
            total += len(chunk)
            if total > limit:
                raise FileTooLargeError()
            hasher.update(chunk)
            fh.write(chunk)
        fh.flush()
        os.fsync(fh.fileno())
    qf.size = total
    qf.sha256 = hasher.hexdigest()


def _chain(first: bytes, rest: Iterator[bytes]) -> Iterator[bytes]:
    if first:
        yield first
    yield from rest
