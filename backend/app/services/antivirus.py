"""
ClamAV integration via the clamd daemon (pyclamd, TCP port 3310).

Policy: **fail closed**. If clamd is unreachable, times out, rejects the
stream size, or returns an ERROR verdict, the file is treated as unscanned
and is not allowed to proceed to storage.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import BinaryIO

import pyclamd

from app.core.config import settings

logger = logging.getLogger("secureshare.antivirus")


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"


@dataclass(frozen=True)
class ScanResult:
    verdict: Verdict
    signature: str | None = None


class ScannerUnavailableError(Exception):
    """ClamAV could not produce a trustworthy verdict."""


class ClamAVScanner:
    def __init__(self, host: str | None = None, port: int | None = None, timeout: float | None = None):
        self.host = host or settings.CLAMAV_HOST
        self.port = port or settings.CLAMAV_PORT
        self.timeout = timeout or settings.CLAMAV_TIMEOUT_SECONDS

    def _connect(self) -> pyclamd.ClamdNetworkSocket:
        try:
            cd = pyclamd.ClamdNetworkSocket(host=self.host, port=self.port, timeout=self.timeout)
            if not cd.ping():
                raise ScannerUnavailableError("clamd did not respond to PING")
            return cd
        except ScannerUnavailableError:
            raise
        except Exception as exc:
            raise ScannerUnavailableError(f"Cannot reach clamd at {self.host}:{self.port}: {exc}") from exc

    def scan_stream(self, stream: BinaryIO | bytes) -> ScanResult:
        """Pipe a file stream into clamd using INSTREAM (``scan_stream``)."""
        cd = self._connect()
        try:
            result = cd.scan_stream(stream)
        except pyclamd.BufferTooLongError as exc:
            raise ScannerUnavailableError(
                "clamd StreamMaxLength is smaller than the upload limit"
            ) from exc
        except Exception as exc:
            raise ScannerUnavailableError(f"clamd scan failed: {exc}") from exc

        if result is None:
            return ScanResult(Verdict.CLEAN)

        # result looks like {'stream': ('FOUND', 'Eicar-Test-Signature')}
        for status, reason in result.values():
            if status == "FOUND":
                return ScanResult(Verdict.INFECTED, signature=reason)
        # Any ERROR verdict → we cannot vouch for the file.
        raise ScannerUnavailableError(f"clamd returned error verdict: {result}")


_scanner: ClamAVScanner | None = None


def get_scanner() -> ClamAVScanner:
    """FastAPI dependency (override in tests)."""
    global _scanner
    if _scanner is None:
        _scanner = ClamAVScanner()
    return _scanner
