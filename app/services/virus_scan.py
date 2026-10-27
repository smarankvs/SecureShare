import logging
import socket
from typing import Optional, Tuple
from app.core.config import settings
from app.core.exceptions import BadRequestException

logger = logging.getLogger("secureshare.virus_scan")

# Standard EICAR test string (used by cybersecurity analysts to verify AV scanners safely)
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Known dangerous executable / shell script headers that must never be in document payloads
DANGEROUS_SIGNATURES = [
    (b"MZ", "DOS/Windows Executable PE header"),
    (b"\x7fELF", "Linux ELF Executable header"),
    (b"#!/", "Executable script header"),
    (b"<script", "Embedded raw HTML script tag"),
]


class VirusScannerService:
    """
    Antivirus and Malicious Payload Detection Service.
    Supports ClamAV daemon integration and static signature inspection.
    """

    def __init__(self):
        self.enabled = settings.CLAMAV_ENABLED
        self.host = settings.CLAMAV_HOST
        self.port = settings.CLAMAV_PORT

    def scan_file_bytes(self, file_content: bytes) -> Tuple[bool, Optional[str]]:
        """
        Scan in-memory file bytes.
        Returns:
            (is_clean: bool, threat_details: Optional[str])
        """
        # 1. Check for EICAR test virus signature
        if EICAR_SIGNATURE in file_content:
            logger.warning("ALERT: EICAR test signature detected in uploaded file!")
            return False, "Eicar-Test-Signature"

        # 2. Heuristic check: Dangerous executable headers inside document payloads
        for sig, description in DANGEROUS_SIGNATURES:
            if file_content.startswith(sig):
                logger.warning(f"ALERT: Dangerous payload signature detected ({description})!")
                return False, f"MaliciousHeader:{description}"

        # 3. ClamAV Daemon scan (if enabled)
        if self.enabled:
            return self._scan_with_clamd(file_content)

        return True, None

    def _scan_with_clamd(self, data: bytes) -> Tuple[bool, Optional[str]]:
        """Send stream to ClamAV clamd daemon over TCP INSTREAM protocol."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10.0)
                sock.connect((self.host, self.port))
                # ClamAV INSTREAM command
                sock.sendall(b"zINSTREAM\0")

                # Send data in chunks with length prefix (big-endian 4-byte unsigned int)
                chunk_size = 2048
                for i in range(0, len(data), chunk_size):
                    chunk = data[i:i + chunk_size]
                    sock.sendall(len(chunk).to_bytes(4, byteorder="big") + chunk)

                # Send 0-length chunk to indicate end of stream
                sock.sendall((0).to_bytes(4, byteorder="big"))

                # Read response
                response = sock.recv(1024).decode("utf-8", errors="ignore").strip()

                if "OK" in response:
                    return True, None
                elif "FOUND" in response:
                    threat_name = response.split(":")[1].replace("FOUND", "").strip() if ":" in response else response
                    logger.warning(f"ClamAV detected malware: {threat_name}")
                    return False, threat_name
                else:
                    logger.error(f"Unexpected ClamAV response: {response}")
                    return True, None
        except Exception as exc:
            logger.error(f"ClamAV daemon connection failed: {exc}. Permitting file with static scan.")
            return True, None

    def assert_clean(self, file_content: bytes) -> None:
        """
        Perform scan and raise BadRequestException if malware is detected.
        """
        is_clean, threat = self.scan_file_bytes(file_content)
        if not is_clean:
            raise BadRequestException(f"Security Alert: Malicious file detected ({threat}). Upload rejected.")


virus_scanner = VirusScannerService()
