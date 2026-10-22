import logging
import sys
from app.core.config import settings


def setup_logging() -> None:
    """
    Configure enterprise structured logging for SecureShare.
    Outputs clear, standardized log records for incident detection and monitoring.
    """
    log_level = logging.DEBUG if settings.DEBUG else logging.INFO

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z"
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Avoid duplicate handlers on reload
    if not root_logger.handlers:
        root_logger.addHandler(handler)
    else:
        root_logger.handlers = [handler]

    # Silence overly verbose external libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)
