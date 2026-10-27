"""Microsoft Entra ID (Azure AD) token verification.

Fetches and caches the tenant JWKS (JSON Web Key Set) public certificates and
validates RS256 bearer tokens issued by Entra ID. Only the immutable `oid`
claim is used as the application-level identity; email is treated as mutable
display/contact data.

Security properties:
- Algorithm allow-list is hard-coded to RS256 (blocks `alg=none` and HS256 key
  confusion attacks).
- `aud`, `iss`, `tid`, `exp`, `nbf` and `iat` are validated with a configurable
  clock-skew leeway.
- JWKS are cached but force-refreshed at most once per cooldown window, so an
  attacker cannot turn an unknown `kid` into an unbounded request amplifier
  against login.microsoftonline.com.
- On IdP unavailability the last known good keys are reused (fail-safe for
  availability) while signature validation still fails closed for bad tokens.
"""
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import jwt
import requests
from jwt import PyJWK

from app.core.config import settings
from app.core.exceptions import UnauthorizedException

logger = logging.getLogger("secureshare.entra")

ALLOWED_ALGORITHMS = ["RS256"]


@dataclass
class EntraClaims:
    """Normalised, application-relevant subset of an Entra ID token."""

    oid: str
    email: str
    name: str = ""
    tid: str = ""
    roles: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


class JWKSProvider:
    """Thread-safe, TTL-based cache of Entra ID signing keys."""

    def __init__(self) -> None:
        self._keys: Dict[str, PyJWK] = {}
        self._fetched_at: float = 0.0
        self._last_refresh_attempt: float = 0.0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _fetch(self) -> Dict[str, PyJWK]:
        uri = settings.get_entra_jwks_uri()
        if not uri:
            raise UnauthorizedException("Identity provider is not configured.")

        response = requests.get(uri, timeout=settings.JWKS_HTTP_TIMEOUT_SECONDS)
        response.raise_for_status()
        payload = response.json()

        keys: Dict[str, PyJWK] = {}
        for jwk in payload.get("keys", []):
            kid = jwk.get("kid")
            if not kid:
                continue
            try:
                keys[kid] = PyJWK(jwk)
            except Exception as exc:  # malformed key must not break the set
                logger.warning("Skipping malformed JWKS key %s: %s", kid, exc)

        if not keys:
            raise UnauthorizedException("Identity provider returned no usable signing keys.")

        return keys

    def _refresh(self) -> None:
        self._keys = self._fetch()
        self._fetched_at = time.monotonic()
        self._last_refresh_attempt = self._fetched_at

    def _is_fresh(self) -> bool:
        return (time.monotonic() - self._fetched_at) < settings.JWKS_CACHE_TTL_SECONDS

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def get_key(self, kid: str) -> Optional[PyJWK]:
        """Return the signing key for `kid`, refreshing the cache when needed."""
        with self._lock:
            if kid in self._keys and self._is_fresh():
                return self._keys[kid]

            now = time.monotonic()
            cooldown_elapsed = (
                now - self._last_refresh_attempt
            ) >= settings.JWKS_REFRESH_COOLDOWN_SECONDS

            if cooldown_elapsed:
                try:
                    self._refresh()
                except Exception as exc:
                    logger.error("JWKS refresh failed: %s", exc)
                    # Reuse stale keys rather than failing every request.
                    if kid in self._keys:
                        return self._keys[kid]
                    return None
            elif not self._is_fresh():
                # Cache expired but refresh is throttled: still serve known keys.
                return self._keys.get(kid)

            return self._keys.get(kid)

    def invalidate(self) -> None:
        """Drop cached keys (useful for tests and key-rotation events)."""
        with self._lock:
            self._keys = {}
            self._fetched_at = 0.0
            self._last_refresh_attempt = 0.0


# Module-level singleton shared by all requests.
jwks_provider = JWKSProvider()


def _extract_email(payload: Dict[str, Any]) -> str:
    for claim in ("preferred_username", "email", "upn", "unique_name"):
        value = payload.get(claim)
        if value and isinstance(value, str) and "@" in value:
            return value.lower()
    return ""


def verify_entra_token(token: str) -> EntraClaims:
    """
    Verify an Entra ID RS256 access token and return its normalised claims.

    Raises `UnauthorizedException` on any validation failure. The exception
    message is intentionally generic to avoid leaking which check failed.
    """
    if settings.AUTH_MODE not in ("entra", "both"):
        raise UnauthorizedException("Entra ID authentication is not enabled.")

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise UnauthorizedException("Invalid authentication token.")

    algorithm = header.get("alg")
    if algorithm not in ALLOWED_ALGORITHMS:
        logger.warning("Rejected Entra token with disallowed alg=%s", algorithm)
        raise UnauthorizedException("Invalid authentication token.")

    kid = header.get("kid")
    if not kid:
        raise UnauthorizedException("Invalid authentication token.")

    signing_key = jwks_provider.get_key(kid)
    if signing_key is None:
        logger.warning("No Entra signing key found for kid=%s", kid)
        raise UnauthorizedException("Invalid authentication token.")

    audience = settings.ENTRA_CLIENT_ID
    issuer = settings.get_entra_issuer()
    if not audience or not issuer:
        logger.error("Entra ID verification attempted without ENTRA_CLIENT_ID/tenant configuration.")
        raise UnauthorizedException("Identity provider is not configured.")

    try:
        payload = jwt.decode(
            token,
            key=signing_key.key,
            algorithms=ALLOWED_ALGORITHMS,
            audience=audience,
            issuer=issuer,
            leeway=settings.JWT_LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "oid", "tid"]},
        )
    except jwt.ExpiredSignatureError:
        raise UnauthorizedException("Authentication token has expired.")
    except jwt.PyJWTError as exc:
        logger.warning("Entra token verification failed: %s", exc)
        raise UnauthorizedException("Invalid authentication token.")

    tenant_id = payload.get("tid", "")
    if settings.ENTRA_TENANT_ID and tenant_id != settings.ENTRA_TENANT_ID:
        logger.warning("Rejected token from unexpected tenant=%s", tenant_id)
        raise UnauthorizedException("Invalid authentication token.")

    oid = payload.get("oid")
    if not oid:
        raise UnauthorizedException("Invalid authentication token.")

    email = _extract_email(payload)
    if not email:
        raise UnauthorizedException("Authentication token is missing a verified email claim.")

    name = payload.get("name") or email.split("@")[0]
    roles = payload.get("roles") or []

    return EntraClaims(
        oid=str(oid),
        email=email,
        name=str(name)[:100],
        tid=str(tenant_id),
        roles=list(roles) if isinstance(roles, list) else [],
        raw=payload,
    )
