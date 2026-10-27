# Sharing & Access Control API (Member 2)

Recipient-bound, time-limited, quota-limited document sharing with a four-gate
download gatekeeper.

## Authentication modes

`AUTH_MODE` in `.env` selects the identity source:

| Mode | Behaviour |
|---|---|
| `local` (default) | App-issued HS256 tokens from `/api/v1/auth/login`. Existing flows unchanged. |
| `entra` | Microsoft Entra ID RS256 tokens verified against tenant JWKS. Only `oid` is trusted as identity. |
| `both` | Dispatches per token shape (`kid`/`RS256` → Entra, otherwise local). Use during migration. |

Entra configuration: `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID` (API audience),
optional `ENTRA_ISSUER`/`ENTRA_JWKS_URI`. Users are auto-provisioned in the
`users` shadow table keyed on the immutable `oid` claim; an existing local
account with the same verified email is linked rather than duplicated.

Verification enforces: `RS256` only (blocks `alg=none` and HS256 key confusion),
signature, `aud`, `iss`, `tid`, `exp`/`iat` with leeway, `require=[exp, iat, oid,
tid]`. JWKS are cached for 24h and force-refreshed at most once per 5 minutes.

## Endpoints

### `POST /api/v1/shares`

Owner-only. Creates a share grant.

```json
{
  "file_id": "<uuid>",
  "recipient_email": "bob@example.com",
  "expires_at": "2026-10-28T12:00:00Z",
  "max_downloads": 3
}
```

`201` response contains the raw token **exactly once**:

```json
{
  "share_id": "<uuid>",
  "file_id": "<uuid>",
  "recipient_email": "bob@example.com",
  "token": "<token_urlsafe(32)>",
  "token_prefix": "AbCd1234",
  "share_url": "/share/<token>",
  "expires_at": "...",
  "max_downloads": 3,
  "status": "ACTIVE"
}
```

Only `SHA-256(token)` is persisted. Validation: expiry must be in the future and
within `SHARE_MAX_EXPIRY_DAYS` (90); quota between 1 and
`SHARE_MAX_DOWNLOADS_CAP` (100).

### `GET /api/v1/shares?file_id=...`

Lists shares created by the caller or covering files they own. Never returns
token material — only `token_prefix`, status and counters.

### `POST /api/v1/shares/{share_id}/revoke`

Owner-only. Sets `status=REVOKED`, `revoked_at=now()`, `revoked_by=<user>`, and
writes a `SHARE_REVOKED` audit event. Revocation is immediate for subsequent
downloads. Re-revoking returns `400`.

### `POST /api/v1/shares/download`

Canonical download endpoint. The token travels in the **body**, never the URL:

```json
{ "token": "<raw token>" }
```

`200` response:

```json
{
  "share_id": "<uuid>",
  "file_name": "thesis.pdf",
  "content_type": "application/pdf",
  "size": 1024,
  "sha256_hash": "...",
  "download_url": "<short-lived SAS or local download URL>",
  "expires_in_seconds": 300,
  "remaining_downloads": 2
}
```

`POST /api/v1/shares/{token}/download` exists only for compatibility with the
original specification and is hidden from the OpenAPI schema. A bearer secret in
the URL path leaks into access logs, proxies and referrers.

## The four gates (atomic)

All gates are evaluated in a single conditional `UPDATE ... RETURNING`:

1. `status == 'ACTIVE'`
2. `now() < expires_at`
3. `download_count < max_downloads`
4. caller is the recipient (`recipient_user_id == user.id` OR
   `lower(recipient_email) == lower(user.email)`)

Check-then-increment would let concurrent requests exceed the quota; the atomic
reservation guarantees exactly one winner per remaining slot. The counter is
incremented, `last_downloaded_at` is set, and the share flips to `EXHAUSTED` on
the final download in the same statement.

On failure the caller receives a **uniform `404`** — the real reason
(`UNKNOWN_TOKEN`, `REVOKED`, `EXPIRED`, `EXHAUSTED`, `RECIPIENT_MISMATCH`) is
written only to `audit_logs`, so the endpoint cannot be used to enumerate valid
tokens. A third party attempting someone else's link is denied at gate 4.

SAS issuance goes through `blob_service.generate_download_url()` (Member 3's
storage service) with `SHARE_SAS_EXPIRY_MINUTES` (default 5). If issuance fails
after the reservation, the counter is compensated so a transient storage error
does not consume the recipient's quota.

## Audit events

`SHARE_CREATED`, `SHARE_REVOKED`, `SHARE_DOWNLOAD_SUCCESS`,
`SHARE_DOWNLOAD_DENIED`, `SHARE_DOWNLOAD_FAILED`, plus the existing
`UNAUTHORIZED_*` events produced by the ownership validator.

## Known limitation

A SAS URL is valid for its whole TTL (default 5 minutes), so one reserved
download can be fetched more than once inside that window. The counter therefore
measures *share links issued*, not byte transfers.

## Tests

```bash
pytest tests/test_shares.py tests/test_entra.py -q
```

Covers token hashing/non-disclosure, ownership denial, revocation, expiry, quota
exhaustion, recipient spoofing, uniform 404s, audit events, plus Entra
verification (wrong aud/iss/tid, expired, `alg=none`, HS256 confusion, unknown
`kid`, tampered signature, dual-mode operation).
