# SecureShare Backend — DB, Cloud Storage & File Inspection (Member 3)

## Upload pipeline — `POST /api/v1/documents/upload`

```
multipart file
  │ 1. Size gate: >25 MB → 413 (ASGI middleware on Content-Length / streamed bytes,
  │               plus exact byte count while writing)
  │ 2. Magic bytes (python-magic): PDF, PNG, JPEG, DOCX, XLSX, PPTX only → else 415
  │               (filename extension and client Content-Type are ignored)
  │ 3. Quarantine: random UUID filename, 0600, isolated 0700 dir, always purged
  │ 4. ClamAV (pyclamd → clamd:3310, scan_stream / INSTREAM)
  │      INFECTED → purge, scan_status=INFECTED, 400, security alert + audit event
  │      scanner error/unreachable → scan_status=ERROR, 503 (fail closed)
  │ 5. CLEAN → AES-256-GCM with per-file DEK; DEK wrapped by KEK (Key Vault)
  │ 6. Upload ciphertext to the *private* Azure Blob container (UUID blob name)
  ▼
201 {id, original_filename, mime_type, file_size, sha256, scan_status, created_at}
```

## Layout

| Path | Purpose |
|---|---|
| `app/db/models.py` | users, documents, shares, access_events |
| `alembic/` | migrations (`0001_initial_core_schema`) |
| `app/api/v1/documents.py` | upload endpoint |
| `app/middleware/upload_limit.py` | early 25 MB rejection |
| `app/services/file_inspection.py` | magic-byte checks |
| `app/services/quarantine.py` | ephemeral quarantine |
| `app/services/antivirus.py` | ClamAV client |
| `app/services/security_alerts.py` | CRITICAL structured alerts + optional webhook |
| `app/services/encryption.py` | AES-256-GCM envelope encryption |
| `app/services/key_wrapping.py` | **Member 4 integration point** (KEK wrap/unwrap) |
| `app/services/blob_storage.py` | private container, `generate_download_sas()` |

## Short-lived SAS — `generate_download_sas(blob_name)`

User Delegation SAS signed with a key obtained via **Managed Identity**
(`get_user_delegation_key`, cached ~1 h). Token restrictions: `sr=b` (single
blob), `sp=r` (read only), `spr=https`, `se = now + 120 s`.
Required RBAC on the storage account for the identity: *Storage Blob Data
Contributor* (upload) — which includes `generateUserDelegationKey`.

> The blob holds **ciphertext**. A SAS download must be decrypted with the
> unwrapped DEK (envelope metadata lives on the blob: `ss_nonce`,
> `ss_wrapped_dek`, `ss_kek_id`, …); see `encryption.decrypt()`.

## Integration points for teammates

- **Auth (Entra ID):** set `request.state.principal = {"oid": ..., "email": ...}`
  after token validation. `X-Dev-Entra-OID` / `X-Dev-Email` headers work only
  outside production.
- **Key Vault (Member 4):** call
  `register_key_wrap_client(client)` at startup with an object exposing
  `wrap_key(dek) -> WrappedKey` and `unwrap_key(WrappedKey) -> bytes`, or just set
  `AZURE_KEYVAULT_KEK_ID` to use the bundled RSA-OAEP-256 `CryptographyClient`.

## Run locally

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # needs libmagic (brew install libmagic)
docker compose -f docker-compose.dev.yml up -d   # PostgreSQL + ClamAV
cp .env.example .env                      # fill in Azure values
alembic upgrade head
uvicorn main:app --reload
```

## Tests

```bash
pytest -q                                       # SQLite, mocked clamd/Azure
TEST_DATABASE_URL=postgresql+psycopg://... pytest -q   # against PostgreSQL
```
A live EICAR test runs automatically when clamd is reachable on `localhost:3310`.
