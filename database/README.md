# Database

The PostgreSQL schema is managed with **SQLAlchemy 2.0 + Alembic** from the backend:

- Models: [`backend/app/db/models.py`](../backend/app/db/models.py)
- Migrations: [`backend/alembic/versions/`](../backend/alembic/versions/)

```bash
cd backend
export DATABASE_URL=postgresql+psycopg://secureshare:secureshare@localhost:5432/secureshare
alembic upgrade head          # apply
alembic downgrade base        # roll back
alembic revision --autogenerate -m "describe change"   # after editing models
```

## Core tables

| Table | Columns |
|---|---|
| `users` | id, entra_object_id (unique), email (unique), status, created_at |
| `documents` | id, owner_id → users, original_filename, blob_name (unique UUID), mime_type, file_size, sha256, scan_status, created_at |
| `shares` | id, document_id → documents, owner_id → users, recipient_user_id → users, token_hash (unique), expires_at, max_downloads, download_count, status, created_at, revoked_at |
| `access_events` | id, document_id, share_id, user_id, event_type, result, timestamp, ip_address (INET) |

Enums: `user_status`, `scan_status` (PENDING/CLEAN/INFECTED/ERROR), `share_status`,
`access_event_type`, `access_result`. CHECK constraints guard sizes, hash length
and download counters. `access_events` FKs use `ON DELETE SET NULL` so the
audit trail survives deletions.
