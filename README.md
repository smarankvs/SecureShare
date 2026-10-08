# SecureShare: Production-Grade Cloud-Native Secure File Sharing Platform

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?style=flat&logo=FastAPI&logoColor=white)](https://fastapi.tiangolo.com)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Azure Blob Storage](https://img.shields.io/badge/Azure-Blob%20Storage-0078D4.svg?style=flat&logo=microsoftazure&logoColor=white)](https://azure.microsoft.com/en-us/services/storage/blobs/)
[![Azure Key Vault](https://img.shields.io/badge/Azure-Key%20Vault-0078D4.svg?style=flat&logo=microsoftazure&logoColor=white)](https://azure.microsoft.com/en-us/services/key-vault/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg?style=flat&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![DevSecOps](https://img.shields.io/badge/DevSecOps-Bandit%20%7C%20Semgrep%20%7C%20Safety-critical.svg)](https://github.com)

**SecureShare** is a cloud-based document sharing platform built for enterprise and academic environments requiring fine-grained access control, zero-trust cloud secret management, cryptographic file integrity, and proactive malware defense.

---

## 1. System Architecture

```mermaid
flowchart TD
    Client["Web Client / SPA / Mobile"] -->|HTTPS + JWT Bearer| Ingress["FastAPI Application Gateway"]
    
    subgraph Security_Middleware["Security & Defense Layer"]
        Ingress --> RL["Rate Limiting Middleware\n(IP Sliding Window)"]
        RL --> SecHeaders["OWASP Security Headers\n(CSP, HSTS, X-Frame-Options)"]
        SecHeaders --> ReqLogger["Audit & Access Logger\n(X-Request-ID Correlation)"]
        ReqLogger --> JWTAuth["JWT Verification & Context"]
    end

    subgraph Core_Services["Validation & Threat Defense"]
        JWTAuth --> ValSvc["Multi-Layer File Validator\n- Filename Sanitization\n- Ext Whitelist: PDF, PNG, JPG, DOCX\n- Magic Bytes MIME Inspection\n- 25MB Hard Threshold"]
        ValSvc --> VirusScan["Malware & Heuristic Scanner\n(ClamAV + EICAR Signature Check)"]
        VirusScan --> HashEngine["SHA-256 Cryptographic Hasher"]
    end

    subgraph Storage_Cloud["Cloud & Database Layer"]
        HashEngine -->|Private Container / UUID Keys| AzureBlob[("Azure Blob Storage\n'secure-files' Container")]
        HashEngine -->|Parameterized ORM Queries| Postgres[("PostgreSQL Database\n(Users, Files, AuditLogs)")]
        AzureKeyVault[("Azure Key Vault\n(Connection Strings, Keys, DB Passwords)")] -.->|Dynamic Secret Hydration| Ingress
    end
```

---

## 2. Security Capabilities & Best Practices

| Security Feature | Implementation Strategy | Threat Mitigated |
| :--- | :--- | :--- |
| **Zero-Hardcoded Secrets** | Azure Key Vault (`azure-identity`, `azure-keyvault-secrets`) with `.env` fallback | Credential leak in version control |
| **Private Cloud Storage** | Azure Blob Storage private container (`secure-files`) with short-lived (15 min) SAS URLs | Anonymous unauthorized file enumeration |
| **UUID Filename Masking** | Unpredictable UUID v4 generation (`7c12d5ab-xxxx.pdf`), storing original name in metadata | Path traversal & predictable object enumeration |
| **MIME Spoofing Defense** | Deep Magic Byte analysis (`%PDF-`, `\x89PNG`, `\xFF\xD8\xFF`, OpenXML zip header) | Executable payload disguised as image/PDF |
| **Size Enforcement** | Hard 25MB threshold enforced during streaming read | Resource exhaustion / Denial of Service |
| **Password Security** | Bcrypt work factor (12 rounds) with strict complexity validation | Credential stuffing & rainbow table attacks |
| **JWT Session Isolation** | Dual token scheme (Short-lived Access + Refresh) with `jti` replay tracking | Session hijacking |
| **Object-Level Control (IDOR)** | Strict user ownership verification before metadata retrieval, download, or deletion | Insecure Direct Object References (BOLA/IDOR) |
| **Tamper Resistance** | SHA-256 fingerprinting stored in DB and verified during audit | Data alteration / silent corruption |
| **Malware Prevention** | Real-time ClamAV daemon socket scan & EICAR test signature rejection | Malware and ransomware distribution |
| **SQL Injection Defense** | Strictly parameterized queries via SQLAlchemy 2.0 ORM expressions | SQL injection (SQLi) |
| **Tamper-Evident Auditing** | Dedicated `AuditLogs` table recording registration, auth success/failure, uploads, and deletions | Forensic investigation & accountability |

---

## 3. Project Directory Structure

```
SecureShare/
├── app/
│   ├── api/
│   │   ├── auth.py              # User registration, login, token refresh
│   │   ├── upload.py            # POST /upload endpoint with full security pipeline
│   │   ├── files.py             # File metadata, SAS URL generation, deletion, stream
│   │   └── users.py             # User profile and audit log querying
│   ├── core/
│   │   ├── config.py            # Pydantic Settings loaded from .env & Azure Key Vault
│   │   ├── security.py          # Bcrypt password hashing & JWT token generation
│   │   ├── keyvault.py          # Azure Key Vault client with automatic fallback
│   │   └── exceptions.py        # Custom exception handlers (400, 401, 403, 404, 409, 413, 422, 500)
│   ├── db/
│   │   ├── database.py          # SQLAlchemy engine, connection pooling, get_db dependency
│   │   ├── models.py            # Declarative models (Users, Files, AuditLogs)
│   │   └── crud.py              # Parameterized database operations
│   ├── services/
│   │   ├── blob_service.py      # Azure Blob Storage SDK client, SAS tokens, metadata
│   │   ├── encryption.py        # SHA-256 calculation & AES-256-GCM utilities
│   │   ├── validation.py        # Filename sanitization, MIME & Magic Byte verification
│   │   └── virus_scan.py        # Antivirus scanning (ClamAV & heuristic signatures)
│   ├── middleware/
│   │   ├── auth.py              # JWT authentication middleware & dependency
│   │   ├── logging.py           # Request access logging & OWASP secure headers
│   │   └── rate_limit.py        # IP-based sliding window rate limiter
│   ├── schemas/
│   │   └── __init__.py          # Pydantic v2 request & response schemas
│   ├── utils/
│   │   ├── logger.py            # Enterprise structured logging setup
│   │   └── helpers.py           # Helper utilities
│   └── main.py                  # FastAPI application entrypoint & lifespan
│
├── alembic/                     # Database migrations
│   ├── versions/
│   │   └── 0001_initial_schema.py
│   └── env.py
├── tests/                       # Automated test suite
│   ├── conftest.py              # Test client, database fixtures, and auth helpers
│   ├── test_api.py              # Comprehensive integration tests
│   └── test_security.py         # Security tests (crypto, IDOR, MIME spoofing)
│
├── .github/workflows/
│   └── devsecops.yml            # CI/CD Pipeline (SAST, SCA, Pytest)
├── Dockerfile                   # Hardened multi-stage non-root container
├── docker-compose.yml           # Complete stack (FastAPI, Postgres, Azurite, ClamAV)
├── bandit.yaml                  # Bandit SAST security configuration
├── .semgrep.yml                 # Semgrep security rules
├── .safety-policy.yml           # Dependency vulnerability scanning policy
├── alembic.ini                  # Alembic configuration
├── .env.example                 # Environment configuration template
├── .env                         # Active configuration
├── requirements.txt             # Locked project dependencies
└── README.md                    # Documentation
```

---

## 4. Getting Started

### Prerequisites
- Python 3.12+ (or 3.11+)
- Docker & Docker Compose (optional for containerized orchestration)
- Azure Subscription (optional; local emulation supported via Azurite)

### Local Quickstart

1. **Clone the repository and install dependencies:**
   ```bash
   git clone https://github.com/Godsbleedop/SecureShare.git
   cd SecureShare
   pip install -r requirements.txt
   ```

2. **Configure Environment:**
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

3. **Run Database Migrations (PostgreSQL):**
   ```bash
   alembic upgrade head
   ```

4. **Launch Application:**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

5. **Access Interactive Documentation:**
   - Swagger UI: `http://localhost:8000/docs`
   - ReDoc: `http://localhost:8000/redoc`

---

## 5. Docker Compose Environment

Run the full production stack including PostgreSQL, Azure Blob Storage Emulator (Azurite), and ClamAV Antivirus Daemon with a single command:

```bash
docker compose up --build -d
```

Services exposed:
- **FastAPI Backend**: `http://localhost:8000`
- **PostgreSQL Database**: `localhost:5432`
- **Azurite Storage Emulator**: `localhost:10000`
- **ClamAV Antivirus Daemon**: `localhost:3310`

---

## 6. Azure Cloud Configuration

### Azure Key Vault Setup
To enable zero-trust cloud secret retrieval:
1. Create Azure Key Vault in Azure Portal: `az keyvault create --name secureshare-kv --resource-group secureshare-rg`
2. Add secrets:
   ```bash
   az keyvault secret set --vault-name secureshare-kv --name "storage-connection-string" --value "<AZURE_STORAGE_CONNECTION_STRING>"
   az keyvault secret set --vault-name secureshare-kv --name "jwt-secret" --value "<64_CHAR_RANDOM_SECRET>"
   az keyvault secret set --vault-name secureshare-kv --name "database-password" --value "<SECURE_DB_PASSWORD>"
   ```
3. In `.env`, set:
   ```env
   AZURE_KEYVAULT_ENABLED=true
   AZURE_KEYVAULT_URL=https://secureshare-kv.vault.azure.net/
   ```

### Azure Blob Storage Setup
1. Create Storage Account: `az storage account create --name securesharestorage --resource-group secureshare-rg`
2. Create Private Container:
   ```bash
   az storage container create --account-name securesharestorage --name secure-files --public-access off
   ```

---

## 7. DevSecOps & Security Verification

Run automated security scanners locally:

- **Bandit (SAST Python AST Scan):**
  ```bash
  bandit -c bandit.yaml -r app/ -ll -v
  ```

- **Semgrep (Rule-based Code Security Analysis):**
  ```bash
  semgrep scan --config=.semgrep.yml app/
  ```

- **Safety (Dependency Vulnerability Scan):**
  ```bash
  safety check -r requirements.txt
  ```

- **Automated Test Suite:**
  ```bash
  pytest -v
  ```
