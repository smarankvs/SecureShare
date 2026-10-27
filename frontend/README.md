# SecureShare Frontend & Identity Integration

**Member 1: Frontend & Identity Integration (Sneha Nayak)**

Production-grade React + TypeScript single-page application (SPA) featuring Microsoft Entra ID (Azure AD) enterprise authentication, zero-trust token transmission, AES/SAS secure document download handling, and client-side threat defense validation.

---

## 1. System Requirements & Architecture

- **Node.js**: `v18.0.0` or higher (Node 20+ recommended)
- **Package Manager**: `npm`
- **Build Tool**: Vite + TypeScript (ES2023)
- **Identity Provider**: Microsoft Entra ID (OIDC / OAuth 2.0 PKCE via MSAL Browser v5 & MSAL React v5)
- **HTTP Client**: Axios with automated bearer token interception and error normalization
- **Styling**: Modern Vanilla CSS Design System with dark glassmorphism, responsive tables, and accessible modal overlays

---

## 2. Directory Structure

```text
frontend/src/
├── api/
│   └── apiClient.ts            # Axios instance, silent MSAL token interceptor, typed endpoints
├── auth/
│   ├── authConfig.ts           # Entra ID client, tenant, authority & scope configuration
│   ├── msalInstance.ts         # Singleton PublicClientApplication & active account sync
│   └── AuthProvider.tsx        # React Context & hook (useAuth) wrapping MsalProvider
├── components/
│   ├── FileTable.tsx           # Document table with scan status badges and action triggers
│   ├── Icons.tsx               # Lightweight, accessible SVG icon components
│   ├── Navbar.tsx              # Application header, Entra ID badge, and logout controls
│   ├── ProtectedRoute.tsx      # Route guard preserving return URLs
│   ├── ShareModal.tsx          # Recipient-bound share creation dialog (POST /api/v1/shares)
│   └── UploadModal.tsx         # Drag & drop upload dialog with client-side security checks
├── pages/
│   ├── DashboardPage.tsx       # Authenticated file management center & metrics
│   ├── LoginPage.tsx           # Microsoft Entra ID sign-in portal & security architecture
│   └── SharedFilePage.tsx      # Token-preserving recipient download view (/share/:token)
├── types/
│   └── index.ts                # TypeScript interfaces matching backend models
├── App.css                     # Component layouts, modals, tables, and responsive styling
├── App.tsx                     # Application router and provider hierarchy
├── index.css                   # Global tokens, typography, badges, and button styles
└── main.tsx                    # React DOM root entrypoint
```

---

## 3. Microsoft Entra ID App Registration Setup

To authenticate users via Microsoft Entra ID, configure two App Registrations in the Azure Portal:

### 3.1 Backend API App Registration
1. In Azure Portal, navigate to **Microsoft Entra ID** > **App registrations** > **New registration**.
2. Name: `secureshare-backend-api`.
3. Supported account types: **Accounts in this organizational directory only** (Single tenant) or **Multitenant**.
4. Under **Expose an API**:
   - Set **Application ID URI**: `api://<backend-client-id>` (or default).
   - Add a scope:
     - Scope name: `access_as_user`
     - Who can consent: Admins and users
     - Admin consent display name: `Access SecureShare API`
     - Admin consent description: `Allows the app to access SecureShare on behalf of the signed-in user.`

### 3.2 Frontend SPA App Registration
1. In Azure Portal, navigate to **Microsoft Entra ID** > **App registrations** > **New registration**.
2. Name: `secureshare-frontend-spa`.
3. Supported account types: Matching your tenant structure.
4. Under **Redirect URI**:
   - Platform: **Single-page application (SPA)** *(Important: Do NOT choose Web)*
   - Redirect URI: `http://localhost:5173`
5. Under **API permissions**:
   - Click **Add a permission** > **My APIs** > select `secureshare-backend-api`.
   - Select Delegated permissions: `access_as_user`.
   - Click **Grant admin consent** (if required by your tenant policy).

---

## 4. Local Environment Configuration

Copy the example configuration file:

```bash
cd frontend
cp .env.example .env
```

Configure the environment variables in `frontend/.env`:

```env
# Microsoft Entra ID SPA App Registration
VITE_ENTRA_CLIENT_ID=<FRONTEND_SPA_CLIENT_ID>
VITE_ENTRA_TENANT_ID=<AZURE_TENANT_ID>
VITE_ENTRA_REDIRECT_URI=http://localhost:5173
VITE_ENTRA_POST_LOGOUT_REDIRECT_URI=http://localhost:5173/login

# Backend Scope (from Expose an API)
VITE_ENTRA_API_SCOPE=api://<BACKEND_CLIENT_ID>/access_as_user

# SecureShare Backend REST API Base URL
VITE_API_BASE_URL=http://localhost:8000
```

---

## 5. Development & Running

### Install Dependencies
```bash
cd frontend
npm install
```

### Start Development Server
```bash
npm run dev
```
The application will be live at `http://localhost:5173`.

### Production Build & Type Check
```bash
npm run build
```

### Run Linter
```bash
npm run lint
```

---

## 6. How Key Workflows Function

### 6.1 Authentication & Bearer Token Interceptor
- When a user signs in, MSAL initiates an authorization code flow with PKCE against `https://login.microsoftonline.com/<tenant-id>/v2.0`.
- The access token is acquired silently via `msalInstance.acquireTokenSilent()` before every API request to `VITE_API_BASE_URL`.
- The token is attached as `Authorization: Bearer <access_token>`.
- The backend validates the RS256 signature against the tenant JWKS and provisions/links shadow user accounts by immutable `oid`.

### 6.2 Document Upload & Quarantine Inspection
- Upload requests (`POST /api/v1/upload`) are streamed with real-time percentage progress.
- Client-side validation enforces allowed extensions (`.pdf`, `.png`, `.jpg`, `.jpeg`, `.docx`), MIME types, and the strict 25 MB ceiling.
- The backend verifies magic byte signatures and executes ClamAV malware inspection before committing files to private storage.

### 6.3 Document Sharing
- Document owners share files via `POST /api/v1/shares`, setting recipient email, expiration (up to 90 days), and download quota (up to 100).
- The raw 256-bit token is returned exactly once in the response. The backend persists only its SHA-256 digest.
- The user is provided a one-click copyable URL: `http://localhost:5173/share/<token>`.

### 6.4 Recipient View & Gatekeeper Download (`/share/:token`)
- Recipients can open `/share/<token>` directly without prior session state.
- If unauthenticated, the application preserves the URL in `sessionStorage` and prompts the user to sign in with Microsoft Entra ID.
- Upon authentication, the recipient is returned to `/share/<token>`.
- Clicking "Download" submits `{ token }` in the JSON body of `POST /api/v1/shares/download`.
- The backend atomically checks the 4 policy gates (`ACTIVE`, unexpired, quota remaining, recipient email match).
- The returned short-lived Azure SAS URL or streaming download URL is consumed and saved directly to the user's filesystem.

---

## 7. Troubleshooting & Diagnostics

| Symptom | Probable Cause | Resolution |
| :--- | :--- | :--- |
| **`AADSTS50011: The redirect URI specified does not match...`** | The redirect URI in Azure Portal does not match `http://localhost:5173`. | Ensure the App Registration has platform **Single-page application** with URI `http://localhost:5173`. |
| **`401 Unauthorized` on API calls** | Token expired or backend `ENTRA_CLIENT_ID`/`ENTRA_TENANT_ID` mismatch. | Verify backend `.env` matches frontend `VITE_ENTRA_CLIENT_ID` and tenant ID. |
| **`404 Not Found` on `/api/v1/shares/download`** | Share link is invalid, expired, revoked, quota-exhausted, or addressed to another email. | Check backend `audit_logs` table for exact failure reason (`RECIPIENT_MISMATCH`, `EXPIRED`, `EXHAUSTED`). |
| **`413 Payload Too Large`** | File exceeds 25 MB (`26,214,400 bytes`). | Reduce file size below 25 MB. |
| **CORS Errors in browser console** | Backend is not permitting `http://localhost:5173`. | Ensure `CORS_ORIGINS` in backend configuration contains `http://localhost:5173`. |
