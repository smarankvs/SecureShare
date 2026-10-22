# SecureShare Backend Service

FastAPI-powered cybersecurity backend service for SecureShare.

## Structure
The backend application lives inside `app/` and is accessible from both the repository root and this directory:
- Entry point: `app.main:app` (or `python main.py`)
- API endpoints: `/upload`, `/api/v1/auth`, `/api/v1/files`, `/api/v1/users`
- Docs: `http://localhost:8000/docs`

## Run Backend
```bash
# From repository root or backend directory:
pip install -r requirements.txt
uvicorn app.main:app --reload
```
