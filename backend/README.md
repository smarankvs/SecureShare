# Quick Start Terminal Commands

## 1. Start Backend (Terminal 1)
```bash
# Navigate to project root
cd /Users/smarankv/Documents/GitHub/SecureShare

# Create environment file from example (if not already present)
cp -n .env.example .env

# Activate Python virtual environment
source backend/.venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run FastAPI backend server (http://localhost:8000)
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

## 2. Start Frontend (Terminal 2)
```bash
# Navigate to frontend folder
cd /Users/smarankv/Documents/GitHub/SecureShare/frontend

# Create environment file from example (if not already present)
cp -n .env.example .env

# Install dependencies
npm install

# Run Vite dev server (http://localhost:5173)
npm run dev
```

## 3. Run Both in One Shot (Background)
```bash
# From repository root
backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 &
cd frontend && npm run dev
```

## 4. Run Automated Security & Unit Tests
```bash
# Run all 63 unit, integration & security test suites
backend/.venv/bin/pytest tests/ -v
```

## 5. Push Code to Git (Main Branch)
```bash
# Stage all changes
git add .

# Commit changes
git commit -m "Add project execution commands and update configurations"

# Push to main branch
git push origin main
```
