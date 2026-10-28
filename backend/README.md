# Quick Start Terminal Commands

## 1. Start Backend (Terminal 1)
```bash
# Navigate to project root
cd /Users/smarankv/Documents/GitHub/SecureShare

# Create environment file from example (if not already present)
cp -n .env.example .env

# Activate Python virtual environment (created in project root)
source .venv/bin/activate

# Upgrade pip and install backend dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run FastAPI backend server (http://localhost:8000)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## 2. Start Frontend (Terminal 2)
```bash
# Open a new terminal and navigate to frontend folder
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
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 &
cd frontend && npm run dev
```

## 4. Run Automated Security & Unit Tests
```bash
# From repository root with .venv activated:
source .venv/bin/activate
pytest tests/ -v
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
