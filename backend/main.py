from fastapi import FastAPI

app = FastAPI(
    title="SecureShare API",
    description="Secure Cloud-Based Document Sharing Platform API",
    version="0.1.0"
)

@app.get("/")
def read_root():
    return {
        "message": "Welcome to SecureShare API",
        "status": "online"
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }
