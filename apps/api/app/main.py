
from fastapi import FastAPI

app = FastAPI(
    title="Injectra API",
    description="AI Security & Prompt Injection Defense Gateway",
    version="0.1.0"
)

@app.get("/api/v1/health")
def health_check():
    return {
        "status": "ok",
        "service": "injectra-api",
        "version": "0.1.0"
    }
