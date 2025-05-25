# main.py
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from api.jwt_client import JWTClient
import os
from jsonpath_nz import log, jprint

app = FastAPI(title="JWT Authentication Service")

# Initialize JWT client
wasm_path = os.environ.get("WASM_PATH", "/home/ymohammad/rust-wasi-jwt/target/wasm32-wasip1/release/rust_wasi_jwt.wasm")
jwt_client = JWTClient(wasm_path)
log.info(jwt_client)

# Create global JWT context
JWT_SECRET = os.environ.get("JWT_SECRET", "your-256-bit-secret")
JWT_VALIDITY = int(os.environ.get("JWT_VALIDITY", "3600"))
log.info(f"Creating JWT context with secret: {JWT_SECRET} and validity: {JWT_VALIDITY}")
jwt_context_id = jwt_client.create_auth_context(JWT_SECRET, JWT_VALIDITY)
log.info(f"JWT context created with ID: {jwt_context_id}")
# Request/response models
class LoginRequest(BaseModel):
    username: str

class TokenResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    expires_in: int

class ValidationResponse(BaseModel):
    username: str
    valid: bool

# Routes
@app.post("/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """Generate JWT token for user"""
    try:
        token = jwt_client.generate_token(jwt_context_id, request.username)
        return {
            "token": token,
            "token_type": "bearer",
            "expires_in": JWT_VALIDITY
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/validate", response_model=ValidationResponse)
async def validate(token: str):
    """Validate JWT token"""
    try:
        username = jwt_client.validate_token(jwt_context_id, token)
        return {
            "username": username,
            "valid": True
        }
    except Exception as e:
        return {
            "username": "",
            "valid": False
        }

# Health check
@app.get("/health")
async def health():
    return {"status": "healthy"}

# Cleanup on shutdown
@app.on_event("shutdown")
def shutdown_event():
    jwt_client.free_auth_context(jwt_context_id)
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)