from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr

from services.email_utils import canonicalize_email, is_disposable

app = FastAPI(title="guardian-antifraud")


class RegisterRequest(BaseModel):
    email: EmailStr


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/register")
def register(payload: RegisterRequest) -> dict:
    canonical = canonicalize_email(payload.email)
    domain = canonical.rpartition("@")[2]
    if is_disposable(domain):
        raise HTTPException(status_code=400, detail="disposable_domain")
    return {"status": "ok"}
