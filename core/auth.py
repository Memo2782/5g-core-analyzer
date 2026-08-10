"""
Multi-tenant authentication and authorization.
Supports API keys (for service/agent auth) and JWT (for UI users).
"""
import hashlib
import hmac
import os
import time
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import secrets

from core.database import get_db, Tenant, User, PlanType

# Settings
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
API_KEY_PREFIX = "5ga_"

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_scheme = APIKeyHeader(auto_error=False, name="X-API-Key")


class TenantContext:
    """Current request tenant extracted from auth."""
    def __init__(self, tenant_id: str, api_key: str, plan: PlanType):
        self.tenant_id = tenant_id
        self.api_key = api_key
        self.plan = plan


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not hashed_password:
        return False
    if hashed_password.startswith("$2b$") or hashed_password.startswith("$2a$"):
        return pwd_context.verify(plain_password, hashed_password)
    expected = hashlib.sha256(plain_password.encode()).hexdigest()
    return hmac.compare_digest(expected, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def generate_api_key() -> str:
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def _resolve_tenant_by_api_key(db: Session, raw_key: str) -> Optional[Tenant]:
    key_hash = hash_api_key(raw_key)
    return db.query(Tenant).filter(Tenant.api_key == key_hash, Tenant.active == True).first()


def _resolve_tenant_from_token(db: Session, payload: dict) -> Optional[Tenant]:
    tenant_id = payload.get("tenant_id")
    if not tenant_id:
        return None
    return db.query(Tenant).filter(Tenant.id == tenant_id, Tenant.active == True).first()


def get_tenant_from_api_key(
    credentials: Optional[str] = Depends(api_key_scheme),
    db: Session = Depends(get_db),
) -> Optional[TenantContext]:
    if not credentials:
        return None
    tenant = _resolve_tenant_by_api_key(db, credentials)
    if not tenant:
        return None
    return TenantContext(
        tenant_id=tenant.id,
        api_key=credentials,
        plan=tenant.plan,
    )


def get_tenant_from_bearer(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> TenantContext:
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_access_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    tenant = _resolve_tenant_from_token(db, payload)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tenant not found or inactive",
        )
    return TenantContext(
        tenant_id=tenant.id,
        api_key="",
        plan=tenant.plan,
    )


def get_current_tenant(
    api_ctx: Optional[TenantContext] = Depends(get_tenant_from_api_key),
    bearer_ctx: Optional[TenantContext] = Depends(get_tenant_from_bearer),
) -> TenantContext:
    """Accept either API key or bearer token."""
    ctx = api_ctx or bearer_ctx
    if not ctx:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return ctx
