"""
Contract tests for multi-tenant auth and database-backed alert storage.
"""
import json
import os
import hashlib

os.environ["DATABASE_URL"] = "sqlite:///:memory:"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from web_app import app
from core.database import SessionLocal, Tenant, AlertRecord, init_db, User


def simple_hash(password: str) -> str:
    """Simple hash for tests to avoid bcrypt/passlib compatibility issues."""
    return hashlib.sha256(password.encode()).hexdigest()


@pytest.fixture(autouse=True)
def setup_db():
    """Initialize fresh file-based SQLite DB for each test."""
    import os as _os
    test_db = "/tmp/test_5g_analyzer.db"
    if _os.path.exists(test_db):
        _os.remove(test_db)
    _os.environ["DATABASE_URL"] = f"sqlite:///{test_db}"
    init_db()
    yield
    # Cleanup handled by in-memory DB


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def tenant_client(client):
    """Create a tenant and return client with API key header."""
    response = client.post("/api/auth/register", json={
        "name": "Test Telco",
        "email": "admin@testtelco.com",
        "plan": "starter"
    })
    assert response.status_code == 200
    data = response.json()
    api_key = data["api_key"]
    tenant_id = data["tenant_id"]
    
    class AuthenticatedClient:
        def __init__(self, api_key, tenant_id):
            self.api_key = api_key
            self.tenant_id = tenant_id
        
        def request(self, method, url, **kwargs):
            headers = kwargs.pop("headers", {})
            headers["X-API-Key"] = self.api_key
            from fastapi.testclient import TestClient
            return TestClient(app).request(method, url, headers=headers, **kwargs)
        
        def get(self, url, **kwargs):
            return self.request("GET", url, **kwargs)
        
        def post(self, url, **kwargs):
            return self.request("POST", url, **kwargs)
    
    return AuthenticatedClient(api_key, tenant_id)


class TestTenantRegistration:
    """Test tenant creation and API key issuance."""

    def test_register_creates_tenant(self, client):
        """POST /api/auth/register should create a new tenant."""
        response = client.post("/api/auth/register", json={
            "name": "Telco MX",
            "email": "contact@telcomx.com",
            "plan": "starter"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Telco MX"
        assert data["plan"] == "starter"
        assert "api_key" in data
        assert data["api_key"].startswith("5ga_")
        assert "tenant_id" in data

    def test_register_requires_name_and_email(self, client):
        """Missing fields should return 400."""
        response = client.post("/api/auth/register", json={"name": "Test"})
        assert response.status_code == 400

    def test_register_duplicate_slug_gets_unique_suffix(self, client):
        """Duplicate names should auto-resolve with unique slug."""
        client.post("/api/auth/register", json={"name": "Same Name", "email": "a@test.com"})
        response = client.post("/api/auth/register", json={"name": "Same Name", "email": "b@test.com"})
        assert response.status_code == 200
        assert response.json()["tenant_id"] != ""


class TestBearerTokenAuth:
    """Test JWT login flow."""

    def test_login_returns_token(self, client):
        """POST /api/auth/login should return JWT for valid credentials."""
        db = SessionLocal()
        tenant = Tenant(
            id=f"tenant-login-test-{id(self)}",
            name="Login Test Co",
            slug=f"login-test-{id(self)}",
            plan="starter",
            api_key=f"dummy-{id(self)}",
        )
        db.add(tenant)
        db.commit()
        
        user = User(
            id=f"user-login-test-{id(self)}",
            tenant_id=tenant.id,
            email="login@test.com",
            hashed_password=simple_hash("password123"),
        )
        db.add(user)
        db.commit()
        db.close()
        
        response = client.post("/api/auth/login", json={
            "email": "login@test.com",
            "password": "password123"
        })
        if response.status_code != 200:
            print("LOGIN FAIL:", response.status_code, response.text)
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_rejects_bad_password(self, client):
        """Invalid password should return 401."""
        db = SessionLocal()
        tenant = Tenant(
            id=f"tenant-login-fail-{id(self)}",
            name="Login Fail",
            slug=f"login-fail-{id(self)}",
            plan="starter",
            api_key=f"dummy-{id(self)}",
        )
        db.add(tenant)
        db.commit()
        
        user = User(
            id=f"user-login-fail-{id(self)}",
            tenant_id=tenant.id,
            email="fail@test.com",
            hashed_password=simple_hash("correct"),
        )
        db.add(user)
        db.commit()
        db.close()
        
        response = client.post("/api/auth/login", json={
            "email": "fail@test.com",
            "password": "wrong"
        })
        assert response.status_code == 401


class TestTenantIsolation:
    """Test that tenants cannot see each other's data."""

    def test_tenant_info_requires_auth(self, client):
        """GET /api/tenant/me should require authentication."""
        response = client.get("/api/tenant/me")
        assert response.status_code == 401

    def test_tenant_info_returns_correct_tenant(self, client):
        """Authenticated request should return current tenant info."""
        db = SessionLocal()
        tenant = Tenant(
            id=f"tenant-info-{id(self)}",
            name="Info Test Co",
            slug=f"info-test-{id(self)}",
            plan="starter",
            api_key=f"dummy-{id(self)}",
        )
        user = User(
            id=f"user-info-{id(self)}",
            tenant_id=tenant.id,
            email="info@test.com",
            hashed_password=simple_hash("password123"),
        )
        db.add(tenant)
        db.add(user)
        db.commit()
        db.close()

        login = client.post("/api/auth/login", json={
            "email": "info@test.com",
            "password": "password123"
        })
        assert login.status_code == 200
        token = login.json()["access_token"]

        response = client.get("/api/tenant/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Info Test Co"
