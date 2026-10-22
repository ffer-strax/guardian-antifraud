from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_register():
    response = client.post("/register", json={"email": "user@example.com"})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_register_disposable_domain_returns_400():
    response = client.post("/register", json={"email": "alguien@mailinator.com"})
    assert response.status_code == 400
    assert response.json() == {"detail": "disposable_domain"}


def test_register_invalid_format_returns_422():
    response = client.post("/register", json={"email": "esto-no-es-un-correo"})
    assert response.status_code == 422


def test_register_uppercase_and_spaces():
    response = client.post("/register", json={"email": "  Alguien@MAILINATOR.COM  "})
    assert response.status_code == 400
    assert response.json() == {"detail": "disposable_domain"}
