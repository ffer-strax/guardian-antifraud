import logging
from ipaddress import IPv4Address

import psycopg
import pytest
from fastapi.testclient import TestClient

from app import main
from services import asn_lookup, audit_log, geo_lookup
from services.asn_lookup import AsnDatabase
from services.geo_lookup import GeoDatabase

# Se guarda antes de que el fixture fake_audit de conftest lo reemplace.
REAL_WRITE_AUDIT = audit_log.write_audit

client = TestClient(main.app)

HOSTING_IP = "3.5.0.10"


def _int(ip: str) -> int:
    return int(IPv4Address(ip))


@pytest.fixture
def hosting_setup(monkeypatch):
    # IP de hosting en US; "Europe/Madrid" no es de US, así que suma hosting + mismatch = 35.
    monkeypatch.setattr(main, "asn_db", AsnDatabase({16: {_int("3.5.0.0"): 64512}}))
    monkeypatch.setattr(main, "geo_db", GeoDatabase([_int("3.5.0.0")], [_int("3.5.255.255")], ["US"]))
    monkeypatch.setattr(asn_lookup, "_hosting_asns", frozenset({64512}))
    monkeypatch.setattr(geo_lookup, "_country_timezones", {"US": frozenset({"America/New_York"})})
    monkeypatch.setenv("DEBUG_CLIENT_IP_HEADER", "true")


def _register(email="maria.perez@example.com", timezone=None, ip=None):
    body = {"email": email}
    if timezone is not None:
        body["timezone"] = timezone
    headers = {main.DEBUG_IP_HEADER: ip} if ip else {}
    return client.post("/register", json=body, headers=headers)


def test_engine_decision_is_audited(fake_audit, hosting_setup):
    response = _register(timezone="Europe/Madrid", ip=HOSTING_IP)
    assert response.json()["status"] == "verification_required"

    assert len(fake_audit) == 1
    record = fake_audit[0]
    assert record["score"] == 35
    assert record["action"] == "step_up"
    assert record["reasons"] == ["hosting_ip", "tz_country_mismatch"]
    assert record["unverified"] == []
    assert record["ip"] == HOSTING_IP
    assert (record["asn"], record["country"], record["timezone"]) == (64512, "US", "Europe/Madrid")


def test_simulated_ip_is_marked_in_signals(fake_audit, hosting_setup):
    response = _register(timezone="Europe/Madrid", ip=HOSTING_IP)
    assert fake_audit[0]["signals"]["ip_simulated"] is True
    assert fake_audit[0]["signals"]["asn"] == 64512
    # La marca es solo del audit: la respuesta de debug no cambia.
    assert "ip_simulated" not in response.json()["debug_signals"]


def test_simulated_ip_is_marked_in_rejections(fake_audit, hosting_setup):
    _register(email="alguien@mailinator.com", ip=HOSTING_IP)
    assert fake_audit[0]["signals"] == {"ip_simulated": True}


def test_real_ip_has_no_simulated_mark(fake_audit, hosting_setup):
    # Modo debug activo pero sin header (o con uno inválido): la IP es la real.
    _register(timezone="Europe/Madrid")
    _register(email="otro@example.com", ip="no-es-ip")
    _register(email="alguien@mailinator.com")
    assert "ip_simulated" not in fake_audit[0]["signals"]
    assert "ip_simulated" not in fake_audit[1]["signals"]
    assert fake_audit[2]["signals"] is None


def test_allow_is_audited(fake_audit):
    assert _register().json() == {"status": "ok"}
    assert fake_audit[0]["action"] == "allow"
    assert fake_audit[0]["score"] == 0


def test_plain_email_never_in_record(fake_audit):
    _register(email="Maria.Perez@Example.com")
    text = str(fake_audit[0]).lower()
    assert "maria" not in text
    assert "perez" not in text
    assert "example.com" not in text
    assert len(fake_audit[0]["email_hmac"]) == 64


def test_same_canonical_email_gives_same_hmac(fake_audit):
    # Las dos variantes tienen el mismo correo canónico: juanlopez@gmail.com.
    _register(email="juan.lopez+1@gmail.com")
    _register(email="JuanLopez@googlemail.com")
    assert fake_audit[0]["email_hmac"] == fake_audit[1]["email_hmac"]
    assert fake_audit[0]["email_hmac"] == audit_log.email_hmac("juanlopez@gmail.com")


def test_different_key_gives_different_hmac(monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEY", "clave-uno")
    first = audit_log.email_hmac("juanlopez@gmail.com")
    monkeypatch.setenv("AUDIT_HMAC_KEY", "clave-dos")
    assert audit_log.email_hmac("juanlopez@gmail.com") != first


def test_empty_key_uses_dev_key(monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEY", "  ")
    assert audit_log.uses_dev_hmac_key() is True
    monkeypatch.setenv("AUDIT_HMAC_KEY", "clave-real")
    assert audit_log.uses_dev_hmac_key() is False


def test_disposable_rejection_is_audited(fake_audit):
    response = _register(email="alguien@mailinator.com")
    assert response.status_code == 400
    assert response.json() == {"detail": "disposable_domain"}
    record = fake_audit[0]
    assert record["action"] == "rejected"
    assert record["reasons"] == ["disposable_domain"]
    assert record["score"] is None
    assert record["signals"] is None


def test_no_mx_rejection_is_audited(fake_audit, monkeypatch):
    monkeypatch.setattr(main, "check_mx", lambda client, domain, timeout: "no_mail")
    response = _register()
    assert response.status_code == 400
    assert response.json() == {"detail": "domain_cannot_receive_mail"}
    assert fake_audit[0]["action"] == "rejected"
    assert fake_audit[0]["reasons"] == ["domain_cannot_receive_mail"]


def test_rate_limited_request_is_not_audited(fake_audit, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_IP_MAX", "1")
    assert _register(email="a@example.com").status_code == 200
    assert _register(email="b@example.com").status_code == 429
    assert len(fake_audit) == 1


def test_invalid_payload_is_not_audited(fake_audit):
    assert client.post("/register", json={"email": "no-es-correo"}).status_code == 422
    assert fake_audit == []


def test_write_failure_keeps_200_and_logs_no_personal_data(monkeypatch, caplog, hosting_setup):
    # Escritor real con una conexión que falla y trae datos personales en el mensaje:
    # si el log copiara el mensaje de la excepción, aparecerían en caplog.
    def broken_connect(**kwargs):
        raise psycopg.OperationalError(f"fallo para maria.perez@example.com desde {HOSTING_IP}")

    monkeypatch.setattr(audit_log, "write_audit", REAL_WRITE_AUDIT)
    monkeypatch.setattr(audit_log.psycopg, "connect", broken_connect)

    with caplog.at_level(logging.WARNING):
        response = _register(ip=HOSTING_IP)

    assert response.status_code == 200
    assert "No se pudo escribir en audit_log: OperationalError" in caplog.text
    assert "maria.perez" not in caplog.text
    assert HOSTING_IP not in caplog.text
    assert "testclient" not in caplog.text


class FakeConnection:
    """Imita solo lo que usa audit_log: "with psycopg.connect(...) as conn" y conn.execute."""

    def __init__(self, executed):
        self.executed = executed

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        self.executed.append(sql.split()[0])


def test_table_created_on_first_write_if_postgres_was_down(monkeypatch):
    def down(**kwargs):
        raise psycopg.OperationalError("connection refused")

    monkeypatch.setattr(audit_log, "_table_ready", False)
    monkeypatch.setattr(audit_log.psycopg, "connect", down)
    assert audit_log.ensure_table() is False

    executed = []
    monkeypatch.setattr(audit_log.psycopg, "connect", lambda **kwargs: FakeConnection(executed))
    record = {"email_hmac": "x" * 64, "ip": "testclient", "action": "allow", "reasons": []}
    REAL_WRITE_AUDIT(record)
    REAL_WRITE_AUDIT(record)
    # Primera escritura: CREATE + INSERT. Segunda: solo INSERT.
    assert executed == ["CREATE", "INSERT", "INSERT"]
