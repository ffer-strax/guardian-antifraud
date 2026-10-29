import gzip

import pytest

from services import asn_lookup
from services.asn_lookup import get_default_db, is_hosting_asn, load_asn_db

# Base minúscula: un /16 con un /24 más específico dentro, más ruido que debe ignorarse.
SAMPLE_IPASN = """\
; IP-ASN32-DAT file de prueba
; comentario que no debe romper nada

8.8.0.0/16\t100
8.8.8.0/24  200
2001:db8::/32\t300
300.1.2.0/24\t400
"""


@pytest.fixture(params=["plano", "gzip"])
def sample_db(request, tmp_path):
    # Cada test que usa esta fixture corre dos veces: con texto plano y con .gz.
    if request.param == "gzip":
        path = tmp_path / "ipasn.dat.gz"
        with gzip.open(path, "wt", encoding="utf-8") as file:
            file.write(SAMPLE_IPASN)
    else:
        path = tmp_path / "ipasn.dat"
        path.write_text(SAMPLE_IPASN, encoding="utf-8")
    return load_asn_db(path)


def test_longest_prefix_wins(sample_db):
    assert sample_db.lookup("8.8.8.8") == 200
    assert sample_db.lookup("8.8.4.4") == 100


def test_ip_without_asn_returns_none(sample_db):
    assert sample_db.lookup("9.9.9.9") is None


@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1"])
def test_private_loopback_and_link_local_return_none(sample_db, ip):
    assert sample_db.lookup(ip) is None


@pytest.mark.parametrize("ip", ["no-es-ip", "", "999.1.1.1", None])
def test_invalid_ip_returns_none(sample_db, ip):
    assert sample_db.lookup(ip) is None


def test_ipv6_line_ignored(sample_db):
    assert len(sample_db) == 2
    assert sample_db.lookup("2001:db8::1") is None


def test_comments_and_blank_lines_ignored(sample_db):
    # Solo cuentan las dos líneas IPv4; comentarios y vacías no generan entradas.
    assert len(sample_db) == 2


def test_invalid_ipv4_line_skipped_without_losing_the_rest(sample_db):
    # "300.1.2.0/24" no es IPv4 válida: se salta esa línea y las demás se conservan.
    assert len(sample_db) == 2
    assert sample_db.lookup("8.8.8.8") == 200


def test_missing_file_gives_empty_db(tmp_path):
    db = load_asn_db(tmp_path / "no_existe.dat.gz")
    assert len(db) == 0
    assert db.lookup("8.8.8.8") is None


def test_corrupt_gzip_gives_empty_db(tmp_path):
    path = tmp_path / "roto.dat.gz"
    path.write_bytes(b"esto no es gzip")
    assert len(load_asn_db(path)) == 0


def test_default_db_loads_once(monkeypatch, tmp_path):
    # Se apunta a un archivo de prueba: los tests nunca cargan el ipasn real.
    path = tmp_path / "ipasn.dat"
    path.write_text(SAMPLE_IPASN, encoding="utf-8")
    monkeypatch.setattr(asn_lookup, "_DEFAULT_DB_PATH", path)
    monkeypatch.setattr(asn_lookup, "_default_db", None)

    first = get_default_db()
    assert first.lookup("8.8.8.8") == 200
    assert get_default_db() is first


def test_hosting_asn_from_file(monkeypatch, tmp_path):
    path = tmp_path / "hosting.txt"
    path.write_text("# comentario\n64512  ejemplo\n", encoding="utf-8")
    monkeypatch.setattr(asn_lookup, "_HOSTING_ASNS_PATH", path)
    monkeypatch.setattr(asn_lookup, "_hosting_asns", None)

    assert is_hosting_asn(64512) is True
    assert is_hosting_asn(13335) is False
    assert is_hosting_asn(None) is False


def test_hosting_asn_missing_file(monkeypatch, tmp_path):
    monkeypatch.setattr(asn_lookup, "_HOSTING_ASNS_PATH", tmp_path / "no_existe.txt")
    monkeypatch.setattr(asn_lookup, "_hosting_asns", None)

    assert is_hosting_asn(64512) is False
