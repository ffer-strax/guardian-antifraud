import gzip

import pytest

from services import geo_lookup
from services.geo_lookup import load_country_db, timezone_matches_country

# CSV minúsculo con el mismo formato que DB-IP: sin encabezado y sin comillas.
SAMPLE_CSV = """\
0.0.0.0,0.255.255.255,ZZ
1.0.1.0,1.0.3.255,CN
5.0.0.0,5.0.0.255,ZZ
8.8.8.0,8.8.8.255,US
2001:db8::,2001:db8::ffff,JP
"""

SAMPLE_TIMEZONES = """\
# mapa de prueba
ES  Europe/Madrid
ES  Atlantic/Canary
ES  Africa/Ceuta
MX  America/Mexico_City
"""


@pytest.fixture(params=["plano", "gzip"])
def sample_db(request, tmp_path):
    # Cada test que usa esta fixture corre dos veces: con texto plano y con .gz.
    if request.param == "gzip":
        path = tmp_path / "dbip.csv.gz"
        with gzip.open(path, "wt", encoding="utf-8") as file:
            file.write(SAMPLE_CSV)
    else:
        path = tmp_path / "dbip.csv"
        path.write_text(SAMPLE_CSV, encoding="utf-8")
    return load_country_db(path)


@pytest.fixture
def sample_timezones(monkeypatch, tmp_path):
    path = tmp_path / "country_timezones.txt"
    path.write_text(SAMPLE_TIMEZONES, encoding="utf-8")
    monkeypatch.setattr(geo_lookup, "_COUNTRY_TIMEZONES_PATH", path)
    monkeypatch.setattr(geo_lookup, "_country_timezones", None)


def test_ip_inside_range(sample_db):
    assert sample_db.lookup("1.0.2.10") == "CN"


def test_ip_at_range_start(sample_db):
    assert sample_db.lookup("1.0.1.0") == "CN"


def test_ip_at_range_end(sample_db):
    assert sample_db.lookup("1.0.3.255") == "CN"


def test_ip_just_outside_range_returns_none(sample_db):
    assert sample_db.lookup("1.0.4.0") is None
    assert sample_db.lookup("1.0.0.255") is None


def test_zz_row_returns_none(sample_db):
    assert sample_db.lookup("5.0.0.10") is None


def test_ipv6_row_ignored(sample_db):
    # Solo quedan CN y US: las filas ZZ no se guardan y la IPv6 se ignora.
    assert len(sample_db) == 2
    assert sample_db.lookup("2001:db8::1") is None


@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1"])
def test_private_loopback_and_link_local_return_none(sample_db, ip):
    assert sample_db.lookup(ip) is None


@pytest.mark.parametrize("ip", ["no-es-ip", "", "999.1.1.1", None])
def test_invalid_ip_returns_none(sample_db, ip):
    assert sample_db.lookup(ip) is None


def test_missing_file_gives_empty_db(tmp_path):
    db = load_country_db(tmp_path / "no_existe.csv.gz")
    assert len(db) == 0
    assert db.lookup("8.8.8.8") is None


def test_timezone_of_country_matches(sample_timezones):
    assert timezone_matches_country("ES", "Atlantic/Canary") is True


def test_timezone_of_other_country_does_not_match(sample_timezones):
    assert timezone_matches_country("ES", "America/Mexico_City") is False


def test_unknown_country_gives_none(sample_timezones):
    assert timezone_matches_country("FR", "Europe/Paris") is None


@pytest.mark.parametrize("country, timezone", [("ES", None), (None, "Europe/Madrid"), ("ES", "")])
def test_missing_data_gives_none(sample_timezones, country, timezone):
    assert timezone_matches_country(country, timezone) is None


def test_missing_timezones_file_gives_none(monkeypatch, tmp_path):
    monkeypatch.setattr(geo_lookup, "_COUNTRY_TIMEZONES_PATH", tmp_path / "no_existe.txt")
    monkeypatch.setattr(geo_lookup, "_country_timezones", None)
    assert timezone_matches_country("ES", "Europe/Madrid") is None


def test_real_country_timezones_file(monkeypatch):
    # Usa el archivo versionado de verdad (es pequeño), forzando a releerlo.
    monkeypatch.setattr(geo_lookup, "_country_timezones", None)
    assert timezone_matches_country("ES", "Atlantic/Canary") is True
    assert timezone_matches_country("ES", "Europe/Madrid") is True


def test_real_file_accepts_old_names_only_for_their_country(monkeypatch):
    monkeypatch.setattr(geo_lookup, "_country_timezones", None)
    assert timezone_matches_country("IN", "Asia/Calcutta") is True
    assert timezone_matches_country("UA", "Europe/Kiev") is True
    assert timezone_matches_country("ES", "Asia/Calcutta") is False


def test_real_file_no_country_timezones_give_none(monkeypatch):
    monkeypatch.setattr(geo_lookup, "_country_timezones", None)
    assert timezone_matches_country("DE", "Europe/Berlin") is True
    assert timezone_matches_country("DE", "CET") is None
    assert timezone_matches_country("MX", "UTC") is None
    assert timezone_matches_country("MX", "Etc/UTC") is None
    assert timezone_matches_country("ES", "Asia/Calcutta") is False
