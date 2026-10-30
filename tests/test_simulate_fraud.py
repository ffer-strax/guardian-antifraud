import importlib.util
import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.main import Fingerprint
from services.behavior_signals import SIGNAL_NAMES
from services.fingerprint_match import FAMILY_THRESHOLD, flatten, similarity

ROOT = Path(__file__).resolve().parents[1]

# El script vive en scripts/, fuera de los paquetes: se carga desde su ruta.
_spec = importlib.util.spec_from_file_location("simulate_fraud", ROOT / "scripts" / "simulate_fraud.py")
simulate_fraud = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(simulate_fraud)

# ASN de hosting fijos para no depender del contenido de backend/data/hosting_asns.txt.
HOSTING_ASNS = [16509, 24940]

ACCOUNT_FIELDS = ["account_id", "created_at", "ip", "asn", "is_hosting", "country", "fingerprint",
                  "timezone", "behavior_flags", "label", "archetype", "group_id"]


@pytest.fixture(scope="module")
def document():
    return simulate_fraud.generate(simulate_fraud.Config(), HOSTING_ASNS)


def _by_archetype(document, archetype):
    return [a for a in document["accounts"] if a["archetype"] == archetype]


def _time(account):
    return datetime.fromisoformat(account["created_at"])


def _subnet(ip):
    return ip.rsplit(".", 1)[0]


# --- Reproducibilidad ---

def test_same_seed_gives_identical_bytes(tmp_path):
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    simulate_fraud.main(["--seed", "7", "--normal", "50", "--out", str(first)])
    simulate_fraud.main(["--seed", "7", "--normal", "50", "--out", str(second)])
    assert first.read_bytes() == second.read_bytes()


def test_different_seed_gives_different_data():
    config = simulate_fraud.Config(normal=50)
    one = simulate_fraud.to_json(simulate_fraud.generate(config, HOSTING_ASNS))
    other = simulate_fraud.to_json(simulate_fraud.generate(simulate_fraud.Config(seed=8, normal=50), HOSTING_ASNS))
    assert one != other


def test_global_random_is_not_used():
    # Si el script usara el random global, cambiar su estado cambiaría la salida.
    import random
    random.seed(1)
    first = simulate_fraud.to_json(simulate_fraud.generate(simulate_fraud.Config(normal=20), HOSTING_ASNS))
    random.seed(999)
    second = simulate_fraud.to_json(simulate_fraud.generate(simulate_fraud.Config(normal=20), HOSTING_ASNS))
    assert first == second


# --- Cabecera honesta y conteos ---

def test_header_declares_synthetic(document):
    assert document["synthetic"] is True
    assert document["seed"] == simulate_fraud.DEFAULT_SEED
    assert document["generated_with"] == simulate_fraud.VERSION


def test_default_counts_per_archetype(document):
    counts = Counter(a["archetype"] for a in document["accounts"])
    assert counts["normal"] == 400
    assert counts["datacenter_bot"] == 20
    assert counts["residential_proxy_farm"] == 12
    assert counts["device_reuse_farm"] == 6
    assert counts["internet_cafe"] == 12
    assert counts["shared_ip_noise"] == 45
    households = defaultdict(int)
    for account in _by_archetype(document, "shared_household"):
        households[account["group_id"]] += 1
    assert len(households) == 20
    assert all(size in (2, 3) for size in households.values())


def test_cli_parameters_change_counts():
    config, _ = simulate_fraud.parse_args(["--normal", "3", "--datacenter-bots", "4", "--proxy-farm", "5",
                                           "--device-farm", "7", "--households", "1",
                                           "--cafe-accounts", "9", "--shared-ip-users", "31"])
    counts = Counter(a["archetype"] for a in simulate_fraud.generate(config, HOSTING_ASNS)["accounts"])
    assert (counts["normal"], counts["datacenter_bot"], counts["residential_proxy_farm"],
            counts["device_reuse_farm"], counts["internet_cafe"], counts["shared_ip_noise"]) == (3, 4, 5, 7, 9, 31)


def test_summary_lists_archetypes_and_labels(document):
    text = simulate_fraud.summary(document)
    for name in list(simulate_fraud.FRAUD_ARCHETYPES) + list(simulate_fraud.LEGIT_ARCHETYPES) + ["fraud", "legit"]:
        assert name in text


# --- Forma de cada cuenta ---

def test_every_account_has_all_fields(document):
    ids = set()
    for account in document["accounts"]:
        assert list(account) == ACCOUNT_FIELDS
        ids.add(account["account_id"])
        assert ipaddress.ip_address(account["ip"]).version == 4
        assert ipaddress.ip_address(account["ip"]).is_global
        assert isinstance(account["asn"], int)
        assert isinstance(account["is_hosting"], bool)
        assert re.fullmatch(r"[A-Z]{2}", account["country"])
        assert account["created_at"].endswith("Z")
        assert _time(account).utcoffset() == timedelta(0)
        assert account["label"] in ("legit", "fraud")
        assert isinstance(account["timezone"], str)
    assert len(ids) == len(document["accounts"])


def test_behavior_flags_are_the_seven_signals(document):
    assert simulate_fraud.BEHAVIOR_FLAGS == SIGNAL_NAMES
    for account in document["accounts"]:
        assert tuple(account["behavior_flags"]) == SIGNAL_NAMES
        assert all(isinstance(value, bool) for value in account["behavior_flags"].values())


def test_fraud_and_legit_both_exist(document):
    labels = Counter(a["label"] for a in document["accounts"])
    assert labels["fraud"] > 0
    assert labels["legit"] > 0
    for account in document["accounts"]:
        expected = "fraud" if account["archetype"] in simulate_fraud.FRAUD_ARCHETYPES else "legit"
        assert account["label"] == expected


def test_start_date_is_controlled_not_now(document):
    start = datetime.fromisoformat(simulate_fraud.DEFAULT_START)
    end = start + timedelta(days=simulate_fraud.Config().days)
    assert all(start <= _time(a) <= end for a in document["accounts"])


# --- Arquetipos de fraude ---

def test_datacenter_bots(document):
    bots = _by_archetype(document, "datacenter_bot")
    assert len({_subnet(a["ip"]) for a in bots}) == 1
    assert len({a["ip"] for a in bots}) == len(bots)
    assert all(a["is_hosting"] and a["asn"] in HOSTING_ASNS for a in bots)
    assert all(a["behavior_flags"]["form_too_fast"] for a in bots)
    # Huellas distintas, pero con muy pocos valores posibles.
    assert len({a["fingerprint"]["canvasHash"] for a in bots}) == len(bots)
    assert len({a["fingerprint"]["platform"] for a in bots}) == 1
    times = sorted(_time(a) for a in bots)
    assert times[-1] - times[0] <= timedelta(minutes=30)


def test_residential_proxy_farm(document):
    farm = _by_archetype(document, "residential_proxy_farm")
    assert len({_subnet(a["ip"]) for a in farm}) == len(farm)
    assert not any(a["is_hosting"] for a in farm)
    # El mismo dispositivo con variaciones pequeñas: todas en la misma familia que la primera.
    first = flatten(farm[0]["fingerprint"], farm[0]["timezone"])
    assert all(similarity(first, flatten(a["fingerprint"], a["timezone"])) >= FAMILY_THRESHOLD for a in farm)
    assert len({a["fingerprint"]["canvasHash"] for a in farm}) == 2
    times = sorted(_time(a) for a in farm)
    assert times[-1] - times[0] <= timedelta(hours=4)


def test_device_reuse_farm_within_15_minutes(document):
    farm = _by_archetype(document, "device_reuse_farm")
    assert len(farm) == 6
    assert len({a["ip"] for a in farm}) == 1
    assert all(a["fingerprint"] == farm[0]["fingerprint"] for a in farm)
    times = sorted(_time(a) for a in farm)
    assert times[-1] - times[0] <= timedelta(minutes=15)


# --- Arquetipos legítimos ---

def test_normal_users_are_independent(document):
    normal = _by_archetype(document, "normal")
    assert len({a["ip"] for a in normal}) == len(normal)
    assert len({a["fingerprint"]["canvasHash"] for a in normal}) == len(normal)
    assert all(a["group_id"] is None for a in normal)


def test_households_share_device_and_ip_days_apart(document):
    groups = defaultdict(list)
    for account in _by_archetype(document, "shared_household"):
        groups[account["group_id"]].append(account)
    for members in groups.values():
        assert len({a["ip"] for a in members}) == 1
        assert all(a["fingerprint"] == members[0]["fingerprint"] for a in members)
        times = sorted(_time(a) for a in members)
        assert all(later - earlier >= timedelta(days=1) for earlier, later in zip(times, times[1:]))


def test_internet_cafe_is_spread_over_weeks(document):
    cafe = _by_archetype(document, "internet_cafe")
    assert 8 <= len(cafe) <= 15
    assert len({a["ip"] for a in cafe}) == 1
    assert all(a["fingerprint"] == cafe[0]["fingerprint"] for a in cafe)
    times = sorted(_time(a) for a in cafe)
    assert times[-1] - times[0] >= timedelta(weeks=1)


def test_shared_ip_noise_has_distinct_devices(document):
    users = _by_archetype(document, "shared_ip_noise")
    assert 30 <= len(users) <= 60
    assert len({a["ip"] for a in users}) == 1
    assert len({a["fingerprint"]["canvasHash"] for a in users}) == len(users)


# --- Huella igual a la del collector ---

def _object_keys(source: str, function: str, indent: int) -> set:
    body = source.split(f"function {function}(", 1)[1].split("\n}\n", 1)[0]
    returned = body.split("return {", 1)[1]
    return set(re.findall(rf"^ {{{indent}}}(\w+):", returned, flags=re.MULTILINE))


def test_fingerprint_fields_match_collector(document):
    source = (ROOT / "frontend" / "collector.js").read_text(encoding="utf-8")
    collector_keys = _object_keys(source, "collectFingerprint", 4)
    screen_keys = _object_keys(source, "collectFingerprint", 6)
    for account in document["accounts"]:
        assert set(account["fingerprint"]) == collector_keys
        assert set(account["fingerprint"]["screen"]) == screen_keys
        # Y el servidor las aceptaría tal cual.
        Fingerprint.model_validate(account["fingerprint"])
