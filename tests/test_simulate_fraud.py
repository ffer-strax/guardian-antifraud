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


def _groups(document, archetype):
    groups = defaultdict(list)
    for account in _by_archetype(document, archetype):
        groups[account["group_id"]].append(account)
    return groups


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
    # Tamaños por grupo x grupos: 5 granjas de cada fraude, 3 cibercafés y 3 IPs compartidas.
    assert counts["datacenter_bot"] == 5 * 8
    assert counts["residential_proxy_farm"] == 5 * 6
    assert counts["device_reuse_farm"] == 5 * 6
    assert counts["internet_cafe"] == 3 * 12
    assert counts["shared_ip_noise"] == 3 * 45
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
    # Cada tamaño se multiplica por los grupos por defecto (5 granjas, 3 cibercafés, 3 IPs compartidas).
    assert (counts["normal"], counts["datacenter_bot"], counts["residential_proxy_farm"],
            counts["device_reuse_farm"], counts["internet_cafe"], counts["shared_ip_noise"]) == (
        3, 5 * 4, 5 * 5, 5 * 7, 3 * 9, 3 * 31)


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
    for bots in _groups(document, "datacenter_bot").values():
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
    for farm in _groups(document, "residential_proxy_farm").values():
        assert len({_subnet(a["ip"]) for a in farm}) == len(farm)
        assert not any(a["is_hosting"] for a in farm)
        # El mismo dispositivo con variaciones pequeñas: todas en la misma familia que la primera.
        first = flatten(farm[0]["fingerprint"], farm[0]["timezone"])
        assert all(similarity(first, flatten(a["fingerprint"], a["timezone"])) >= FAMILY_THRESHOLD
                   for a in farm)
        assert len({a["fingerprint"]["canvasHash"] for a in farm}) == 2
        times = sorted(_time(a) for a in farm)
        assert times[-1] - times[0] <= timedelta(hours=4)


def test_device_reuse_farm_within_15_minutes(document):
    for farm in _groups(document, "device_reuse_farm").values():
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
    for cafe in _groups(document, "internet_cafe").values():
        assert 8 <= len(cafe) <= 15
        assert len({a["ip"] for a in cafe}) == 1
        assert all(a["fingerprint"] == cafe[0]["fingerprint"] for a in cafe)
        times = sorted(_time(a) for a in cafe)
        assert times[-1] - times[0] >= timedelta(weeks=1)


def test_shared_ip_noise_has_distinct_devices(document):
    for users in _groups(document, "shared_ip_noise").values():
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


# --- Varios grupos por arquetipo ---

def test_groups_per_archetype_with_defaults(document):
    expected = {"datacenter_bot": 5, "residential_proxy_farm": 5, "device_reuse_farm": 5, "normal": 0,
                "shared_household": 20, "internet_cafe": 3, "shared_ip_noise": 3}
    assert document["groups_per_archetype"] == expected
    for archetype, total in expected.items():
        if total:
            assert len(_groups(document, archetype)) == total


def test_header_parameters_include_group_options(document):
    parameters = document["parameters"]
    assert (parameters["farms_per_archetype"], parameters["cafes"], parameters["shared_ips"]) == (5, 3, 3)
    assert (parameters["datacenter_bots"], parameters["proxy_farm"], parameters["device_farm"]) == (8, 6, 6)


def test_groups_are_independent(document):
    # Dueño de cada cuenta: su grupo, o la propia cuenta si no tiene grupo (usuarios normales).
    archetype_of_group = {}
    owners = {"ip": defaultdict(set), "subnet": defaultdict(set), "canvas": defaultdict(set),
              "device": defaultdict(set)}
    for account in document["accounts"]:
        if account["group_id"]:
            assert archetype_of_group.setdefault(account["group_id"], account["archetype"]) == account["archetype"]
        owner = account["group_id"] or account["account_id"]
        owners["ip"][account["ip"]].add(owner)
        owners["subnet"][_subnet(account["ip"])].add(owner)
        owners["canvas"][account["fingerprint"]["canvasHash"]].add(owner)
        owners["device"][str(account["fingerprint"])].add(owner)
    for kind, mapping in owners.items():
        shared = {key: found for key, found in mapping.items() if len(found) > 1}
        assert shared == {}, f"{kind} compartido entre grupos: {shared}"


def test_every_fraud_farm_has_at_least_four_accounts(document):
    for archetype in simulate_fraud.FRAUD_ARCHETYPES:
        assert all(len(farm) >= 4 for farm in _groups(document, archetype).values())


@pytest.mark.parametrize("flag", ["--datacenter-bots", "--proxy-farm", "--device-farm"])
def test_farm_smaller_than_four_fails_clearly(flag, capsys):
    with pytest.raises(SystemExit):
        simulate_fraud.parse_args([flag, "3"])
    error = capsys.readouterr().err
    assert "al menos 4 cuentas" in error
    assert f"{flag}=3" in error


def test_generate_also_rejects_small_farms():
    with pytest.raises(ValueError, match="al menos 4 cuentas"):
        simulate_fraud.generate(simulate_fraud.Config(device_farm=2), HOSTING_ASNS)


def test_new_parameters_change_counts():
    config, _ = simulate_fraud.parse_args(["--normal", "10", "--farms-per-archetype", "2",
                                           "--cafes", "1", "--shared-ips", "4"])
    document = simulate_fraud.generate(config, HOSTING_ASNS)
    counts = Counter(a["archetype"] for a in document["accounts"])
    assert (counts["datacenter_bot"], counts["residential_proxy_farm"], counts["device_reuse_farm"],
            counts["internet_cafe"], counts["shared_ip_noise"]) == (2 * 8, 2 * 6, 2 * 6, 1 * 12, 4 * 45)
    groups = document["groups_per_archetype"]
    assert (groups["datacenter_bot"], groups["internet_cafe"], groups["shared_ip_noise"]) == (2, 1, 4)


def test_groups_of_same_archetype_start_at_different_times(document):
    for archetype, total in document["groups_per_archetype"].items():
        if total < 2:
            continue
        starts = sorted(min(_time(a) for a in members) for members in _groups(document, archetype).values())
        assert len(set(starts)) == len(starts), archetype
        if archetype in simulate_fraud.FRAUD_ARCHETYPES:
            # 5 granjas repartidas en 60 días: la primera y la última empiezan con un mes o más de diferencia.
            assert starts[-1] - starts[0] >= timedelta(days=30), archetype
