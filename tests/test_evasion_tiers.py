import importlib.util
import math
import random
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from services import asn_lookup, geo_lookup, risk_engine
from services.asn_lookup import AsnDatabase
from services.geo_lookup import GeoDatabase

ROOT = Path(__file__).resolve().parents[1]

# run_campaign.py agrega scripts/ al path e importa evasion_bot: se carga desde su ruta.
_spec = importlib.util.spec_from_file_location("run_campaign_tiers", ROOT / "scripts" / "run_campaign.py")
run_campaign = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_campaign)
evasion_bot = run_campaign.evasion_bot

SEED = 20261030


def _int(ip: str) -> int:
    return int(IPv4Address(ip))


# Bases chicas: 1.x y 2.x son de México con ASN residenciales; 3.x es de México pero de AWS
# (16509, que sí está en backend/data/hosting_asns.txt); el resto del espacio es de US.
FAKE_ASN = AsnDatabase({8: {_int("1.0.0.0"): 64600, _int("2.0.0.0"): 64601, _int("3.0.0.0"): 16509,
                            _int("4.0.0.0"): 64700}})
FAKE_GEO = GeoDatabase([_int("1.0.0.0"), _int("4.0.0.0")], [_int("3.255.255.255"), _int("255.255.255.255")],
                       ["MX", "US"])


def _fake_pool(seed=SEED, size=35):
    # Funciones reales de la API (is_hosting_asn, timezone_matches_country) sobre las bases chicas.
    return evasion_bot.pick_residential_ips(
        random.Random(seed), size, country_of=FAKE_GEO.lookup, asn_of=FAKE_ASN.lookup,
        is_hosting_asn=asn_lookup.is_hosting_asn, timezone_matches=geo_lookup.timezone_matches_country)


def _straightness(points):
    path = sum(math.dist(a, b) for a, b in zip(points, points[1:]))
    return math.dist(points[0], points[-1]) / path


# --- Nivel 1: no cambia ---

def test_tier1_plan_is_the_naive_bot():
    plan = evasion_bot.tier_plan("1", 3, SEED)
    assert [entry["kind"] for entry in plan] == ["naive"] * 3
    assert all(entry["debug_ip"] == evasion_bot.DATACENTER_IP for entry in plan)
    assert [entry["email"] for entry in plan] == [evasion_bot.bot_email(SEED, "1", i) for i in range(3)]


# --- Nivel 2: humanización básica ---

def test_tier2_keeps_datacenter_ip_and_container_fingerprint():
    for entry in evasion_bot.tier_plan("2", 5, SEED):
        assert entry["debug_ip"] == evasion_bot.DATACENTER_IP
        # Sin opciones de contexto: zona UTC y huella del contenedor, como el nivel 1.
        assert entry["context_options"] == {}
        assert entry["init_script"] is None
        assert entry["touch"] is False


def test_tier2_typing_delays_vary_per_key():
    for entry in evasion_bot.tier_plan("2", 5, SEED):
        delays = entry["typing_delays_ms"]
        assert len(delays) == len(entry["email"]) - 1
        assert all(60 <= delay <= 220 for delay in delays)
        assert len(set(delays)) > 1  # No es un retraso constante.


def test_tier2_waits_and_moves_mouse_enough():
    for entry in evasion_bot.tier_plan("2", 5, SEED):
        assert 6000 <= entry["wait_before_submit_ms"] <= 15000
        assert all(steps >= 25 for steps in entry["mouse"]["steps"])


@pytest.mark.parametrize("seed", range(40))
def test_bezier_path_is_curved_and_reaches_target(seed):
    rng = random.Random(seed)
    points = evasion_bot.bezier_path((50.0, 500.0), (600.0, 140.0), rng, 30)
    assert len(points) == 30
    assert points[-1] == (600.0, 140.0)
    # Más curva que el umbral de mouse_linear (rectitud > 0.98).
    assert _straightness([(50.0, 500.0)] + points) < 0.98


def test_bezier_path_is_deterministic():
    first = evasion_bot.bezier_path((0, 0), (300, 200), random.Random("x"), 30)
    assert evasion_bot.bezier_path((0, 0), (300, 200), random.Random("x"), 30) == first


# --- Nivel 3: red residencial ---

def test_residential_pool_is_mexican_and_not_hosting():
    pool = _fake_pool()
    assert len(pool) == 35
    assert len(set(pool)) == 35
    assert len({ip.rsplit(".", 1)[0] for ip in pool}) == 35  # Un /24 por IP.
    for ip in pool:
        assert FAKE_GEO.lookup(ip) == "MX"
        # Las mismas comprobaciones que hace la API: ni hosting_ip ni tz_country_mismatch.
        assert asn_lookup.is_hosting_asn(FAKE_ASN.lookup(ip)) is False
        assert geo_lookup.timezone_matches_country(FAKE_GEO.lookup(ip), "America/Mexico_City") is True
        assert not ip.startswith("3.")  # El /8 de AWS nunca entra.


def test_residential_pool_is_deterministic_per_seed():
    assert _fake_pool(seed=1) == _fake_pool(seed=1)
    assert _fake_pool(seed=1) != _fake_pool(seed=2)


def test_residential_pool_fails_clearly_when_impossible():
    with pytest.raises(RuntimeError, match="IPs residenciales"):
        evasion_bot.pick_residential_ips(
            random.Random(0), 1, country_of=lambda ip: "US", asn_of=lambda ip: 64600,
            is_hosting_asn=lambda asn: False, timezone_matches=lambda c, tz: True, max_attempts=1000)


@pytest.mark.parametrize("n, expected", [(10, 35), (50, 50)])
def test_pool_has_at_least_35_ips(monkeypatch, n, expected):
    sizes = []

    def fake_pool(seed, tier, size):
        sizes.append(size)
        return _fake_pool(size=size)

    monkeypatch.setattr(evasion_bot, "residential_pool", fake_pool)
    evasion_bot.tier_plan("3", n, SEED)
    assert sizes == [expected]


def test_tier3_uses_a_distinct_mexican_ip_per_registration():
    plan = evasion_bot.tier_plan("3", 35, SEED, ip_pool=_fake_pool())
    assert len({entry["debug_ip"] for entry in plan}) == 35
    for entry in plan:
        assert entry["context_options"]["timezone_id"] == "America/Mexico_City"
        assert entry["touch"] is False
        assert all(steps >= 25 for steps in entry["mouse"]["steps"])


def test_tier3_fingerprint_varies_between_registrations():
    plan = evasion_bot.tier_plan("3", 10, SEED, ip_pool=_fake_pool())
    viewports = {tuple(entry["context_options"]["viewport"].values()) for entry in plan}
    cores = {entry["fingerprint_overrides"]["hardwareConcurrency"] for entry in plan}
    languages = {tuple(entry["fingerprint_overrides"]["languages"]) for entry in plan}
    assert len(viewports) > 1 and len(cores) > 1 and len(languages) > 1
    for entry in plan:
        overrides = entry["fingerprint_overrides"]
        assert entry["context_options"]["screen"] == entry["context_options"]["viewport"]
        assert entry["context_options"]["locale"] == overrides["languages"][0]
        assert f"get: () => {overrides['hardwareConcurrency']}" in entry["init_script"]


# --- Nivel 3b: exención táctil ---

def test_tier3b_emulates_a_touch_phone():
    plan = evasion_bot.tier_plan("3b", 10, SEED, ip_pool=_fake_pool())
    for entry in plan:
        options = entry["context_options"]
        assert options["has_touch"] is True
        assert options["is_mobile"] is True
        assert (options["viewport"]["width"], options["viewport"]["height"]) in evasion_bot.MOBILE_SIZES
        assert options["timezone_id"] == "America/Mexico_City"
        # Toques en vez de ratón (así pointer_kind sale "touch"), con el tecleo humanizado del nivel 2.
        assert entry["touch"] is True
        assert entry["mouse"] is None
        assert all(60 <= delay <= 220 for delay in entry["typing_delays_ms"])


# --- Determinismo de todos los niveles ---

@pytest.mark.parametrize("tier", ["1", "2", "3", "3b"])
def test_same_seed_gives_same_plan(tier):
    pool = _fake_pool()
    assert evasion_bot.tier_plan(tier, 5, SEED, ip_pool=pool) == evasion_bot.tier_plan(tier, 5, SEED, ip_pool=pool)
    assert evasion_bot.tier_plan(tier, 5, SEED, ip_pool=pool) != evasion_bot.tier_plan(tier, 5, SEED + 1, ip_pool=pool)


def test_plan_does_not_touch_global_random():
    random.seed(1)
    first = evasion_bot.tier_plan("2", 3, SEED)
    random.seed(999)
    assert evasion_bot.tier_plan("2", 3, SEED) == first


# --- Medición sin device_reuse ---

def test_rescore_uses_real_engine_weights():
    weights = risk_engine.WEIGHTS
    reasons = ["hosting_ip", "device_reuse_high", "form_too_fast"]
    full = weights["hosting_ip"] + weights["device_reuse_high"] + weights["form_too_fast"]
    assert run_campaign.rescore(reasons)[0] == min(risk_engine.MAX_SCORE, full)
    score, action = run_campaign.without_device_reuse({"reasons": reasons})
    assert score == weights["hosting_ip"] + weights["form_too_fast"]
    # La acción sale de los umbrales reales del motor.
    expected = [name for minimum, name in risk_engine.THRESHOLDS if score >= minimum][-1]
    assert action == expected


def test_rescore_matches_the_engine_itself():
    signals = {"is_hosting": True, "timezone_matches_country": False, "timezone": "Europe/Madrid",
               "device_family_size": 4, "form_too_fast": True}
    decision = risk_engine.evaluate(signals)
    assert run_campaign.rescore(decision.reasons) == (decision.score, decision.action)


def _decided(reasons):
    score, action = run_campaign.rescore(reasons)
    return {"tier": "2", "score": score, "action": action, "reasons": reasons}


def test_summary_without_device_reuse():
    results = [
        _decided(["hosting_ip", "tz_utc", "device_reuse_high", "dwell_uniform"]),
        _decided(["hosting_ip", "tz_utc", "device_reuse_low", "dwell_uniform"]),
        _decided(["hosting_ip", "tz_utc", "dwell_uniform"]),
    ]
    [row] = run_campaign.summarize(results)
    scores = sorted(r["score"] for r in results)
    without = sorted(run_campaign.without_device_reuse(r)[0] for r in results)
    assert (row["score_median"], row["score_min"]) == (scores[1], scores[0])
    assert (row["score_median_without_reuse"], row["score_min_without_reuse"]) == (without[1], without[0])
    changed = sum(r["action"] != run_campaign.without_device_reuse(r)[1] for r in results)
    assert row["actions_changed_without_reuse"] == changed
    assert changed >= 1


def test_mismatched_weights_abort_the_campaign():
    result = _decided(["hosting_ip"]) | {"has_debug_risk": True, "score": 99}
    with pytest.raises(run_campaign.CampaignError, match="reconstruye la imagen"):
        run_campaign.check_result(result)


def test_wider_table_still_goes_into_the_readme(tmp_path):
    table = run_campaign.render_table(run_campaign.summarize([_decided(["hosting_ip", "device_reuse_low"])]))
    table_file = tmp_path / "campaign_table.md"
    table_file.write_text(table + "\n", encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text(f"# R\n{run_campaign.TABLE_START}\nvieja\n{run_campaign.TABLE_END}\n", encoding="utf-8")
    run_campaign.update_readme_from(table_file, readme)
    assert table in readme.read_text(encoding="utf-8")
    assert "Cambian de acción sin device_reuse" in readme.read_text(encoding="utf-8")
