import copy
import importlib.util
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import networkx as nx
import pytest

from services.account_graph import EDGE_FAMILIES, FarmCluster, build_graph, detect_farms

ROOT = Path(__file__).resolve().parents[1]


def _load_script(name):
    # Los scripts viven en scripts/, fuera de los paquetes: se cargan desde su ruta.
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


simulate_fraud = _load_script("simulate_fraud")
detect_farms_script = _load_script("detect_farms")

BASE = datetime(2026, 9, 1, tzinfo=timezone.utc)

DEVICE = {
    "canvasHash": "a" * 64,
    "webglRenderer": "ANGLE (Intel HD 530)",
    "hardwareConcurrency": 8,
    "screen": {"width": 1920, "height": 1080, "colorDepth": 24},
    "languages": ["es-MX", "es"],
    "platform": "Win32",
    "maxTouchPoints": 0,
}


def _other_device(number):
    """Un dispositivo que no se parece a DEVICE ni a otro número: bloque de candidatos distinto."""
    return {**DEVICE, "canvasHash": f"{number:064x}", "webglRenderer": f"GPU {number}",
            "screen": {"width": 1000 + number, "height": 700, "colorDepth": 24}}


def _account(account_id, hours, ip, fingerprint=None):
    return {
        "account_id": account_id,
        "created_at": (BASE + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ip": ip,
        "fingerprint": copy.deepcopy(fingerprint or DEVICE),
        "timezone": "America/Mexico_City",
        # Verdad de referencia: el detector no debe leerla (hay tests que lo comprueban).
        "label": "fraud",
        "archetype": "manual",
        "group_id": None,
    }


def _types(graph, a, b):
    return graph.edges[a, b]["types"] if graph.has_edge(a, b) else set()


# --- Aristas ---

def test_exact_device_edge():
    graph = build_graph([_account("a", 0, "5.1.0.1"), _account("b", 1, "5.2.0.1")])
    assert "same_device_exact" in _types(graph, "a", "b")
    assert "same_ip" not in _types(graph, "a", "b")


def test_similar_device_connects_inside_window():
    # Navegador actualizado: solo cambia el canvas -> similitud 0.80.
    updated = {**DEVICE, "canvasHash": "b" * 64}
    graph = build_graph([_account("a", 0, "5.1.0.1"), _account("b", 47, "5.2.0.1", updated)])
    assert _types(graph, "a", "b") == {"similar_device"}


def test_similar_device_never_connects_outside_window():
    updated = {**DEVICE, "canvasHash": "b" * 64}
    graph = build_graph([_account("a", 0, "5.1.0.1"), _account("b", 49, "5.2.0.1", updated)])
    assert not graph.has_edge("a", "b")
    # Tampoco el dispositivo exacto: la ventana vale para todos los tipos de arista.
    graph = build_graph([_account("a", 0, "5.1.0.1"), _account("c", 49, "5.2.0.1")])
    assert not graph.has_edge("a", "c")


@pytest.mark.parametrize("hours, connected", [(47, True), (48, True), (49, False)])
def test_ip_edge_respects_window(hours, connected):
    graph = build_graph([_account("a", 0, "5.1.0.1", _other_device(1)),
                         _account("b", hours, "5.1.0.1", _other_device(2))])
    assert ("same_ip" in _types(graph, "a", "b")) is connected


def test_same_subnet_edge():
    graph = build_graph([_account("a", 0, "5.1.0.1", _other_device(1)),
                         _account("b", 1, "5.1.0.2", _other_device(2))])
    assert _types(graph, "a", "b") == {"same_subnet24"}


@pytest.mark.parametrize("count, edges_expected", [(25, True), (26, False)])
def test_hub_ip_and_subnet_are_ignored(count, edges_expected):
    # Escuela o CGNAT: muchas cuentas, cada una con su dispositivo, en la misma IP y en una hora.
    accounts = [_account(f"u{n:02d}", n / 60, "5.1.0.1", _other_device(n)) for n in range(count)]
    graph = build_graph(accounts)
    assert (graph.number_of_edges() > 0) is edges_expected


# --- Detección ---

def test_min_cluster_size_three_versus_four():
    trio = [_account(f"t{n}", n, "5.1.0.1") for n in range(3)]
    assert detect_farms(trio) == []
    assert len(detect_farms(trio, min_cluster_size=3)) == 1


def test_evidence_families():
    # Misma IP, dispositivos distintos: solo familia "network".
    network_only = [_account(f"n{n}", n, "5.1.0.1", _other_device(n)) for n in range(4)]
    clusters = detect_farms(network_only)
    assert [c.families for c in clusters] == [("network",)]
    assert detect_farms(network_only, min_evidence_families=2) == []
    # Mismo dispositivo y misma IP: las dos familias.
    both = [_account(f"b{n}", n, "5.1.0.1") for n in range(4)]
    assert [c.families for c in detect_farms(both, min_evidence_families=2)] == [("device", "network")]


def test_device_farm_of_six_in_ten_minutes_is_flagged():
    farm = [_account(f"f{n}", n * 2 / 60, "5.1.0.1") for n in range(6)]
    clusters = detect_farms(farm)
    assert len(clusters) == 1
    cluster = clusters[0]
    assert cluster.accounts == tuple(f"f{n}" for n in range(6))
    assert cluster.size == 6
    assert cluster.families == ("device", "network")
    assert {"same_device_exact", "same_ip"} <= set(cluster.edge_types)
    assert cluster.span_hours == round(10 / 60, 2)  # span_hours va redondeado a 2 decimales.


def test_internet_cafe_spread_over_weeks_is_not_flagged():
    # 12 personas en el mismo equipo e IP, una cada 3 días (33 días en total).
    cafe = [_account(f"c{n:02d}", n * 72, "5.1.0.1") for n in range(12)]
    assert detect_farms(cafe) == []


def test_cluster_reports_time_span():
    farm = [_account(f"f{n}", n, "5.1.0.1") for n in range(4)]
    cluster = detect_farms(farm)[0]
    assert (cluster.first_created_at, cluster.last_created_at) == ("2026-09-01T00:00:00Z", "2026-09-01T03:00:00Z")
    assert cluster.span_hours == 3.0


# --- Regla de oro y determinismo, sobre el conjunto sintético por defecto ---

@pytest.fixture(scope="module")
def synthetic_accounts():
    return simulate_fraud.generate(simulate_fraud.Config(), [16509, 24940])["accounts"]


def test_result_ignores_ground_truth_fields(synthetic_accounts):
    expected = detect_farms(synthetic_accounts)

    removed = [{k: v for k, v in a.items() if k not in ("label", "archetype", "group_id")}
               for a in synthetic_accounts]
    assert detect_farms(removed) == expected

    shuffled = copy.deepcopy(synthetic_accounts)
    truths = [(a["label"], a["archetype"], a["group_id"]) for a in shuffled]
    random.Random(0).shuffle(truths)
    for account, (label, archetype, group_id) in zip(shuffled, truths):
        account["label"], account["archetype"], account["group_id"] = label, archetype, group_id
    assert detect_farms(shuffled) == expected


def test_result_is_deterministic(synthetic_accounts):
    first = detect_farms(synthetic_accounts)
    assert detect_farms(synthetic_accounts) == first
    reordered = list(synthetic_accounts)
    random.Random(1).shuffle(reordered)
    assert detect_farms(reordered) == first


def test_structural_guarantees_on_default_data(synthetic_accounts):
    clusters = detect_farms(synthetic_accounts)
    flagged = [account_id for c in clusters for account_id in c.accounts]
    assert len(flagged) == len(set(flagged))  # Ninguna cuenta en dos clústeres.
    assert all(isinstance(c, FarmCluster) and c.size >= 4 and c.families for c in clusters)
    assert all(list(c.accounts) == sorted(c.accounts) for c in clusters)
    # Cada granja de un solo dispositivo (misma IP, 10 minutos) queda detectada entera.
    flagged_set = set(flagged)
    farms = {}
    for account in synthetic_accounts:
        if account["archetype"] == "device_reuse_farm":
            farms.setdefault(account["group_id"], []).append(account["account_id"])
    assert farms
    assert all(all(account_id in flagged_set for account_id in members) for members in farms.values())


def test_evaluation_script_runs_on_small_data():
    config = simulate_fraud.Config(normal=30, households=3, shared_ip_users=30)
    accounts = simulate_fraud.generate(config, [16509])["accounts"]
    result = detect_farms_script.evaluate(accounts, window_hours=48, min_size=4, min_families=1,
                                          device_sim=0.75, hub_max=25)
    assert len(result["sweep"]) == 12
    assert set(result["fraud_groups"]) == {"datacenter_bot", "device_reuse_farm", "residential_proxy_farm"}
    assert "Barrido" in detect_farms_script.report(result, "prueba")


# --- v2: regla de ráfaga y regla de evidencia fuerte ---

V1 = {"burst_rule": False, "strong_evidence": False}


def _similar_only(count):
    # El mismo modelo de equipo con canvas distinto (similitud 0.80), cada cuenta en su propia red.
    return [_account(f"s{n}", n, f"5.{n + 1}.0.1", {**DEVICE, "canvasHash": f"{n:064x}"}) for n in range(count)]


def test_chain_of_40_hour_gaps_is_not_flagged():
    # A-B-C-D a 40 h entre consecutivas (120 h de tramo), misma IP y mismo equipo.
    chain = [_account(f"k{n}", n * 40, "5.1.0.1") for n in range(4)]
    assert detect_farms(chain) == []
    # v1 sí lo marcaba: es el encadenamiento que corta la regla de ráfaga.
    assert [c.size for c in detect_farms(chain, **V1)] == [4]


def test_four_accounts_same_ip_within_ten_minutes_are_flagged():
    burst = [_account(f"r{n}", n * 3 / 60, "5.1.0.1", _other_device(n)) for n in range(4)]
    clusters = detect_farms(burst)
    assert [c.accounts for c in clusters] == [("r0", "r1", "r2", "r3")]
    assert clusters[0].span_hours <= 10 / 60


def test_cluster_joined_only_by_fuzzy_similarity_is_not_flagged():
    accounts = _similar_only(4)
    graph = build_graph(accounts)
    assert graph.number_of_edges() > 0
    assert all(data["types"] == {"similar_device"} for _, _, data in graph.edges(data=True))
    assert detect_farms(accounts) == []
    assert [c.size for c in detect_farms(accounts, **V1)] == [4]


def test_account_with_only_weak_edge_is_not_added_to_strong_cluster():
    farm = [_account(f"f{n}", n, "5.1.0.1") for n in range(4)]
    lookalike = _account("x", 2, "5.9.0.1", {**DEVICE, "canvasHash": "c" * 64})
    accounts = farm + [lookalike]
    assert _types(build_graph(accounts), "f0", "x") == {"similar_device"}
    assert [c.accounts for c in detect_farms(accounts)] == [("f0", "f1", "f2", "f3")]
    assert [c.size for c in detect_farms(accounts, **V1)] == [5]


def test_overlapping_bursts_use_disjoint_windows():
    # Horas 0, 1, 2, 3, 47.5, 48.5, 49 y 50: la primera ventana se queda con 0..47.5, y 48.5, 49
    # y 50 quedan fuera porque solo cumplían junto a 47.5, que ya está usada.
    hours = [0, 1, 2, 3, 47.5, 48.5, 49, 50]
    accounts = [_account(f"w{n}", hour, "5.1.0.1") for n, hour in enumerate(hours)]
    assert [c.accounts for c in detect_farms(accounts)] == [("w0", "w1", "w2", "w3", "w4")]


def test_each_rule_fixes_its_own_problem():
    chain = [_account(f"k{n}", n * 40, "5.1.0.1") for n in range(4)]
    fuzzy = _similar_only(4)
    # Solo evidencia fuerte: la cadena (aristas fuertes) sigue marcada; el grupo difuso ya no.
    assert detect_farms(chain, burst_rule=False) != []
    assert detect_farms(fuzzy, burst_rule=False) == []
    # Solo ráfaga: el grupo difuso (todo en 3 h) sigue marcado; la cadena ya no.
    assert detect_farms(fuzzy, strong_evidence=False) != []
    assert detect_farms(chain, strong_evidence=False) == []


def _v1_reference(accounts):
    """v1 escrita aparte: componentes conexos filtrados por tamaño y familias, nada más."""
    graph = build_graph(accounts)
    clusters = []
    for component in nx.connected_components(graph):
        if len(component) < 4:
            continue
        types = sorted({t for _, _, data in graph.subgraph(component).edges(data=True) for t in data["types"]})
        families = sorted({EDGE_FAMILIES[t] for t in types})
        if len(families) < 1:
            continue
        times = sorted((graph.nodes[node]["created"], graph.nodes[node]["created_at"]) for node in component)
        clusters.append(FarmCluster(tuple(sorted(component)), len(component), tuple(types), tuple(families),
                                    times[0][1], times[-1][1], round((times[-1][0] - times[0][0]) / 3600, 2)))
    return sorted(clusters, key=lambda c: (c.first_created_at, c.accounts))


def test_rules_off_reproduce_v1_exactly(synthetic_accounts):
    expected = _v1_reference(synthetic_accounts)
    assert expected  # Que la comparación no sea trivial.
    assert detect_farms(synthetic_accounts, **V1) == expected


@pytest.mark.parametrize("burst, strong", [(False, False), (True, False), (False, True), (True, True)])
def test_every_variant_ignores_truth_and_is_deterministic(synthetic_accounts, burst, strong):
    options = {"burst_rule": burst, "strong_evidence": strong}
    expected = detect_farms(synthetic_accounts, **options)
    removed = [{k: v for k, v in a.items() if k not in ("label", "archetype", "group_id")}
               for a in synthetic_accounts]
    assert detect_farms(removed, **options) == expected
    reordered = list(synthetic_accounts)
    random.Random(2).shuffle(reordered)
    assert detect_farms(reordered, **options) == expected


def test_v2_clusters_never_span_more_than_the_window(synthetic_accounts):
    for window in (6, 24, 48, 168):
        for cluster in detect_farms(synthetic_accounts, window_hours=window):
            assert cluster.span_hours <= window
            assert cluster.size >= 4


def test_evaluation_compares_four_variants():
    config = simulate_fraud.Config(normal=30, households=3, shared_ip_users=30)
    accounts = simulate_fraud.generate(config, [16509])["accounts"]
    result = detect_farms_script.evaluate(accounts, window_hours=48, min_size=4, min_families=1,
                                          device_sim=0.75, hub_max=25)
    assert list(result["variants"]) == [name for name, _, _ in detect_farms_script.VARIANTS]
    assert result["variant"] == "v2 (ambas)"
    text = detect_farms_script.report(result, "prueba")
    assert "Comparación de variantes" in text
    assert "Pérdida de recall" in text
