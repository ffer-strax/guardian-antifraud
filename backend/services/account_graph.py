"""Grafo de cuentas para detectar granjas. Análisis por lotes: sin red ni base de datos.

REGLA DE ORO: la construcción del grafo y la detección solo leen account_id, created_at, ip,
fingerprint y timezone (ver _view). label, archetype y group_id son la verdad de referencia y
solo los usa la evaluación (scripts/detect_farms.py).
"""
import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

import networkx as nx

from services.fingerprint_match import flatten, similarity

# Umbrales por defecto. Son HIPÓTESIS a medir con scripts/detect_farms.py, no valores comprobados.
TIME_WINDOW_HOURS = 48        # Dos cuentas solo se conectan si se crearon con esta diferencia o menos.
DEVICE_SIM_THRESHOLD = 0.75   # Similitud mínima de huella para similar_device (la de fingerprint_match).
HUB_MAX_ACCOUNTS = 25         # Una IP o un /24 con más cuentas es un hub (escuela, CGNAT): no crea aristas.
MIN_CLUSTER_SIZE = 4          # Cuentas mínimas para marcar un clúster como granja.
MIN_EVIDENCE_FAMILIES = 1     # Familias de evidencia distintas (device, network) que debe cubrir el clúster.

# Tipo de arista -> familia de evidencia.
EDGE_FAMILIES = {
    "same_device_exact": "device",
    "similar_device": "device",
    "same_ip": "network",
    "same_subnet24": "network",
}

# Atributos estables de la huella: los mismos 4 del índice de device_fingerprints.
STABLE_KEYS = ("platform", "hardware_concurrency", "screen_w", "screen_h")


@dataclass(frozen=True)
class FarmCluster:
    accounts: tuple[str, ...]
    size: int
    edge_types: tuple[str, ...]
    families: tuple[str, ...]
    first_created_at: str
    last_created_at: str
    span_hours: float


@dataclass(frozen=True)
class _Account:
    account_id: str
    created_at: str
    created: float          # Segundos desde 1970, para comparar ventanas.
    ip: str | None
    subnet24: str | None
    device: dict | None     # Huella plana (forma de fingerprint_match.flatten).


def _parse_time(text: str) -> float:
    moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def _subnet24(ip: str | None) -> str | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if address.version != 4:
        return None
    return str(ipaddress.ip_network(f"{address}/24", strict=False))


def _view(raw: dict) -> _Account:
    """Copia SOLO los campos permitidos: así label, archetype y group_id no pueden influir."""
    ip = raw.get("ip")
    return _Account(
        account_id=raw["account_id"],
        created_at=raw["created_at"],
        created=_parse_time(raw["created_at"]),
        ip=ip,
        subnet24=_subnet24(ip),
        device=flatten(raw.get("fingerprint"), raw.get("timezone")),
    )


def _stable(device: dict | None) -> tuple | None:
    if device is None:
        return None
    values = tuple(device.get(key) for key in STABLE_KEYS)
    return None if None in values else values


def _connect(graph: nx.Graph, members: list[_Account], edge_type: str, window_seconds: float,
             check=None) -> None:
    """Une las cuentas del grupo que caen dentro de la ventana. `members` va ordenado por fecha,
    así que en cuanto la diferencia supera la ventana se corta: no se comparan todos contra todos."""
    for index, first in enumerate(members):
        for second in members[index + 1:]:
            if second.created - first.created > window_seconds:
                break
            if check is None or check(first, second):
                if graph.has_edge(first.account_id, second.account_id):
                    graph.edges[first.account_id, second.account_id]["types"].add(edge_type)
                else:
                    graph.add_edge(first.account_id, second.account_id, types={edge_type})


def build_graph(accounts: list[dict], *, window_hours: float = TIME_WINDOW_HOURS,
                device_sim_threshold: float = DEVICE_SIM_THRESHOLD,
                hub_max_accounts: int = HUB_MAX_ACCOUNTS) -> nx.Graph:
    """Una arista por pareja de cuentas relacionadas; su atributo "types" dice por qué."""
    views = sorted((_view(raw) for raw in accounts), key=lambda v: (v.created, v.account_id))
    window_seconds = window_hours * 3600
    graph = nx.Graph()
    for view in views:
        graph.add_node(view.account_id, created_at=view.created_at, created=view.created)

    by_ip, by_subnet, by_exact_device, by_block = (defaultdict(list) for _ in range(4))
    for view in views:
        if view.ip:
            by_ip[view.ip].append(view)
        if view.subnet24:
            by_subnet[view.subnet24].append(view)
        stable = _stable(view.device)
        if stable is not None:
            # Bloque de candidatos: la similitud solo se calcula entre huellas con estos 4 iguales.
            by_block[stable].append(view)
            if view.device.get("canvas_hash") is not None:
                by_exact_device[(view.device["canvas_hash"], *stable)].append(view)

    for members in by_ip.values():
        if len(members) <= hub_max_accounts:
            _connect(graph, members, "same_ip", window_seconds)
    for members in by_subnet.values():
        if len(members) <= hub_max_accounts:
            _connect(graph, members, "same_subnet24", window_seconds)
    for members in by_exact_device.values():
        _connect(graph, members, "same_device_exact", window_seconds)

    def similar(first: _Account, second: _Account) -> bool:
        return similarity(first.device, second.device) >= device_sim_threshold

    # La similitud difusa nunca conecta fuera de la ventana: _connect corta antes de compararlas.
    for members in by_block.values():
        _connect(graph, members, "similar_device", window_seconds, check=similar)
    return graph


def detect_farms(accounts: list[dict], *, window_hours: float = TIME_WINDOW_HOURS,
                 min_cluster_size: int = MIN_CLUSTER_SIZE,
                 min_evidence_families: int = MIN_EVIDENCE_FAMILIES,
                 device_sim_threshold: float = DEVICE_SIM_THRESHOLD,
                 hub_max_accounts: int = HUB_MAX_ACCOUNTS) -> list[FarmCluster]:
    """Componentes conexos del grafo que cumplen tamaño y familias de evidencia. Orden determinista."""
    graph = build_graph(accounts, window_hours=window_hours, device_sim_threshold=device_sim_threshold,
                        hub_max_accounts=hub_max_accounts)
    clusters = []
    for component in nx.connected_components(graph):
        if len(component) < min_cluster_size:
            continue
        edge_types = sorted({t for _, _, data in graph.subgraph(component).edges(data=True) for t in data["types"]})
        families = sorted({EDGE_FAMILIES[t] for t in edge_types})
        if len(families) < min_evidence_families:
            continue
        times = sorted((graph.nodes[node]["created"], graph.nodes[node]["created_at"]) for node in component)
        clusters.append(FarmCluster(
            accounts=tuple(sorted(component)),
            size=len(component),
            edge_types=tuple(edge_types),
            families=tuple(families),
            first_created_at=times[0][1],
            last_created_at=times[-1][1],
            span_hours=round((times[-1][0] - times[0][0]) / 3600, 2),
        ))
    clusters.sort(key=lambda c: (c.first_created_at, c.accounts))
    return clusters
