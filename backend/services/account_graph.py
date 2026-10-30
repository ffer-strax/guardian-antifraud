"""Grafo de cuentas para detectar granjas. Análisis por lotes: sin red ni base de datos.

REGLA DE ORO: la construcción del grafo y la detección solo leen account_id, created_at, ip,
fingerprint y timezone (ver _view). label, archetype y group_id son la verdad de referencia y
solo los usa la evaluación (scripts/detect_farms.py).

v1: los componentes conexos del grafo que cumplen tamaño y familias se marcan como granja.

v2 agrega dos reglas, que son HIPÓTESIS medidas con scripts/detect_farms.py (se pueden apagar
para reproducir v1 exactamente):
- Ráfaga (burst_rule): la ventana limita cada arista, no el clúster, así que A-B a 40 h y B-C a
  40 h quedaban juntos aunque A y C estuvieran a 80 h (encadenamiento: así se marcaban los
  cibercafés). Ahora solo se marcan grupos de >= MIN_CLUSTER_SIZE cuentas dentro de UNA ventana
  de TIME_WINDOW_HOURS, en ventanas disjuntas: el tramo de un clúster nunca supera la ventana.
- Evidencia fuerte (strong_evidence): con perfiles de poca variedad (como los sintéticos), dos
  dispositivos distintos superan 0.75 de similitud con frecuencia. Por eso similar_device es una
  arista DÉBIL: sirve para unir, nunca para marcar sola. Cada cuenta marcada necesita al menos
  una arista fuerte (dispositivo exacto, misma IP o mismo /24) con otra cuenta de su clúster.
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
BURST_RULE = True             # v2: solo se marcan ráfagas de >= MIN_CLUSTER_SIZE cuentas dentro de una ventana.
STRONG_EVIDENCE = True        # v2: cada cuenta marcada necesita una arista fuerte dentro de su clúster.

# Tipo de arista -> familia de evidencia.
EDGE_FAMILIES = {
    "same_device_exact": "device",
    "similar_device": "device",
    "same_ip": "network",
    "same_subnet24": "network",
}

# Aristas fuertes: pueden marcar. similar_device es débil: solo une.
STRONG_EDGE_TYPES = frozenset({"same_device_exact", "same_ip", "same_subnet24"})

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


def _by_time(graph: nx.Graph, nodes) -> list[str]:
    return sorted(nodes, key=lambda node: (graph.nodes[node]["created"], node))


def _keep_strong(graph: nx.Graph, piece: list[str]) -> list[str]:
    """Cuentas del trozo con al menos una arista fuerte hacia otra cuenta del MISMO trozo."""
    members = set(piece)
    return [node for node in piece
            if any(other in members and graph.edges[node, other]["types"] & STRONG_EDGE_TYPES
                   for other in graph.neighbors(node))]


def _connected_parts(graph: nx.Graph, piece: list[str]) -> list[list[str]]:
    """Partes conexas del trozo usando solo aristas entre sus propias cuentas: si se quitó una
    cuenta que hacía de puente, lo que unía queda separado."""
    parts = [_by_time(graph, part) for part in nx.connected_components(graph.subgraph(piece))]
    return sorted(parts, key=lambda part: (graph.nodes[part[0]]["created"], part[0]))


def _bursts(graph: nx.Graph, piece: list[str], window_seconds: float, min_size: int) -> list[list[str]]:
    """Ráfagas en ventanas disjuntas, con dos punteros sobre el trozo ordenado por fecha: desde la
    cuenta `start`, todas las que caben en la ventana; si son >= min_size forman un clúster y se
    sigue después de la última; si no, se avanza una cuenta."""
    times = [graph.nodes[node]["created"] for node in piece]
    bursts = []
    start = end = 0
    while start < len(piece):
        end = max(end, start)
        while end + 1 < len(piece) and times[end + 1] - times[start] <= window_seconds:
            end += 1
        if end - start + 1 >= min_size:
            bursts.append(piece[start:end + 1])
            start = end + 1
        else:
            start += 1
    return bursts


def _cluster(graph: nx.Graph, piece: list[str], min_size: int, min_families: int) -> FarmCluster | None:
    if len(piece) < min_size:
        return None
    edge_types = sorted({t for _, _, data in graph.subgraph(piece).edges(data=True) for t in data["types"]})
    families = sorted({EDGE_FAMILIES[t] for t in edge_types})
    if len(families) < min_families:
        return None
    times = sorted((graph.nodes[node]["created"], graph.nodes[node]["created_at"]) for node in piece)
    return FarmCluster(
        accounts=tuple(sorted(piece)),
        size=len(piece),
        edge_types=tuple(edge_types),
        families=tuple(families),
        first_created_at=times[0][1],
        last_created_at=times[-1][1],
        span_hours=round((times[-1][0] - times[0][0]) / 3600, 2),
    )


def detect_farms(accounts: list[dict], *, window_hours: float = TIME_WINDOW_HOURS,
                 min_cluster_size: int = MIN_CLUSTER_SIZE,
                 min_evidence_families: int = MIN_EVIDENCE_FAMILIES,
                 device_sim_threshold: float = DEVICE_SIM_THRESHOLD,
                 hub_max_accounts: int = HUB_MAX_ACCOUNTS,
                 burst_rule: bool = BURST_RULE,
                 strong_evidence: bool = STRONG_EVIDENCE) -> list[FarmCluster]:
    """Clústeres marcados como granja, en orden determinista.

    Los componentes conexos son los candidatos. Con las dos reglas apagadas cada componente es un
    trozo único y el resultado es exactamente el de v1."""
    graph = build_graph(accounts, window_hours=window_hours, device_sim_threshold=device_sim_threshold,
                        hub_max_accounts=hub_max_accounts)
    window_seconds = window_hours * 3600
    clusters = []
    for component in nx.connected_components(graph):
        pieces = [_by_time(graph, component)]
        # Se repite hasta que nada cambie: quitar cuentas puede partir un trozo o dejar una ráfaga corta.
        while True:
            refined = []
            for piece in pieces:
                if strong_evidence:
                    piece = _keep_strong(graph, piece)
                for part in _connected_parts(graph, piece):
                    refined.extend(_bursts(graph, part, window_seconds, min_cluster_size) if burst_rule else [part])
            if refined == pieces:
                break
            pieces = refined
        for piece in pieces:
            cluster = _cluster(graph, piece, min_cluster_size, min_evidence_families)
            if cluster is not None:
                clusters.append(cluster)
    clusters.sort(key=lambda c: (c.first_created_at, c.accounts))
    return clusters
