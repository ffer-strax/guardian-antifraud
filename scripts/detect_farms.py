"""Corre el detector de granjas (backend/services/account_graph.py) sobre las cuentas sintéticas y
lo mide contra la verdad de referencia. Reporta los resultados tal como salen, buenos o malos.

Solo ESTE script lee label, archetype y group_id, y solo después de detectar, para medir.

Uso desde la raíz del repo (necesita networkx: pip install -r backend/requirements.txt):
    python scripts/simulate_fraud.py      # genera data/synthetic_accounts.json
    python scripts/detect_farms.py
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from services import account_graph
from services.fingerprint_match import flatten, similarity

DEFAULT_INPUT = ROOT / "data" / "synthetic_accounts.json"

# Un grupo de fraude cuenta como detectado si al menos esta parte de sus cuentas queda marcada.
GROUP_DETECTED_SHARE = 0.80

SWEEP_WINDOWS = (6, 24, 48, 168)
SWEEP_MIN_SIZES = (3, 4, 6)

# Variantes del detector para la tabla comparativa: (nombre, burst_rule, strong_evidence).
VARIANTS = (
    ("v1 (sin reglas)", False, False),
    ("solo ráfaga", True, False),
    ("solo evidencia fuerte", False, True),
    ("v2 (ambas)", True, True),
)


def _variant_name(burst_rule: bool, strong_evidence: bool) -> str:
    return next(name for name, burst, strong in VARIANTS if (burst, strong) == (burst_rule, strong_evidence))


def _owner(account: dict) -> str:
    # Los usuarios normales no tienen grupo: cada uno es su propio "grupo" de una cuenta.
    return account["group_id"] or account["account_id"]


def _archetypes(accounts: list[dict], label: str) -> list[str]:
    return sorted({a["archetype"] for a in accounts if a["label"] == label})


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def account_metrics(accounts: list[dict], flagged: set[str]) -> dict:
    tp = sum(1 for a in accounts if a["label"] == "fraud" and a["account_id"] in flagged)
    fp = sum(1 for a in accounts if a["label"] == "legit" and a["account_id"] in flagged)
    fn = sum(1 for a in accounts if a["label"] == "fraud" and a["account_id"] not in flagged)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and precision + recall > 0 else None)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def _groups(accounts: list[dict], archetype: str) -> dict[str, list[dict]]:
    groups = defaultdict(list)
    for account in accounts:
        if account["archetype"] == archetype:
            groups[_owner(account)].append(account)
    return groups


def fraud_group_detection(accounts: list[dict], flagged: set[str]) -> dict:
    result = {}
    for archetype in _archetypes(accounts, "fraud"):
        groups = _groups(accounts, archetype)
        detected = sum(
            1 for members in groups.values()
            if sum(a["account_id"] in flagged for a in members) / len(members) >= GROUP_DETECTED_SHARE
        )
        result[archetype] = {"detected": detected, "total": len(groups)}
    return result


def legit_false_positives(accounts: list[dict], flagged: set[str]) -> dict:
    """Cuentas legítimas marcadas y grupos con al menos una cuenta marcada, por arquetipo."""
    result = {}
    for archetype in _archetypes(accounts, "legit"):
        members = [a for a in accounts if a["archetype"] == archetype]
        groups = _groups(accounts, archetype)
        grouped = archetype != "normal"
        result[archetype] = {
            "accounts_flagged": sum(a["account_id"] in flagged for a in members),
            "accounts_total": len(members),
            "groups_flagged": (sum(any(a["account_id"] in flagged for a in g) for g in groups.values())
                               if grouped else None),
            "groups_total": len(groups) if grouped else None,
        }
    return result


def mixed_clusters(accounts: list[dict], clusters: list) -> list[dict]:
    """Clústeres con cuentas de más de un grupo, o de fraude y legítimo a la vez."""
    by_id = {a["account_id"]: a for a in accounts}
    mixed = []
    for cluster in clusters:
        members = [by_id[account_id] for account_id in cluster.accounts]
        owners = {_owner(a) for a in members}
        labels = sorted({a["label"] for a in members})
        if len(owners) > 1 or len(labels) > 1:
            mixed.append({
                "size": cluster.size,
                "groups": len(owners),
                "labels": labels,
                "archetypes": dict(sorted(Counter(a["archetype"] for a in members).items())),
                "edge_types": list(cluster.edge_types),
                "span_hours": cluster.span_hours,
            })
    return mixed


def cross_group_similarity(accounts: list[dict], threshold: float, window_hours: float) -> dict:
    """Parejas de cuentas de grupos distintos con similitud >= umbral: en total y dentro de la ventana."""
    prepared = [(_owner(a), datetime.fromisoformat(a["created_at"]).timestamp(),
                 flatten(a["fingerprint"], a["timezone"])) for a in accounts]
    total = within = 0
    for (owner_a, time_a, device_a), (owner_b, time_b, device_b) in combinations(prepared, 2):
        if owner_a == owner_b or similarity(device_a, device_b) < threshold:
            continue
        total += 1
        if abs(time_a - time_b) <= window_hours * 3600:
            within += 1
    return {"pairs_total": total, "pairs_within_window": within}


def _hide_truth(accounts: list[dict]) -> list[dict]:
    """Copia de las cuentas SIN la verdad de referencia: es lo único que ve el detector."""
    return [{k: v for k, v in a.items() if k not in ("label", "archetype", "group_id")} for a in accounts]


def sweep(accounts: list[dict], min_families: int, device_sim: float, hub_max: int,
          burst_rule: bool, strong_evidence: bool) -> list[dict]:
    rows = []
    hidden = _hide_truth(accounts)
    fraud_groups = sum(len(_groups(accounts, k)) for k in _archetypes(accounts, "fraud"))
    for window in SWEEP_WINDOWS:
        for min_size in SWEEP_MIN_SIZES:
            clusters = account_graph.detect_farms(
                hidden, window_hours=window, min_cluster_size=min_size, min_evidence_families=min_families,
                device_sim_threshold=device_sim, hub_max_accounts=hub_max,
                burst_rule=burst_rule, strong_evidence=strong_evidence)
            flagged = {account_id for c in clusters for account_id in c.accounts}
            detected = sum(v["detected"] for v in fraud_group_detection(accounts, flagged).values())
            legit_flagged = sum(1 for a in accounts if a["label"] == "legit" and a["account_id"] in flagged)
            rows.append({"window_hours": window, "min_size": min_size, "clusters": len(clusters),
                         "fraud_group_recall": _ratio(detected, fraud_groups),
                         "fraud_groups_detected": detected, "fraud_groups_total": fraud_groups,
                         "legit_accounts_flagged": legit_flagged})
    return rows


def variant_summary(accounts: list[dict], clusters: list) -> dict:
    """Una fila de la tabla comparativa."""
    flagged = {account_id for c in clusters for account_id in c.accounts}
    metrics = account_metrics(accounts, flagged)
    return {
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "fraud_groups": fraud_group_detection(accounts, flagged),
        "fraud_accounts_flagged": {
            archetype: sum(1 for a in accounts if a["archetype"] == archetype and a["account_id"] in flagged)
            for archetype in _archetypes(accounts, "fraud")
        },
        "legit_accounts_flagged": {
            archetype: value["accounts_flagged"]
            for archetype, value in legit_false_positives(accounts, flagged).items()
        },
        "mixed_clusters": len(mixed_clusters(accounts, clusters)),
    }


def recall_losses(variants: dict) -> list[dict]:
    """Arquetipos de fraude que cada variante detecta PEOR que v1 (grupos o cuentas)."""
    baseline = variants["v1 (sin reglas)"]
    losses = []
    for name, summary in variants.items():
        for archetype, groups in summary["fraud_groups"].items():
            before_groups = baseline["fraud_groups"][archetype]["detected"]
            before_accounts = baseline["fraud_accounts_flagged"][archetype]
            after_accounts = summary["fraud_accounts_flagged"][archetype]
            if groups["detected"] < before_groups or after_accounts < before_accounts:
                losses.append({"variant": name, "archetype": archetype,
                               "groups": f"{before_groups} -> {groups['detected']} de {groups['total']}",
                               "accounts": f"{before_accounts} -> {after_accounts}"})
    return losses


def evaluate(accounts: list[dict], *, window_hours: float, min_size: int, min_families: int,
             device_sim: float, hub_max: int, burst_rule: bool = account_graph.BURST_RULE,
             strong_evidence: bool = account_graph.STRONG_EVIDENCE) -> dict:
    # 1) Detección SIN la verdad de referencia: se le pasan cuentas sin label/archetype/group_id.
    hidden = _hide_truth(accounts)
    thresholds = {"window_hours": window_hours, "min_cluster_size": min_size,
                  "min_evidence_families": min_families, "device_sim_threshold": device_sim,
                  "hub_max_accounts": hub_max}
    clusters = account_graph.detect_farms(hidden, **thresholds, burst_rule=burst_rule,
                                          strong_evidence=strong_evidence)
    flagged = {account_id for c in clusters for account_id in c.accounts}
    # Las 4 variantes con los mismos umbrales, para compararlas entre sí.
    variants = {
        name: variant_summary(accounts, account_graph.detect_farms(hidden, **thresholds, burst_rule=burst,
                                                                    strong_evidence=strong))
        for name, burst, strong in VARIANTS
    }
    # 2) Medición: recién aquí se usa la verdad de referencia.
    return {
        "parameters": {"window_hours": window_hours, "min_size": min_size, "min_families": min_families,
                       "device_sim": device_sim, "hub_max": hub_max, "burst_rule": burst_rule,
                       "strong_evidence": strong_evidence},
        "variant": _variant_name(burst_rule, strong_evidence),
        "accounts": len(accounts),
        "labels": dict(sorted(Counter(a["label"] for a in accounts).items())),
        "clusters": [asdict(c) for c in clusters],
        "cluster_sizes": dict(sorted(Counter(c.size for c in clusters).items())),
        "account_metrics": account_metrics(accounts, flagged),
        "fraud_groups": fraud_group_detection(accounts, flagged),
        "legit_false_positives": legit_false_positives(accounts, flagged),
        "mixed_clusters": mixed_clusters(accounts, clusters),
        "cross_group_similarity": cross_group_similarity(accounts, device_sim, window_hours),
        "sweep": sweep(accounts, min_families, device_sim, hub_max, burst_rule, strong_evidence),
        "variants": variants,
        "recall_losses": recall_losses(variants),
    }


# Nombres cortos para que la tabla comparativa quepa en la terminal.
SHORT_NAMES = {"datacenter_bot": "dc_bot", "residential_proxy_farm": "proxy", "device_reuse_farm": "dev_farm",
               "internet_cafe": "cafe", "normal": "normal", "shared_household": "hogar",
               "shared_ip_noise": "ip_comp"}


def _variant_table(variants: dict) -> list[str]:
    first = next(iter(variants.values()))
    fraud = list(first["fraud_groups"])
    legit = list(first["legit_accounts_flagged"])
    lines = [
        "   variante              | precisión | recall | grupos de fraude detectados  | "
        "cuentas legítimas marcadas     | mezclados",
        "                         |           |        | " + " ".join(f"{SHORT_NAMES.get(k, k):>8}" for k in fraud)
        + " | " + " ".join(f"{SHORT_NAMES.get(k, k):>7}" for k in legit) + " |",
    ]
    for name, summary in variants.items():
        groups = " ".join(f"{summary['fraud_groups'][k]['detected']}/{summary['fraud_groups'][k]['total']}".rjust(8)
                          for k in fraud)
        legits = " ".join(f"{summary['legit_accounts_flagged'][k]:>7}" for k in legit)
        lines.append(f"   {name:<22}| {_fmt(summary['precision']):>9} | {_fmt(summary['recall']):>6} | "
                     f"{groups} | {legits} | {summary['mixed_clusters']:>9}")
    lines.append("   (" + ", ".join(f"{SHORT_NAMES.get(k, k)}={k}" for k in fraud + legit) + ")")
    return lines


def report(result: dict, source: str) -> str:
    p = result["parameters"]
    m = result["account_metrics"]
    lines = [
        f"Detector de granjas sobre {source}",
        f"Cuentas: {result['accounts']} ({', '.join(f'{k} {v}' for k, v in result['labels'].items())})",
        f"Variante: {result['variant']} (ráfaga={'sí' if p['burst_rule'] else 'no'}, "
        f"evidencia fuerte={'sí' if p['strong_evidence'] else 'no'})",
        f"Parámetros: ventana {p['window_hours']} h, tamaño mínimo {p['min_size']}, familias mínimas "
        f"{p['min_families']}, similitud {p['device_sim']}, hub > {p['hub_max']} cuentas",
        "",
        f"1) Clústeres marcados: {len(result['clusters'])}",
        f"   Tamaños (tamaño: cuántos): {result['cluster_sizes']}",
    ]
    for cluster in result["clusters"]:
        lines.append(f"   - {cluster['size']:>3} cuentas  familias={','.join(cluster['families'])}  "
                     f"aristas={','.join(cluster['edge_types'])}  abarca {cluster['span_hours']} h")
    lines += [
        "",
        "2) Por cuenta (positivo = fraude):",
        f"   TP {m['tp']}  FP {m['fp']}  FN {m['fn']}",
        f"   precisión {_fmt(m['precision'])}  recall {_fmt(m['recall'])}  F1 {_fmt(m['f1'])}",
        "",
        f"3) Grupos de fraude detectados (>= {GROUP_DETECTED_SHARE:.0%} de sus cuentas en clústeres marcados):",
    ]
    for archetype, value in result["fraud_groups"].items():
        lines.append(f"   {archetype:<24} {value['detected']}/{value['total']}")
    lines += ["", "4) Falsos positivos en legítimos (grupo marcado = al menos una cuenta marcada):"]
    for archetype, value in result["legit_false_positives"].items():
        groups = ("" if value["groups_total"] is None
                  else f"   grupos {value['groups_flagged']}/{value['groups_total']}")
        lines.append(f"   {archetype:<24} cuentas {value['accounts_flagged']}/{value['accounts_total']}{groups}")
    lines += ["", f"5) Clústeres mezclados (más de un grupo, o fraude y legítimo juntos): {len(result['mixed_clusters'])}"]
    for mixed in result["mixed_clusters"]:
        lines.append(f"   - {mixed['size']} cuentas de {mixed['groups']} grupos, labels={'+'.join(mixed['labels'])}, "
                     f"arquetipos={mixed['archetypes']}, aristas={','.join(mixed['edge_types'])}")
    s = result["cross_group_similarity"]
    lines += [
        "",
        f"6) Parejas de cuentas de grupos distintos con similitud >= {p['device_sim']}:",
        f"   en total: {s['pairs_total']}   dentro de la ventana de {p['window_hours']} h: {s['pairs_within_window']}",
        "",
        f"7) Barrido de sensibilidad, variante {result['variant']} "
        "(recall de grupos de fraude / cuentas legítimas marcadas):",
        "   ventana h | min-size | clústeres | grupos fraude detectados | recall grupos | legítimas marcadas",
    ]
    for row in result["sweep"]:
        lines.append(f"   {row['window_hours']:>9} | {row['min_size']:>8} | {row['clusters']:>9} | "
                     f"{row['fraud_groups_detected']:>10}/{row['fraud_groups_total']:<13} | "
                     f"{_fmt(row['fraud_group_recall']):>13} | {row['legit_accounts_flagged']:>18}")
    lines += ["", "8) Comparación de variantes (mismos umbrales que arriba):"]
    lines += _variant_table(result["variants"])
    lines += ["", "9) Pérdida de recall frente a v1 (por arquetipo de fraude):"]
    if not result["recall_losses"]:
        lines.append("   Ninguna variante pierde grupos ni cuentas de fraude frente a v1.")
    for loss in result["recall_losses"]:
        lines.append(f"   - {loss['variant']}: {loss['archetype']} pierde recall "
                     f"(grupos {loss['groups']}, cuentas de fraude marcadas {loss['accounts']})")
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evalúa el detector de granjas contra la verdad de referencia.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--window-hours", type=float, default=account_graph.TIME_WINDOW_HOURS)
    parser.add_argument("--min-size", type=int, default=account_graph.MIN_CLUSTER_SIZE)
    parser.add_argument("--min-families", type=int, default=account_graph.MIN_EVIDENCE_FAMILIES)
    parser.add_argument("--device-sim", type=float, default=account_graph.DEVICE_SIM_THRESHOLD)
    parser.add_argument("--hub-max", type=int, default=account_graph.HUB_MAX_ACCOUNTS)
    parser.add_argument("--burst-rule", action=argparse.BooleanOptionalAction, default=account_graph.BURST_RULE,
                        help="Regla de ráfaga de v2 (--no-burst-rule para apagarla)")
    parser.add_argument("--strong-evidence", action=argparse.BooleanOptionalAction,
                        default=account_graph.STRONG_EVIDENCE,
                        help="Regla de evidencia fuerte de v2 (--no-strong-evidence para apagarla)")
    parser.add_argument("--json-out", type=Path, default=None, help="Guarda también el resultado en JSON")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if not args.input.exists():
        sys.exit(f"No existe {args.input}. Genéralo primero con: python scripts/simulate_fraud.py")
    accounts = json.loads(args.input.read_text(encoding="utf-8"))["accounts"]
    result = evaluate(accounts, window_hours=args.window_hours, min_size=args.min_size,
                      min_families=args.min_families, device_sim=args.device_sim, hub_max=args.hub_max,
                      burst_rule=args.burst_rule, strong_evidence=args.strong_evidence)
    print(report(result, args.input))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"\nResultado JSON escrito en {args.json_out}")


if __name__ == "__main__":
    main()
