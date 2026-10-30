"""Campaña de evasión (Fase 6): corre los niveles de bot en orden contra la API en modo debug y resume
qué decidió el motor de riesgo para cada uno.

Antes de CADA nivel vacía audit_log y device_fingerprints (TRUNCATE), para que las huellas de un
nivel no cuenten como "dispositivo reutilizado" en el siguiente.

Reproducibilidad: con la misma semilla y el mismo código, las ENTRADAS son las mismas (correos, IPs
simuladas y huellas del mismo Chromium). Los RESULTADOS pueden variar con el estado que no se
vacía: Redis guarda los límites por correo y la caché MX. Como los correos se repiten con la misma
semilla, correr la campaña más de 5 veces en 10 minutos choca con el límite por correo (429).

Uso: exporta la variable en la terminal para los dos comandos (si no, compose recrea la API sin el
modo debug al lanzar los bots):
    export DEBUG_CLIENT_IP_HEADER=true
    docker compose up -d
    docker compose --profile bots run --rm bots python scripts/run_campaign.py --tiers 1 --per-tier 10

La campaña escribe data/campaign_results.json y data/campaign_table.md (./data está montado en el
contenedor) y NUNCA toca el README. Para pasar la tabla al README hay un modo aparte, que solo usa
la librería estándar y se corre fuera de Docker (por ejemplo, desde Windows):
    python scripts/run_campaign.py --update-readme-from data/campaign_table.md
"""
import argparse
import json
import os
import statistics
import sys
from collections import Counter
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
ROOT = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))

# Solo librería estándar al importar: Playwright y psycopg se importan dentro de las funciones que
# los usan, así el modo --update-readme-from corre en cualquier Python.
import evasion_bot

DEFAULT_SEED = 20261030
DEFAULT_OUT = ROOT / "data" / "campaign_results.json"
DEFAULT_TABLE_OUT = ROOT / "data" / "campaign_table.md"
README = ROOT / "README.md"
TABLE_START = "<!-- CAMPAIGN_TABLE_START -->"
TABLE_END = "<!-- CAMPAIGN_TABLE_END -->"

# Límite por IP de la API: 40 registros cada 60 s, sobre la IP REAL (la del contenedor de bots).
# Con 1.6 s entre registros caben como mucho 38 en cualquier minuto.
MIN_SAFE_PACE_SECONDS = 1.6

ACTIONS = ("allow", "step_up", "review", "block")
TABLES_TO_RESET = ("audit_log", "device_fingerprints")
DEBUG_HINT = "levanta la API con DEBUG_CLIENT_IP_HEADER=true"
DEVICE_REUSE_SIGNALS = ("device_reuse_low", "device_reuse_high")


class CampaignError(RuntimeError):
    pass


def _risk_engine():
    """El motor real de backend/ (montado en solo lectura en el contenedor de bots). Se importa
    recién aquí: el modo --update-readme-from no lo necesita y debe correr solo con la librería estándar."""
    sys.path.insert(0, str(ROOT / "backend"))
    from services import risk_engine
    return risk_engine


def rescore(reasons: list[str], excluded: tuple[str, ...] = ()) -> tuple[int, str]:
    """Puntaje y acción que daría el motor con estas razones, sin las de `excluded`. Usa los pesos y
    umbrales reales del motor, con el mismo tope 0-100."""
    engine = _risk_engine()
    score = sum(engine.WEIGHTS[reason] for reason in reasons if reason not in excluded)
    score = max(0, min(engine.MAX_SCORE, score))
    action = engine.THRESHOLDS[0][1]
    for minimum, name in engine.THRESHOLDS:
        if score >= minimum:
            action = name
    return score, action


def without_device_reuse(result: dict) -> tuple[int, str]:
    return rescore(result["reasons"] or [], DEVICE_REUSE_SIGNALS)


def pace_warning(pace: float) -> str | None:
    if pace < MIN_SAFE_PACE_SECONDS:
        return (f"Aviso: --pace-seconds {pace} es menor que {MIN_SAFE_PACE_SECONDS} s; la campaña puede pasar "
                f"del límite de 40 registros por minuto desde la misma IP y recibir 429.")
    return None


def check_result(result: dict) -> None:
    """Corta la campaña en cuanto una respuesta no trae debug_risk, o si los pesos montados de
    backend/ no reproducen el puntaje de la API (las métricas sin device_reuse saldrían mal)."""
    if result["has_debug_risk"]:
        expected = (result["score"], result["action"])
        if rescore(result["reasons"]) != expected:
            raise CampaignError(f"Los pesos de backend/ dan {rescore(result['reasons'])} y la API dio {expected} "
                                f"para {result['reasons']}: reconstruye la imagen de la API (docker compose build api).")
        return
    if result["status"] is not None:
        # Es una decisión del motor, pero sin explicación: la API no está en modo debug.
        raise CampaignError(f"La respuesta no trae debug_risk: {DEBUG_HINT}.")
    raise CampaignError(f"La respuesta no trae debug_risk (HTTP {result['http_status']}, detail="
                        f"{result['detail']!r}): no es una decisión del motor. Si es 429, baja el ritmo; "
                        f"si no, {DEBUG_HINT}.")


def is_strict_evasion(action: str | None) -> bool:
    """Evasión estricta: la cuenta pasa sin ninguna fricción."""
    return action == "allow"


def is_lax_evasion(action: str | None) -> bool:
    """Evasión laxa: allow o step_up. El paso de verificación no existe todavía, así que step_up deja entrar."""
    return action in ("allow", "step_up")


def annotate(result: dict) -> dict:
    """Agrega al resultado el puntaje y la acción que habría sin device_reuse_low/high."""
    score, action = without_device_reuse(result)
    return {**result, "score_without_reuse": score, "action_without_reuse": action}


def summarize(results: list[dict]) -> list[dict]:
    """Una fila por nivel, en el orden en que se corrieron."""
    tiers = list(dict.fromkeys(r["tier"] for r in results))
    rows = []
    for tier in tiers:
        rows_of_tier = [r for r in results if r["tier"] == tier]
        actions = Counter(r["action"] for r in rows_of_tier)
        reasons = Counter(reason for r in rows_of_tier for reason in (r["reasons"] or []))
        scores = [r["score"] for r in rows_of_tier]
        rescored = [without_device_reuse(r) for r in rows_of_tier]
        scores_without = [score for score, _ in rescored]
        rows.append({
            "tier": tier,
            "registrations": len(rows_of_tier),
            "actions": {action: actions.get(action, 0) for action in ACTIONS},
            "strict_evasion": sum(is_strict_evasion(r["action"]) for r in rows_of_tier),
            "lax_evasion": sum(is_lax_evasion(r["action"]) for r in rows_of_tier),
            # Empates por nombre, para que la tabla sea estable.
            "top_reasons": sorted(reasons.items(), key=lambda item: (-item[1], item[0]))[:3],
            "score_median": statistics.median(scores),
            "score_min": min(scores),
            "score_median_without_reuse": statistics.median(scores_without),
            "score_min_without_reuse": min(scores_without),
            "actions_changed_without_reuse": sum(r["action"] != action for r, (_, action) in zip(rows_of_tier, rescored)),
        })
    return rows


def _share(count: int, total: int) -> str:
    return f"{count}/{total} ({count / total:.0%})" if total else "0/0"


def _number(value: float) -> str:
    # La mediana de una cantidad par de puntajes puede terminar en .5.
    return str(int(value)) if float(value).is_integer() else f"{value:.1f}"


def render_table(summary: list[dict]) -> str:
    lines = [
        "| Nivel | Registros | allow | step_up | review | block | Evasión estricta | Evasión laxa "
        "| Señales más frecuentes (top 3) | Score mediano | Score mínimo | Mediano sin device_reuse "
        "| Mínimo sin device_reuse | Cambian de acción sin device_reuse |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in summary:
        name = evasion_bot.TIER_NAMES.get(row["tier"])
        tier = f"{row['tier']} ({name})" if name else row["tier"]
        reasons = ", ".join(f"{reason} ({count})" for reason, count in row["top_reasons"]) or "—"
        total = row["registrations"]
        lines.append(
            f"| {tier} | {total} | " + " | ".join(str(row["actions"][a]) for a in ACTIONS)
            + f" | {_share(row['strict_evasion'], total)} | {_share(row['lax_evasion'], total)} | {reasons}"
            + f" | {_number(row['score_median'])} | {row['score_min']}"
            + f" | {_number(row['score_median_without_reuse'])} | {row['score_min_without_reuse']}"
            + f" | {row['actions_changed_without_reuse']}/{total} |"
        )
    return "\n".join(lines)


def replace_between_markers(text: str, table: str, newline: str = "\n") -> str:
    """Reemplaza lo que haya entre los dos marcadores del README; falla si no están (o están al revés)."""
    start, end = text.find(TABLE_START), text.find(TABLE_END)
    if start == -1 or end == -1 or end < start:
        raise CampaignError(f"El README no tiene los marcadores {TABLE_START} y {TABLE_END} (en ese orden); "
                            f"agrégalos donde va la tabla.")
    table = newline.join(table.splitlines())
    return f"{text[:start + len(TABLE_START)]}{newline}{table}{newline}{text[end:]}"


def update_readme_from(table_path: Path, readme: Path) -> None:
    """Pone en el README la tabla guardada por una campaña. Solo librería estándar."""
    try:
        table = table_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise CampaignError(f"No se pudo leer la tabla {table_path}: {exc.strerror or exc}")
    if not table:
        raise CampaignError(f"La tabla {table_path} está vacía")
    # newline="": se respetan los saltos de línea que ya tiene el README (CRLF en Windows, LF en Linux),
    # para que el cambio no ensucie el diff con todo el archivo.
    with open(readme, encoding="utf-8", newline="") as file:
        text = file.read()
    newline = "\r\n" if "\r\n" in text else "\n"
    updated = replace_between_markers(text, table, newline)
    with open(readme, "w", encoding="utf-8", newline="") as file:
        file.write(updated)


def reset_tables() -> list[str]:
    """TRUNCATE de las tablas que existan. Devuelve cuáles vació."""
    import psycopg  # Perezoso: solo hace falta en el contenedor de bots.

    emptied = []
    with psycopg.connect(
        # Mismas variables y defaults que el servicio postgres de docker-compose.yml.
        host=os.getenv("POSTGRES_HOST", "").strip() or "localhost",
        user=os.getenv("POSTGRES_USER", "").strip() or "guardian",
        password=os.getenv("POSTGRES_PASSWORD", "").strip() or "cambia_esto",
        dbname=os.getenv("POSTGRES_DB", "").strip() or "guardian",
        connect_timeout=5,
    ) as conn:
        for table in TABLES_TO_RESET:
            # La API crea las tablas al arrancar o en su primera escritura: puede que aún no existan.
            if conn.execute("SELECT to_regclass(%s)", (table,)).fetchone()[0] is not None:
                conn.execute(f"TRUNCATE {table}")
                emptied.append(table)
    return emptied


def _from_root(path: Path) -> str:
    """Ruta relativa a la raíz del repo, que vale igual dentro del contenedor (/work) y fuera."""
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Corre la campaña de evasión y resume las decisiones del motor.")
    parser.add_argument("--tiers", default="1,2,3", help="Niveles separados por comas, en orden")
    parser.add_argument("--per-tier", type=int, default=35)
    parser.add_argument("--pace-seconds", type=float, default=evasion_bot.DEFAULT_PACE_SECONDS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Resultados crudos en JSON")
    parser.add_argument("--table-out", type=Path, default=DEFAULT_TABLE_OUT, help="Tabla Markdown del resumen")
    parser.add_argument("--update-readme-from", type=Path, default=None, metavar="TABLA",
                        help=f"NO corre la campaña: solo copia esa tabla al README, entre {TABLE_START} "
                             f"y {TABLE_END}")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if args.update_readme_from is not None:
        try:
            update_readme_from(args.update_readme_from, README)
        except (CampaignError, OSError) as exc:
            sys.exit(f"No se actualizó el README: {exc}")
        print(f"Tabla de {args.update_readme_from} copiada en {README}")
        return

    tiers = [tier.strip() for tier in args.tiers.split(",") if tier.strip()]
    # Antes de vaciar nada: todos los niveles pedidos tienen que existir.
    try:
        for tier in tiers:
            evasion_bot.ensure_implemented(tier)
    except (ValueError, NotImplementedError) as exc:
        sys.exit(str(exc))
    warning = pace_warning(args.pace_seconds)
    if warning:
        print(warning, file=sys.stderr)

    results = []
    try:
        for tier in tiers:
            emptied = reset_tables()
            print(f"Nivel {tier}: tablas vaciadas ({', '.join(emptied) or 'ninguna existía'}); "
                  f"{args.per_tier} registros cada {args.pace_seconds} s...", flush=True)
            results += evasion_bot.run_tier(tier, args.per_tier, args.pace_seconds, args.seed,
                                            on_result=check_result)
    except CampaignError as exc:
        sys.exit(f"Campaña abortada: {exc}")

    summary = summarize(results)
    table = render_table(summary)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "seed": args.seed, "tiers": tiers, "per_tier": args.per_tier, "pace_seconds": args.pace_seconds,
        "summary": summary, "results": [annotate(result) for result in results],
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.table_out.parent.mkdir(parents=True, exist_ok=True)
    args.table_out.write_text(table + "\n", encoding="utf-8")
    print()
    print(table)
    print(f"\nResultados crudos en {_from_root(args.out)}")
    print(f"Tabla en {_from_root(args.table_out)} "
          f"(para el README: python scripts/run_campaign.py --update-readme-from {_from_root(args.table_out)})")


if __name__ == "__main__":
    main()
