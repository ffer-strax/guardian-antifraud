"""Genera cuentas SINTÉTICAS con etiqueta verdadera (legit/fraud) para medir el detector de grafos.

No llama a la API ni toca la base de datos: solo escribe un JSON. Nada de esto es tráfico real.
Con la misma semilla y los mismos parámetros, el archivo sale idéntico byte a byte.

Uso desde la raíz del repo (solo librería estándar; funciona en python:3.12-slim):
    python scripts/simulate_fraud.py
    python scripts/simulate_fraud.py --seed 7 --normal 1000 --out /tmp/cuentas.json
"""
import argparse
import copy
import ipaddress
import json
import random
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from services.asn_lookup import load_hosting_asns

VERSION = "simulate_fraud.py v1"
DEFAULT_SEED = 20261029
DEFAULT_OUT = ROOT / "data" / "synthetic_accounts.json"
DEFAULT_START = "2026-09-01T00:00:00Z"
HOSTING_ASNS_PATH = BACKEND_DIR / "data" / "hosting_asns.txt"

MINUTE = 60
HOUR = 60 * MINUTE
DAY = 24 * HOUR

# Las 7 señales de backend/services/behavior_signals.py (un test comprueba que coinciden).
BEHAVIOR_FLAGS = (
    "form_too_fast",
    "keystroke_uniform",
    "dwell_uniform",
    "mouse_linear",
    "no_mouse_movement",
    "no_keyboard_events",
    "behavior_missing",
)

FRAUD_ARCHETYPES = ("datacenter_bot", "residential_proxy_farm", "device_reuse_farm")
LEGIT_ARCHETYPES = ("normal", "shared_household", "internet_cafe", "shared_ip_noise")

# Probabilidad de que cada señal salga True por arquetipo. SON SUPUESTOS DEL SCRIPT, no mediciones.
_LEGIT_FLAGS = {
    "form_too_fast": 0.03,       # Autocompletado y envío rápido.
    "keystroke_uniform": 0.01,
    "dwell_uniform": 0.01,
    "mouse_linear": 0.02,
    "no_mouse_movement": 0.05,   # Gente que navega solo con teclado.
    "no_keyboard_events": 0.02,
    "behavior_missing": 0.02,    # JavaScript bloqueado.
}
FLAG_PROBABILITIES = {
    "normal": _LEGIT_FLAGS,
    "shared_household": _LEGIT_FLAGS,
    "internet_cafe": _LEGIT_FLAGS,
    "shared_ip_noise": _LEGIT_FLAGS,
    # El enunciado exige form_too_fast=True en todos los bots de datacenter.
    "datacenter_bot": {"form_too_fast": 1.0, "keystroke_uniform": 0.8, "dwell_uniform": 0.8,
                       "mouse_linear": 0.4, "no_mouse_movement": 0.5, "no_keyboard_events": 0.15,
                       "behavior_missing": 0.0},
    "residential_proxy_farm": {"form_too_fast": 0.5, "keystroke_uniform": 0.5, "dwell_uniform": 0.4,
                               "mouse_linear": 0.3, "no_mouse_movement": 0.2, "no_keyboard_events": 0.1,
                               "behavior_missing": 0.05},
    # Personas creando cuentas a mano, rápido: casi todo parece humano.
    "device_reuse_farm": {"form_too_fast": 0.3, "keystroke_uniform": 0.1, "dwell_uniform": 0.1,
                          "mouse_linear": 0.1, "no_mouse_movement": 0.1, "no_keyboard_events": 0.05,
                          "behavior_missing": 0.02},
}

# País -> (peso, zona horaria, idiomas, ASN residenciales inventados del rango privado RFC 6996).
COUNTRIES = {
    "MX": (60, "America/Mexico_City", ["es-MX", "es"], [64600, 64601, 64602]),
    "CO": (10, "America/Bogota", ["es-CO", "es"], [64610, 64611]),
    "AR": (10, "America/Argentina/Buenos_Aires", ["es-AR", "es"], [64620, 64621]),
    "ES": (10, "Europe/Madrid", ["es-ES", "es"], [64630, 64631]),
    "US": (10, "America/New_York", ["en-US", "en"], [64640, 64641]),
}

# Perfiles de dispositivo con valores típicos de navegadores reales.
DEVICE_PROFILES = [
    {"weight": 55, "platform": "Win32", "cores": [4, 8, 12, 16], "touch": 0, "depth": 24,
     "screens": [(1920, 1080), (1366, 768), (1536, 864), (2560, 1440)],
     "renderers": ["ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
                   "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)",
                   "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"]},
    {"weight": 15, "platform": "MacIntel", "cores": [8, 10], "touch": 0, "depth": 30,
     "screens": [(1440, 900), (1512, 982), (1728, 1117)],
     "renderers": ["ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)",
                   "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)"]},
    {"weight": 5, "platform": "Linux x86_64", "cores": [4, 8], "touch": 0, "depth": 24,
     "screens": [(1920, 1080)],
     "renderers": ["ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL 4.6)"]},
    {"weight": 10, "platform": "iPhone", "cores": [4, 6], "touch": 5, "depth": 24,
     "screens": [(390, 844), (393, 852), (375, 667)],
     "renderers": ["Apple GPU"]},
    {"weight": 15, "platform": "Linux armv8l", "cores": [8], "touch": 5, "depth": 24,
     "screens": [(412, 915), (360, 800)],
     "renderers": ["Adreno (TM) 610", "Mali-G52 MC2"]},
]

# Navegador sin cabeza en un servidor: pocos valores posibles (baja variedad).
HEADLESS_RENDERERS = [
    "Google SwiftShader",
    "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)",
]


# Una granja de fraude con menos cuentas no se distingue de un hogar o de ruido.
MIN_FARM_ACCOUNTS = 4


@dataclass(frozen=True)
class Config:
    seed: int = DEFAULT_SEED
    start: str = DEFAULT_START
    days: int = 60
    normal: int = 400
    farms_per_archetype: int = 5  # Granjas independientes de CADA arquetipo de fraude.
    datacenter_bots: int = 8      # Los tamaños son cuentas POR GRUPO.
    proxy_farm: int = 6
    device_farm: int = 6
    households: int = 20          # Hogares (cada uno con 2 o 3 cuentas).
    cafes: int = 3
    cafe_accounts: int = 12
    shared_ips: int = 3
    shared_ip_users: int = 45


def validate_config(config: Config) -> str | None:
    """Mensaje de error si la configuración no sirve; None si está bien."""
    if config.farms_per_archetype > 0:
        small = [f"{flag}={size}" for flag, size in (("--datacenter-bots", config.datacenter_bots),
                                                    ("--proxy-farm", config.proxy_farm),
                                                    ("--device-farm", config.device_farm))
                 if size < MIN_FARM_ACCOUNTS]
        if small:
            return (f"Cada granja de fraude necesita al menos {MIN_FARM_ACCOUNTS} cuentas; "
                    f"valores demasiado chicos: {', '.join(small)}")
    if config.datacenter_bots > 254:
        return "--datacenter-bots no puede pasar de 254 (las cuentas de una granja comparten un /24)"
    return None


def _parse_start(text: str) -> datetime:
    moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


@dataclass
class _Generator:
    config: Config
    hosting_asns: list[int]
    rng: random.Random = field(init=False)
    start: datetime = field(init=False)
    window: int = field(init=False)
    used_subnets: set = field(default_factory=set, init=False)
    accounts: list = field(default_factory=list, init=False)
    group_counters: dict = field(default_factory=dict, init=False)

    def __post_init__(self):
        # Generador local: nunca se toca el random global.
        self.rng = random.Random(self.config.seed)
        self.start = _parse_start(self.config.start)
        self.window = self.config.days * DAY

    # --- Piezas reutilizables ---

    def _new_subnet(self) -> str:
        """Un /24 público que nadie más usa: así no aparecen vecinos de red por casualidad."""
        while True:
            subnet = f"{self.rng.randint(1, 223)}.{self.rng.randint(0, 255)}.{self.rng.randint(0, 255)}"
            if subnet not in self.used_subnets and ipaddress.ip_address(f"{subnet}.1").is_global:
                self.used_subnets.add(subnet)
                return subnet

    def _host(self, subnet: str) -> str:
        return f"{subnet}.{self.rng.randint(1, 254)}"

    def _country(self) -> str:
        names = list(COUNTRIES)
        return self.rng.choices(names, weights=[COUNTRIES[name][0] for name in names])[0]

    def _residential_asn(self, country: str) -> int:
        return self.rng.choice(COUNTRIES[country][3])

    def _canvas_hash(self) -> str:
        return f"{self.rng.getrandbits(256):064x}"

    def _device(self, country: str) -> dict:
        profile = self.rng.choices(DEVICE_PROFILES, weights=[p["weight"] for p in DEVICE_PROFILES])[0]
        width, height = self.rng.choice(profile["screens"])
        return {
            "canvasHash": self._canvas_hash(),
            "webglRenderer": self.rng.choice(profile["renderers"]),
            "hardwareConcurrency": self.rng.choice(profile["cores"]),
            "screen": {"width": width, "height": height, "colorDepth": profile["depth"]},
            "languages": list(COUNTRIES[country][2]),
            "platform": profile["platform"],
            "maxTouchPoints": profile["touch"],
        }

    def _headless_device(self) -> dict:
        width, height = self.rng.choice([(800, 600), (1920, 1080)])
        return {
            "canvasHash": self._canvas_hash(),
            "webglRenderer": self.rng.choice(HEADLESS_RENDERERS),
            "hardwareConcurrency": self.rng.choice([2, 4]),
            "screen": {"width": width, "height": height, "colorDepth": 24},
            "languages": ["en-US"],
            "platform": "Linux x86_64",
            "maxTouchPoints": 0,
        }

    def _flags(self, archetype: str, fingerprint: dict) -> dict:
        probabilities = FLAG_PROBABILITIES[archetype]
        flags = {name: self.rng.random() < probabilities[name] for name in BEHAVIOR_FLAGS}
        # Combinaciones imposibles en behavior_signals.py se corrigen para que el dato sea coherente.
        if flags["behavior_missing"]:
            return {name: name == "behavior_missing" for name in BEHAVIOR_FLAGS}
        if fingerprint["maxTouchPoints"] > 0:
            flags["mouse_linear"] = False
            flags["no_mouse_movement"] = False
        if flags["no_mouse_movement"]:
            flags["mouse_linear"] = False
        if flags["no_keyboard_events"]:
            flags["keystroke_uniform"] = False
            flags["dwell_uniform"] = False
        return flags

    def _group_id(self, prefix: str) -> str:
        self.group_counters[prefix] = self.group_counters.get(prefix, 0) + 1
        return f"{prefix}-{self.group_counters[prefix]:02d}"

    def _staggered_start(self, index: int, total: int, span: int) -> int:
        """Inicio del grupo `index` de `total`: la ventana se parte en `total` franjas y cada grupo
        empieza al azar dentro de la suya, así los del mismo arquetipo no arrancan a la vez."""
        room = max(0, self.window - span)
        slot = room // total
        return index * slot + self.rng.randint(0, slot)

    def _offsets(self, count: int, span: int, begin: int) -> list[int]:
        """`count` instantes ordenados dentro de un tramo de `span` segundos que empieza en `begin`."""
        return sorted(begin + self.rng.randint(0, span) for _ in range(count))

    def _add(self, archetype: str, group_id: str | None, offset: int, ip: str, asn: int,
             is_hosting: bool, country: str, fingerprint: dict, tz: str) -> None:
        created = self.start + timedelta(seconds=offset)
        self.accounts.append({
            "account_id": None,  # Se asigna al final, después de ordenar por fecha.
            "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ip": ip,
            "asn": asn,
            "is_hosting": is_hosting,
            "country": country,
            "fingerprint": fingerprint,
            "timezone": tz,
            "behavior_flags": self._flags(archetype, fingerprint),
            "label": "fraud" if archetype in FRAUD_ARCHETYPES else "legit",
            "archetype": archetype,
            "group_id": group_id,
        })

    # --- Arquetipos de fraude ---

    # Cada grupo pide su propio /24 nuevo y su propio dispositivo (canvas aleatorio de 256 bits):
    # ningún grupo comparte IP, /24 ni dispositivo con otro, y el grafo no los fusiona por accidente.

    def datacenter_bots(self) -> None:
        """Por granja: IPs de hosting del mismo /24, huellas distintas pero de baja variedad, en minutos."""
        farms, count = self.config.farms_per_archetype, self.config.datacenter_bots
        for index in range(farms):
            subnet = self._new_subnet()
            asn = self.rng.choice(self.hosting_asns)
            group = self._group_id("datacenter_bot")
            hosts = self.rng.sample(range(1, 255), count)
            span = self.rng.randint(5 * MINUTE, 30 * MINUTE)
            begin = self._staggered_start(index, farms, span)
            for host, offset in zip(hosts, self._offsets(count, span, begin)):
                self._add("datacenter_bot", group, offset, f"{subnet}.{host}", asn, True, "US",
                          self._headless_device(), "UTC")

    def residential_proxy_farm(self) -> None:
        """Por granja: un /24 distinto por cuenta y sin hosting, pero el mismo dispositivo, en pocas horas."""
        farms, count = self.config.farms_per_archetype, self.config.proxy_farm
        for farm in range(farms):
            device = self._device("MX")
            # A mitad de la campaña el navegador se actualiza: solo cambia el canvas.
            updated_canvas = self._canvas_hash()
            update_at = count // 2
            group = self._group_id("proxy_farm")
            span = self.rng.randint(2 * HOUR, 4 * HOUR)
            begin = self._staggered_start(farm, farms, span)
            for index, offset in enumerate(self._offsets(count, span, begin)):
                fingerprint = copy.deepcopy(device)
                if index >= update_at:
                    fingerprint["canvasHash"] = updated_canvas
                subnet = self._new_subnet()
                self._add("residential_proxy_farm", group, offset, self._host(subnet),
                          self._residential_asn("MX"), False, "MX", fingerprint, COUNTRIES["MX"][1])

    def device_reuse_farm(self) -> None:
        """Por granja: el mismo dispositivo y la misma IP, todas las cuentas en unos 10 minutos."""
        farms, count = self.config.farms_per_archetype, self.config.device_farm
        for index in range(farms):
            ip = self._host(self._new_subnet())
            asn = self._residential_asn("MX")
            device = self._device("MX")
            group = self._group_id("device_farm")
            begin = self._staggered_start(index, farms, 10 * MINUTE)
            for offset in self._offsets(count, 10 * MINUTE, begin):
                self._add("device_reuse_farm", group, offset, ip, asn, False, "MX",
                          copy.deepcopy(device), COUNTRIES["MX"][1])

    # --- Arquetipos legítimos ---

    def normal_users(self) -> None:
        """Usuarios independientes: dispositivo e IP propios, a lo largo de toda la ventana."""
        for _ in range(self.config.normal):
            country = self._country()
            ip = self._host(self._new_subnet())
            self._add("normal", None, self.rng.randint(0, self.window), ip, self._residential_asn(country),
                      False, country, self._device(country), COUNTRIES[country][1])

    def shared_households(self) -> None:
        """Grupos de 2-3 cuentas con el mismo dispositivo e IP, separadas por días o semanas."""
        total = self.config.households
        for index in range(total):
            size = self.rng.choice([2, 3])
            gaps = [self.rng.randint(3 * DAY, 21 * DAY) for _ in range(size - 1)]
            offset = self._staggered_start(index, total, sum(gaps))
            country = self._country()
            ip = self._host(self._new_subnet())
            asn = self._residential_asn(country)
            device = self._device(country)
            group = self._group_id("household")
            for gap in [0] + gaps:
                offset += gap
                self._add("shared_household", group, offset, ip, asn, False, country,
                          copy.deepcopy(device), COUNTRIES[country][1])

    def internet_cafe(self) -> None:
        """Por cibercafé: un dispositivo y una IP con cuentas de personas distintas, repartidas en semanas."""
        cafes, count = self.config.cafes, self.config.cafe_accounts
        for index in range(cafes):
            span = self.rng.randint(14 * DAY, 42 * DAY)
            begin = self._staggered_start(index, cafes, span)
            # La primera y la última quedan en los extremos: el tramo mide `span` seguro.
            middle = [begin + self.rng.randint(0, span) for _ in range(max(0, count - 2))]
            offsets = sorted([begin, begin + span][:count] + middle)
            ip = self._host(self._new_subnet())
            asn = self._residential_asn("MX")
            device = self._device("MX")
            group = self._group_id("cafe")
            for offset in offsets:
                self._add("internet_cafe", group, offset, ip, asn, False, "MX",
                          copy.deepcopy(device), COUNTRIES["MX"][1])

    def shared_ip_noise(self) -> None:
        """Por IP compartida (escuela o CGNAT): muchos usuarios, cada uno con su dispositivo."""
        shared_ips, count = self.config.shared_ips, self.config.shared_ip_users
        for index in range(shared_ips):
            # Cada IP está activa al menos media ventana, empezando en su propia franja.
            span = self.rng.randint(self.window // 2, self.window)
            begin = self._staggered_start(index, shared_ips, span)
            ip = self._host(self._new_subnet())
            asn = self._residential_asn("MX")
            group = self._group_id("shared_ip")
            for _ in range(count):
                self._add("shared_ip_noise", group, begin + self.rng.randint(0, span), ip, asn, False, "MX",
                          self._device("MX"), COUNTRIES["MX"][1])

    def run(self) -> list[dict]:
        self.datacenter_bots()
        self.residential_proxy_farm()
        self.device_reuse_farm()
        self.normal_users()
        self.shared_households()
        self.internet_cafe()
        self.shared_ip_noise()
        # Orden por fecha (desempates fijos) e ids secuenciales: no dependen del orden de generación.
        self.accounts.sort(key=lambda a: (a["created_at"], a["archetype"], a["ip"], a["fingerprint"]["canvasHash"]))
        for number, account in enumerate(self.accounts, start=1):
            account["account_id"] = f"acc-{number:05d}"
        return self.accounts


def groups_per_archetype(accounts: list[dict]) -> dict:
    """Grupos distintos de cada arquetipo (los usuarios normales no tienen grupo)."""
    return {
        archetype: len({a["group_id"] for a in accounts if a["archetype"] == archetype and a["group_id"]})
        for archetype in FRAUD_ARCHETYPES + LEGIT_ARCHETYPES
    }


def generate(config: Config, hosting_asns: list[int]) -> dict:
    """Documento completo: cabecera honesta + lista de cuentas."""
    error = validate_config(config)
    if error:
        raise ValueError(error)
    if config.farms_per_archetype > 0 and not hosting_asns:
        raise ValueError("Hace falta al menos un ASN de hosting para los bots de datacenter")
    accounts = _Generator(config, sorted(hosting_asns)).run()
    return {
        "synthetic": True,
        "description": "Cuentas SINTÉTICAS generadas por un script para medir un detector. "
                       "No representan tráfico ni usuarios reales.",
        "seed": config.seed,
        "generated_with": VERSION,
        "parameters": asdict(config),
        "groups_per_archetype": groups_per_archetype(accounts),
        "notes": [
            "ip, asn y country son inventados; una IP puede coincidir por azar con una real, pero no la representa.",
            "Los ASN residenciales son del rango privado 64512-65534 (RFC 6996); "
            "los de hosting vienen de backend/data/hosting_asns.txt.",
            "Las probabilidades de behavior_flags son supuestos del script, no mediciones.",
            "label, archetype y group_id son la verdad de referencia: el detector no debe leerlos.",
        ],
        "accounts": accounts,
    }


def to_json(document: dict) -> str:
    # Sin hora de generación ni nada que dependa del sistema: mismo contenido, mismos bytes.
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def summary(document: dict) -> str:
    accounts = document["accounts"]
    parameters = ", ".join(f"{key}={value}" for key, value in document["parameters"].items())
    lines = [f"Cuentas sintéticas: {len(accounts)} (semilla {document['seed']})",
             f"  Parámetros: {parameters}"]
    for archetype in FRAUD_ARCHETYPES + LEGIT_ARCHETYPES:
        count = sum(1 for a in accounts if a["archetype"] == archetype)
        groups = document["groups_per_archetype"][archetype]
        label = "fraud" if archetype in FRAUD_ARCHETYPES else "legit"
        lines.append(f"  {archetype:<24} {label:<6} {count:>5} cuentas  {groups:>3} grupos")
    for label in ("fraud", "legit"):
        lines.append(f"  total {label:<18} {sum(1 for a in accounts if a['label'] == label):>12}")
    return "\n".join(lines)


def _non_negative(text: str) -> int:
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("debe ser 0 o mayor")
    return value


def parse_args(argv: list[str] | None = None) -> tuple[Config, Path]:
    defaults = Config()
    parser = argparse.ArgumentParser(description="Genera cuentas sintéticas con etiqueta verdadera.")
    parser.add_argument("--seed", type=int, default=defaults.seed)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--start", default=defaults.start, help="Fecha base en ISO 8601 (UTC)")
    parser.add_argument("--days", type=_non_negative, default=defaults.days, help="Ventana de tiempo en días")
    parser.add_argument("--normal", type=_non_negative, default=defaults.normal)
    parser.add_argument("--farms-per-archetype", type=_non_negative, default=defaults.farms_per_archetype,
                        help="Granjas independientes de cada arquetipo de fraude")
    parser.add_argument("--datacenter-bots", type=_non_negative, default=defaults.datacenter_bots,
                        help="Cuentas por granja de bots de datacenter")
    parser.add_argument("--proxy-farm", type=_non_negative, default=defaults.proxy_farm,
                        help="Cuentas por granja de proxies residenciales")
    parser.add_argument("--device-farm", type=_non_negative, default=defaults.device_farm,
                        help="Cuentas por granja de un solo dispositivo")
    parser.add_argument("--households", type=_non_negative, default=defaults.households,
                        help="Número de hogares (cada uno con 2 o 3 cuentas)")
    parser.add_argument("--cafes", type=_non_negative, default=defaults.cafes,
                        help="Número de cibercafés independientes")
    parser.add_argument("--cafe-accounts", type=_non_negative, default=defaults.cafe_accounts,
                        help="Cuentas por cibercafé")
    parser.add_argument("--shared-ips", type=_non_negative, default=defaults.shared_ips,
                        help="Número de IPs compartidas (escuela o CGNAT) independientes")
    parser.add_argument("--shared-ip-users", type=_non_negative, default=defaults.shared_ip_users,
                        help="Usuarios por IP compartida")
    args = parser.parse_args(argv)
    try:
        _parse_start(args.start)
    except ValueError:
        parser.error("--start debe ser una fecha ISO 8601, por ejemplo 2026-09-01T00:00:00Z")
    config = Config(
        seed=args.seed, start=args.start, days=args.days, normal=args.normal,
        farms_per_archetype=args.farms_per_archetype, datacenter_bots=args.datacenter_bots,
        proxy_farm=args.proxy_farm, device_farm=args.device_farm, households=args.households,
        cafes=args.cafes, cafe_accounts=args.cafe_accounts,
        shared_ips=args.shared_ips, shared_ip_users=args.shared_ip_users,
    )
    error = validate_config(config)
    if error:
        parser.error(error)
    return config, args.out


def main(argv: list[str] | None = None) -> None:
    config, out = parse_args(argv)
    document = generate(config, list(load_hosting_asns(HOSTING_ASNS_PATH)))
    out.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n": mismos bytes en Windows y en Linux.
    with open(out, "w", encoding="utf-8", newline="\n") as file:
        file.write(to_json(document))
    print(summary(document))
    print(f"Escrito {out}")


if __name__ == "__main__":
    main()
