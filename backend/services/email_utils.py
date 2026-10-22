from pathlib import Path

GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}

_DISPOSABLE_FILE = Path(__file__).resolve().parent.parent / "data" / "disposable_domains.txt"


def _load_disposable_domains() -> set[str]:
    lines = _DISPOSABLE_FILE.read_text(encoding="utf-8").splitlines()
    return {line.strip().lower() for line in lines if line.strip()}


# Se carga una sola vez, cuando Python importa este módulo.
DISPOSABLE_DOMAINS = _load_disposable_domains()


def canonicalize_email(email: str) -> str:
    email = email.strip().lower()
    local, sep, domain = email.rpartition("@")
    if not sep:
        return email

    if domain in GMAIL_DOMAINS:
        local = local.split("+", 1)[0].replace(".", "")
        domain = "gmail.com"

    return f"{local}@{domain}"


def is_disposable(domain: str) -> bool:
    return domain in DISPOSABLE_DOMAINS
