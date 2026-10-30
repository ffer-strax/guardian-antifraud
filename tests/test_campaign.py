import importlib.util
import json
import sys
from pathlib import Path

import pytest

from services.email_utils import canonicalize_email

ROOT = Path(__file__).resolve().parents[1]

# run_campaign.py agrega scripts/ al path e importa evasion_bot: se carga desde su ruta.
_spec = importlib.util.spec_from_file_location("run_campaign", ROOT / "scripts" / "run_campaign.py")
run_campaign = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_campaign)
evasion_bot = run_campaign.evasion_bot


def _result(action, reasons=(), tier="1", index=0, debug=True, status=None, http_status=200):
    body = {"status": status or {"allow": "ok", "step_up": "verification_required",
                                 "review": "pending_review", "block": "blocked"}.get(action)}
    if debug:
        body["debug_risk"] = {"score": 0, "action": action, "reasons": list(reasons), "unverified": []}
    return evasion_bot.to_result(tier, index, http_status, body, 0.5)


# --- Bot ---

def test_importing_the_bot_does_not_load_playwright():
    # En la CI no hay Playwright: se importa recién dentro de run_tier.
    assert "playwright" not in sys.modules


def test_bot_emails_are_deterministic_and_distinct():
    assert evasion_bot.bot_email(1, "1", 0) == evasion_bot.bot_email(1, "1", 0)
    emails = [evasion_bot.bot_email(20261030, "1", i) for i in range(35)]
    assert all(e.endswith("@gmail.com") for e in emails)
    # Distintos también después de canonicalizar (Gmail ignora puntos y +etiquetas).
    assert len({canonicalize_email(e) for e in emails}) == 35
    assert evasion_bot.bot_email(1, "1", 0) != evasion_bot.bot_email(2, "1", 0)
    assert evasion_bot.bot_email(1, "1", 0) != evasion_bot.bot_email(1, "2", 0)


def test_result_reads_debug_risk():
    result = _result("step_up", ["hosting_ip", "form_too_fast"])
    assert (result["action"], result["reasons"], result["has_debug_risk"]) == (
        "step_up", ["hosting_ip", "form_too_fast"], True)
    missing = evasion_bot.to_result("1", 0, 429, {"detail": "rate_limited"}, 0.1)
    assert (missing["action"], missing["has_debug_risk"], missing["detail"]) == (None, False, "rate_limited")


def test_browser_is_full_chromium_with_secure_origin_flag():
    # El headless-shell por defecto ignora el flag y el canvasHash saldría en fnv1a, no en SHA-256.
    options = evasion_bot.launch_options()
    assert options["headless"] is True
    assert options["channel"] == "chromium"
    assert f"--unsafely-treat-insecure-origin-as-secure={evasion_bot.API_URL}" in options["args"]


def test_unimplemented_tiers_fail_clearly():
    for tier in ("2", "3", "3b"):
        with pytest.raises(NotImplementedError, match=f"nivel {tier}"):
            evasion_bot.ensure_implemented(tier)
    with pytest.raises(ValueError, match="desconocido"):
        evasion_bot.ensure_implemented("9")


# --- Agregación y evasión ---

@pytest.mark.parametrize("action, strict, lax", [
    ("allow", True, True),
    ("step_up", False, True),
    ("review", False, False),
    ("block", False, False),
])
def test_strict_versus_lax_evasion(action, strict, lax):
    assert run_campaign.is_strict_evasion(action) is strict
    assert run_campaign.is_lax_evasion(action) is lax


SAMPLE = [
    _result("allow", ["tz_utc"]),
    _result("step_up", ["hosting_ip", "form_too_fast"]),
    _result("step_up", ["hosting_ip", "form_too_fast"]),
    _result("review", ["hosting_ip", "form_too_fast", "device_reuse_low"]),
    _result("block", ["hosting_ip", "form_too_fast", "device_reuse_high"]),
    _result("block", ["hosting_ip", "device_reuse_high"]),
]


def test_summary_counts_actions_and_evasion():
    [row] = run_campaign.summarize(SAMPLE)
    assert row["registrations"] == 6
    assert row["actions"] == {"allow": 1, "step_up": 2, "review": 1, "block": 2}
    assert (row["strict_evasion"], row["lax_evasion"]) == (1, 3)
    assert row["top_reasons"] == [("hosting_ip", 5), ("form_too_fast", 4), ("device_reuse_high", 2)]


def test_summary_keeps_tier_order():
    results = [_result("allow", tier="1"), _result("block", tier="3"), _result("allow", tier="1")]
    assert [row["tier"] for row in run_campaign.summarize(results)] == ["1", "3"]


def test_render_table():
    table = run_campaign.render_table(run_campaign.summarize(SAMPLE))
    lines = table.splitlines()
    assert lines[0] == ("| Nivel | Registros | allow | step_up | review | block | Evasión estricta | Evasión laxa "
                        "| Señales más frecuentes (top 3) |")
    assert lines[2] == ("| 1 (bot ingenuo) | 6 | 1 | 2 | 1 | 2 | 1/6 (17%) | 3/6 (50%) "
                        "| hosting_ip (5), form_too_fast (4), device_reuse_high (2) |")


# --- README ---

def test_readme_markers_are_replaced():
    text = f"antes\n{run_campaign.TABLE_START}\ntabla vieja\n{run_campaign.TABLE_END}\ndespués\n"
    updated = run_campaign.replace_between_markers(text, "| nueva |")
    assert updated == f"antes\n{run_campaign.TABLE_START}\n| nueva |\n{run_campaign.TABLE_END}\ndespués\n"


@pytest.mark.parametrize("text", [
    "README sin marcadores",
    f"{run_campaign.TABLE_END}\n{run_campaign.TABLE_START}",  # Al revés.
])
def test_readme_without_markers_fails_clearly(text):
    with pytest.raises(run_campaign.CampaignError, match="marcadores"):
        run_campaign.replace_between_markers(text, "| nueva |")


# --- Comprobaciones de la campaña ---

def test_decision_without_debug_risk_is_rejected():
    with pytest.raises(run_campaign.CampaignError, match="DEBUG_CLIENT_IP_HEADER=true"):
        run_campaign.check_result(_result("allow", debug=False))


def test_error_response_is_rejected_with_its_code():
    rate_limited = evasion_bot.to_result("1", 0, 429, {"detail": "rate_limited"}, 0.1)
    with pytest.raises(run_campaign.CampaignError, match="HTTP 429"):
        run_campaign.check_result(rate_limited)


def test_result_with_debug_risk_passes():
    run_campaign.check_result(_result("block"))


@pytest.mark.parametrize("pace, warns", [(1.0, True), (1.59, True), (1.6, False), (2.0, False)])
def test_pace_warning(pace, warns):
    assert (run_campaign.pace_warning(pace) is not None) is warns


# --- main() con el navegador y la base reemplazados ---

@pytest.fixture
def fake_campaign(monkeypatch, tmp_path):
    events = []
    # Que ningún test escriba data/campaign_table.md en el repo.
    monkeypatch.setattr(run_campaign, "DEFAULT_TABLE_OUT", tmp_path / "campaign_table.md")

    def fake_reset():
        events.append("reset")
        return ["audit_log", "device_fingerprints"]

    def fake_run_tier(tier, n, pace, seed, on_result=None):
        events.append(f"run {tier}")
        results = [_result("step_up", ["hosting_ip"], tier=tier, index=i) for i in range(n)]
        for result in results:
            on_result(result)
        return results

    monkeypatch.setattr(run_campaign, "reset_tables", fake_reset)
    monkeypatch.setattr(evasion_bot, "run_tier", fake_run_tier)
    return events


def test_tables_are_reset_before_each_tier(fake_campaign, tmp_path, capsys):
    out = tmp_path / "campaign.json"
    run_campaign.main(["--tiers", "1,1", "--per-tier", "2", "--out", str(out)])
    assert fake_campaign == ["reset", "run 1", "reset", "run 1"]
    saved = json.loads(out.read_text(encoding="utf-8"))
    assert len(saved["results"]) == 4
    assert "| 1 (bot ingenuo) | 4 |" in capsys.readouterr().out


def test_unimplemented_tier_aborts_before_touching_the_database(fake_campaign, tmp_path):
    with pytest.raises(SystemExit, match="nivel 2"):
        run_campaign.main(["--tiers", "1,2", "--out", str(tmp_path / "x.json")])
    assert fake_campaign == []


def test_campaign_aborts_when_api_is_not_in_debug_mode(monkeypatch, tmp_path):
    def run_without_debug(tier, n, pace, seed, on_result=None):
        on_result(_result("allow", debug=False))

    monkeypatch.setattr(run_campaign, "reset_tables", lambda: [])
    monkeypatch.setattr(evasion_bot, "run_tier", run_without_debug)
    with pytest.raises(SystemExit, match="DEBUG_CLIENT_IP_HEADER=true"):
        run_campaign.main(["--tiers", "1", "--out", str(tmp_path / "x.json")])


def test_low_pace_prints_a_warning(fake_campaign, tmp_path, capsys):
    run_campaign.main(["--tiers", "1", "--per-tier", "1", "--pace-seconds", "1", "--out", str(tmp_path / "x.json")])
    assert "Aviso" in capsys.readouterr().err


def test_campaign_writes_table_file(fake_campaign, tmp_path, capsys):
    table_out = tmp_path / "tabla.md"
    run_campaign.main(["--tiers", "1", "--per-tier", "2", "--out", str(tmp_path / "x.json"),
                       "--table-out", str(table_out)])
    table = table_out.read_text(encoding="utf-8")
    assert table.startswith("| Nivel | Registros |")
    assert "| 1 (bot ingenuo) | 2 |" in table
    assert table.strip() in capsys.readouterr().out


# --- Modo --update-readme-from (solo librería estándar, sin campaña) ---

@pytest.fixture
def readme_mode(fake_campaign, monkeypatch, tmp_path):
    # Si el modo importara psycopg o Playwright, estas entradas lo harían fallar.
    for module in ("psycopg", "playwright", "playwright.sync_api"):
        monkeypatch.setitem(sys.modules, module, None)
    readme = tmp_path / "README.md"
    monkeypatch.setattr(run_campaign, "README", readme)
    table = tmp_path / "campaign_table.md"
    table.write_text("| Nivel | Registros |\n|---|---|\n| 1 (bot ingenuo) | 10 |\n", encoding="utf-8")
    return readme, table, fake_campaign


def test_update_readme_from_table_without_running_campaign(readme_mode):
    readme, table, events = readme_mode
    readme.write_text(f"# R\n{run_campaign.TABLE_START}\nvieja\n{run_campaign.TABLE_END}\nfin\n", encoding="utf-8")
    run_campaign.main(["--update-readme-from", str(table)])
    assert readme.read_text(encoding="utf-8") == (
        f"# R\n{run_campaign.TABLE_START}\n| Nivel | Registros |\n|---|---|\n| 1 (bot ingenuo) | 10 |\n"
        f"{run_campaign.TABLE_END}\nfin\n")
    assert events == []  # Ni vació tablas ni corrió bots.


def test_update_readme_from_keeps_windows_line_endings(readme_mode):
    readme, table, _ = readme_mode
    original = f"# R\r\n{run_campaign.TABLE_START}\r\nvieja\r\n{run_campaign.TABLE_END}\r\nfin\r\n"
    readme.write_bytes(original.encode("utf-8"))
    run_campaign.main(["--update-readme-from", str(table)])
    updated = readme.read_bytes().decode("utf-8")
    assert "| 1 (bot ingenuo) | 10 |\r\n" in updated
    assert "\n" not in updated.replace("\r\n", "")  # Ningún LF suelto.


def test_update_readme_from_without_markers_leaves_readme_untouched(readme_mode):
    readme, table, _ = readme_mode
    readme.write_text("# README sin marcadores\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="marcadores"):
        run_campaign.main(["--update-readme-from", str(table)])
    assert readme.read_text(encoding="utf-8") == "# README sin marcadores\n"


def test_update_readme_from_missing_table_fails_clearly(readme_mode, tmp_path):
    readme, _, _ = readme_mode
    readme.write_text(f"{run_campaign.TABLE_START}\n{run_campaign.TABLE_END}\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="No se pudo leer la tabla"):
        run_campaign.main(["--update-readme-from", str(tmp_path / "no_existe.md")])


def test_readme_is_not_touched_by_default(fake_campaign, monkeypatch, tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("original", encoding="utf-8")
    monkeypatch.setattr(run_campaign, "README", readme)
    run_campaign.main(["--tiers", "1", "--per-tier", "1", "--out", str(tmp_path / "x.json")])
    assert readme.read_text(encoding="utf-8") == "original"
