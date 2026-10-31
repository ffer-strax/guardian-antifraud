import importlib.util
import random
import statistics
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Se carga desde su ruta, como los otros scripts. Solo se prueban las funciones puras: sin red ni Docker.
_spec = importlib.util.spec_from_file_location("measure_latency", ROOT / "scripts" / "measure_latency.py")
measure_latency = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(measure_latency)


# --- Percentiles ---

def test_percentile_interpolates_between_neighbors():
    values = list(range(1, 101))
    assert measure_latency.percentile(values, 50) == pytest.approx(50.5)
    assert measure_latency.percentile(values, 95) == pytest.approx(95.05)
    assert measure_latency.percentile(values, 99) == pytest.approx(99.01)


@pytest.mark.parametrize("p", [1, 25, 50, 90, 95, 99])
def test_percentile_matches_statistics_quantiles(p):
    rng = random.Random(p)
    values = [rng.uniform(5, 400) for _ in range(137)]
    expected = statistics.quantiles(values, n=100, method="inclusive")[p - 1]
    assert measure_latency.percentile(values, p) == pytest.approx(expected)


def test_percentile_does_not_depend_on_order():
    values = [30.0, 10.0, 50.0, 20.0, 40.0]
    assert measure_latency.percentile(values, 95) == measure_latency.percentile(sorted(values), 95)
    assert values == [30.0, 10.0, 50.0, 20.0, 40.0]  # No ordena la lista que recibe.


def test_percentile_edges():
    assert measure_latency.percentile([7.0], 95) == 7.0
    assert measure_latency.percentile([3.0, 1.0, 2.0], 0) == 1.0
    assert measure_latency.percentile([3.0, 1.0, 2.0], 100) == 3.0


@pytest.mark.parametrize("values, p", [([], 50), ([1.0], -1), ([1.0], 101)])
def test_percentile_rejects_invalid_input(values, p):
    with pytest.raises(ValueError):
        measure_latency.percentile(values, p)


def test_latency_stats_summary():
    values = [100.0] * 90 + [400.0] * 10
    stats = measure_latency.latency_stats(values)
    assert stats["n"] == 100
    assert stats["p50_ms"] == 100.0
    assert stats["p95_ms"] == 400.0
    assert stats["p99_ms"] == 400.0
    assert stats["max_ms"] == 400.0
    assert stats["over_target_pct"] == 10.0
    assert stats["p95_below_target"] is False


def test_exactly_300_ms_is_not_over_but_p95_must_be_below():
    stats = measure_latency.latency_stats([300.0] * 20)
    assert stats["over_target_pct"] == 0.0
    assert stats["p95_below_target"] is False
    assert measure_latency.latency_stats([299.9] * 20)["p95_below_target"] is True


def test_latency_stats_without_valid_responses():
    stats = measure_latency.latency_stats([])
    assert stats["n"] == 0
    assert stats["p95_ms"] is None
    assert stats["p95_below_target"] is None


# --- Clasificación de códigos de estado ---

@pytest.mark.parametrize("code", [200, 202, 403])
def test_engine_decisions_count_for_latency(code):
    assert measure_latency.classify_status(code) == measure_latency.SCORED


def test_400_and_429_are_counted_apart():
    assert measure_latency.classify_status(400) == measure_latency.REJECTED
    assert measure_latency.classify_status(429) == measure_latency.RATE_LIMITED


@pytest.mark.parametrize("code", [201, 401, 404, 422, 500, 503])
def test_other_codes_do_not_count(code):
    assert measure_latency.classify_status(code) == measure_latency.OTHER
