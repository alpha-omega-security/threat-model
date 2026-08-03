"""Tier-4 robustness checks: determinism, sidecar round-trip, graceful failure."""
from __future__ import annotations

import io

import yaml

import mutate  # noqa: F401  (path wiring via conftest)
from threatmodel_eval import (
    Model, load_sidecar, run_prose_checks, run_sidecar_checks, validate,
)


def test_validation_is_deterministic():
    r1 = validate(mutate.GOLDEN_MODEL, mutate.GOLDEN_SIDECAR)
    r2 = validate(mutate.GOLDEN_MODEL, mutate.GOLDEN_SIDECAR)
    assert r1.failed_check_ids() == r2.failed_check_ids()
    assert r1.render(verbose=True) == r2.render(verbose=True)


def test_sidecar_round_trips_through_yaml():
    sidecar = load_sidecar(mutate.GOLDEN_SIDECAR)
    dumped = yaml.safe_dump(sidecar, sort_keys=False)
    reloaded = yaml.safe_load(io.StringIO(dumped))
    model = Model.from_file(mutate.GOLDEN_MODEL)
    report = run_sidecar_checks(reloaded, model)
    assert report.ok, report.render()


def test_docs_poor_model_fails_gracefully():
    # A near-empty document must be rejected with errors, not crash.
    thin = "# Threat model — mystery\n\n## 1.1 Header\n\nTODO.\n"
    report = run_prose_checks(Model.from_text(thin))
    assert not report.ok
    assert any(f.check_id.startswith("G2.section-1.") for f in report.errors)


def test_empty_document_does_not_crash():
    report = run_prose_checks(Model.from_text(""))
    assert not report.ok  # every required section missing
