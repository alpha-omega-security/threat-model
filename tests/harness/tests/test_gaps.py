"""Tests for the gap analyzer — the honesty signal a job surfaces.

Confirms the analyzer reads the golden model's own uncertainty markers and
that a deliberately thin / inconsistent model lights up the right gap fields.
"""
from __future__ import annotations

import mutate
from threatmodel_eval import (
    Model, analyze_gaps, run_prose_checks, run_sidecar_checks, load_sidecar,
)


def _analyze(model_src, sidecar: dict | None = None, preds=None):
    model = model_src if isinstance(model_src, Model) else Model.from_text(model_src)
    report = run_prose_checks(model)
    if sidecar is not None:
        report.extend(run_sidecar_checks(sidecar, model).findings)
    return analyze_gaps(model, report, preds), model, report


def _golden():
    return Model.from_file(mutate.GOLDEN_MODEL)


def test_golden_gap_report_is_clean():
    gr, _, _ = _analyze(_golden(), load_sidecar(mutate.GOLDEN_SIDECAR))
    assert gr.validation_errors == 0
    assert not gr.missing_sections
    assert not gr.dangling_inferred
    # The golden carries provenance counts and, if any inferred claims remain,
    # a matching §1.18 question for each.
    assert gr.confidence  # documented/maintainer/inferred present
    d = gr.to_dict()
    assert set(d) >= {"status", "confidence", "open_questions",
                      "missing_sections", "validation_errors"}


def test_open_questions_are_extracted():
    gr, model, _ = _analyze(_golden(),
                            load_sidecar(mutate.GOLDEN_SIDECAR))
    assert gr.open_questions == sorted(
        model.open_question_ids(),
        key=lambda q: int(q[1:]) if q[1:].isdigit() else 0)


def test_thin_model_reports_missing_sections():
    thin = "\n".join(
        f"## {n}. Placeholder\n\nN/A\n" for n in range(1, 4))
    gr, _, _ = _analyze("# Threat model\n\n" + thin)
    # Only sections 1-3 (thin/na) exist; the rest are missing.
    assert "10" in gr.missing_sections
    assert gr.validation_errors > 0


def test_model_gap_predictions_surface():
    gr, _, _ = _analyze(
        _golden(), load_sidecar(mutate.GOLDEN_SIDECAR),
        preds={"finding-a": "MODEL-GAP", "finding-b": "KNOWN-NON-FINDING",
               "finding-c": "MODEL-GAP"})
    assert gr.model_gap_findings == ["finding-a", "finding-c"]


def test_render_is_stringable():
    gr, _, _ = _analyze(_golden(), load_sidecar(mutate.GOLDEN_SIDECAR))
    out = gr.render()
    assert "Gap analysis" in out
    assert "open questions" in out
