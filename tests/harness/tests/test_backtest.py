"""Tests for the Tier-2 triage backtest scorer.

Verifies the asymmetric accounting: perfect predictions score clean, wrongly
*closing* a VALID finding is flagged as a disqualifying fail-safe violation, and
wrongly *escalating* a non-finding is recorded as a cheap over-escalation.
"""
from __future__ import annotations

from pathlib import Path

import mutate  # noqa: F401  (ensures harness dir on path via conftest)
from threatmodel_eval import load_corpus, score

# mutate.py lives at tests/harness/; corpora live at tests/corpora/.
_TESTS_DIR = Path(mutate.__file__).resolve().parents[1]
_CORPUS = sorted((_TESTS_DIR / "corpora").glob("**/corpus.jsonl"))


def _corpus():
    assert _CORPUS, "no corpus files found"
    return load_corpus(_CORPUS)


def test_reference_predictions_score_perfect():
    corpus = _corpus()
    preds = {c.id: c.ground_truth for c in corpus}
    card = score(corpus, preds)
    assert card.ok
    assert card.agreement == 1.0
    assert card.unique_routing_rate == 1.0
    assert not card.failsafe_violations
    assert not card.unknown_predictions


def test_wrongly_closing_valid_is_failsafe_violation():
    corpus = _corpus()
    preds = {c.id: c.ground_truth for c in corpus}
    # Find a VALID item and wrongly close it.
    valid = next(c for c in corpus if c.ground_truth == "VALID")
    preds[valid.id] = "OUT-OF-MODEL: trusted-input"
    card = score(corpus, preds)
    assert not card.ok
    assert any(v["id"] == valid.id for v in card.failsafe_violations)


def test_over_escalation_is_safe_not_disqualifying():
    corpus = _corpus()
    preds = {c.id: c.ground_truth for c in corpus}
    closed = next(c for c in corpus if c.ground_truth in {
        "OUT-OF-MODEL: trusted-input", "BY-DESIGN: property-disclaimed"})
    preds[closed.id] = "VALID"
    card = score(corpus, preds)
    assert card.ok  # escalating a non-finding is safe
    assert any(o["id"] == closed.id for o in card.over_escalations)


def test_unknown_disposition_is_rejected():
    corpus = _corpus()
    preds = {c.id: c.ground_truth for c in corpus}
    some = corpus[0]
    preds[some.id] = "MADE-UP-DISPOSITION"
    card = score(corpus, preds)
    assert not card.ok
    assert any(u["id"] == some.id for u in card.unknown_predictions)


def test_missing_prediction_recorded():
    corpus = _corpus()
    preds = {c.id: c.ground_truth for c in corpus}
    dropped = corpus[0].id
    del preds[dropped]
    card = score(corpus, preds)
    assert dropped in card.missing_predictions
    assert not card.ok


def test_empty_prediction_set_is_not_acceptable():
    corpus = _corpus()
    card = score(corpus, {})
    assert card.n_scored == 0
    assert len(card.missing_predictions) == len(corpus)
    assert not card.ok


def test_corpus_labels_are_valid_dispositions():
    from threatmodel_eval import DISPOSITIONS
    for c in _corpus():
        assert c.ground_truth in DISPOSITIONS, f"{c.id}: {c.ground_truth}"
