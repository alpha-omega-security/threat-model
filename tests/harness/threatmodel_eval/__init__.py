"""Threat-model evaluation harness.

Deterministic validation (Tiers 0–1), triage-routing backtest scoring (Tier 2),
and a pluggable live-agent runner for end-to-end generation. See
``tests/harness/README.md`` and the strategy in the repo root.
"""
from __future__ import annotations

from pathlib import Path

from .backtest import (
    CLOSING,
    CorpusItem,
    Scorecard,
    load_corpus,
    load_predictions,
    score,
)
from .checks import DISPOSITIONS, run_prose_checks
from .compat import Closure, Edge, analyze_compat
from .gaps import GapReport, analyze_gaps
from .parse import Model, load_sidecar
from .replay import (
    Episode,
    ReplayReport,
    ReplayScorecard,
    load_episodes,
    score_replay,
)
from .report import Finding, Report
from .sidecar import run_sidecar_checks
from .triage import TriageResult, triage

__all__ = [
    "DISPOSITIONS",
    "CLOSING",
    "Model",
    "Report",
    "Finding",
    "Closure",
    "Edge",
    "CorpusItem",
    "Scorecard",
    "TriageResult",
    "Episode",
    "ReplayReport",
    "ReplayScorecard",
    "GapReport",
    "load_corpus",
    "load_episodes",
    "load_predictions",
    "load_sidecar",
    "analyze_gaps",
    "run_prose_checks",
    "run_sidecar_checks",
    "analyze_compat",
    "score",
    "score_replay",
    "triage",
    "validate",
]


def validate(model_path: str | Path, sidecar_path: str | Path | None = None) -> Report:
    """Validate a prose model (and optional sidecar) and return a merged Report."""
    model = Model.from_file(model_path)
    report = run_prose_checks(model)
    if sidecar_path is not None:
        sidecar = load_sidecar(sidecar_path)
        report.extend(run_sidecar_checks(sidecar, model).findings)
    return report
