"""Threat-model evaluation harness.

Deterministic validation (Tiers 0–1), triage-routing backtest scoring (Tier 2),
and a pluggable live-agent runner for end-to-end generation. See
``tests/harness/README.md`` and the strategy in the repo root.
"""
from __future__ import annotations

import json
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
from .apisurface import run_api_checks
from .buildscope import run_buildscope_checks
from .citations import run_citation_checks
from .compat import Closure, Edge, analyze_compat
from .gaps import GapReport, analyze_gaps
from .jsonreport import run_json_checks
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
    "run_json_checks",
    "analyze_compat",
    "score",
    "score_replay",
    "triage",
    "validate",
]


def validate(model_path: str | Path, sidecar_path: str | Path | None = None,
             source_root: str | Path | None = None, *,
             json_report_path: str | Path | None = None) -> Report:
    """Validate a prose model (and optional sidecar) and return a merged Report.

    ``source_root`` is the tree the model was written from. When supplied, the
    model's ``file:line`` citations are resolved against it -- the only check
    here that compares a claim to something outside the document.

    ``json_report_path`` is the flat ``threat-model.json`` export. Its checks
    compare the export against the sidecar, so supplying it without a sidecar
    is itself a validation failure, reported rather than raised.
    """
    model = Model.from_file(model_path)
    report = run_prose_checks(model)
    sidecar = None
    if sidecar_path is not None:
        sidecar = load_sidecar(sidecar_path)
        report.extend(run_sidecar_checks(sidecar, model).findings)
    if source_root is not None:
        report.extend(run_citation_checks(model, source_root).findings)
        report.extend(run_buildscope_checks(model, source_root).findings)
        report.extend(run_api_checks(model, source_root).findings)
    if json_report_path is not None:
        report.extend(_json_findings(json_report_path, sidecar, model))
    return report


def _json_findings(json_report_path: str | Path, sidecar: dict | None,
                   model: Model) -> list[Finding]:
    if sidecar is None:
        return [Finding(
            "JSON.requires-sidecar", "sidecar", "error", False,
            "threat-model.json was supplied without threat-model.yaml; the "
            "JSON checks compare the export against the sidecar",
            str(json_report_path))]
    try:
        json_report = json.loads(
            Path(json_report_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        json_report = None
        problem = f"cannot load threat-model.json: {exc}"
    else:
        if not isinstance(json_report, dict):
            json_report = None
            problem = "top level of threat-model.json must be an object"
    if json_report is None:
        # Reuse the schema check's identity: an unreadable or wrong-shaped
        # document is the same failure an author has to fix first.
        return [Finding("JSON.schema-valid", "sidecar", "error", False,
                        problem, str(json_report_path))]
    return run_json_checks(json_report, sidecar, model).findings
