"""Gap analysis over a generated threat model.

A threat model is only useful if it is honest about what it does *not* yet
cover. This module distills the model's own uncertainty signals into a single
structured report a job run can surface:

- **Open questions** — the §1.18 items the author left for a maintainer.
- **Inferred claims** — body claims tagged ``(inferred, QN)``; each should map
  to an open question, so any that do not are *dangling*.
- **Coverage gaps** — required sections that are missing or too thin to be
  substantive.
- **Validation** — the deterministic Tier-0/1 error and warning counts.
- **Routing gaps** (optional) — findings a triage pass sent to ``MODEL-GAP``,
  i.e. real reports the model could not route.

None of this re-implements the checks; it reads the parsed :class:`Model` plus
an already-computed :class:`Report` and, optionally, a triage prediction map.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .checks import REQUIRED_SECTIONS
from .parse import Model
from .report import Report


@dataclass
class GapReport:
    status: str | None = None
    confidence: dict = field(default_factory=dict)      # documented/maintainer/inferred
    open_questions: list[str] = field(default_factory=list)
    dangling_inferred: list[str] = field(default_factory=list)
    missing_sections: list[str] = field(default_factory=list)
    thin_sections: list[str] = field(default_factory=list)
    validation_errors: int = 0
    validation_warnings: int = 0
    model_gap_findings: list[str] = field(default_factory=list)
    triage_summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "confidence": self.confidence,
            "open_questions": self.open_questions,
            "dangling_inferred": self.dangling_inferred,
            "missing_sections": self.missing_sections,
            "thin_sections": self.thin_sections,
            "validation_errors": self.validation_errors,
            "validation_warnings": self.validation_warnings,
            "model_gap_findings": self.model_gap_findings,
            "triage_summary": self.triage_summary,
        }

    def render(self) -> str:
        c = self.confidence
        conf = (f"{c.get('documented', 0)} documented / "
                f"{c.get('maintainer', 0)} maintainer / "
                f"{c.get('inferred', 0)} inferred") if c else "n/a"
        L = [
            "Gap analysis",
            f"  status:            {self.status or 'unknown'}",
            f"  body claims:       {conf}",
            f"  open questions:    {len(self.open_questions)}"
            + (f"  ({', '.join(self.open_questions)})" if self.open_questions else ""),
            f"  validation:        {self.validation_errors} error(s),"
            f" {self.validation_warnings} warning(s)",
        ]
        if self.dangling_inferred:
            L.append(f"  !! inferred tags with no §1.18 question: "
                     f"{', '.join(self.dangling_inferred)}")
        if self.missing_sections:
            L.append(f"  !! missing sections: {', '.join(self.missing_sections)}")
        if self.thin_sections:
            L.append(f"  thin/non-substantive sections: "
                     f"{', '.join(self.thin_sections)}")
        if self.model_gap_findings:
            L.append(f"  routing gaps (MODEL-GAP): "
                     f"{len(self.model_gap_findings)}"
                     f"  ({', '.join(self.model_gap_findings)})")
        if self.triage_summary:
            t = self.triage_summary
            L.append(f"  triage:            {t.get('scored', 0)} scored;"
                     f" catch {t.get('catch_rate', 0):.0%},"
                     f" cry-wolf {t.get('cry_wolf_rate', 0):.0%}")
        return "\n".join(L)


def _referenced_question_ids(model: Model) -> set[str]:
    """Q-IDs referenced by body provenance tags, e.g. ``(inferred, Q7)``."""
    ids: set[str] = set()
    for kind, detail in model.provenance_details():
        if kind != "inferred":
            continue
        for q in re.findall(r"Q\d+", detail, re.IGNORECASE):
            ids.add(q.upper())
    return ids


def analyze_gaps(model: Model, report: Report,
                 predictions: dict[str, str] | None = None) -> GapReport:
    """Summarize what a generated model does not yet cover."""
    gr = GapReport()
    gr.status = model.stated_status()
    gr.confidence = model.tag_counts()

    gr.open_questions = sorted(
        model.open_question_ids(),
        key=lambda q: int(q[1:]) if q[1:].isdigit() else 0,
    )
    referenced = _referenced_question_ids(model)
    gr.dangling_inferred = sorted(
        referenced - model.open_question_ids(),
        key=lambda q: int(q[1:]) if q[1:].isdigit() else 0,
    )

    for num in REQUIRED_SECTIONS:
        s = model.section(num)
        if s is None:
            gr.missing_sections.append(num)
        elif not s.substantive:
            gr.thin_sections.append(num)

    gr.validation_errors = len(report.errors)
    gr.validation_warnings = len(report.warnings)

    if predictions:
        gr.model_gap_findings = sorted(
            fid for fid, disp in predictions.items() if disp == "MODEL-GAP")

    return gr
