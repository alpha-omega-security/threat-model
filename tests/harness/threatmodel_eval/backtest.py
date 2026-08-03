"""Tier-2 triage backtest scorer.

Scores predicted triage dispositions against a labeled corpus. The headline
metric is the **fail-safe rate**: how often a finding whose ground truth is
``VALID`` was wrongly *closed* (routed to an OUT-OF-MODEL / BY-DESIGN /
KNOWN-NON-FINDING disposition). That error is asymmetric and disqualifying —
wrongly closing a real vulnerability is far worse than wrongly escalating a
non-finding, so it is tracked separately from plain agreement.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .checks import DISPOSITIONS

# Dispositions that close a report against the reporter.
CLOSING = {
    d for d in DISPOSITIONS
    if d.startswith("OUT-OF-MODEL") or d.startswith("BY-DESIGN")
    or d == "KNOWN-NON-FINDING"
}
# Dispositions that keep a finding open / escalate (fail safe).
OPEN = {"VALID", "VALID-HARDENING", "MODEL-GAP"}


@dataclass
class CorpusItem:
    id: str
    project: str
    source: str
    summary: str
    ground_truth: str
    contested: bool = False
    requires: str = ""
    notes: str = ""
    signal: dict = field(default_factory=dict)


def load_corpus(paths: Iterable[str | Path]) -> list[CorpusItem]:
    items: list[CorpusItem] = []
    for p in paths:
        p = Path(p)
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            items.append(CorpusItem(
                id=d["id"], project=d.get("project", ""),
                source=d.get("source", ""), summary=d.get("summary", ""),
                ground_truth=d["ground_truth_disposition"],
                contested=bool(d.get("contested", False)),
                requires=d.get("requires", ""), notes=d.get("notes", ""),
                signal=d.get("signal") or {},
            ))
    return items


def load_predictions(path: str | Path) -> dict[str, str]:
    preds: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        preds[d["id"]] = d["predicted_disposition"]
    return preds


@dataclass
class Scorecard:
    n: int = 0
    n_contested: int = 0
    n_scored: int = 0
    agreement: float = 0.0
    agreement_excl_contested: float = 0.0
    unique_routing_rate: float = 0.0
    failsafe_violations: list[dict] = field(default_factory=list)
    over_escalations: list[dict] = field(default_factory=list)
    hardening_missed: list[dict] = field(default_factory=list)
    unknown_predictions: list[dict] = field(default_factory=list)
    missing_predictions: list[str] = field(default_factory=list)
    model_gap_predicted: int = 0
    model_gap_truth: int = 0
    confusion: dict[str, int] = field(default_factory=dict)

    @property
    def failsafe_rate(self) -> float:
        return len(self.failsafe_violations) / self.n_scored if self.n_scored else 0.0

    @property
    def ok(self) -> bool:
        """A run is acceptable only when every corpus item was validly scored
        and no VALID finding was wrongly closed."""
        return (
            self.n_scored == self.n
            and not self.missing_predictions
            and not self.unknown_predictions
            and not self.failsafe_violations
        )

    def to_dict(self) -> dict:
        return {
            "n": self.n, "n_contested": self.n_contested, "n_scored": self.n_scored,
            "agreement": round(self.agreement, 4),
            "agreement_excl_contested": round(self.agreement_excl_contested, 4),
            "unique_routing_rate": round(self.unique_routing_rate, 4),
            "failsafe_rate": round(self.failsafe_rate, 4),
            "failsafe_violations": self.failsafe_violations,
            "over_escalations": [o["id"] for o in self.over_escalations],
            "hardening_missed": [h["id"] for h in self.hardening_missed],
            "unknown_predictions": self.unknown_predictions,
            "missing_predictions": self.missing_predictions,
            "model_gap_predicted": self.model_gap_predicted,
            "model_gap_truth": self.model_gap_truth,
            "confusion": self.confusion,
            "ok": self.ok,
        }

    def render(self) -> str:
        L = [
            "Triage backtest scorecard",
            f"  items:            {self.n} ({self.n_contested} contested)",
            f"  scored:           {self.n_scored}",
            f"  agreement:        {self.agreement:.0%}"
            f"  (excl. contested: {self.agreement_excl_contested:.0%})",
            f"  unique-routing:   {self.unique_routing_rate:.0%}",
            f"  FAIL-SAFE rate:   {self.failsafe_rate:.0%}"
            f"  ({len(self.failsafe_violations)} valid finding(s) wrongly closed)",
        ]
        if self.failsafe_violations:
            L.append("  !! FAIL-SAFE VIOLATIONS (disqualifying):")
            for v in self.failsafe_violations:
                L.append(f"       {v['id']}: truth={v['truth']} predicted={v['pred']}")
        if self.unknown_predictions:
            L.append("  !! predictions outside the closed disposition set:")
            for v in self.unknown_predictions:
                L.append(f"       {v['id']}: {v['pred']!r}")
        if self.missing_predictions:
            L.append(f"  missing predictions: {', '.join(self.missing_predictions)}")
        if self.over_escalations:
            L.append(f"  over-escalations (safe): "
                     f"{', '.join(o['id'] for o in self.over_escalations)}")
        L.append("")
        L.append(f"  => {'OK' if self.ok else 'NOT ACCEPTABLE'}")
        return "\n".join(L)


def score(corpus: list[CorpusItem], predictions: dict[str, str]) -> Scorecard:
    sc = Scorecard(n=len(corpus))
    sc.n_contested = sum(1 for c in corpus if c.contested)
    sc.model_gap_truth = sum(1 for c in corpus if c.ground_truth == "MODEL-GAP")

    agree = agree_uncontested = n_uncontested = unique = 0
    for item in corpus:
        pred = predictions.get(item.id)
        if pred is None:
            sc.missing_predictions.append(item.id)
            continue
        sc.n_scored += 1
        key = f"{item.ground_truth} -> {pred}"
        sc.confusion[key] = sc.confusion.get(key, 0) + 1

        if pred in DISPOSITIONS:
            unique += 1
        else:
            sc.unknown_predictions.append({"id": item.id, "pred": pred})

        if pred == "MODEL-GAP":
            sc.model_gap_predicted += 1

        if pred == item.ground_truth:
            agree += 1
            if not item.contested:
                agree_uncontested += 1
        if not item.contested:
            n_uncontested += 1

        # Asymmetric error accounting.
        if item.ground_truth == "VALID" and pred in CLOSING:
            sc.failsafe_violations.append(
                {"id": item.id, "truth": item.ground_truth, "pred": pred})
        elif item.ground_truth == "VALID-HARDENING" and pred in CLOSING:
            sc.hardening_missed.append(
                {"id": item.id, "truth": item.ground_truth, "pred": pred})
        elif item.ground_truth in CLOSING and pred in ("VALID", "VALID-HARDENING"):
            sc.over_escalations.append(
                {"id": item.id, "truth": item.ground_truth, "pred": pred})

    sc.agreement = agree / sc.n_scored if sc.n_scored else 0.0
    sc.agreement_excl_contested = (
        agree_uncontested / n_uncontested if n_uncontested else 0.0)
    sc.unique_routing_rate = unique / sc.n_scored if sc.n_scored else 0.0
    return sc
