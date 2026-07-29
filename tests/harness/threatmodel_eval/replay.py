"""Tier-5 historical-replay scorer (time-travel triage testing).

Where the Tier-2 backtest scores a flat corpus of distilled findings, this tier
replays **real historical disclosures** against a *fixed* threat model to answer
two operational questions per *episode*:

- **Catch**: would the pipeline have kept a now-known vulnerability *open*?
  Routing a real vuln to any closing disposition is a **miss** — the asymmetric,
  disqualifying error (identical in spirit to the Tier-2 fail-safe violation).
- **Cry-wolf**: does the pipeline escalate ordinary operational noise? Each
  episode pairs its real vuln with same-month reports the maintainers closed as
  ``invalid`` / ``wontfix``; escalating one of those controls to ``VALID`` /
  ``VALID-HARDENING`` is a false alarm.

An *episode* is one real vulnerability plus its same-month control reports. The
threat model is held fixed (generation leakage is accepted by design — this tier
measures the *triage* skill, not blind generation), so a pass reflects routing
quality given real report text.

Controls are scored as a binary **must-not-escalate**: a maintainer's
``invalid`` / ``wontfix`` label does not map cleanly onto the closed §1.17
disposition set, so we only require the triager not to cry wolf, rather than
demanding an exact disposition match. ``contested`` items (where the maintainer
ruling is itself arguable) are excluded from the strict metrics.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .backtest import CLOSING
from .checks import DISPOSITIONS

# Predicting one of these against a control is crying wolf.
_ESCALATING = {"VALID", "VALID-HARDENING"}


@dataclass
class ReplayReport:
    """A single triage target — either the real vuln or a control."""
    id: str
    kind: str                      # "vuln" | "control"
    ground_truth: str = ""         # dispositions; vulns usually VALID
    contested: bool = False
    source: str = ""               # CVE / GHSA / issue URL
    report_file: str = ""          # vendored raw text, relative to dataset dir
    close_reason: str = ""         # controls: invalid | wontfix | not_planned
    summary: str = ""


@dataclass
class Episode:
    episode_id: str
    project: str
    month: str
    vuln: ReplayReport
    controls: list[ReplayReport] = field(default_factory=list)
    fix_commit: str = ""
    parent_sha: str = ""

    def reports(self) -> list[ReplayReport]:
        return [self.vuln, *self.controls]


def load_episodes(paths: Iterable[str | Path]) -> list[Episode]:
    episodes: list[Episode] = []
    for p in paths:
        p = Path(p)
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            v = d["vuln"]
            vuln = ReplayReport(
                id=v["id"], kind="vuln",
                ground_truth=v.get("ground_truth", "VALID"),
                contested=bool(v.get("contested", False)),
                source=v.get("source", ""),
                report_file=v.get("report_file", ""),
                summary=v.get("summary", ""),
            )
            controls = [
                ReplayReport(
                    id=c["id"], kind="control",
                    ground_truth=c.get("ground_truth", ""),
                    contested=bool(c.get("contested", False)),
                    source=c.get("issue_url", c.get("source", "")),
                    report_file=c.get("report_file", ""),
                    close_reason=c.get("close_reason", ""),
                    summary=c.get("summary", ""),
                )
                for c in d.get("controls", [])
            ]
            episodes.append(Episode(
                episode_id=d["episode_id"], project=d.get("project", ""),
                month=d.get("month", ""), vuln=vuln, controls=controls,
                fix_commit=d.get("fix_commit", v.get("fix_commit", "")),
                parent_sha=d.get("parent_sha", v.get("parent_sha", "")),
            ))
    return episodes


@dataclass
class ReplayScorecard:
    n_episodes: int = 0
    n_vulns_scored: int = 0
    n_controls_scored: int = 0
    n_contested: int = 0
    misses: list[dict] = field(default_factory=list)          # vuln wrongly closed
    cry_wolves: list[dict] = field(default_factory=list)      # control escalated
    unknown_predictions: list[dict] = field(default_factory=list)
    missing_predictions: list[str] = field(default_factory=list)
    per_episode: list[dict] = field(default_factory=list)
    cry_wolf_threshold: float = 0.0

    @property
    def catch_rate(self) -> float:
        if not self.n_vulns_scored:
            return 0.0
        return (self.n_vulns_scored - len(self.misses)) / self.n_vulns_scored

    @property
    def cry_wolf_rate(self) -> float:
        if not self.n_controls_scored:
            return 0.0
        return len(self.cry_wolves) / self.n_controls_scored

    @property
    def ok(self) -> bool:
        """Acceptable only when every real vuln was caught (never wrongly
        closed), no prediction is missing or outside the closed set, and the
        cry-wolf rate stays at or below the configured threshold."""
        return (
            not self.misses
            and not self.missing_predictions
            and not self.unknown_predictions
            and self.cry_wolf_rate <= self.cry_wolf_threshold
        )

    def to_dict(self) -> dict:
        return {
            "n_episodes": self.n_episodes,
            "n_vulns_scored": self.n_vulns_scored,
            "n_controls_scored": self.n_controls_scored,
            "n_contested": self.n_contested,
            "catch_rate": round(self.catch_rate, 4),
            "cry_wolf_rate": round(self.cry_wolf_rate, 4),
            "cry_wolf_threshold": self.cry_wolf_threshold,
            "misses": self.misses,
            "cry_wolves": self.cry_wolves,
            "unknown_predictions": self.unknown_predictions,
            "missing_predictions": self.missing_predictions,
            "per_episode": self.per_episode,
            "ok": self.ok,
        }

    def render(self) -> str:
        L = [
            "Historical-replay scorecard",
            f"  episodes:        {self.n_episodes}",
            f"  vulns scored:    {self.n_vulns_scored}"
            f"  ({self.n_contested} contested excluded)",
            f"  controls scored: {self.n_controls_scored}",
            f"  CATCH rate:      {self.catch_rate:.0%}"
            f"  ({len(self.misses)} real vuln(s) wrongly closed)",
            f"  CRY-WOLF rate:   {self.cry_wolf_rate:.0%}"
            f"  (threshold {self.cry_wolf_threshold:.0%};"
            f" {len(self.cry_wolves)} control(s) escalated)",
        ]
        if self.misses:
            L.append("  !! CATCH MISSES (disqualifying):")
            for m in self.misses:
                L.append(f"       {m['id']} [{m['episode']}]:"
                         f" truth={m['truth']} predicted={m['pred']}")
        if self.cry_wolves:
            L.append("  cry-wolf (control escalated):")
            for c in self.cry_wolves:
                L.append(f"       {c['id']} [{c['episode']}]: predicted={c['pred']}")
        if self.unknown_predictions:
            L.append("  !! predictions outside the closed disposition set:")
            for u in self.unknown_predictions:
                L.append(f"       {u['id']}: {u['pred']!r}")
        if self.missing_predictions:
            L.append(f"  missing predictions: {', '.join(self.missing_predictions)}")
        L.append("")
        L.append(f"  => {'OK' if self.ok else 'NOT ACCEPTABLE'}")
        return "\n".join(L)


def score_replay(
    episodes: list[Episode],
    predictions: dict[str, str],
    cry_wolf_threshold: float = 0.0,
) -> ReplayScorecard:
    """Score one prediction set (report id -> disposition) over the episodes."""
    sc = ReplayScorecard(n_episodes=len(episodes),
                         cry_wolf_threshold=cry_wolf_threshold)

    for ep in episodes:
        ep_entry: dict = {"episode": ep.episode_id, "project": ep.project,
                          "month": ep.month, "caught": None, "cry_wolves": []}

        # --- the real vulnerability -------------------------------------
        v = ep.vuln
        vpred = predictions.get(v.id)
        if vpred is None:
            sc.missing_predictions.append(v.id)
        elif vpred not in DISPOSITIONS:
            sc.unknown_predictions.append({"id": v.id, "pred": vpred})
        elif v.contested:
            sc.n_contested += 1
        else:
            sc.n_vulns_scored += 1
            if vpred in CLOSING:
                sc.misses.append({"id": v.id, "episode": ep.episode_id,
                                  "truth": v.ground_truth, "pred": vpred})
                ep_entry["caught"] = False
            else:
                ep_entry["caught"] = True

        # --- the same-month controls ------------------------------------
        for c in ep.controls:
            cpred = predictions.get(c.id)
            if cpred is None:
                sc.missing_predictions.append(c.id)
                continue
            if cpred not in DISPOSITIONS:
                sc.unknown_predictions.append({"id": c.id, "pred": cpred})
                continue
            if c.contested:
                sc.n_contested += 1
                continue
            sc.n_controls_scored += 1
            if cpred in _ESCALATING:
                entry = {"id": c.id, "episode": ep.episode_id, "pred": cpred}
                sc.cry_wolves.append(entry)
                ep_entry["cry_wolves"].append(c.id)

        sc.per_episode.append(ep_entry)

    return sc
