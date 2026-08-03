"""Pluggable runners that produce threat-model artifacts for a project.

The exact CLI of the generating agent is environment-specific, so generation is
abstracted behind :class:`AgentRunner`. Two implementations ship:

- :class:`StubRunner` — offline. Reuses a project's golden fixture and derives
  reference predictions from the corpus. It proves the *pipeline* runs
  end-to-end without an agent; it is **not** a measure of agent quality.
- :class:`SubprocessRunner` — the real extension point. Runs a configurable
  command that must write ``threat-model.md``, ``threat-model.yaml`` and
  ``predictions.jsonl`` into the run's output directory.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .backtest import load_corpus
from .checks import DISPOSITIONS


class RunnerError(RuntimeError):
    pass


@dataclass
class ProjectSpec:
    name: str
    corpus: Path
    repo: str = ""
    ref: str = ""
    golden_model: Path | None = None
    golden_sidecar: Path | None = None

    @classmethod
    def from_dict(cls, d: dict, base: Path) -> "ProjectSpec":
        def _p(key):
            v = d.get(key)
            return (base / v) if v else None
        return cls(
            name=d["name"],
            corpus=base / d["corpus"],
            repo=d.get("repo", ""),
            ref=d.get("ref", ""),
            golden_model=_p("golden_model"),
            golden_sidecar=_p("golden_sidecar"),
        )


@dataclass
class Artifacts:
    model_path: Path
    sidecar_path: Path | None
    predictions_path: Path | None
    runner: str = ""


class AgentRunner(Protocol):
    name: str

    def generate(self, spec: ProjectSpec, outdir: Path) -> Artifacts:
        ...


class StubRunner:
    """Offline pipeline smoke test — reuses goldens, emits perfect predictions.

    Explicitly NOT a quality signal: it trivially passes because it replays the
    reference labels. Use it to confirm the harness wiring works with no agent.
    """

    name = "stub"

    def generate(self, spec: ProjectSpec, outdir: Path) -> Artifacts:
        outdir.mkdir(parents=True, exist_ok=True)
        model_path = sidecar_path = None
        if spec.golden_model and spec.golden_model.exists():
            model_path = outdir / "threat-model.md"
            shutil.copyfile(spec.golden_model, model_path)
        if spec.golden_sidecar and spec.golden_sidecar.exists():
            sidecar_path = outdir / "threat-model.yaml"
            shutil.copyfile(spec.golden_sidecar, sidecar_path)

        # Reference predictions == ground truth (perfect; stub only).
        preds_path = outdir / "predictions.jsonl"
        with preds_path.open("w", encoding="utf-8") as fh:
            for item in load_corpus([spec.corpus]):
                fh.write(json.dumps({
                    "id": item.id,
                    "predicted_disposition": item.ground_truth,
                }) + "\n")
        return Artifacts(model_path, sidecar_path, preds_path, self.name)


class SubprocessRunner:
    """Run a configurable command that generates the artifacts.

    The command template may reference these placeholders, substituted per
    project: ``{name} {repo} {ref} {corpus} {outdir} {skill_dir}``. The command
    is responsible for cloning/preparing the project, invoking the threat-model
    skill, triaging the corpus, and writing ``threat-model.md``,
    ``threat-model.yaml`` and ``predictions.jsonl`` into ``{outdir}``.
    """

    name = "subprocess"

    def __init__(self, command_template: str, skill_dir: Path,
                 cwd: Path | None = None, timeout: int | None = None):
        if not command_template:
            raise RunnerError("SubprocessRunner requires a command template")
        self.command_template = command_template
        self.skill_dir = skill_dir
        self.cwd = cwd
        self.timeout = timeout

    def generate(self, spec: ProjectSpec, outdir: Path) -> Artifacts:
        outdir.mkdir(parents=True, exist_ok=True)
        cmd = self.command_template.format(
            name=spec.name, repo=spec.repo, ref=spec.ref,
            corpus=str(spec.corpus), outdir=str(outdir),
            skill_dir=str(self.skill_dir),
        )
        proc = subprocess.run(
            shlex.split(cmd), shell=False,
            cwd=str(self.cwd) if self.cwd else None,
            timeout=self.timeout, capture_output=True, text=True,
            encoding="utf-8", errors="replace", env={**os.environ},
        )
        (outdir / "runner.stdout.log").write_text(proc.stdout or "", encoding="utf-8")
        (outdir / "runner.stderr.log").write_text(proc.stderr or "", encoding="utf-8")
        if proc.returncode != 0:
            raise RunnerError(
                f"generator command failed ({proc.returncode}) for {spec.name}; "
                f"see {outdir / 'runner.stderr.log'}")

        model = outdir / "docs" / "threat-model.md"
        if not model.exists():
            model = outdir / "threat-model.md"
        if not model.exists():
            # The generator preserves the model's canonical relative path
            # (normally docs/threat-model.md); fall back to any match in scope.
            found = sorted(outdir.rglob("threat-model.md"))
            if found:
                model = found[0]
        if not model.exists():
            raise RunnerError(
                f"generator did not produce threat-model.md under {outdir} "
                f"for {spec.name}")
        sidecar = outdir / "threat-model.yaml"
        preds = outdir / "predictions.jsonl"
        return Artifacts(
            model,
            sidecar if sidecar.exists() else None,
            preds if preds.exists() else None,
            self.name,
        )


# --------------------------------------------------------------------------
# Tier-5 historical replay runners
# --------------------------------------------------------------------------
@dataclass
class ReplaySpec:
    """A replay dataset plus the FIXED model triaged against it."""
    name: str
    episodes: Path
    dataset_dir: Path
    model: Path | None = None
    sidecar: Path | None = None

    @classmethod
    def from_dict(cls, d: dict, base: Path) -> "ReplaySpec":
        episodes = base / d["episodes"]
        dataset_dir = episodes.parent

        def _p(key):
            v = d.get(key)
            return (base / v) if v else None

        return cls(
            name=d["name"], episodes=episodes, dataset_dir=dataset_dir,
            model=_p("model"), sidecar=_p("sidecar"),
        )


class ReplayRunner(Protocol):
    name: str

    def predict(self, spec: ReplaySpec, outdir: Path) -> Path:
        """Produce a predictions.jsonl for every report in the episodes."""
        ...


def _report_path(spec: ReplaySpec, report) -> Path | None:
    if not report.report_file:
        return None
    return spec.dataset_dir / report.report_file


class StubTriageRunner:
    """Offline replay wiring proof — emits a *correct*, non-escalating routing.

    Vulns get their labeled ground truth (kept open); controls get a
    non-escalating disposition (their ground truth if usable, else
    ``KNOWN-NON-FINDING``). It trivially yields a clean replay scorecard, so it
    proves the wiring — it is **not** a quality signal.
    """

    name = "stub"

    def predict(self, spec: ReplaySpec, outdir: Path) -> Path:
        from .replay import load_episodes  # local import avoids a cycle

        outdir.mkdir(parents=True, exist_ok=True)
        preds_path = outdir / "predictions.jsonl"
        with preds_path.open("w", encoding="utf-8") as fh:
            for ep in load_episodes([spec.episodes]):
                fh.write(json.dumps({
                    "id": ep.vuln.id,
                    "predicted_disposition": ep.vuln.ground_truth or "VALID",
                }) + "\n")
                for c in ep.controls:
                    gt = c.ground_truth if c.ground_truth in DISPOSITIONS \
                        else "KNOWN-NON-FINDING"
                    fh.write(json.dumps({
                        "id": c.id, "predicted_disposition": gt,
                    }) + "\n")
        return preds_path


class SubprocessTriageRunner:
    """Run a configurable per-report triage command against a fixed model.

    The command is invoked once per report with these placeholders, and must
    print exactly one disposition string on stdout:
    ``{name} {model} {sidecar} {report} {id} {outdir} {skill_dir}``.
    """

    name = "subprocess"

    def __init__(self, command_template: str, skill_dir: Path,
                 cwd: Path | None = None, timeout: int | None = None):
        if not command_template:
            raise RunnerError("SubprocessTriageRunner requires a command template")
        self.command_template = command_template
        self.skill_dir = skill_dir
        self.cwd = cwd
        self.timeout = timeout

    def predict(self, spec: ReplaySpec, outdir: Path) -> Path:
        from .replay import load_episodes  # local import avoids a cycle

        outdir.mkdir(parents=True, exist_ok=True)
        if spec.model is None or not spec.model.exists():
            raise RunnerError(f"replay '{spec.name}' has no fixed model to triage")

        preds_path = outdir / "predictions.jsonl"
        with preds_path.open("w", encoding="utf-8") as fh:
            for ep in load_episodes([spec.episodes]):
                for report in ep.reports():
                    disp = self._one(spec, report, outdir)
                    fh.write(json.dumps({
                        "id": report.id, "predicted_disposition": disp,
                    }) + "\n")
        return preds_path

    def _one(self, spec: ReplaySpec, report, outdir: Path) -> str:
        report_path = _report_path(spec, report)
        cmd = self.command_template.format(
            name=spec.name,
            model=str(spec.model) if spec.model else "",
            sidecar=str(spec.sidecar) if spec.sidecar else "",
            report=str(report_path) if report_path else "",
            id=report.id, outdir=str(outdir), skill_dir=str(self.skill_dir),
        )
        proc = subprocess.run(
            shlex.split(cmd), shell=False,
            cwd=str(self.cwd) if self.cwd else None,
            timeout=self.timeout, capture_output=True, text=True,
            encoding="utf-8", errors="replace", env={**os.environ},
        )
        if proc.returncode != 0:
            raise RunnerError(
                f"triage command failed ({proc.returncode}) for {report.id}:\n"
                f"{(proc.stderr or '').strip()}")
        disp = (proc.stdout or "").strip().splitlines()[-1].strip() \
            if (proc.stdout or "").strip() else ""
        if not disp:
            raise RunnerError(f"triage command produced no disposition for {report.id}")
        return disp
