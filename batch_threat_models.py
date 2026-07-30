#!/usr/bin/env python3
"""Run a matrix of threat-model generations (targets x configurations).

This orchestrates :mod:`new_threat_model` across a list of target repositories
and a set of generation configurations, collects every artifact into a
structured output tree, and (re)builds a Markdown report after each job. When
all configurations for a given target have finished, it asks a comparison model
(Opus by default) to summarize how the resulting models differ and folds that
summary into the report.

Inputs
------
``--targets`` FILE
    A flat file of target repository URLs, one per line. Blank lines and lines
    beginning with ``#`` are ignored. An optional second whitespace-separated
    token pins a git ref, e.g.::

        https://github.com/madler/zlib
        https://github.com/jashkenas/underscore  1.13.8   # name, ref

``--configs`` FILE
    A JSON file describing the generation configurations. It may be either a
    JSON array of configuration objects, or an object with these keys::

        {
          "defaults": { "agent": "copilot", "triage_policy": "strict" },
          "configs": [
            { "name": "flash-high",  "model": "MAI-Code-1-Flash",  "effort": "high" },
            { "name": "sonnet-high", "agent": "claude",
              "model": "claude-sonnet-4.6", "effort": "high" }
          ],
          "compare": { "agent": "copilot", "model": "claude-opus-4.8" }
        }

    Each configuration object accepts: ``name`` (column label; derived from
    agent/model/effort when omitted), ``agent`` (``copilot`` | ``claude``),
    ``model``, ``effort``, ``triage_policy`` (``strict`` | ``relaxed``), and
    ``extra_args`` (a list passed through to the generator). Keys in
    ``defaults`` are applied to every configuration that does not override them.

Output tree
-----------
::

    <out>/
      README.md                         # the regenerated report
      batch-state.json                  # machine-readable roll-up
      <target>/
        comparison.md                   # Opus diff summary (once complete)
        <config>/
          docs/threat-model.md
          threat-model.yaml
          <agent>.log                   # the agent transcript
          run.log                       # the generator's stdout
          status.json                   # per-job outcome

Resumability
------------
A job that already produced a model (``status`` ``ok`` or ``invalid``) is
skipped on a re-run unless ``--force`` is given; jobs that failed to produce a
model are retried. A target's comparison is regenerated only when missing (or
with ``--force``/``--force-compare``).

Requirements
------------
Python 3.8+, ``git``, and whichever agent CLI(s) your configurations name
(``copilot`` and/or ``claude``), plus the comparison agent CLI. See
``new_threat_model.py`` for authentication details. Only run against
repositories you trust.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_GENERATOR = SCRIPT_DIR / "new_threat_model.py"
DEFAULT_VALIDATOR = SCRIPT_DIR / "tests" / "harness" / "validate_model.py"

# Cell status markers (chosen to render on GitHub).
_MARK = {
    "ok": "\u2705",       # produced and validates
    "invalid": "\u26a0\ufe0f",  # produced but validation failed
    "failed": "\u274c",   # generation produced no model
    "pending": "\u23f3",  # not run yet
}


class BatchError(Exception):
    """A fatal, user-facing error that aborts the batch with a message."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def slugify(text: str) -> str:
    """A filesystem- and URL-fragment-safe slug."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", text.strip()).strip("-._")
    return slug or "item"


def name_from_url(url: str) -> str:
    tail = re.sub(r"\.git$", "", url).rstrip("/").split("/")[-1]
    return tail or slugify(url)


def _color(text: str, code: str) -> str:
    if os.name != "nt" and sys.stdout.isatty() and "NO_COLOR" not in os.environ:
        return f"\033[{code}m{text}\033[0m"
    return text


def step(msg: str) -> None:
    print(_color(f"==> {msg}", "36"), flush=True)


def warn(msg: str) -> None:
    print(_color(f"warning: {msg}", "33"), flush=True)


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------
class Target:
    __slots__ = ("url", "ref", "name", "slug")

    def __init__(self, url: str, ref: str = "") -> None:
        self.url = url
        self.ref = ref
        self.name = name_from_url(url)
        self.slug = slugify(self.name)


def load_targets(path: Path) -> List[Target]:
    if not path.exists():
        raise BatchError(f"targets file not found: {path}")
    targets: List[Target] = []
    seen: set = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        url = parts[0]
        ref = parts[1] if len(parts) > 1 else ""
        t = Target(url, ref)
        if t.slug in seen:
            warn(f"duplicate target slug '{t.slug}' ({url}); skipping the duplicate")
            continue
        seen.add(t.slug)
        targets.append(t)
    if not targets:
        raise BatchError(f"no usable target URLs found in {path}")
    return targets


class Config:
    __slots__ = ("name", "slug", "agent", "model", "effort", "triage_policy", "extra_args")

    def __init__(self, raw: Dict, defaults: Dict) -> None:
        merged = {**defaults, **raw}
        self.agent = str(merged.get("agent", "copilot"))
        if self.agent not in ("copilot", "claude"):
            raise BatchError(f"config agent must be 'copilot' or 'claude', got '{self.agent}'")
        self.model = str(merged.get("model", "") or "")
        self.effort = str(merged.get("effort", "") or "")
        self.triage_policy = str(merged.get("triage_policy", "strict"))
        if self.triage_policy not in ("strict", "relaxed"):
            raise BatchError(f"config triage_policy must be 'strict' or 'relaxed', got '{self.triage_policy}'")
        extra = merged.get("extra_args", []) or []
        if not isinstance(extra, list):
            raise BatchError("config 'extra_args' must be a list")
        self.extra_args = [str(a) for a in extra]
        default_name = "-".join(p for p in (self.agent, self.model, self.effort) if p) or "config"
        self.name = str(merged.get("name", default_name))
        self.slug = slugify(self.name)


def load_configs(path: Path) -> Tuple[List[Config], Dict]:
    if not path.exists():
        raise BatchError(f"configs file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BatchError(f"could not parse configs JSON {path}: {exc}") from exc

    if isinstance(data, list):
        raw_configs, defaults, compare = data, {}, {}
    elif isinstance(data, dict):
        raw_configs = data.get("configs")
        if not isinstance(raw_configs, list):
            raise BatchError("configs object must contain a 'configs' array")
        defaults = data.get("defaults", {}) or {}
        compare = data.get("compare", {}) or {}
    else:
        raise BatchError("configs JSON must be an array or an object")

    configs = [Config(rc, defaults) for rc in raw_configs]
    if not configs:
        raise BatchError("no configurations defined")
    slugs = [c.slug for c in configs]
    if len(set(slugs)) != len(slugs):
        raise BatchError(f"configuration names must be unique after slugifying: {slugs}")
    return configs, compare


# ---------------------------------------------------------------------------
# Subprocess plumbing
# ---------------------------------------------------------------------------
def _command_for(exe: str, cli_args: Sequence[str]) -> List[str]:
    """Wrap Windows batch launchers (``copilot.cmd``) via ``cmd /c``."""
    if os.name == "nt" and exe.lower().endswith((".cmd", ".bat")):
        return ["cmd", "/c", exe, *cli_args]
    return [exe, *cli_args]


def run_subprocess(cmd: Sequence[str], cwd: Optional[Path], log_path: Path, echo: bool) -> int:
    """Run ``cmd``, teeing output to ``log_path`` and (optionally) the console."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as log_fh:
        proc = subprocess.Popen(
            list(cmd),
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            log_fh.write(line)
            log_fh.flush()
            if echo:
                sys.stdout.write(line)
                sys.stdout.flush()
        return proc.wait()


# ---------------------------------------------------------------------------
# Job execution
# ---------------------------------------------------------------------------
def job_dir(out_dir: Path, target: Target, config: Config) -> Path:
    return out_dir / target.slug / config.slug


def read_status(jdir: Path) -> Optional[Dict]:
    status_file = jdir / "status.json"
    if not status_file.exists():
        return None
    try:
        return json.loads(status_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _confidence(sidecar: Path) -> Optional[str]:
    """Best-effort compact confidence read from the sidecar (stdlib only)."""
    if not sidecar.exists():
        return None
    m = re.search(
        r"confidence:\s*\{([^}]*)\}", sidecar.read_text(encoding="utf-8", errors="replace")
    )
    if not m:
        return None
    fields = dict(re.findall(r"(\w+)\s*:\s*(\d+)", m.group(1)))
    doc, inf = fields.get("documented"), fields.get("inferred")
    if doc is None and inf is None:
        return None
    return f"{doc or 0}d/{inf or 0}i"


def run_job(
    args: argparse.Namespace,
    target: Target,
    config: Config,
    echo: bool,
) -> Dict:
    """Generate one (target, config) model and return its status record."""
    out_dir = Path(args.out).resolve()
    jdir = job_dir(out_dir, target, config)

    existing = read_status(jdir)
    if existing and not args.force and existing.get("status") in ("ok", "invalid"):
        step(f"[skip] {target.slug} / {config.slug} — already {existing['status']}")
        return existing

    jdir.mkdir(parents=True, exist_ok=True)
    cmd: List[str] = [
        args.python, str(args.generator),
        "--repo", target.url,
        "--out", str(jdir),
        "--project", target.name,
        "--agent", config.agent,
        "--triage-policy", config.triage_policy,
    ]
    if target.ref:
        cmd += ["--ref", target.ref]
    if config.model:
        cmd += ["--model", config.model]
    if config.effort:
        cmd += ["--effort", config.effort]
    if args.validator:
        cmd += ["--validator-path", str(args.validator)]
    cmd += config.extra_args

    step(f"[run ] {target.slug} / {config.slug}  ({config.agent} {config.model or 'default'} {config.effort})")
    started = _now()
    exit_code = run_subprocess(cmd, cwd=SCRIPT_DIR, log_path=jdir / "run.log", echo=echo)

    model_path = jdir / "docs" / "threat-model.md"
    sidecar_path = jdir / "threat-model.yaml"
    have_model = model_path.exists()

    validated: Optional[bool] = None
    if have_model and args.validator and Path(args.validator).exists():
        vcmd = [args.python, str(args.validator), str(model_path)]
        if sidecar_path.exists():
            vcmd.append(str(sidecar_path))
        validated = run_subprocess(vcmd, cwd=SCRIPT_DIR, log_path=jdir / "validate.log", echo=False) == 0

    if not have_model:
        status = "failed"
    elif validated is False:
        status = "invalid"
    else:
        status = "ok"

    record = {
        "status": status,
        "target": target.name,
        "target_url": target.url,
        "config": config.name,
        "agent": config.agent,
        "model": config.model,
        "effort": config.effort,
        "triage_policy": config.triage_policy,
        "exit_code": exit_code,
        "validated": validated,
        "confidence": _confidence(sidecar_path),
        "has_model": have_model,
        "has_sidecar": sidecar_path.exists(),
        "started": started,
        "finished": _now(),
    }
    (jdir / "status.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    marker = {"ok": "ok", "invalid": "produced but INVALID", "failed": "FAILED"}[status]
    step(f"[done] {target.slug} / {config.slug} — {marker}")
    return record


# ---------------------------------------------------------------------------
# Comparison step
# ---------------------------------------------------------------------------
def build_compare_prompt(target: Target, configs: Sequence[Config], records: Dict[str, Dict]) -> str:
    lines = [
        f"You are comparing several security threat models that were generated for the",
        f"same target project, '{target.name}' ({target.url}), under different generation",
        "configurations. Each configuration's model lives in a subdirectory of the current",
        "directory:",
        "",
    ]
    for c in configs:
        rec = records.get(c.slug) or {}
        if rec.get("has_model"):
            lines.append(
                f"  - {c.slug}/docs/threat-model.md  "
                f"(agent {c.agent}, model {c.model or 'default'}, effort {c.effort or 'unset'})"
            )
    lines += [
        "",
        "Read each of those docs/threat-model.md files. Then write a concise Markdown",
        "comparison to a file named 'comparison.md' in the current directory. Cover:",
        "  - Scope: which components / entry points each model puts in vs. out of scope.",
        "  - The disclaimed properties and the disposition/triage stance each takes.",
        "  - Provenance depth: documented vs. inferred/assumption balance and confidence.",
        "  - Any material disagreements about the security contract, and which model is",
        "    better grounded in the repository's own materials.",
        "  - A one-line recommendation on which configuration produced the strongest model.",
        "Keep it under ~400 words, use short sentences, and lead with a one-row-per-model",
        "summary table. Write ONLY comparison.md; do not modify the threat models or any",
        "other file.",
    ]
    return "\n".join(lines)


def run_comparison(
    args: argparse.Namespace,
    target: Target,
    configs: Sequence[Config],
    records: Dict[str, Dict],
    compare_agent: str,
    compare_model: str,
) -> bool:
    """Ask the comparison model to write ``comparison.md`` for a target."""
    tdir = Path(args.out).resolve() / target.slug
    comparison = tdir / "comparison.md"
    if comparison.exists() and not (args.force or args.force_compare):
        return True

    produced = [c for c in configs if (records.get(c.slug) or {}).get("has_model")]
    if len(produced) < 2:
        warn(f"[cmp ] {target.slug} — fewer than two models produced; skipping comparison")
        return False

    exe = shutil.which(compare_agent)
    if exe is None:
        warn(f"[cmp ] comparison agent '{compare_agent}' not found on PATH; skipping {target.slug}")
        return False

    prompt = build_compare_prompt(target, configs, records)
    if compare_agent == "claude":
        cli = ["-p", prompt, "--dangerously-skip-permissions"]
        if compare_model:
            cli += ["--model", compare_model]
    else:
        cli = ["-p", prompt, "--allow-all-tools", "--deny-tool", "shell(git push)", "--no-color"]
        if compare_model:
            cli += ["--model", compare_model]

    step(f"[cmp ] {target.slug} — comparing {len(produced)} models with {compare_agent} {compare_model or 'default'}")
    code = run_subprocess(_command_for(exe, cli), cwd=tdir, log_path=tdir / "comparison.log", echo=args.jobs == 1)
    if code != 0 or not comparison.exists():
        warn(f"[cmp ] {target.slug} — comparison did not produce comparison.md (exit {code})")
        return False
    return True


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------
def _rel(path: Path, base: Path) -> str:
    return os.path.relpath(path, base).replace(os.sep, "/")


def _cell(out_dir: Path, summary_dir: Path, target: Target, config: Config) -> str:
    jdir = job_dir(out_dir, target, config)
    rec = read_status(jdir)
    if not rec:
        return _MARK["pending"]
    status = rec.get("status", "pending")
    mark = _MARK.get(status, _MARK["pending"])
    if status == "failed":
        log = jdir / "run.log"
        link = f" [log]({_rel(log, summary_dir)})" if log.exists() else ""
        return f"{mark}{link}"
    model_path = jdir / "docs" / "threat-model.md"
    yaml_path = jdir / "threat-model.yaml"
    parts = [mark]
    if model_path.exists():
        parts.append(f"[md]({_rel(model_path, summary_dir)})")
    if yaml_path.exists():
        parts.append(f"[yaml]({_rel(yaml_path, summary_dir)})")
    conf = rec.get("confidence")
    cell = parts[0] + " " + " · ".join(parts[1:]) if len(parts) > 1 else parts[0]
    if conf:
        cell += f"<br>`{conf}`"
    return cell


def render_report(
    args: argparse.Namespace,
    targets: Sequence[Target],
    configs: Sequence[Config],
    compare_enabled: bool,
) -> str:
    out_dir = Path(args.out).resolve()
    summary_path = Path(args.summary).resolve() if args.summary else out_dir / "README.md"
    summary_dir = summary_path.parent

    lines: List[str] = []
    lines.append("# Threat-model batch report")
    lines.append("")
    lines.append(
        f"_Updated {_now()} — {len(targets)} target(s) × {len(configs)} configuration(s)._"
    )
    lines.append("")

    # Results matrix: rows = targets, columns = configurations.
    header = "| Target | " + " | ".join(c.name for c in configs) + " |"
    divider = "| --- | " + " | ".join("---" for _ in configs) + " |"
    lines.append("## Results")
    lines.append("")
    lines.append(header)
    lines.append(divider)
    for t in targets:
        row = [f"[{t.name}]({t.url})"]
        for c in configs:
            row.append(_cell(out_dir, summary_dir, t, c))
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    lines.append(
        f"Legend: {_MARK['ok']} validates · {_MARK['invalid']} produced, validation failed · "
        f"{_MARK['failed']} generation failed · {_MARK['pending']} pending. "
        "Cell footnote `Nd/Mi` = documented / inferred provenance-tag counts."
    )
    lines.append("")

    # Configuration legend.
    lines.append("## Configurations")
    lines.append("")
    lines.append("| Name | Agent | Model | Effort | Triage policy |")
    lines.append("| --- | --- | --- | --- | --- |")
    for c in configs:
        lines.append(
            f"| {c.name} | {c.agent} | {c.model or '(default)'} | {c.effort or '—'} | {c.triage_policy} |"
        )
    lines.append("")

    # Per-target comparisons.
    if compare_enabled:
        lines.append("## Comparisons")
        lines.append("")
        for t in targets:
            lines.append(f"### {t.name}")
            lines.append("")
            comparison = out_dir / t.slug / "comparison.md"
            if comparison.exists():
                body = comparison.read_text(encoding="utf-8", errors="replace").strip()
                lines.append(body)
                lines.append("")
                lines.append(f"_[Full comparison]({_rel(comparison, summary_dir)})_")
            else:
                produced = sum(
                    1 for c in configs
                    if (read_status(job_dir(out_dir, t, c)) or {}).get("has_model")
                )
                if produced < 2:
                    lines.append("_Pending — needs at least two produced models to compare._")
                else:
                    lines.append("_Pending — comparison not generated yet._")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_report(
    args: argparse.Namespace,
    targets: Sequence[Target],
    configs: Sequence[Config],
    compare_enabled: bool,
    lock: threading.Lock,
) -> None:
    summary_path = Path(args.summary).resolve() if args.summary else Path(args.out).resolve() / "README.md"
    content = render_report(args, targets, configs, compare_enabled)
    with lock:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(content, encoding="utf-8")
        _write_state(args, targets, configs)


def _write_state(args: argparse.Namespace, targets: Sequence[Target], configs: Sequence[Config]) -> None:
    out_dir = Path(args.out).resolve()
    state = {"updated": _now(), "targets": {}}
    for t in targets:
        state["targets"][t.slug] = {
            "url": t.url,
            "ref": t.ref,
            "configs": {
                c.slug: (read_status(job_dir(out_dir, t, c)) or {"status": "pending"})
                for c in configs
            },
            "comparison": (out_dir / t.slug / "comparison.md").exists(),
        }
    (out_dir / "batch-state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="batch_threat_models.py",
        description="Run a matrix of threat-model generations and build a comparison report.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--targets", required=True, help="Flat file of target repo URLs (one per line).")
    p.add_argument("--configs", required=True, help="JSON file describing generation configurations.")
    p.add_argument("--out", required=True, help="Root output directory for the run tree and report.")
    p.add_argument("--summary", default="", help="Report path (default: <out>/README.md).")
    p.add_argument("--generator", default=str(DEFAULT_GENERATOR), help="Path to new_threat_model.py.")
    p.add_argument("--validator", default=str(DEFAULT_VALIDATOR), help="Path to validate_model.py (empty to skip).")
    p.add_argument("--python", default=sys.executable or "python", help="Python interpreter for the generator/validator.")
    p.add_argument("--jobs", type=int, default=1, help="Number of generations to run concurrently.")
    p.add_argument("--compare-agent", default="", help="Agent CLI for the comparison step (default: from configs 'compare', else copilot).")
    p.add_argument("--compare-model", default="", help="Model for the comparison step (default: from configs 'compare', else claude-opus-4.8).")
    p.add_argument("--no-compare", action="store_true", help="Skip the per-target comparison step.")
    p.add_argument("--force", action="store_true", help="Regenerate every job and comparison, ignoring existing output.")
    p.add_argument("--force-compare", action="store_true", help="Regenerate comparisons even if present.")
    p.add_argument("--dry-run", action="store_true", help="Print the job matrix and exit without running anything.")
    return p.parse_args(argv)


def run(args: argparse.Namespace) -> int:
    generator = Path(args.generator).resolve()
    if not generator.exists():
        raise BatchError(f"generator not found: {generator}")
    args.generator = generator
    args.validator = Path(args.validator).resolve() if args.validator else None
    if args.validator and not args.validator.exists():
        warn(f"validator not found at {args.validator}; per-job validation status will be blank")
        args.validator = None

    targets = load_targets(Path(args.targets).resolve())
    configs, compare_cfg = load_configs(Path(args.configs).resolve())

    compare_enabled = not args.no_compare
    compare_agent = args.compare_agent or compare_cfg.get("agent", "copilot")
    compare_model = args.compare_model or compare_cfg.get("model", "claude-opus-4.8")
    if compare_cfg.get("enabled") is False and not (args.compare_agent or args.compare_model):
        compare_enabled = False

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    step(
        f"{len(targets)} target(s) × {len(configs)} configuration(s) = "
        f"{len(targets) * len(configs)} job(s); jobs={args.jobs}"
    )
    for t in targets:
        print(f"    target  {t.slug:24} {t.url}" + (f"  @{t.ref}" if t.ref else ""))
    for c in configs:
        print(f"    config  {c.slug:24} agent={c.agent} model={c.model or '(default)'} effort={c.effort or '—'}")
    if compare_enabled:
        print(f"    compare {compare_agent} / {compare_model}")

    if args.dry_run:
        step("DRY RUN — no generation will happen")
        return 0

    lock = threading.Lock()
    write_report(args, targets, configs, compare_enabled, lock)

    # Track remaining configs per target so we can compare as soon as a target completes.
    remaining: Dict[str, set] = {t.slug: {c.slug for c in configs} for t in targets}
    records: Dict[str, Dict[str, Dict]] = {t.slug: {} for t in targets}
    echo = args.jobs == 1

    def handle(target: Target, config: Config) -> None:
        rec = run_job(args, target, config, echo=echo)
        do_compare = False
        with lock:
            records[target.slug][config.slug] = rec
            remaining[target.slug].discard(config.slug)
            if not remaining[target.slug]:
                do_compare = compare_enabled
        # Refresh the report after every job so progress is visible incrementally.
        write_report(args, targets, configs, compare_enabled, lock)
        if do_compare:
            run_comparison(args, target, configs, records[target.slug], compare_agent, compare_model)
            write_report(args, targets, configs, compare_enabled, lock)

    jobs = [(t, c) for t in targets for c in configs]
    if args.jobs <= 1:
        for t, c in jobs:
            handle(t, c)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = [pool.submit(handle, t, c) for t, c in jobs]
            for fut in concurrent.futures.as_completed(futures):
                fut.result()  # surface exceptions

    write_report(args, targets, configs, compare_enabled, lock)

    summary_path = Path(args.summary).resolve() if args.summary else out_dir / "README.md"
    step(f"Done — report at {summary_path}")

    # Exit non-zero if any job failed to produce a model.
    failures = sum(
        1 for t in targets for c in configs
        if (read_status(job_dir(out_dir, t, c)) or {}).get("status") == "failed"
    )
    if failures:
        warn(f"{failures} job(s) failed to produce a model; see the report and run.log files")
        return 1
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        return run(parse_args(argv))
    except BatchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("aborted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
