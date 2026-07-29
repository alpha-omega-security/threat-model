#!/usr/bin/env python3
"""Clone a target repository and generate a threat model for it.

This is the generation adapter behind the harness's ``subprocess`` runner
(``tests/harness/run_eval.py``). It:

  1. clones the target repo (shallow, optional ref) into a work directory;
  2. copies the threat-model skill set into the clone's ``.github/skills`` so the
     coding agent CLI discovers it (repository-level skills);
  3. invokes either the GitHub Copilot CLI (``copilot -p <prompt>
     --allow-all-tools``) or the Claude CLI (``claude -p <prompt>
     --dangerously-skip-permissions``) to drive the ``threat-model``
     orchestrator skill, producing ``docs/threat-model.md`` and
     ``threat-model.yaml`` and -- if a corpus is supplied -- triaging each
     finding into ``predictions.jsonl``;
  4. runs the deterministic validator and, for up to ``--max-repair-attempts``
     passes, feeds any errors back to the agent for a targeted repair (disable
     with ``--no-repair``);
  5. copies the artifacts into the output directory the harness reads.

Use ``--agent`` to choose which CLI drives the run: ``copilot`` (default) or
``claude``.

The argument names line up with the ``run_eval.py`` subprocess placeholders::

    {name}->--project  {repo}->--repo  {ref}->--ref
    {corpus}->--corpus {outdir}->--out {skill_dir}->--skill-dir

Examples
--------
    ./new_threat_model.py --project zlib --repo https://github.com/madler/zlib --out ./out/zlib

    ./new_threat_model.py --agent claude --project zlib \
        --repo https://github.com/madler/zlib --out ./out/zlib

    # Wired into the evaluation orchestrator:
    python tests/harness/run_eval.py --runner subprocess \
      --command "python ./new_threat_model.py --project {name} --repo {repo} \
--ref {ref} --corpus {corpus} --out {outdir} --skill-dir {skill_dir}"

Requirements
------------
Python 3.8+ and ``git``, plus -- depending on ``--agent`` -- one of:
  - the GitHub Copilot CLI (``copilot``, install with
    ``npm install -g @github/copilot``), authenticated by running ``copilot``
    once interactively; ``--allow-all-tools`` grants it the same file/shell
    access you have in the clone directory.
  - the Claude CLI (``claude``, install with
    ``npm install -g @anthropic-ai/claude-code``), authenticated by running
    ``claude`` once interactively; ``--dangerously-skip-permissions`` grants it
    the same file/shell access you have in the clone directory.

Only run against repositories you trust.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent


class ScriptError(Exception):
    """A fatal, user-facing error that aborts the run with a message."""


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------
class Console:
    """Small stdout helper mirroring the script's colored step/warn output."""

    def __init__(self, color: Optional[bool] = None) -> None:
        if color is None:
            color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        self.color = color

    def _paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def step(self, message: str) -> None:
        print(self._paint(f"==> {message}", "36"))  # cyan

    def warn(self, message: str) -> None:
        print(self._paint(f"warning: {message}", "33"))  # yellow

    def info(self, message: str = "") -> None:
        print(message)


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------
def _command_for(exe: str, cli_args: Sequence[str]) -> List[str]:
    """Build an argv list, wrapping Windows batch launchers via ``cmd /c``.

    npm installs CLIs such as ``copilot`` as ``copilot.cmd`` on Windows, which
    cannot be launched directly by ``CreateProcess``; run those through cmd.exe.
    """
    if os.name == "nt" and exe.lower().endswith((".cmd", ".bat")):
        return ["cmd", "/c", exe, *cli_args]
    return [exe, *cli_args]


def stream_command(
    cmd: Sequence[str],
    cwd: Optional[Path] = None,
    log_path: Optional[Path] = None,
) -> int:
    """Run ``cmd``, teeing merged stdout/stderr to the console and an optional log.

    Returns the process exit code. Child output is decoded as UTF-8 so the
    agent CLIs' check marks, box drawing, and em dashes render correctly rather
    than as mojibake.
    """
    log_fh = open(log_path, "a", encoding="utf-8") if log_path else None
    try:
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
            sys.stdout.write(line)
            sys.stdout.flush()
            if log_fh:
                log_fh.write(line)
                log_fh.flush()
        return proc.wait()
    finally:
        if log_fh:
            log_fh.close()


def capture_command(cmd: Sequence[str]) -> Tuple[int, str]:
    """Run ``cmd`` and return ``(exit_code, merged_output)``."""
    result = subprocess.run(
        list(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.returncode, result.stdout or ""


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------
def copy_into(src_dir: Path, dest_dir: Path) -> None:
    """Copy the *contents* of ``src_dir`` into ``dest_dir`` (merging, overwriting)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    for item in src_dir.iterdir():
        target = dest_dir / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True)
        else:
            shutil.copy2(item, target)


def copy_artifact(src: Path, dest: Path) -> bool:
    """Copy ``src`` to ``dest`` if it exists; return whether it was copied."""
    if src.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        return True
    return False


def find_in_scope(work_dir: Path, preferred_relative: Path, filename: str) -> Path:
    """Locate a produced artifact within ``work_dir``.

    Prefer the canonical relative path; otherwise search recursively, staying in
    scope so a monorepo run never grabs a sibling package's file. Falls back to
    the preferred (possibly missing) path so callers can test ``.exists()``.
    """
    preferred = work_dir / preferred_relative
    if preferred.exists():
        return preferred
    for found in work_dir.rglob(filename):
        if found.is_file():
            return found
    return preferred


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------
def build_subdir_note(subdir: str) -> str:
    if not subdir:
        return ""
    return (
        "\n\n"
        "This project lives in the subdirectory:\n"
        f"    {subdir}\n"
        "within a larger repository (often a monorepo). Model ONLY the package in that\n"
        "subdirectory. You may read the rest of the repository for context, but the\n"
        "contract, entry points, and artifacts must be scoped to this package. Write\n"
        "docs/threat-model.md and threat-model.yaml INSIDE that subdirectory (i.e. the\n"
        "current working directory), not at the repository root."
    )


def build_corpus_instruction(corpus: Optional[Path]) -> str:
    if not corpus:
        return ""
    return (
        "\n"
        "After the model is written, triage the finding corpus at:\n"
        f"    {corpus}\n"
        "It is JSON Lines; each line has at least an 'id' and a 'summary'. Using the\n"
        "threat-model-triage skill and the model you just wrote, assign each finding\n"
        "EXACTLY ONE disposition from the closed set in section 1.17:\n"
        "    VALID, VALID-HARDENING, OUT-OF-MODEL: trusted-input,\n"
        "    OUT-OF-MODEL: adversary-not-in-scope, OUT-OF-MODEL: unsupported-component,\n"
        "    OUT-OF-MODEL: non-default-build, OUT-OF-MODEL: dependency-contract,\n"
        "    BY-DESIGN: property-disclaimed, KNOWN-NON-FINDING, MODEL-GAP\n"
        "Write the results to ./predictions.jsonl in the repo root, one JSON object per\n"
        "line with exactly these keys, e.g.:\n"
        '    {"id": "<finding id>", "predicted_disposition": "VALID"}\n'
        "Use the disposition labels verbatim. Do not invent new dispositions."
    )


PROMPT_TEMPLATE = """You are generating a security threat model for the project checked out in the
current directory ({project}).{subdir_note}

Use the threat-model skill (the orchestrator) and its specialist skills, which
are available in .github/skills of this repository. Follow the skill's procedure
faithfully: a threat model is the implicit security contract between this project
and its downstream users — assumptions, guarantees, disclaimed properties, and
known misuses. It is NOT an audit, a pentest, a CVE list, or a bug hunt. Do not
modify the project's source code.

Produce the two-artifact deliverable the skill specifies:
  1. docs/threat-model.md  — the prose model, written to the canonical section
      structure, with every non-trivial claim carrying a source-labeled
      (documented, source) / dated (maintainer, YYYY-MM) / conservative-default
      (assumption, QN) / open (inferred, QN) provenance tag, a draft-confidence
      count, a declared triage policy, a seven-step triager quick-start in the
      header, a complete contract-dimension matrix, the closed disposition
      table in 1.17, and section 1.19.
  2. threat-model.yaml      — the machine-readable sidecar (schema
      threat-model-sidecar/v2) derived from and SHA-256-bound to the prose, in
      the repo root.

Write the prose so a human can read it: short, direct sentences carrying one
idea each, plain words ("uses" not "utilizes"), active voice with a real subject,
real verbs instead of nominalizations, and short bulleted lists or table rows
instead of piled-up noun stacks and long comma-separated clauses. Target the
reading level of good developer documentation, not a research paper. Keep every
operand, capability, and provenance tag — accuracy first — but say the same
precise thing in fewer, plainer words.

Work only from what you can read in this repository (README, docs, headers,
SECURITY*, source). Where a claim cannot be confirmed from the project's own
materials, first try to cite a maintainer-authored source; a fact stated in the
README, headers, or API docs is (documented, source). Record a demonstrably-
absent guarantee (no thread-safety, no resource bound, no failure atomicity) as
a (documented) section 1.12 disclaimer rather than an open question. Only where
you must reason past what is verifiable, tag (assumption, QN) for a conservative
default you would act on, or (inferred, QN) for a genuinely open question, and
record a matching item in section 1.18 using the same QN rather than fabricating
a maintainer position.

Declare the triage policy '{triage_policy}' in the section 1.1 header and set the
sidecar's top-level triage_policy field to match. Under 'strict' an (assumption)
escalates like (inferred) and never closes a report; under 'relaxed' an
(assumption) may license only the low-blast-radius closes (trusted-input,
adversary-not-in-scope, unsupported-component, non-default-build, and a
non-security-critical property-disclaimed) as a provisional, challengeable
close. Under BOTH policies an (assumption) never licenses KNOWN-NON-FINDING, a
security-critical property-disclaimed, or dependency-contract, and (inferred)
never closes.{corpus_instruction}

When you are done, briefly list the files you created."""


def build_prompt(
    project: str, subdir: str, triage_policy: str, corpus: Optional[Path]
) -> str:
    return PROMPT_TEMPLATE.format(
        project=project,
        subdir_note=build_subdir_note(subdir),
        triage_policy=triage_policy,
        corpus_instruction=build_corpus_instruction(corpus),
    )


def build_repair_prompt(validator_output: str) -> str:
    return f"""The threat model you produced in the current directory has validation errors that
must be fixed. Below is the deterministic validator's report of
docs/threat-model.md and threat-model.yaml:

{validator_output}

Fix ONLY these problems, editing in place, without changing anything the
validator did not flag and without touching the project's source code:
  - Preserve the canonical section structure and all correct existing content.
  - If a §1.1 draft-confidence count disagrees with the body, RECOUNT the
    (documented) / (maintainer) / (inferred) tags and correct the header number.
  - Every provenance tag must carry its detail: (documented, source),
    (maintainer, YYYY-MM), (assumption, QN), or (inferred, QN). Fill any bare tag.
  - Every (inferred, QN) and (assumption, QN) must have a matching QN item in
    §1.18; add the missing question or fix the reference so they resolve.
  - §1.1 must contain the seven-step triager quick-start naming the contract
    dimensions, the disposition PRECEDENCE, and §1.17.
  - After editing docs/threat-model.md, REGENERATE threat-model.yaml so its
    prose_version SHA-256 matches the edited prose exactly, and correct any bad
    component provenance the validator named.

Consult the threat-model skill's output-structure reference if unsure. When done,
briefly list what you changed."""


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="new_threat_model.py",
        description="Clone a repository and generate a threat model with a coding-agent CLI.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--repo", required=True, help="Target repository URL to clone.")
    parser.add_argument("--out", required=True, help="Output directory for the collected artifacts.")
    parser.add_argument("--project", default="", help="Project name (derived from the repo URL if omitted).")
    parser.add_argument("--ref", default="", help="Branch, tag, or commit to check out (default branch if omitted).")
    parser.add_argument("--subdir", default="", help="Model only this subdirectory of a monorepo.")
    parser.add_argument("--corpus", default="", help="JSON Lines finding corpus to triage into predictions.jsonl.")
    parser.add_argument(
        "--skill-dir",
        default=str(SCRIPT_DIR / ".." / ".github" / "skills"),
        help="Directory holding the threat-model skill set to install into the clone.",
    )
    parser.add_argument("--work-root", default="", help="Root for clones (default: a temp subfolder).")
    parser.add_argument("--model", default="", help="Model name to pass to the agent CLI (--model).")
    parser.add_argument("--triage-policy", choices=["strict", "relaxed"], default="strict", help="Triage policy declared in the model.")
    parser.add_argument("--agent", choices=["copilot", "claude"], default="copilot", help="Which coding-agent CLI drives the run.")
    parser.add_argument("--copilot-path", default="copilot", help="Path to the Copilot CLI executable.")
    parser.add_argument("--claude-path", default="claude", help="Path to the Claude CLI executable.")
    parser.add_argument("--extra-copilot-args", nargs="*", default=[], help="Extra arguments appended to the Copilot invocation.")
    parser.add_argument("--extra-claude-args", nargs="*", default=[], help="Extra arguments appended to the Claude invocation.")
    parser.add_argument("--max-repair-attempts", type=int, default=2, help="Max validate->repair passes (0 disables repair).")
    parser.add_argument("--no-repair", action="store_true", help="Skip the validate/repair loop entirely.")
    parser.add_argument(
        "--validator-path",
        default=str(SCRIPT_DIR / ".." / "tests" / "harness" / "validate_model.py"),
        help="Path to the deterministic model validator.",
    )
    parser.add_argument("--python-path", default=sys.executable or "python", help="Python interpreter used to run the validator.")
    parser.add_argument("--keep-clone", action="store_true", help="Keep the clone directory instead of deleting it.")
    parser.add_argument("--dry-run", action="store_true", help="Print the plan and prompt, then exit without cloning.")
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Clone
# ---------------------------------------------------------------------------
def clone_repository(console: Console, repo: str, ref: str, clone_dir: Path) -> None:
    if clone_dir.exists():
        console.step(f"Removing stale clone at {clone_dir}")
        shutil.rmtree(clone_dir, ignore_errors=True)
    clone_dir.parent.mkdir(parents=True, exist_ok=True)

    console.step(f"Cloning {repo} -> {clone_dir}")
    if ref:
        code = stream_command(["git", "clone", "--depth", "1", "--branch", ref, repo, str(clone_dir)])
        if code != 0:
            console.warn(f"shallow clone of ref '{ref}' failed; retrying with a full clone + checkout")
            if clone_dir.exists():
                shutil.rmtree(clone_dir, ignore_errors=True)
            if stream_command(["git", "clone", repo, str(clone_dir)]) != 0:
                raise ScriptError(f"git clone failed for {repo}")
            if stream_command(["git", "-C", str(clone_dir), "checkout", ref]) != 0:
                raise ScriptError(f"git checkout of ref '{ref}' failed")
    else:
        if stream_command(["git", "clone", "--depth", "1", repo, str(clone_dir)]) != 0:
            raise ScriptError(f"git clone failed for {repo}")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def run_validator(
    python_path: str, validator_path: Path, model_path: Path, sidecar_path: Optional[Path]
) -> Tuple[bool, str]:
    cmd = [python_path, str(validator_path), str(model_path)]
    if sidecar_path and sidecar_path.exists():
        cmd.append(str(sidecar_path))
    code, output = capture_command(cmd)
    return code == 0, output


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
def run(args: argparse.Namespace, console: Console) -> int:
    project = args.project or re.sub(r"\.git$", "", args.repo).rstrip("/").split("/")[-1]

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    skill_dir = Path(args.skill_dir).resolve()
    if not skill_dir.exists():
        raise ScriptError(f"skill directory not found: {skill_dir}")

    validator_path = Path(args.validator_path).resolve() if args.validator_path else None

    corpus: Optional[Path] = None
    if args.corpus:
        corpus = Path(args.corpus).resolve()
        if not corpus.exists():
            raise ScriptError(f"corpus file not found: {corpus}")

    work_root = Path(args.work_root).resolve() if args.work_root else Path(tempfile.gettempdir()) / "threat-model-runs"
    clone_dir = work_root / project

    # --- Tool preflight ---
    if shutil.which("git") is None:
        raise ScriptError("git is required but was not found on PATH.")

    agent_path_arg = args.claude_path if args.agent == "claude" else args.copilot_path
    agent_exe = shutil.which(agent_path_arg) or agent_path_arg
    agent_available = shutil.which(agent_path_arg) is not None
    if not agent_available and not args.dry_run:
        if args.agent == "claude":
            raise ScriptError(
                f"Claude CLI ('{args.claude_path}') not found on PATH. Install it with "
                "'npm install -g @anthropic-ai/claude-code' and authenticate by running 'claude' once."
            )
        raise ScriptError(
            f"Copilot CLI ('{args.copilot_path}') not found on PATH. Install it with "
            "'npm install -g @github/copilot' and authenticate by running 'copilot' once."
        )

    python_available = shutil.which(args.python_path) is not None or Path(args.python_path).exists()

    prompt = build_prompt(project, args.subdir, args.triage_policy, corpus)

    # --- Dry run: show the plan and exit ---
    if args.dry_run:
        _print_dry_run(console, args, project, clone_dir, skill_dir, corpus, out_dir, validator_path, prompt)
        return 0

    # --- Clone ---
    clone_repository(console, args.repo, args.ref, clone_dir)
    commit = subprocess.run(
        ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE, text=True, encoding="utf-8", check=True,
    ).stdout.strip()
    console.step(f"Checked out {commit}")

    # Resolve the directory the agent runs in (a subdirectory for monorepo packages).
    work_dir = clone_dir
    if args.subdir:
        work_dir = clone_dir / args.subdir
        if not work_dir.exists():
            raise ScriptError(f"subdirectory '{args.subdir}' not found in clone (expected at {work_dir}).")
        console.step(f"Scoping generation to subdirectory: {args.subdir}")

    # --- Install the skills so the agent CLI discovers them ---
    # The agent CLI discovers repository skills from `.github/skills` relative to
    # the directory it is launched in. When scoping to a monorepo subdirectory
    # that directory is work_dir, not the repo root, so the skills must live
    # there; otherwise every skill(threat-model-*) call resolves to "not found".
    dest_skills = work_dir / ".github" / "skills"
    console.step(f"Installing threat-model skills into {dest_skills}")
    copy_into(skill_dir, dest_skills)

    # --- Run the coding agent CLI to generate the model ---
    log_file = out_dir / f"{args.agent}.log"
    if log_file.exists():
        log_file.unlink()

    def invoke_agent(prompt_text: str) -> int:
        if args.agent == "claude":
            cli_args = ["-p", prompt_text, "--dangerously-skip-permissions"]
            if args.model:
                cli_args += ["--model", args.model]
            cli_args += list(args.extra_claude_args)
        else:
            cli_args = ["-p", prompt_text, "--allow-all-tools", "--deny-tool", "shell(git push)", "--no-color"]
            if args.model:
                cli_args += ["--model", args.model]
            cli_args += list(args.extra_copilot_args)
        return stream_command(_command_for(agent_exe, cli_args), cwd=work_dir, log_path=log_file)

    console.step(f"Running {args.agent} CLI (log: {log_file})")
    agent_exit = invoke_agent(prompt)
    if agent_exit != 0:
        raise ScriptError(f"{args.agent} CLI exited with code {agent_exit}. See {log_file}.")

    # --- Validate -> repair loop ---
    _repair_loop(console, args, work_dir, validator_path, python_available, invoke_agent)

    # --- Collect artifacts into the output directory ---
    have_model, rel_model, have_sidecar, have_predictions = _collect_artifacts(
        console, work_dir, out_dir, corpus
    )

    # --- Cleanup and summary ---
    if not args.keep_clone:
        console.step(f"Removing clone {clone_dir}")
        shutil.rmtree(clone_dir, ignore_errors=True)
    else:
        console.step(f"Keeping clone at {clone_dir}")

    console.info()
    console.step(f"Done — {project} @ {commit}")
    console.info(f"  threat-model.md   : {f'ok ({rel_model})' if have_model else 'MISSING'}")
    console.info(f"  threat-model.yaml : {'ok' if have_sidecar else 'missing'}")
    if corpus:
        console.info(f"  predictions.jsonl : {'ok' if have_predictions else 'missing'}")
    console.info(f"  output dir        : {out_dir}")

    if not have_model:
        raise ScriptError(f"{args.agent} did not produce a threat-model.md — see {log_file}.")
    return 0


def _repair_loop(
    console: Console,
    args: argparse.Namespace,
    work_dir: Path,
    validator_path: Optional[Path],
    python_available: bool,
    invoke_agent,
) -> None:
    """Feed validator errors back to the agent for up to N targeted repair passes.

    Closes the loop on common authoring slips (header count drift, bare
    provenance tags, a §1.18 QN with no matching claim, a missing quick-start
    token, a stale sidecar hash) that would otherwise surface only downstream.
    """
    repair_enabled = (
        not args.no_repair
        and validator_path is not None
        and validator_path.exists()
        and python_available
    )
    if not repair_enabled:
        if not args.no_repair:
            console.warn("validate/repair loop skipped (python or validator unavailable)")
        return
    if args.max_repair_attempts < 1:
        console.step("Repair disabled (--max-repair-attempts 0); leaving generated model as-is")
        return

    assert validator_path is not None
    model_path = find_in_scope(work_dir, Path("docs") / "threat-model.md", "threat-model.md")
    sidecar_path = find_in_scope(work_dir, Path("threat-model.yaml"), "threat-model.yaml")
    if not model_path.exists():
        console.warn("no threat-model.md to validate; skipping repair")
        return

    ok, output = run_validator(args.python_path, validator_path, model_path, sidecar_path)
    attempt = 0
    while not ok and attempt < args.max_repair_attempts:
        attempt += 1
        console.warn(f"validation failed; requesting repair pass {attempt}/{args.max_repair_attempts}")
        rc = invoke_agent(build_repair_prompt(output))
        if rc != 0:
            console.warn(f"repair pass {attempt} exited with code {rc}; stopping repair loop")
            break
        model_path = find_in_scope(work_dir, Path("docs") / "threat-model.md", "threat-model.md")
        sidecar_path = find_in_scope(work_dir, Path("threat-model.yaml"), "threat-model.yaml")
        ok, output = run_validator(args.python_path, validator_path, model_path, sidecar_path)

    if ok:
        suffix = f" after {attempt} repair pass(es)" if attempt else ""
        console.step(f"Model validates clean{suffix}")
    else:
        console.warn(f"model still has validation errors after {attempt} repair pass(es); collecting as-is")


def _collect_artifacts(
    console: Console, work_dir: Path, out_dir: Path, corpus: Optional[Path]
) -> Tuple[bool, Optional[str], bool, bool]:
    """Copy the model, sidecar, and (optional) predictions from work_dir into out_dir.

    Fallback searches stay within work_dir so a monorepo run never grabs a
    sibling package's file.
    """
    console.step(f"Collecting artifacts into {out_dir}")

    # Prose model: prefer docs/threat-model.md, else the first match in scope.
    model_src = find_in_scope(work_dir, Path("docs") / "threat-model.md", "threat-model.md")

    # Preserve the model's canonical relative path (normally docs/threat-model.md)
    # under out_dir. The sidecar's prose_version binding names that path
    # ("docs/threat-model.md@sha256:<digest>"), so flattening it would break the
    # prose-version path check even though the content digest still matches.
    have_model = False
    rel_model: Optional[str] = None
    if model_src.exists():
        rel_model = os.path.relpath(model_src, work_dir)
        if not rel_model or rel_model.startswith(".."):
            rel_model = "threat-model.md"
        model_dest = out_dir / rel_model
        model_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(model_src, model_dest)
        have_model = True

    sidecar_src = find_in_scope(work_dir, Path("threat-model.yaml"), "threat-model.yaml")
    have_sidecar = copy_artifact(sidecar_src, out_dir / "threat-model.yaml")

    have_predictions = False
    if corpus:
        have_predictions = copy_artifact(work_dir / "predictions.jsonl", out_dir / "predictions.jsonl")

    return have_model, rel_model, have_sidecar, have_predictions


def _print_dry_run(
    console: Console,
    args: argparse.Namespace,
    project: str,
    clone_dir: Path,
    skill_dir: Path,
    corpus: Optional[Path],
    out_dir: Path,
    validator_path: Optional[Path],
    prompt: str,
) -> None:
    console.step("DRY RUN — no clone or generation will happen")
    console.info(f"Project    : {project}")
    console.info(f"Repo       : {args.repo}")
    console.info(f"Ref        : {args.ref or '(default branch)'}")
    console.info(f"Clone dir  : {clone_dir}")
    console.info(f"Subdir     : {args.subdir or '(repo root)'}")
    console.info(f"Skill dir  : {skill_dir}")
    console.info(f"Corpus     : {corpus if corpus else '(none — predictions skipped)'}")
    console.info(f"Output dir : {out_dir}")

    if args.no_repair:
        repair_plan = "disabled (--no-repair)"
    elif not validator_path or not validator_path.exists():
        repair_plan = f"skipped (validator not found at {validator_path})"
    else:
        repair_plan = f"up to {args.max_repair_attempts} pass(es) via {validator_path}"
    console.info(f"Repair     : {repair_plan}")
    console.info()

    model_suffix = f" --model {args.model}" if args.model else ""
    if args.agent == "claude":
        console.info("claude invocation:")
        console.info(f"  {args.claude_path} -p <prompt> --dangerously-skip-permissions{model_suffix}")
    else:
        console.info("copilot invocation:")
        console.info(f"  {args.copilot_path} -p <prompt> --allow-all-tools --deny-tool 'shell(git push)' --no-color{model_suffix}")
    console.info()
    console.info("----- prompt -----")
    console.info(prompt)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    console = Console()
    try:
        return run(args, console)
    except ScriptError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("aborted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
