"""End-to-end threat-model job for an *arbitrary* GitHub repository.

Point this at any repo and it runs the whole pipeline and writes a scorecard:

    1. **Generate** — clone + drive the threat-model skill via a pluggable
       command (default: ``new_threat_model.py``) to produce
       ``threat-model.md`` + ``threat-model.yaml``.
    2. **Validate** — the deterministic Tier-0/1 structure + consistency checks.
    3. **Gaps** — distill the model's own uncertainty: open questions, inferred
       claims, thin/missing sections, dangling provenance, validation findings.
    4. **History** (opt-in, ``--with-history``) — discover the repo's published
       security advisories, vendor them as a replay dataset, triage each against
       the fresh model with ``--triage-command``, and score **catch** /
       **cry-wolf**. No hand-authored corpus or golden required.

Unlike ``run_eval.py`` (which iterates a fixed ``projects.json`` registry with
pre-authored corpora/goldens), this takes an ad-hoc repo and needs no prior
curation — quality scoring and gap analysis come from the model itself and,
optionally, the repo's own advisory history.

Example:
    python run_job.py --repo https://github.com/madler/zlib \\
        --with-history --token $env:GITHUB_TOKEN \\
        --triage-command "pwsh ./scripts/triage.ps1 -Model {model} -Report {report}"
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import fetch_replay
    from threatmodel_eval import (
        Model, analyze_gaps, load_episodes, run_prose_checks,
        run_sidecar_checks, load_sidecar, score_replay,
    )
    from threatmodel_eval.runners import (
        Artifacts, ProjectSpec, SubprocessRunner, ReplaySpec,
        SubprocessTriageRunner,
    )
else:  # pragma: no cover
    from . import fetch_replay
    from .threatmodel_eval import (
        Model, analyze_gaps, load_episodes, run_prose_checks,
        run_sidecar_checks, load_sidecar, score_replay,
    )
    from .threatmodel_eval.runners import (
        Artifacts, ProjectSpec, SubprocessRunner, ReplaySpec,
        SubprocessTriageRunner,
    )

_HARNESS = Path(__file__).resolve().parent
_REPO = _HARNESS.parents[1]

_DEFAULT_GEN_COMMAND = (
    'python ./new_threat_model.py --project "{name}" --repo "{repo}" '
    '--ref "{ref}" --out "{outdir}" --skill-dir "{skill_dir}"'
)


def _derive_name(repo: str) -> str:
    return repo.rstrip("/").removesuffix(".git").split("/")[-1] or "project"


def _run_history(args, name: str, model_path: Path, sidecar_path: Path | None,
                 run_root: Path) -> dict | None:
    """Discover advisories, vendor a replay dataset, triage, and score."""
    if not args.triage_command:
        return {"skipped": "no --triage-command given; dataset not scored"}
    http = fetch_replay._Http(args.token)
    repo_slug = fetch_replay._repo_slug(args.repo)
    try:
        vulns = fetch_replay.discover_repo_advisories(http, repo_slug,
                                                      limit=args.history_limit)
    except Exception as exc:  # pragma: no cover - network
        return {"error": f"advisory discovery failed: {exc}"}
    if not vulns:
        return {"skipped": "no published security advisories found for this repo"}

    dataset_dir = run_root / "history"
    sources = {"repo": args.repo, "controls_per_episode": args.controls,
               "vulns": vulns}
    try:
        fetch_replay.build_dataset(name, sources, dataset_dir, http)
    except Exception as exc:  # pragma: no cover - network
        return {"error": f"dataset build failed: {exc}"}

    spec = ReplaySpec(name=name, episodes=dataset_dir / "episodes.jsonl",
                      dataset_dir=dataset_dir, model=model_path,
                      sidecar=sidecar_path)
    runner = SubprocessTriageRunner(
        args.triage_command,
        skill_dir=Path(args.skill_dir) if args.skill_dir
        else (_REPO / "skills"),
        cwd=_REPO, timeout=args.timeout)
    try:
        preds_path = runner.predict(spec, run_root / "history" / "out")
    except Exception as exc:  # pragma: no cover - agent
        return {"error": f"triage failed: {exc}"}

    preds = {}
    for line in preds_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            d = json.loads(line)
            preds[d["id"]] = d["predicted_disposition"]
    card = score_replay(load_episodes([spec.episodes]), preds,
                        args.cry_wolf_threshold).to_dict()
    card["predictions"] = preds
    return card


def _render_report(name: str, repo: str, val: dict, gaps: dict | None,
                   history: dict | None, overall_ok: bool) -> str:
    L = [f"# Threat-model job — {name}", "",
         f"- repo: {repo}",
         f"- overall: **{'PASS' if overall_ok else 'FAIL'}**", ""]
    # Validation.
    if val.get("present"):
        L.append(f"## Validation — {'ok' if val['ok'] else 'FAIL'}")
        L.append(f"- {len(val['errors'])} error(s), {len(val['warnings'])} warning(s)")
        for e in val["errors"]:
            L.append(f"  - ⛔ {e}")
        for w in val["warnings"][:10]:
            L.append(f"  - ⚠️ {w}")
    else:
        L.append("## Validation — FAIL (no model produced)")
        for e in val["errors"]:
            L.append(f"  - ⛔ {e}")
    L.append("")
    # Gaps.
    if gaps:
        c = gaps["confidence"]
        L.append("## Gaps")
        L.append(f"- status: {gaps.get('status') or 'unknown'}")
        L.append(f"- body claims: {c.get('documented', 0)} documented / "
                 f"{c.get('maintainer', 0)} maintainer / {c.get('inferred', 0)} inferred")
        L.append(f"- open questions: {len(gaps['open_questions'])}"
                 + (f" ({', '.join(gaps['open_questions'])})"
                    if gaps['open_questions'] else ""))
        if gaps["dangling_inferred"]:
            L.append(f"- ⛔ inferred tags with no §1.18 question: "
                     f"{', '.join(gaps['dangling_inferred'])}")
        if gaps["missing_sections"]:
            L.append(f"- ⛔ missing sections: {', '.join(gaps['missing_sections'])}")
        if gaps["thin_sections"]:
            L.append(f"- thin sections: {', '.join(gaps['thin_sections'])}")
        if gaps.get("model_gap_findings"):
            L.append(f"- routing gaps (MODEL-GAP): {len(gaps['model_gap_findings'])}")
        L.append("")
    # History.
    if history:
        L.append("## History replay")
        if "skipped" in history:
            L.append(f"- skipped: {history['skipped']}")
        elif "error" in history:
            L.append(f"- ⛔ {history['error']}")
        else:
            L.append(f"- catch rate: {history['catch_rate']:.0%} "
                     f"({len(history['misses'])} real vuln(s) wrongly closed)")
            L.append(f"- cry-wolf rate: {history['cry_wolf_rate']:.0%}")
            for m in history["misses"]:
                L.append(f"  - ⛔ missed `{m['id']}` -> {m['pred']}")
        L.append("")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run a threat-model job on a repo.")
    ap.add_argument("--repo", required=True, help="GitHub repo URL")
    ap.add_argument("--ref", default="", help="branch/tag/commit to check out")
    ap.add_argument("--name", default="", help="project name (derived if omitted)")
    ap.add_argument("--command", default=_DEFAULT_GEN_COMMAND,
                    help="generation command template")
    ap.add_argument("--skill-dir", default="")
    ap.add_argument("--out", default=str(_REPO / "tests" / "runs"))
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--with-history", action="store_true",
                    help="discover advisories, triage them, score catch/cry-wolf")
    ap.add_argument("--triage-command", default="",
                    help="per-report triage command (required for history scoring)")
    ap.add_argument("--token", default="", help="GitHub token for advisory/issue APIs")
    ap.add_argument("--history-limit", type=int, default=10)
    ap.add_argument("--controls", type=int, default=5)
    ap.add_argument("--cry-wolf-threshold", type=float, default=0.0)
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    name = args.name or _derive_name(args.repo)
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_root = Path(args.out) / f"job-{name}-{ts}"
    run_root.mkdir(parents=True, exist_ok=True)

    skill_dir = Path(args.skill_dir) if args.skill_dir \
        else (_REPO / "skills")
    spec = ProjectSpec(name=name, corpus=Path(""), repo=args.repo, ref=args.ref)
    runner = SubprocessRunner(args.command, skill_dir=skill_dir,
                              cwd=_REPO, timeout=args.timeout)

    # 1) Generate.
    try:
        art = runner.generate(spec, run_root / "generate")
    except Exception as exc:
        val = {"present": False, "ok": False,
               "errors": [f"generation failed: {exc}"], "warnings": []}
        _finish(run_root, name, args.repo, val, None, None, False)
        return 1

    # 2) Validate.
    val, model, report = _validate_full(art)

    # 3) Gaps.
    gaps = analyze_gaps(model, report).to_dict() if model is not None else None

    # 4) History (opt-in).
    history = None
    if args.with_history:
        history = _run_history(args, name, art.model_path,
                               art.sidecar_path, run_root)
        if history and model is not None and history.get("predictions"):
            gaps = analyze_gaps(model, report, history["predictions"]).to_dict()

    overall_ok = bool(val.get("ok")) and (
        history is None or "error" not in history
        and not history.get("misses"))
    _finish(run_root, name, args.repo, val, gaps, history, overall_ok)
    return 0 if overall_ok else 1


def _validate_full(art: Artifacts):
    if art.model_path is None or not art.model_path.exists():
        return ({"present": False, "ok": False,
                 "errors": ["no threat-model.md produced"], "warnings": []},
                None, None)
    model = Model.from_file(art.model_path)
    report = run_prose_checks(model)
    if art.sidecar_path and art.sidecar_path.exists():
        report.extend(run_sidecar_checks(load_sidecar(art.sidecar_path), model).findings)
    val = {
        "present": True, "ok": report.ok,
        "errors": [f"{f.check_id}: {f.message}" for f in report.errors],
        "warnings": [f"{f.check_id}: {f.message}" for f in report.warnings],
    }
    return val, model, report


def _finish(run_root: Path, name: str, repo: str, val: dict,
            gaps: dict | None, history: dict | None, overall_ok: bool) -> None:
    scorecard = {"name": name, "repo": repo, "overall_ok": overall_ok,
                 "validation": val, "gaps": gaps, "history": history}
    (run_root / "scorecard.json").write_text(
        json.dumps(scorecard, indent=2), encoding="utf-8")
    report_md = _render_report(name, repo, val, gaps, history, overall_ok)
    (run_root / "report.md").write_text(report_md, encoding="utf-8")
    print(report_md)
    print(f"\nartifacts: {run_root}")


if __name__ == "__main__":
    raise SystemExit(main())
