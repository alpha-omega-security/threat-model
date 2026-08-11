"""End-to-end evaluation orchestrator.

For each configured project: (1) obtain threat-model artifacts via a pluggable
runner, (2) run the Tier-0/1 deterministic validator over the model + sidecar,
(3) score triage predictions against the labeled corpus (Tier 2), then write an
aggregate scorecard (JSON + Markdown) under ``tests/runs/<timestamp>/``.

Examples:
    # Offline pipeline smoke test (no agent; reuses goldens):
    python run_eval.py --runner stub

    # Live end-to-end against a real generating agent:
    python run_eval.py --runner subprocess \\
        --command "python ./new_threat_model.py --project {name} --repo {repo} --out {outdir}"

Exit code is non-zero if any model fails validation or any run has a fail-safe
triage violation.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from threatmodel_eval import (
        Model, load_corpus, load_predictions, run_prose_checks,
        run_sidecar_checks, load_sidecar, score,
    )
    from threatmodel_eval.runners import (
        Artifacts, ProjectSpec, StubRunner, SubprocessRunner,
    )
else:  # pragma: no cover
    from .threatmodel_eval import (
        Model, load_corpus, load_predictions, run_prose_checks,
        run_sidecar_checks, load_sidecar, score,
    )
    from .threatmodel_eval.runners import (
        Artifacts, ProjectSpec, StubRunner, SubprocessRunner,
    )

_HARNESS = Path(__file__).resolve().parent
_REPO = _HARNESS.parents[1]


def _validate_artifacts(art: Artifacts) -> dict:
    if art.model_path is None or not art.model_path.exists():
        # No model produced. For the offline stub this is expected for projects
        # without a golden; a live runner that fails to produce one raises
        # RunnerError instead, surfaced as a runner error by the caller.
        return {"present": False, "ok": True, "skipped": True,
                "errors": [], "warnings": []}
    model = Model.from_file(art.model_path)
    report = run_prose_checks(model)
    if art.sidecar_path and art.sidecar_path.exists():
        report.extend(run_sidecar_checks(
            load_sidecar(art.sidecar_path), model, art.sidecar_path).findings)
    return {
        "present": True,
        "ok": report.ok,
        "errors": [f"{f.check_id}: {f.message}" for f in report.errors],
        "warnings": [f"{f.check_id}: {f.message}" for f in report.warnings],
    }


def _score_artifacts(art: Artifacts, spec: ProjectSpec) -> dict | None:
    if art.predictions_path is None or not art.predictions_path.exists():
        return None
    corpus = load_corpus([spec.corpus])
    preds = load_predictions(art.predictions_path)
    return score(corpus, preds).to_dict()


def _load_specs(config: Path) -> list[ProjectSpec]:
    data = json.loads(config.read_text(encoding="utf-8"))
    return [ProjectSpec.from_dict(p, _REPO) for p in data["projects"]]


def _build_runner(args) -> object:
    if args.runner == "stub":
        return StubRunner()
    skill_dir = Path(args.skill_dir) if args.skill_dir else (_REPO / "skills")
    return SubprocessRunner(args.command, skill_dir=skill_dir,
                            cwd=_REPO, timeout=args.timeout)


def _render_summary(runner_name: str, results: list[dict], overall_ok: bool) -> str:
    L = [f"# Threat-model evaluation scorecard", "",
         f"- runner: `{runner_name}`",
         f"- overall: **{'PASS' if overall_ok else 'FAIL'}**", ""]
    if runner_name == "stub":
        L.append("> ⚠️ stub runner reuses goldens and replays reference labels — "
                 "this is a pipeline smoke test, not a measure of agent quality.")
        L.append("")
    L.append("| Project | Model | Validation | Backtest agreement | Fail-safe |")
    L.append("| --- | --- | --- | --- | --- |")
    for r in results:
        v = r["validation"]
        bt = r["backtest"]
        model = "yes" if v.get("present") else "—"
        if v.get("skipped"):
            val = "skipped"
        elif v.get("ok"):
            val = "ok"
        else:
            val = f"{len(v.get('errors', []))} error(s)"
        if bt:
            agr = f"{bt['agreement']:.0%}"
            fs = "clean" if not bt["failsafe_violations"] else \
                f"⛔ {len(bt['failsafe_violations'])}"
        else:
            agr = fs = "—"
        L.append(f"| {r['name']} | {model} | {val} | {agr} | {fs} |")
    L.append("")
    for r in results:
        v = r["validation"]
        if v.get("errors"):
            L.append(f"## {r['name']} — validation errors")
            for e in v["errors"]:
                L.append(f"- {e}")
            L.append("")
        bt = r["backtest"]
        if bt and bt["failsafe_violations"]:
            L.append(f"## {r['name']} — FAIL-SAFE violations (disqualifying)")
            for fv in bt["failsafe_violations"]:
                L.append(f"- `{fv['id']}`: truth={fv['truth']} predicted={fv['pred']}")
            L.append("")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the threat-model evaluation.")
    ap.add_argument("--runner", choices=["stub", "subprocess"], default="stub")
    ap.add_argument("--config", default=str(_HARNESS / "projects.json"))
    ap.add_argument("--command", default="",
                    help="subprocess runner command template")
    ap.add_argument("--skill-dir", default="",
                    help="path to the threat-model skills (subprocess runner)")
    ap.add_argument("--out", default=str(_REPO / "tests" / "runs"))
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--only", default="", help="comma-separated project names")
    args = ap.parse_args(argv)

    specs = _load_specs(Path(args.config))
    if args.only:
        wanted = {s.strip() for s in args.only.split(",")}
        specs = [s for s in specs if s.name in wanted]

    runner = _build_runner(args)
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_root = Path(args.out) / ts
    run_root.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    for spec in specs:
        outdir = run_root / spec.name
        entry: dict = {"name": spec.name}
        try:
            art = runner.generate(spec, outdir)
            entry["validation"] = _validate_artifacts(art)
            entry["backtest"] = _score_artifacts(art, spec)
        except Exception as exc:  # runner or generation failure
            entry["validation"] = {"present": False, "ok": False,
                                   "errors": [f"runner error: {exc}"],
                                   "warnings": []}
            entry["backtest"] = None
        results.append(entry)

    overall_ok = all(
        r["validation"].get("ok", False) or not r["validation"].get("present")
        for r in results
    ) and all(
        (r["backtest"] is None) or (not r["backtest"]["failsafe_violations"]
                                    and not r["backtest"]["unknown_predictions"])
        for r in results
    )

    scorecard = {"timestamp": ts, "runner": runner.name,
                 "overall_ok": overall_ok, "results": results}
    (run_root / "scorecard.json").write_text(
        json.dumps(scorecard, indent=2), encoding="utf-8")
    summary = _render_summary(runner.name, results, overall_ok)
    (run_root / "summary.md").write_text(summary, encoding="utf-8")

    print(summary)
    print(f"\nartifacts: {run_root}")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
