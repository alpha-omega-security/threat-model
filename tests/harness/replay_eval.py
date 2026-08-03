"""Tier-5 historical-replay orchestrator (time-travel triage testing).

For each project that ships a replay dataset: triage every report (the real
vuln + its same-month invalid/wontfix controls) against the project's FIXED
threat model, then score the two operational metrics — **catch rate** (real
vulns kept open) and **cry-wolf rate** (controls not escalated).

Because a live triage agent is nondeterministic, ``--repeats`` runs the whole
prediction pass N times; the run is acceptable only when *every* repeat catches
every real vuln (zero misses) and stays at or below the cry-wolf threshold. The
headline scorecard is built from the per-report modal disposition, and a
stability figure reports how often the modal answer recurred.

Examples:
    # Offline wiring proof (no agent; replays a correct routing):
    python replay_eval.py --runner stub

    # Live end-to-end against a real triage agent, 3 repeats:
    python replay_eval.py --runner subprocess --repeats 3 \\
        --command "python ./triage.py --model {model} --sidecar {sidecar} --report {report}"

Exit code is non-zero if any repeat misses a real vuln, emits an unknown
disposition, or exceeds the cry-wolf threshold.
"""
from __future__ import annotations

import argparse
import collections
import datetime as _dt
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from threatmodel_eval import load_episodes, score_replay
    from threatmodel_eval.runners import (
        ReplaySpec, StubTriageRunner, SubprocessTriageRunner,
    )
else:  # pragma: no cover
    from .threatmodel_eval import load_episodes, score_replay
    from .threatmodel_eval.runners import (
        ReplaySpec, StubTriageRunner, SubprocessTriageRunner,
    )

_HARNESS = Path(__file__).resolve().parent
_REPO = _HARNESS.parents[1]


def _load_specs(config: Path) -> list[ReplaySpec]:
    data = json.loads(config.read_text(encoding="utf-8"))
    specs = []
    for p in data["projects"]:
        rep = p.get("replay")
        if not rep:
            continue
        specs.append(ReplaySpec.from_dict({"name": p["name"], **rep}, _REPO))
    return specs


def _build_runner(args):
    if args.runner == "stub":
        return StubTriageRunner()
    skill_dir = Path(args.skill_dir) if args.skill_dir else (_REPO / "skills")
    return SubprocessTriageRunner(args.command, skill_dir=skill_dir,
                                  cwd=_REPO, timeout=args.timeout)


def _read_preds(path: Path) -> dict[str, str]:
    preds: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        preds[d["id"]] = d["predicted_disposition"]
    return preds


def _modal(per_report_runs: dict[str, list[str]]) -> tuple[dict[str, str], dict[str, float]]:
    modal: dict[str, str] = {}
    stability: dict[str, float] = {}
    for rid, disps in per_report_runs.items():
        counts = collections.Counter(disps)
        best, n = counts.most_common(1)[0]
        modal[rid] = best
        stability[rid] = n / len(disps)
    return modal, stability


def _run_project(spec: ReplaySpec, runner, run_root: Path, repeats: int,
                 threshold: float) -> dict:
    episodes = load_episodes([spec.episodes])
    per_report_runs: dict[str, list[str]] = collections.defaultdict(list)
    repeat_cards = []
    for i in range(repeats):
        outdir = run_root / spec.name / f"repeat-{i}"
        preds_path = runner.predict(spec, outdir)
        preds = _read_preds(preds_path)
        for rid, disp in preds.items():
            per_report_runs[rid].append(disp)
        repeat_cards.append(score_replay(episodes, preds, threshold).to_dict())

    modal, stability = _modal(per_report_runs)
    headline = score_replay(episodes, modal, threshold).to_dict()

    # The run is acceptable only if EVERY repeat was acceptable.
    all_repeats_ok = all(rc["ok"] for rc in repeat_cards)
    min_stability = min(stability.values()) if stability else 1.0

    return {
        "name": spec.name,
        "episodes": len(episodes),
        "headline": headline,
        "repeats": repeats,
        "all_repeats_ok": all_repeats_ok,
        "min_stability": round(min_stability, 4),
        "unstable_reports": sorted(r for r, s in stability.items() if s < 1.0),
        "ok": headline["ok"] and all_repeats_ok,
    }


def _render_summary(runner_name: str, results: list[dict], overall_ok: bool) -> str:
    L = ["# Historical-replay scorecard", "",
         f"- runner: `{runner_name}`",
         f"- overall: **{'PASS' if overall_ok else 'FAIL'}**", ""]
    if runner_name == "stub":
        L.append("> ⚠️ stub runner replays a correct routing — this is a wiring "
                 "proof, not a measure of triage quality.")
        L.append("")
    L.append("| Project | Episodes | Catch | Cry-wolf | Stability | Result |")
    L.append("| --- | --- | --- | --- | --- | --- |")
    for r in results:
        h = r["headline"]
        res = "ok" if r["ok"] else "⛔ FAIL"
        L.append(f"| {r['name']} | {r['episodes']} | {h['catch_rate']:.0%} | "
                 f"{h['cry_wolf_rate']:.0%} | {r['min_stability']:.0%} | {res} |")
    L.append("")
    for r in results:
        h = r["headline"]
        if h["misses"]:
            L.append(f"## {r['name']} — CATCH MISSES (disqualifying)")
            for m in h["misses"]:
                L.append(f"- `{m['id']}` [{m['episode']}]: "
                         f"truth={m['truth']} predicted={m['pred']}")
            L.append("")
        if h["cry_wolves"]:
            L.append(f"## {r['name']} — cry-wolf (controls escalated)")
            for c in h["cry_wolves"]:
                L.append(f"- `{c['id']}` [{c['episode']}]: predicted={c['pred']}")
            L.append("")
        if not r["all_repeats_ok"]:
            L.append(f"## {r['name']} — nondeterministic failure")
            L.append("- at least one repeat missed a vuln or exceeded threshold "
                     "even though the modal routing passed")
            L.append("")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the historical-replay evaluation.")
    ap.add_argument("--runner", choices=["stub", "subprocess"], default="stub")
    ap.add_argument("--config", default=str(_HARNESS / "projects.json"))
    ap.add_argument("--command", default="", help="per-report triage command template")
    ap.add_argument("--skill-dir", default="")
    ap.add_argument("--out", default=str(_REPO / "tests" / "runs"))
    ap.add_argument("--repeats", type=int, default=1,
                    help="prediction passes per project (determinism gate)")
    ap.add_argument("--cry-wolf-threshold", type=float, default=0.0)
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--only", default="", help="comma-separated project names")
    args = ap.parse_args(argv)

    # Windows consoles default to cp1252; the summary uses a few glyphs.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    specs = _load_specs(Path(args.config))
    if args.only:
        wanted = {s.strip() for s in args.only.split(",")}
        specs = [s for s in specs if s.name in wanted]
    if not specs:
        print("no replay datasets configured (projects[].replay); nothing to do.")
        return 0

    runner = _build_runner(args)
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_root = Path(args.out) / f"replay-{ts}"
    run_root.mkdir(parents=True, exist_ok=True)

    results = []
    for spec in specs:
        try:
            results.append(_run_project(spec, runner, run_root, args.repeats,
                                        args.cry_wolf_threshold))
        except Exception as exc:  # runner / dataset failure
            results.append({"name": spec.name, "episodes": 0,
                            "headline": {"catch_rate": 0.0, "cry_wolf_rate": 1.0,
                                         "misses": [], "cry_wolves": [], "ok": False},
                            "repeats": args.repeats, "all_repeats_ok": False,
                            "min_stability": 0.0, "unstable_reports": [],
                            "ok": False, "error": f"{exc}"})

    overall_ok = all(r["ok"] for r in results)
    scorecard = {"timestamp": ts, "runner": runner.name,
                 "repeats": args.repeats,
                 "cry_wolf_threshold": args.cry_wolf_threshold,
                 "overall_ok": overall_ok, "results": results}
    (run_root / "replay-scorecard.json").write_text(
        json.dumps(scorecard, indent=2), encoding="utf-8")
    summary = _render_summary(runner.name, results, overall_ok)
    (run_root / "replay-summary.md").write_text(summary, encoding="utf-8")

    print(summary)
    print(f"\nartifacts: {run_root}")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
