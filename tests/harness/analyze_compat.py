"""CLI: analyze cross-model compatibility over a dependency closure.

Given the threat-model sidecars for a project and its dependency tree, check
each dependency edge for contract mismatches — places where a consumer relies
on a guarantee its dependency disclaims, treats an adversary the dependency
ignores, or consumes tainted output. See ``threatmodel_eval/compat.py`` for the
full rule set.

Usage:
    # From a closure manifest (nodes + edges + sidecar paths):
    python -m tests.harness.analyze_compat --manifest CLOSURE.json [-v]

    # Or scan a directory of generated models and supply edges as JSON:
    python -m tests.harness.analyze_compat --dir out/ --edges edges.json [-v]

``edges.json`` is a list of ``{"consumer": ..., "dependency": ..., "via": ...}``
objects (``via`` optional). Exit code is non-zero when any error-severity
mismatch is found.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from threatmodel_eval import Closure, Edge, analyze_compat  # type: ignore
else:  # pragma: no cover - import style depends on invocation
    from .threatmodel_eval import Closure, Edge, analyze_compat


def _load_edges(path: str) -> list[Edge]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [Edge(e["consumer"], e["dependency"], e.get("via", "")) for e in data]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Analyze cross-model compatibility over a dependency closure.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--manifest", help="closure manifest JSON (nodes + edges)")
    src.add_argument("--dir", help="directory to scan for threat-model.yaml files")
    ap.add_argument("--edges", help="edges JSON list (required with --dir)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="also print passing checks")
    args = ap.parse_args(argv)

    if args.manifest:
        closure = Closure.from_manifest(args.manifest)
        label = args.manifest
    else:
        if not args.edges:
            ap.error("--edges is required when using --dir")
        closure = Closure.from_dir(args.dir, _load_edges(args.edges))
        label = args.dir

    report = analyze_compat(closure)
    print(f"Analyzing closure {label} "
          f"({len(closure.sidecars)} models, {len(closure.edges)} edges)")
    print(report.render(verbose=args.verbose))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
