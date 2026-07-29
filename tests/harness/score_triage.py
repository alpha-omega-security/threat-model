"""CLI: score predicted triage dispositions against the labeled corpus.

Usage:
    # score a predictions file (JSONL of {"id":..., "predicted_disposition":...})
    python score_triage.py PREDICTIONS.jsonl

    # offline sanity check: score ground truth against itself (should be 100%/0)
    python score_triage.py --reference

Exit code is non-zero if any VALID finding was wrongly closed (fail-safe
violation) or a prediction fell outside the closed disposition set.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from threatmodel_eval import (
        load_corpus, load_predictions, load_sidecar, score, triage,
    )
else:  # pragma: no cover
    from .threatmodel_eval import (
        load_corpus, load_predictions, load_sidecar, score, triage,
    )

_REPO = Path(__file__).resolve().parents[1]
_DEFAULT_CORPUS = _REPO / "corpora"


def _corpus_files(root: Path) -> list[Path]:
    return sorted(root.glob("**/corpus.jsonl"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score triage predictions vs corpus.")
    ap.add_argument("predictions", nargs="?",
                    help="JSONL predictions file (id -> predicted_disposition)")
    ap.add_argument("--corpus", default=str(_DEFAULT_CORPUS),
                    help="corpus root containing **/corpus.jsonl")
    ap.add_argument("--reference", action="store_true",
                    help="use ground truth as predictions (scorer self-check)")
    ap.add_argument("--engine", metavar="SIDECAR",
                    help="route each corpus finding's structured signal through "
                         "the deterministic reference triage engine against "
                         "this sidecar (proves the model routes, not the labels)")
    args = ap.parse_args(argv)

    files = _corpus_files(Path(args.corpus))
    if not files:
        print(f"no corpus.jsonl found under {args.corpus}", file=sys.stderr)
        return 2
    corpus = load_corpus(files)

    if args.engine:
        sidecar = load_sidecar(args.engine)
        preds = {c.id: triage(c.signal, sidecar).disposition for c in corpus}
    elif args.reference:
        preds = {c.id: c.ground_truth for c in corpus}
    elif args.predictions:
        preds = load_predictions(args.predictions)
    else:
        ap.error("provide a predictions file, --reference, or --engine SIDECAR")
        return 2  # unreachable

    card = score(corpus, preds)
    print(card.render())
    return 0 if card.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
