"""CLI: validate a threat-model prose document (and optional companions).

Usage:
    python -m tests.harness.validate_model MODEL.md [SIDECAR.yaml] [-v]

Or from the harness dir:
    python validate_model.py MODEL.md [SIDECAR.yaml] [--json-report FILE] [-v]

Exit code is non-zero when any error-severity check fails.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as a loose script (python validate_model.py ...).
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from threatmodel_eval import validate  # type: ignore
else:  # pragma: no cover - import style depends on invocation
    from .threatmodel_eval import validate


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Validate a threat-model document.")
    ap.add_argument("model", help="path to the prose threat-model markdown")
    ap.add_argument("sidecar", nargs="?", help="optional threat-model.yaml sidecar")
    ap.add_argument("--source-root", default=None,
                    help="tree the model was written from; enables resolving "
                         "its file:line code citations against real source")
    ap.add_argument("--json-report", default=None,
                    help="optional threat-model.json export; checked against "
                         "the sidecar, so requires SIDECAR too")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="also print passing checks")
    args = ap.parse_args(argv)

    report = validate(args.model, args.sidecar, args.source_root,
                      json_report_path=args.json_report)
    print(f"Validating {args.model}"
          + (f" + {args.sidecar}" if args.sidecar else "")
          + (f" + {args.json_report}" if args.json_report else ""))
    print(report.render(verbose=args.verbose))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
