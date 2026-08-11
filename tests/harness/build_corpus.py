#!/usr/bin/env python3
"""Draft finding corpora for batch targets from OSV, for human review.

A corpus is the only independent measure this harness has: it holds real
findings with a hand-assigned disposition, and scoring a model against it says
whether the model would route a genuine report correctly. Today three projects
have one. Writing the rest by hand is the bottleneck.

Most of that work is collection, and collection is free — OSV already indexes
advisories per package for every ecosystem the batch targets. This tool does
the collection and proposes a disposition. It does **not** produce ground truth.

The distinction is the whole point, so it is enforced structurally: a drafted
file carries ``proposed_disposition`` and no ``ground_truth_disposition``, which
means ``load_corpus`` raises on it. A drafted corpus cannot be scored against
until a person has read each item and promoted it. Machine-guessed labels
scored as if they were ground truth would measure nothing and look like a
number, which is worse than having no number.

What the proposal is worth: an advisory the project published *and fixed* is
almost always ``VALID`` — the maintainers acted, so it violated something they
consider a guarantee. That is also the disposition that matters most, because
closing one is the failure the fail-safe gate exists to catch. Everything else
is left blank.

What this does not give you: the ``OUT-OF-MODEL`` and ``BY-DESIGN`` half of a
good corpus. Those come from reports the project declined — "wontfix", "not
planned", "works as intended" — which live in the issue tracker, not in OSV. A
corpus of nothing but fixed advisories is a weak test, because a model that
routes everything ``VALID`` scores perfectly on it. Pull the declined-report
side from ``fetch_security_context.py`` output and add it before trusting a
score.

Usage:
    python build_corpus.py --targets ../../batch/targets.example.txt --out ../corpora
    python build_corpus.py --targets ... --since 2024-01-01   # holdout split
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

_OSV_QUERY = "https://api.osv.dev/v1/query"
_UA = "threat-model-corpus-builder"


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", name.strip().lower()).strip("-") or "target"


def osv_query(ecosystem: str, name: str, timeout: int = 30) -> list[dict]:
    """All OSV records for one package. Empty list on any failure."""
    body = json.dumps({"package": {"ecosystem": ecosystem, "name": name}}).encode()
    req = urllib.request.Request(
        _OSV_QUERY, data=body,
        headers={"Content-Type": "application/json", "User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp).get("vulns") or []
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        print(f"    ! OSV query failed for {ecosystem}:{name}: {exc}", file=sys.stderr)
        return []


def _fixed_versions(record: dict) -> list[str]:
    out = []
    for aff in record.get("affected") or []:
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    out.append(str(ev["fixed"]))
    return out


def _cve(record: dict) -> str:
    """The upstream CVE for this record, else its own id.

    Distro trackers mint their own id per CVE (``UBUNTU-CVE-2026-56411``);
    normalising to the CVE makes those dedupe against the upstream record
    instead of arriving twice under different names.
    """
    for alias in record.get("aliases") or []:
        if str(alias).startswith("CVE-"):
            return str(alias)
    rid = str(record.get("id", ""))
    m = re.search(r"(CVE-\d{4}-\d+)$", rid)
    return m.group(1) if m else rid


def _usable(record: dict, summary: str) -> bool:
    """Is this record one triageable finding, rather than a bundle or a nuisance?

    Distro *advisories* (``USN-…``) roll several unrelated CVEs into one
    notice summarised as "curl vulnerabilities" — there is no single finding to
    route. Malicious-package records describe a hostile upload, not a defect in
    the project under test. Both would pad a corpus without testing anything.
    """
    rid = str(record.get("id", ""))
    if rid.startswith(("USN-", "DSA-", "RHSA-", "MAL-", "GO-")):
        return False
    return len(summary) >= 40


def _severity(record: dict) -> str:
    for s in record.get("severity") or []:
        if s.get("score"):
            return str(s["score"])
    return ""


def draft_items(project: str, ecosystem: str, package: str,
                records: list[dict], since: Optional[str], limit: int) -> list[dict]:
    """One draft item per distinct advisory, newest first."""
    seen: set[str] = set()
    items: list[dict] = []
    for rec in sorted(records, key=lambda r: r.get("published", ""), reverse=True):
        if rec.get("withdrawn"):
            continue
        key = _cve(rec)
        if not key or key in seen:
            continue
        seen.add(key)
        published = str(rec.get("published", ""))[:10]
        if since and published and published < since:
            continue
        summary = (rec.get("summary") or rec.get("details") or "").strip()
        summary = " ".join(summary.split())[:400]
        if not _usable(rec, summary):
            continue
        fixed = _fixed_versions(rec)
        items.append({
            "id": f"{_slug(project)}-{key.lower()}",
            "project": project,
            "source": key,
            "osv_id": rec.get("id", ""),
            "published": published,
            "summary": summary,
            # A published-and-fixed advisory means the maintainers treated it as
            # a real defect in code they support, so VALID is the likely call --
            # but the model's scope decides, and only a person can check that.
            "proposed_disposition": "VALID" if fixed else "",
            "proposal_basis": (f"fixed in {', '.join(fixed[:3])}" if fixed
                               else "no fix recorded in OSV; disposition unclear"),
            "severity": _severity(rec),
            "reviewed": False,
            "notes": "DRAFT — set ground_truth_disposition by hand, then delete "
                     "proposed_disposition and set reviewed: true.",
        })
        if len(items) >= limit:
            break
    return items


def parse_targets(path: Path) -> list[tuple[str, str, str]]:
    """(project, ecosystem, package) for every target naming an osv-package."""
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        url = tokens[0]
        pkg = next((t.split("=", 1)[1] for t in tokens[1:]
                    if t.startswith("osv-package=")), "")
        if not pkg or ":" not in pkg:
            continue
        eco, _, name = pkg.partition(":")
        project = url.rstrip("/").rsplit("/", 1)[-1]
        out.append((project, eco.strip(), name.strip()))
    return out


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--targets", required=True, help="batch targets file")
    ap.add_argument("--out", required=True, help="corpora root (one dir per project)")
    ap.add_argument("--since", default="", help="only advisories published on/after YYYY-MM-DD")
    ap.add_argument("--limit", type=int, default=40, help="max items per project")
    ap.add_argument("--sleep", type=float, default=0.4, help="seconds between OSV calls")
    args = ap.parse_args(argv)

    targets = parse_targets(Path(args.targets))
    if not targets:
        print("no targets carry an osv-package= token", file=sys.stderr)
        return 2

    out_root = Path(args.out)
    total = 0
    for project, eco, name in targets:
        records = osv_query(eco, name)
        items = draft_items(project, eco, name, records, args.since or None, args.limit)
        proposed = sum(1 for i in items if i["proposed_disposition"])
        dest = out_root / _slug(project) / "corpus.draft.jsonl"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text("".join(json.dumps(i) + "\n" for i in items), encoding="utf-8")
        print(f"  {project:22} {eco:8} {len(records):4} advisories -> "
              f"{len(items):3} drafted ({proposed} with a proposal)  {dest}")
        total += len(items)
        time.sleep(args.sleep)

    print(f"\n{total} draft items written. None are ground truth.")
    print("Review each, set ground_truth_disposition, rename to corpus.jsonl.")
    print("Add declined reports (wontfix / not-planned) before trusting a score — "
          "a corpus of only fixed advisories cannot catch over-closing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
