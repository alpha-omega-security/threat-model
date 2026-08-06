"""Fetch and vendor historical-replay datasets (Tier-5 build step).

Given a per-project ``sources.json`` listing the real vulnerabilities (by CVE /
GHSA id) and, optionally, explicit control issue numbers, this resolves each
vuln's fixing commit and its parent (the pre-fix snapshot), downloads the real
report text, discovers same-month ``invalid`` / ``wontfix`` control issues, and
writes an offline-reproducible dataset:

    tests/replay/<project>/
        episodes.jsonl        one episode per vuln (+ its controls)
        reports/<id>.md       vendored raw report text
        manifest.json         provenance: source URLs, fetch ts, sha256

Network access happens only here (at build time); the scored replay reads only
the vendored files. Requires a GitHub token (``--token`` or ``GITHUB_TOKEN``)
for the commit / issue / search APIs and OSV.dev for vuln→commit resolution.

The pure resolution helpers (``osv_fix_commits``, ``classify_control``,
``same_month``) are import-safe and unit-tested without the network.

sources.json shape:
    {
      "repo": "https://github.com/madler/zlib",
      "vulns": [
        {"id": "CVE-2022-37434", "report_url": "https://github.com/madler/zlib/issues/605",
         "ground_truth": "VALID"}
      ],
      "controls_per_episode": 5
    }
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_HARNESS = Path(__file__).resolve().parent
_REPO = _HARNESS.parents[1]

# Reuse the SSRF/redirect guard rather than growing a second copy of it.
sys.path.insert(0, str(_REPO))
from fetch_security_context import _OPENER  # noqa: E402

_INVALID_LABELS = {"invalid", "wontfix", "won't fix", "not a bug", "duplicate",
                   "works as intended", "by design", "question", "support"}


# --------------------------------------------------------------------------
# Pure, import-safe helpers (unit-tested; no network)
# --------------------------------------------------------------------------
def osv_fix_commits(osv: dict) -> list[str]:
    """Extract fixing commit SHAs from an OSV vuln record's GIT ranges."""
    commits: list[str] = []
    for aff in osv.get("affected", []):
        for rng in aff.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            for ev in rng.get("events", []):
                fixed = ev.get("fixed")
                if fixed:
                    commits.append(fixed)
    # De-dup, keep order.
    seen: set[str] = set()
    return [c for c in commits if not (c in seen or seen.add(c))]


def classify_control(issue: dict) -> bool:
    """True when a closed issue looks like invalid / wontfix operational noise.

    A GitHub issue closed with ``state_reason == "not_planned"`` (the modern
    wontfix signal) or carrying an invalid/wontfix-style label qualifies. Pull
    requests and still-open issues never qualify.
    """
    if issue.get("pull_request"):
        return False
    if issue.get("state") != "closed":
        return False
    if issue.get("state_reason") == "not_planned":
        return True
    labels = {
        (lb.get("name", "") if isinstance(lb, dict) else str(lb)).strip().lower()
        for lb in issue.get("labels", [])
    }
    return bool(labels & _INVALID_LABELS)


def same_month(iso_ts: str, month: str) -> bool:
    """True when an ISO-8601 timestamp falls in ``month`` (``YYYY-MM``)."""
    if not iso_ts or not month:
        return False
    return iso_ts[:7] == month


def slugify(text: str) -> str:
    keep = [c.lower() if c.isalnum() else "-" for c in text]
    slug = "".join(keep)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


# --------------------------------------------------------------------------
# Network layer (build-time only)
# --------------------------------------------------------------------------
class _Http:
    """Token-carrying GitHub/OSV client.

    Requests go through the shared redirect guard from
    ``fetch_security_context``: it re-validates every redirect hop against the
    public-endpoint rules and drops the ``Authorization`` header when a redirect
    crosses to another host, so the GitHub token cannot be carried off
    api.github.com by a redirect.
    """

    def __init__(self, token: str = ""):
        self.token = token

    def get_json(self, url: str) -> dict:
        req = urllib.request.Request(url, headers=self._headers())
        with _OPENER.open(req, timeout=30) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))

    def get_json_list(self, url: str) -> list:
        req = urllib.request.Request(url, headers=self._headers())
        with _OPENER.open(req, timeout=30) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
        return data if isinstance(data, list) else []

    def _headers(self) -> dict:
        return {"User-Agent": "threat-model-replay-fetcher",
                "Accept": "application/vnd.github+json",
                **({"Authorization": f"Bearer {self.token}"} if self.token else {})}


def _repo_slug(repo_url: str) -> str:
    """``https://github.com/owner/name`` -> ``owner/name``, API-path safe.

    The slug is interpolated into api.github.com paths, so it must not be able
    to carry the request somewhere else: a value with ``..`` segments could
    climb out of ``/repos/``, and ``?``/``#`` could append a query or fragment.
    """
    path = urllib.parse.urlparse(repo_url).path.strip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    parts = [p for p in path.split("/") if p]
    if len(parts) != 2 or any(p in (".", "..") for p in parts):
        raise ValueError(f"expected a repo URL of the form host/owner/name, got: {repo_url}")
    return "/".join(urllib.parse.quote(p, safe="") for p in parts)


def _parent_sha(http: _Http, repo_slug: str, sha: str) -> str:
    data = http.get_json(f"https://api.github.com/repos/{repo_slug}/commits/{sha}")
    parents = data.get("parents") or []
    return parents[0]["sha"] if parents else ""


def _issue_number_from_url(url: str) -> int | None:
    parts = urllib.parse.urlparse(url).path.rstrip("/").split("/")
    if parts and parts[-1].isdigit():
        return int(parts[-1])
    return None


def _fetch_issue(http: _Http, repo_slug: str, number: int) -> dict:
    return http.get_json(
        f"https://api.github.com/repos/{repo_slug}/issues/{number}")


def _fetch_month_controls(http: _Http, repo_slug: str, month: str,
                          limit: int) -> list[dict]:
    """Search for issues closed as invalid/wontfix in the given month."""
    q = (f"repo:{repo_slug} type:issue state:closed "
         f"closed:{month}-01..{month}-31")
    url = ("https://api.github.com/search/issues?per_page=50&q="
           + urllib.parse.quote(q))
    items = http.get_json(url).get("items", [])
    controls = [it for it in items if classify_control(it)]
    return controls[:limit]


def discover_repo_advisories(http: _Http, repo_slug: str,
                             limit: int = 20) -> list[dict]:
    """Return published security advisories for a repo as vuln source entries.

    Uses the GitHub repository security-advisories API, so *any* repo that
    publishes advisories yields real, labeled vulnerabilities with no hand
    curation. Each entry maps to a ``sources.json`` vuln: the CVE id when
    present, else the GHSA id, with a link back to the advisory.
    """
    url = (f"https://api.github.com/repos/{repo_slug}/security-advisories"
           f"?per_page={min(limit, 100)}&state=published")
    vulns: list[dict] = []
    for adv in http.get_json_list(url):
        vid = adv.get("cve_id") or adv.get("ghsa_id")
        if not vid:
            continue
        vulns.append({"id": vid, "report_url": adv.get("html_url", ""),
                      "ground_truth": "VALID"})
        if len(vulns) >= limit:
            break
    return vulns



def _vendor_report(reports_dir: Path, rid: str, text: str) -> tuple[str, str]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    fname = f"{rid}.md"
    (reports_dir / fname).write_text(text, encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"reports/{fname}", digest


def build_dataset(project: str, sources: dict, out_dir: Path,
                  http: _Http) -> dict:
    repo_slug = _repo_slug(sources["repo"])
    reports_dir = out_dir / "reports"
    controls_per = int(sources.get("controls_per_episode", 5))

    episodes: list[dict] = []
    manifest: dict = {"project": project, "repo": sources["repo"],
                      "fetched_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                      "reports": {}}

    for v in sources["vulns"]:
        vid = v["id"]
        rid = slugify(f"{project}-{vid}")
        osv = http.get_json(
            "https://api.osv.dev/v1/vulns/" + urllib.parse.quote(str(vid), safe=""))
        commits = osv_fix_commits(osv)
        fix_commit = commits[0] if commits else ""
        parent = _parent_sha(http, repo_slug, fix_commit) if fix_commit else ""

        # Vendor the vuln report (explicit URL, else the OSV summary/details).
        report_url = v.get("report_url", "")
        num = _issue_number_from_url(report_url) if report_url else None
        if num is not None:
            issue = _fetch_issue(http, repo_slug, num)
            body = f"# {issue.get('title','')}\n\n{issue.get('body','') or ''}"
            month = (issue.get("created_at") or "")[:7]
        else:
            body = f"# {vid}\n\n{osv.get('summary','')}\n\n{osv.get('details','')}"
            month = (osv.get("published") or "")[:7]
        rfile, digest = _vendor_report(reports_dir, rid, body)
        manifest["reports"][rid] = {"source": report_url or f"osv:{vid}",
                                    "sha256": digest}

        # Discover same-month controls.
        controls: list[dict] = []
        if month:
            for it in _fetch_month_controls(http, repo_slug, month, controls_per):
                cid = slugify(f"{project}-issue-{it['number']}")
                ctext = f"# {it.get('title','')}\n\n{it.get('body','') or ''}"
                cfile, cdigest = _vendor_report(reports_dir, cid, ctext)
                manifest["reports"][cid] = {"source": it.get("html_url", ""),
                                            "sha256": cdigest}
                controls.append({
                    "id": cid, "issue_url": it.get("html_url", ""),
                    "close_reason": it.get("state_reason", "") or "labelled",
                    "report_file": cfile, "contested": False,
                })

        episodes.append({
            "episode_id": rid, "project": project, "month": month,
            "fix_commit": fix_commit, "parent_sha": parent,
            "vuln": {"id": rid, "source": vid, "fix_commit": fix_commit,
                     "parent_sha": parent, "report_ref": report_url,
                     "report_file": rfile,
                     "ground_truth": v.get("ground_truth", "VALID"),
                     "contested": bool(v.get("contested", False))},
            "controls": controls,
        })

    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "episodes.jsonl").open("w", encoding="utf-8") as fh:
        for ep in episodes:
            fh.write(json.dumps(ep) + "\n")
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    return {"episodes": len(episodes),
            "reports": len(manifest["reports"]), "out": str(out_dir)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Fetch/vendor a replay dataset.")
    ap.add_argument("--project", required=True)
    ap.add_argument("--sources", default="",
                    help="path to sources.json (default tests/replay/<project>/sources.json)")
    ap.add_argument("--out", default="",
                    help="dataset output dir (default tests/replay/<project>)")
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    args = ap.parse_args(argv)

    out_dir = Path(args.out) if args.out else (_REPO / "tests" / "replay" / args.project)
    sources_path = Path(args.sources) if args.sources else (out_dir / "sources.json")
    if not sources_path.exists():
        print(f"sources file not found: {sources_path}", file=sys.stderr)
        return 2
    if not args.token:
        print("warning: no GitHub token; commit/issue/search calls may be "
              "rate-limited", file=sys.stderr)

    sources = json.loads(sources_path.read_text(encoding="utf-8"))
    http = _Http(args.token)
    try:
        result = build_dataset(args.project, sources, out_dir, http)
    except urllib.error.HTTPError as exc:  # pragma: no cover - network
        print(f"fetch failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
