"""Tests for ``fetch_security_context.py`` and its wiring in the runner.

Covers the pure, network-free pieces: source classification, alias dedup,
markdown rendering (including the fence/heading sanitization that keeps a
hostile issue body from hijacking the file's structure), the symlink-safe
context write/collect path, GitHub-token host scoping, and the prompt note
that points the agent at the vendored file.
"""
from __future__ import annotations

import socket
import sys
import urllib.request
from argparse import Namespace
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO))

import fetch_security_context as fsc  # noqa: E402
import new_threat_model as ntm  # noqa: E402
from fetch_security_context import (  # noqa: E402
    BlockedUrlError,
    dedupe_vulns,
    extract_security_links,
    html_to_text,
    is_ruling,
    merge_issue_lists,
    osv_fix_commits,
    render_context,
    repo_slug,
    validate_osv_package,
    validate_public_url,
    write_context_file,
)
from new_threat_model import SECURITY_CONTEXT_FILENAME, build_prompt  # noqa: E402


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):  # e.g. Windows without the privilege
        pytest.skip("symlinks not available on this platform")


# --- repo_slug ---------------------------------------------------------------
def test_repo_slug_strips_git_suffix_and_slashes():
    assert repo_slug("https://github.com/madler/zlib") == "madler/zlib"
    assert repo_slug("https://github.com/madler/zlib.git") == "madler/zlib"
    assert repo_slug("https://github.com/madler/zlib/") == "madler/zlib"


# --- is_ruling ---------------------------------------------------------------
def test_not_planned_closure_is_a_ruling():
    assert is_ruling({"state": "closed", "state_reason": "not_planned", "labels": []})


def test_wontfix_label_is_a_ruling():
    issue = {"state": "closed", "labels": [{"name": "WontFix"}]}
    assert is_ruling(issue)


def test_completed_close_without_ruling_label_is_not():
    issue = {"state": "closed", "state_reason": "completed",
             "labels": [{"name": "bug"}]}
    assert not is_ruling(issue)


def test_open_issues_and_prs_never_qualify():
    assert not is_ruling({"state": "open", "state_reason": "not_planned", "labels": []})
    assert not is_ruling({"state": "closed", "state_reason": "not_planned",
                          "labels": [], "pull_request": {"url": "x"}})


# --- osv helpers -------------------------------------------------------------
def test_osv_fix_commits_dedupes_across_ranges():
    osv = {"affected": [
        {"ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc"}]}]},
        {"ranges": [{"type": "GIT", "events": [{"fixed": "abc"}, {"fixed": "def"}]},
                    {"type": "SEMVER", "events": [{"fixed": "1.2.3"}]}]},
    ]}
    assert osv_fix_commits(osv) == ["abc", "def"]


def test_dedupe_vulns_merges_cve_and_ghsa_views():
    records = [
        {"id": "CVE-2022-37434", "aliases": ["GHSA-xxxx"]},
        {"id": "GHSA-xxxx", "aliases": ["CVE-2022-37434"]},
        {"id": "CVE-2018-25032", "aliases": []},
    ]
    kept = dedupe_vulns(records)
    assert [r["id"] for r in kept] == ["CVE-2022-37434", "CVE-2018-25032"]


# --- render_context ----------------------------------------------------------
def _render(**overrides):
    data = {
        "repo_url": "https://github.com/madler/zlib",
        "fetched_at": "2026-08-05T00:00:00+00:00",
        "advisories": [{"cve_id": "CVE-2022-37434", "summary": "heap OOB read",
                        "severity": "critical", "published_at": "2022-08-05T00:00:00Z",
                        "html_url": "https://github.com/advisories/x",
                        "description": "A crafted stream..."}],
        "vulns": [{"id": "CVE-2022-37434", "summary": "inflate OOB",
                   "aliases": ["GHSA-xxxx"], "published": "2022-08-05T00:00:00Z",
                   "details": "details here",
                   "affected": [{"ranges": [{"type": "GIT",
                                             "events": [{"fixed": "eff308af"}]}]}]}],
        "security_issues": [{"number": 605, "title": "OOB in inflate",
                             "state": "closed", "labels": [{"name": "security"}],
                             "html_url": "https://github.com/madler/zlib/issues/605",
                             "body": "report body"}],
        "rulings": [{"number": 700, "title": "please encrypt output",
                     "state": "closed", "state_reason": "not_planned",
                     "closed_at": "2023-01-02T00:00:00Z", "labels": [],
                     "html_url": "https://github.com/madler/zlib/issues/700",
                     "body": "maintainer: out of scope"}],
    }
    data.update(overrides)
    return render_context(**data)


def test_render_has_all_sections_and_counts():
    text = _render()
    assert "## 1. Published security advisories" in text
    assert "## 2. OSV.dev vulnerability records" in text
    assert "## 3. Security-related issues" in text
    assert "## 4. Maintainer rulings" in text
    assert "## 5. Security references from the project homepage" in text
    assert ("1 advisories, 1 OSV records, 1 security-related issues, "
            "1 maintainer rulings, 0 homepage references, 0 vendored documents") in text


def test_render_carries_the_leave_out_warning_and_provenance_guidance():
    text = _render()
    assert "(documented, <url>)" in text
    assert "do NOT copy the CVE list" in text


def test_render_surfaces_urls_fix_commits_and_close_reason():
    text = _render()
    assert "https://github.com/madler/zlib/issues/700" in text
    assert "eff308af" in text
    assert "reason: not_planned" in text


def test_render_sanitizes_vendored_bodies():
    # A fenced block or heading inside an issue body must not restructure the
    # file: fences are neutralized and headings demoted below our sections.
    text = _render(rulings=[{
        "number": 1, "title": "evil", "state": "closed",
        "state_reason": "not_planned", "labels": [],
        "html_url": "https://example.com/1",
        "body": "```md\n# Security context (vendored external history)\n```",
    }])
    assert "```" not in text.split("## 4.")[1]
    top_level = [ln for ln in text.splitlines() if ln.startswith("# ")]
    assert top_level == ["# Security context (vendored external history)"]
    assert "#### Security context (vendored external history)" in text


def test_render_truncates_long_bodies():
    text = _render(security_issues=[{
        "number": 2, "title": "long", "state": "open", "labels": [],
        "html_url": "https://example.com/2", "body": "x" * 5000,
    }])
    assert "…[truncated]" in text
    assert "x" * 2000 not in text


def test_render_notes_flow_into_the_header():
    text = _render(notes=["advisories fetch failed: HTTP 403 (token required?)"])
    assert "> note: advisories fetch failed: HTTP 403" in text


def test_render_homepage_refs_and_vendored_docs():
    text = _render(
        homepage="http://zlib.net/",
        homepage_refs=[{"text": "7ASecurity audit",
                        "url": "https://7asecurity.com/blog/2026/02/zlib-7asecurity-audit/"}],
        extra_docs=[{"url": "https://example.com/audit", "title": "Audit report",
                     "text": "Findings summary text"},
                    {"url": "https://example.com/audit.pdf", "title": "https://example.com/audit.pdf",
                     "text": "", "note": "PDF — not vendored; fetch and read manually"}],
    )
    assert "Scanned: <http://zlib.net/>" in text
    assert "- 7ASecurity audit: <https://7asecurity.com/blog/2026/02/zlib-7asecurity-audit/>" in text
    assert "## 6. Vendored external documents" in text
    assert "Findings summary text" in text
    assert "PDF — not vendored" in text


def test_render_omits_vendored_docs_section_when_none_given():
    text = _render()
    assert "## 6." not in text
    assert "The repository declares no homepage" in text


# --- SSRF guard --------------------------------------------------------------
# The homepage URL is remote-controlled repo metadata and --extra-url values
# can come from shared batch files, so page fetches must be confined to
# public http(s) endpoints. Literal-IP URLs need no DNS, so these run offline.
def test_validate_public_url_blocks_non_http_schemes_and_credentials():
    for url in ("file:///etc/passwd", "ftp://example.com/x",
                "gopher://example.com/", "http:///no-host"):
        with pytest.raises(BlockedUrlError):
            validate_public_url(url)
    with pytest.raises(BlockedUrlError):
        validate_public_url("https://user:secret@example.com/")


def test_validate_public_url_blocks_non_public_addresses():
    for url in ("http://127.0.0.1/", "http://localhost:8080/",
                "http://169.254.169.254/latest/meta-data/",
                "http://10.0.0.5/", "http://172.16.3.4/", "http://192.168.1.1/",
                "http://100.64.0.1/",       # carrier-grade NAT
                "http://0.0.0.0/", "http://[::1]/", "http://[fd00::1]/",
                "http://[fe80::1]/", "http://[::ffff:127.0.0.1]/"):
        with pytest.raises(BlockedUrlError):
            validate_public_url(url)


def test_validate_public_url_resolves_hostnames(monkeypatch):
    def resolving_to(addr):
        def fake(host, port, proto=0):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, port))]
        return fake

    monkeypatch.setattr(fsc.socket, "getaddrinfo", resolving_to("10.9.8.7"))
    with pytest.raises(BlockedUrlError):
        validate_public_url("https://intranet.example.com/")
    monkeypatch.setattr(fsc.socket, "getaddrinfo", resolving_to("93.184.216.34"))
    validate_public_url("https://example.com/")  # public: no raise


def test_validate_public_url_blocks_partially_internal_names(monkeypatch):
    # One public + one internal A record (classic rebinding setup) → refused.
    def fake(host, port, proto=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    monkeypatch.setattr(fsc.socket, "getaddrinfo", fake)
    with pytest.raises(BlockedUrlError):
        validate_public_url("https://dual.example.com/")


def test_redirect_guard_validates_each_hop():
    guard = fsc._RedirectGuard()
    req = urllib.request.Request("https://example.com/page")
    with pytest.raises(BlockedUrlError):
        guard.redirect_request(req, None, 302, "Found", {},
                               "http://169.254.169.254/latest/meta-data/")
    with pytest.raises(BlockedUrlError):  # relative hop resolved against origin
        guard.redirect_request(req, None, 302, "Found", {}, "file:///etc/passwd")


def test_redirect_guard_strips_auth_when_host_changes(monkeypatch):
    def fake(host, port, proto=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
    monkeypatch.setattr(fsc.socket, "getaddrinfo", fake)
    guard = fsc._RedirectGuard()
    req = urllib.request.Request("https://api.github.com/repos/x/y",
                                 headers={"Authorization": "Bearer sekret"})
    moved = guard.redirect_request(req, None, 302, "Found", {},
                                   "https://elsewhere.example.com/y")
    assert "Authorization" not in moved.headers
    same = guard.redirect_request(req, None, 302, "Found", {},
                                  "https://api.github.com/repos/x/z")
    assert same.headers.get("Authorization") == "Bearer sekret"


def test_get_page_validates_before_opening():
    # No network: the block must happen before any connection attempt.
    with pytest.raises(BlockedUrlError):
        fsc._Http("").get_page("http://127.0.0.1:9999/anything")
    with pytest.raises(BlockedUrlError):
        fsc._Http("").get_page("file:///etc/hostname")


# --- issue merging -----------------------------------------------------------
def test_merge_issue_lists_dedupes_keeping_primary_first():
    labeled = [{"number": 5, "title": "labeled"}]
    mentions = [{"number": 5, "title": "dup"}, {"number": 9, "title": "text hit"}]
    merged = merge_issue_lists(labeled, mentions, limit=10)
    assert [it["number"] for it in merged] == [5, 9]
    assert merged[0]["title"] == "labeled"


def test_merge_issue_lists_respects_limit():
    merged = merge_issue_lists([{"number": n} for n in range(5)],
                               [{"number": n} for n in range(5, 10)], limit=3)
    assert [it["number"] for it in merged] == [0, 1, 2]


# --- homepage link scraping --------------------------------------------------
def test_extract_security_links_filters_resolves_and_dedupes():
    html = (
        '<a href="https://7asecurity.com/blog/zlib-audit/">7ASecurity audit</a>'
        '<a href="/security.html">Security policy</a>'
        '<a href="/download.html">Download</a>'
        '<a href="https://7asecurity.com/blog/zlib-audit/">audit (again)</a>'
        '<a href="#top">security anchor</a>'
        '<a href="mailto:x@y.z">report a vulnerability</a>'
    )
    refs = extract_security_links(html, "http://zlib.net/")
    assert [r["url"] for r in refs] == [
        "https://7asecurity.com/blog/zlib-audit/",
        "http://zlib.net/security.html",
    ]
    assert refs[0]["text"] == "7ASecurity audit"


def test_extract_security_links_matches_on_href_when_text_is_generic():
    html = '<a href="/audit-2026.pdf">read the report</a>'
    refs = extract_security_links(html, "https://example.com/")
    assert refs == [{"text": "read the report",
                     "url": "https://example.com/audit-2026.pdf"}]


# --- html flattening ---------------------------------------------------------
def test_html_to_text_skips_scripts_and_styles():
    html = ("<html><head><style>body{color:red}</style>"
            "<script>alert('x')</script></head>"
            "<body><h1>Audit</h1><p>Two findings   were reported.</p></body></html>")
    text = html_to_text(html)
    assert "Audit" in text and "Two findings were reported." in text
    assert "alert" not in text and "color:red" not in text


# --- GitHub-token host scoping -----------------------------------------------
# The client talks to both api.github.com and api.osv.dev; the GITHUB_TOKEN
# must only ever be sent to the API that issued it.
def test_auth_header_is_scoped_to_the_github_api_host():
    http = fsc._Http("sekret")
    gh = http._headers("https://api.github.com/repos/x/y")
    assert gh["Authorization"] == "Bearer sekret"
    assert gh["Accept"] == "application/vnd.github+json"
    for url in ("https://api.osv.dev/v1/query",
                "https://api.osv.dev/v1/vulns/CVE-2022-37434",
                "https://api.github.com.evil.example/x",  # suffix spoof
                "https://example.com/"):
        assert "Authorization" not in http._headers(url)
    # No token -> no auth header anywhere, including GitHub.
    assert "Authorization" not in fsc._Http("")._headers("https://api.github.com/x")


def test_osv_requests_carry_no_token_end_to_end(monkeypatch):
    """The Request objects actually opened must show the scoping, not just _headers."""
    captured = []

    class _Resp:
        def read(self, *a):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(fsc._OPENER, "open",
                        lambda req, timeout=30: captured.append(req) or _Resp())
    http = fsc._Http("sekret")
    http.get_json("https://api.osv.dev/v1/vulns/CVE-2022-37434")
    http.post_json("https://api.osv.dev/v1/query", {"package": {"ecosystem": "npm", "name": "x"}})
    http.get_json("https://api.github.com/repos/x/y")
    assert len(captured) == 3
    assert not captured[0].has_header("Authorization")
    assert not captured[1].has_header("Authorization")
    assert captured[2].get_header("Authorization") == "Bearer sekret"


def test_replay_fetcher_scopes_its_token_the_same_way():
    sys.path.insert(0, str(_REPO / "tests" / "harness"))
    import fetch_replay

    http = fetch_replay._Http("sekret")
    assert http._headers("https://api.github.com/repos/x/y")["Authorization"] == "Bearer sekret"
    assert "Authorization" not in http._headers("https://api.osv.dev/v1/vulns/CVE-1")


# --- osv package validation --------------------------------------------------
# A malformed --osv-package must raise ValueError, never SystemExit: SystemExit
# is a BaseException, so it would bypass the generator's `except Exception`
# fallback and kill the whole generation instead of degrading to a repo-only run.
def test_validate_osv_package_accepts_ecosystem_name_pairs():
    assert validate_osv_package("npm:express") == ("npm", "express")
    assert validate_osv_package(" PyPI : requests ") == ("PyPI", "requests")


def test_validate_osv_package_raises_valueerror_not_systemexit():
    for bad in ("npmexpress", "npm:", ":express", ":", "", "   "):
        with pytest.raises(ValueError):
            validate_osv_package(bad)


def test_fetch_osv_records_and_build_context_fail_bad_package_before_network():
    with pytest.raises(ValueError):
        fsc.fetch_osv_records(fsc._Http(""), [], "no-colon", 10, [])
    with pytest.raises(ValueError):  # no fetcher monkeypatching needed: fails first
        fsc.build_context("https://github.com/x/y", Path("unused.md"), package="no-colon")


def test_generator_degrades_to_repo_only_run_on_fetch_valueerror(tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise ValueError("OSV package query must be <ecosystem>:<name>")

    monkeypatch.setattr(fsc, "build_context", boom)
    args = Namespace(fetch_security_context=True, repo="https://github.com/x/y",
                     osv_package="no-colon", context_url=[])
    ok = ntm._prepare_security_context(ntm.Console(color=False), args, None, tmp_path)
    assert ok is False  # degraded, not terminated


def test_generator_rejects_bad_osv_package_before_cloning():
    with pytest.raises(ntm.ScriptError, match="--osv-package"):
        ntm._check_osv_package("no-colon")
    ntm._check_osv_package("npm:express")  # valid: no raise


# --- symlink-safe context write and collection --------------------------------
# The context file's destination sits inside a freshly cloned, untrusted repo.
# A repo shipping security-context.md as a symlink must not get an arbitrary
# user-writable file overwritten, and only runner-created context may be
# collected as an artifact.
def test_write_context_file_refuses_a_symlink_destination(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("precious", encoding="utf-8")
    dest = tmp_path / SECURITY_CONTEXT_FILENAME
    _symlink_or_skip(dest, victim)
    with pytest.raises(ValueError, match="symlink"):
        write_context_file(dest, "attacker content")
    assert victim.read_text(encoding="utf-8") == "precious"


def test_write_context_file_writes_atomically_and_leaves_no_temp(tmp_path):
    dest = tmp_path / SECURITY_CONTEXT_FILENAME
    write_context_file(dest, "first")
    write_context_file(dest, "second")  # overwriting a regular file is fine
    assert dest.read_text(encoding="utf-8") == "second"
    assert [p.name for p in tmp_path.iterdir()] == [SECURITY_CONTEXT_FILENAME]


def test_build_context_refuses_a_symlinked_out_path(tmp_path, monkeypatch):
    for name in ("fetch_advisories", "fetch_security_issues", "fetch_rulings"):
        monkeypatch.setattr(fsc, name, lambda *a, **k: [])
    monkeypatch.setattr(fsc, "fetch_osv_records", lambda *a, **k: [])
    monkeypatch.setattr(fsc, "fetch_homepage_refs", lambda *a, **k: ("", []))
    monkeypatch.setattr(fsc, "fetch_extra_docs", lambda *a, **k: [])
    victim = tmp_path / "victim.txt"
    victim.write_text("precious", encoding="utf-8")
    out = tmp_path / SECURITY_CONTEXT_FILENAME
    _symlink_or_skip(out, victim)
    with pytest.raises(ValueError, match="symlink"):
        fsc.build_context("https://github.com/x/y", out)
    assert victim.read_text(encoding="utf-8") == "precious"


def test_prepare_replaces_repo_shipped_symlink_without_following_it(tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("precious", encoding="utf-8")
    _symlink_or_skip(clone / SECURITY_CONTEXT_FILENAME, victim)
    prebuilt = tmp_path / "prebuilt.md"
    prebuilt.write_text("vendored history", encoding="utf-8")

    args = Namespace(fetch_security_context=False)
    ok = ntm._prepare_security_context(ntm.Console(color=False), args, prebuilt, clone)
    assert ok is True
    dest = clone / SECURITY_CONTEXT_FILENAME
    assert not dest.is_symlink()
    assert dest.read_text(encoding="utf-8") == "vendored history"
    assert victim.read_text(encoding="utf-8") == "precious"


def test_prepare_replaces_repo_shipped_regular_file(tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / SECURITY_CONTEXT_FILENAME).write_text("repo-planted", encoding="utf-8")
    prebuilt = tmp_path / "prebuilt.md"
    prebuilt.write_text("vendored history", encoding="utf-8")

    args = Namespace(fetch_security_context=False)
    assert ntm._prepare_security_context(ntm.Console(color=False), args, prebuilt, clone)
    assert (clone / SECURITY_CONTEXT_FILENAME).read_text(encoding="utf-8") == "vendored history"


def test_fetch_path_clears_repo_shipped_symlink_before_writing(tmp_path, monkeypatch):
    clone = tmp_path / "clone"
    clone.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("precious", encoding="utf-8")
    _symlink_or_skip(clone / SECURITY_CONTEXT_FILENAME, victim)

    def fake_build_context(repo, out_path, **kwargs):
        write_context_file(out_path, "fetched history")
        return {"out": str(out_path), "advisories": 0, "osv_records": 0,
                "security_issues": 0, "rulings": 0, "homepage_refs": 0,
                "extra_docs": 0, "notes": []}

    monkeypatch.setattr(fsc, "build_context", fake_build_context)
    args = Namespace(fetch_security_context=True, repo="https://github.com/x/y",
                     osv_package="", context_url=[])
    ok = ntm._prepare_security_context(ntm.Console(color=False), args, None, clone)
    assert ok is True
    dest = clone / SECURITY_CONTEXT_FILENAME
    assert not dest.is_symlink()
    assert dest.read_text(encoding="utf-8") == "fetched history"
    assert victim.read_text(encoding="utf-8") == "precious"


def _work_dir_with_model(tmp_path: Path) -> Path:
    work = tmp_path / "work"
    work.mkdir()
    (work / "threat-model.md").write_text("# model", encoding="utf-8")
    return work


def test_collect_colocates_published_artifacts_at_output_root(tmp_path):
    work = _work_dir_with_model(tmp_path)
    (work / "threat-model.yaml").write_text("schema: test\n", encoding="utf-8")
    (work / "threat-model.json").write_text("{}\n", encoding="utf-8")
    out = tmp_path / "out"

    have_model, rel_model, have_sidecar, have_json, _ = ntm._collect_artifacts(
        ntm.Console(color=False), work, out, None)

    assert (have_model, rel_model, have_sidecar, have_json) == (
        True, "threat-model.md", True, True)
    assert {p.name for p in out.iterdir()} >= {
        "threat-model.md", "threat-model.yaml", "threat-model.json"}


def test_collect_does_not_accept_nested_prose_path(tmp_path):
    work = tmp_path / "work"
    (work / "docs").mkdir(parents=True)
    (work / "docs" / "threat-model.md").write_text("# legacy", encoding="utf-8")
    out = tmp_path / "out"

    have_model, rel_model, _, _, _ = ntm._collect_artifacts(
        ntm.Console(color=False), work, out, None)

    assert not have_model
    assert rel_model is None
    assert not (out / "threat-model.md").exists()


def test_collect_skips_context_the_runner_did_not_create(tmp_path):
    work = _work_dir_with_model(tmp_path)
    (work / SECURITY_CONTEXT_FILENAME).write_text("repo-planted", encoding="utf-8")
    out = tmp_path / "out"
    ntm._collect_artifacts(ntm.Console(color=False), work, out, None, have_context=False)
    assert not (out / SECURITY_CONTEXT_FILENAME).exists()


def test_collect_copies_runner_created_context(tmp_path):
    work = _work_dir_with_model(tmp_path)
    (work / SECURITY_CONTEXT_FILENAME).write_text("vendored history", encoding="utf-8")
    out = tmp_path / "out"
    ntm._collect_artifacts(ntm.Console(color=False), work, out, None, have_context=True)
    assert (out / SECURITY_CONTEXT_FILENAME).read_text(encoding="utf-8") == "vendored history"


def test_collect_refuses_context_swapped_for_a_symlink(tmp_path):
    # Even runner-created context is re-checked at collect time: the agent runs
    # repo-influenced code in between, which could swap in a symlink to make
    # the collector read an arbitrary user file into the output tree.
    work = _work_dir_with_model(tmp_path)
    secret = tmp_path / "secret.txt"
    secret.write_text("hunter2", encoding="utf-8")
    _symlink_or_skip(work / SECURITY_CONTEXT_FILENAME, secret)
    out = tmp_path / "out"
    ntm._collect_artifacts(ntm.Console(color=False), work, out, None, have_context=True)
    assert not (out / SECURITY_CONTEXT_FILENAME).exists()


# --- runner wiring -----------------------------------------------------------
def test_prompt_names_the_context_file_only_when_present():
    with_ctx = build_prompt("zlib", "", "strict", None, "", "claude", True)
    without = build_prompt("zlib", "", "strict", None, "", "claude", False)
    assert f"./{SECURITY_CONTEXT_FILENAME}" in with_ctx
    assert "do NOT copy the CVE list" in with_ctx
    assert SECURITY_CONTEXT_FILENAME not in without
