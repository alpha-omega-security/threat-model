"""Tests for ``fetch_security_context.py`` and its wiring in the runner.

Covers the pure, network-free pieces: source classification, alias dedup,
markdown rendering (including the fence/heading sanitization that keeps a
hostile issue body from hijacking the file's structure), and the prompt note
that points the agent at the vendored file.
"""
from __future__ import annotations

import socket
import sys
import urllib.request
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO))

import fetch_security_context as fsc  # noqa: E402
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
    validate_public_url,
)
from new_threat_model import SECURITY_CONTEXT_FILENAME, build_prompt  # noqa: E402


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


# --- runner wiring -----------------------------------------------------------
def test_prompt_names_the_context_file_only_when_present():
    with_ctx = build_prompt("zlib", "", "strict", None, "", "claude", True)
    without = build_prompt("zlib", "", "strict", None, "", "claude", False)
    assert f"./{SECURITY_CONTEXT_FILENAME}" in with_ctx
    assert "do NOT copy the CVE list" in with_ctx
    assert SECURITY_CONTEXT_FILENAME not in without
