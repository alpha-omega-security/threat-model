"""Tests for the batch targets-file parsing in ``batch_threat_models.py``.

The per-target ``key=value`` extension carries repo-specific generator options
(an audit URL, an OSV package) that config-level ``extra_args`` cannot express;
these tests pin the format and its failure modes.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO))

from batch_threat_models import BatchError, load_targets, parse_target_line  # noqa: E402


def test_plain_url_and_bare_ref_still_parse():
    t = parse_target_line("https://github.com/madler/zlib")
    assert (t.url, t.ref, t.extra_args) == ("https://github.com/madler/zlib", "", [])
    t = parse_target_line("https://github.com/jashkenas/underscore 1.13.8")
    assert t.ref == "1.13.8" and t.extra_args == []


def test_options_map_to_generator_flags():
    t = parse_target_line(
        "https://github.com/madler/zlib ref=v1.3.1 osv-package=Debian:zlib "
        "context-url=https://7asecurity.com/zlib-audit/ context-url=https://example.com/2"
    )
    assert t.ref == "v1.3.1"
    assert t.extra_args == [
        "--osv-package", "Debian:zlib",
        "--context-url", "https://7asecurity.com/zlib-audit/",
        "--context-url", "https://example.com/2",
    ]


def test_subdir_option_and_mixed_bare_ref():
    t = parse_target_line("https://github.com/owner/mono main subdir=packages/core")
    assert t.ref == "main"
    assert t.extra_args == ["--subdir", "packages/core"]


def test_unknown_option_fails_loudly():
    with pytest.raises(BatchError, match="unknown target option 'context-uri'"):
        parse_target_line("https://github.com/x/y context-uri=https://example.com")


def test_two_refs_and_empty_value_are_errors():
    with pytest.raises(BatchError, match="two refs"):
        parse_target_line("https://github.com/x/y v1 v2")
    with pytest.raises(BatchError, match="two refs"):
        parse_target_line("https://github.com/x/y v1 ref=v2")
    with pytest.raises(BatchError, match="has no value"):
        parse_target_line("https://github.com/x/y subdir=")


def test_load_targets_keeps_comments_and_dedup_behavior(tmp_path):
    tf = tmp_path / "targets.txt"
    tf.write_text(
        "# comment\n"
        "\n"
        "https://github.com/madler/zlib  osv-package=Debian:zlib\n"
        "https://github.com/madler/zlib  # duplicate slug, skipped\n"
        "https://github.com/libexpat/libexpat  ref=R_2_7_1\n",
        encoding="utf-8",
    )
    targets = load_targets(tf)
    assert [t.slug for t in targets] == ["zlib", "libexpat"]
    assert targets[0].extra_args == ["--osv-package", "Debian:zlib"]
    assert targets[1].ref == "R_2_7_1"
