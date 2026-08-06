"""Tests for the runner command-template argv construction.

Substituting placeholders into the template and splitting the result afterwards
let a value containing a quote inject extra argv entries -- a hostile repo URL
could add flags to the generator invocation. ``build_argv`` splits first and
substitutes per token; these tests pin that boundary.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO / "tests" / "harness"))

from threatmodel_eval.runners import RunnerError, build_argv  # noqa: E402



def test_build_argv_keeps_each_value_as_one_argument():
    argv = build_argv(
        'python ./gen.py --project "{name}" --repo "{repo}" --out "{outdir}"',
        name="p", repo="https://github.com/o/r", outdir="/o")
    assert argv == ["python", "./gen.py", "--project", "p",
                    "--repo", "https://github.com/o/r", "--out", "/o"]


def test_build_argv_refuses_to_let_a_value_inject_arguments():
    # Substituting before splitting turned this into separate argv entries,
    # letting a hostile repo string add flags to the generator invocation.
    evil = 'https://h/r" --extra-claude-args --dangerously-skip-permissions "'
    argv = build_argv('python ./gen.py --repo "{repo}" --out "{outdir}"',
                      repo=evil, outdir="/o")
    assert argv == ["python", "./gen.py", "--repo", evil, "--out", "/o"]
    assert "--dangerously-skip-permissions" not in argv


def test_build_argv_handles_spaces_and_placeholders_inside_tokens():
    argv = build_argv("cmd --repo={repo} --name={name}",
                      repo="https://h/r x", name="a b")
    assert argv == ["cmd", "--repo=https://h/r x", "--name=a b"]


def test_build_argv_reports_an_unknown_placeholder():
    with pytest.raises(RunnerError, match="unknown placeholder"):
        build_argv("cmd --thing {nope}", repo="r")
