"""Tests for export_json.py — the prose+sidecar → threat-model.json converter.

The converter's
promises, in test order: the golden fixture converts and validates clean; a
commit it cannot determine is a refusal that names the flag, never a
fabricated sha; --force writes a failing export but does not soften the exit
code; author-only fields come from the prose, not from thin air; and a claim
the sidecar holds as inferred never surfaces as documented.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

import mutate  # noqa: F401  (puts the harness dir on sys.path via conftest)
from export_json import main

_REPO_URL = "https://github.com/madler/zlib"
_COMMIT = "51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf"


def _convert(tmp_path: Path, *extra: str) -> tuple[int, Path]:
    out = tmp_path / "threat-model.json"
    rc = main([str(mutate.GOLDEN_MODEL), str(mutate.GOLDEN_SIDECAR),
               "--out", str(out), *extra])
    return rc, out


def test_golden_converts_and_validates_clean(tmp_path):
    rc, out = _convert(tmp_path, "--repository", _REPO_URL,
                       "--commit", _COMMIT, "--date", "2026-08-07")
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert text.endswith("}\n")               # trailing newline, per contract
    assert '\n  "spec_version": 1' in text    # two-space indent
    report = json.loads(text)
    assert report["repository"] == _REPO_URL
    assert report["commit"] == _COMMIT
    # The written document passes the JSON gate on a fresh run, not just the
    # converter's own in-process report.
    from threatmodel_eval.jsonreport import run_json_checks
    from threatmodel_eval.parse import Model, load_sidecar
    checks = run_json_checks(report, load_sidecar(mutate.GOLDEN_SIDECAR),
                             Model.from_file(mutate.GOLDEN_MODEL))
    assert checks.ok, checks.render()


def test_missing_commit_fails_naming_the_flag(tmp_path, capsys):
    # The golden header records no commit, so the converter must refuse —
    # a fabricated sha would bind the export to a tree that never existed.
    rc, out = _convert(tmp_path, "--repository", _REPO_URL)
    assert rc == 2
    assert not out.exists()
    assert "--commit" in capsys.readouterr().err


def test_missing_repository_fails_naming_the_flag(tmp_path, capsys):
    rc, out = _convert(tmp_path, "--commit", _COMMIT)
    assert rc == 2
    assert not out.exists()
    assert "--repository" in capsys.readouterr().err


def test_force_writes_despite_induced_failure(tmp_path, capsys):
    # An all-zeros sha passes the shape gate but fails JSON.commit-present.
    rc, out = _convert(tmp_path, "--repository", _REPO_URL,
                       "--commit", "0" * 40)
    assert rc == 1
    assert not out.exists(), "a failing export must not be written silently"
    rc, out = _convert(tmp_path, "--repository", _REPO_URL,
                       "--commit", "0" * 40, "--force")
    assert out.exists(), "--force must write the file"
    assert rc == 1, "--force controls the write, not the verdict"
    assert "WARNING" in capsys.readouterr().err


def test_prose_extraction_fills_description_and_open_questions(tmp_path):
    rc, out = _convert(tmp_path, "--repository", _REPO_URL,
                       "--commit", _COMMIT)
    assert rc == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    # §1.2's first paragraph, not an invented summary.
    assert report["description"].startswith("Primary intended use")
    questions = report["open_questions"]
    assert [q["claim"].split(":", 1)[0] for q in questions] \
        == ["Q1", "Q2", "Q3", "Q4", "Q5"]
    by_id = {q["claim"].split(":", 1)[0]: q for q in questions}
    # "Lands in: §N" mapped to the JSON field name.
    assert by_id["Q2"]["field"] == "out_of_scope"        # lands in §1.3
    assert by_id["Q4"]["field"] == "entry_points"        # lands in §1.7
    assert by_id["Q5"]["field"] == "environment"         # lands in §1.5
    assert all(q.get("proposed") for q in questions)


def test_inferred_never_surfaces_as_documented(tmp_path):
    # As shipped: the golden holds contrib-samples as inferred (Q2).
    rc, out = _convert(tmp_path, "--repository", _REPO_URL,
                       "--commit", _COMMIT)
    assert rc == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    oos = {r["item"]: r["provenance"] for r in report["out_of_scope"]}
    assert oos["contrib-samples"] == "inferred"
    # And under mutation: flip an in-scope documented component to inferred;
    # the JSON row must collapse down, never up.
    sidecar = yaml.safe_load(mutate.GOLDEN_SIDECAR.read_text(encoding="utf-8"))
    for comp in sidecar["components"]:
        if comp["name"] == "core-inflate":
            comp["provenance"] = {"kind": "inferred", "question_id": "Q1"}
    mutated = tmp_path / "mutated-sidecar.yaml"
    mutated.write_text(yaml.safe_dump(sidecar), encoding="utf-8")
    out = tmp_path / "mutated.json"
    rc = main([str(mutate.GOLDEN_MODEL), str(mutated), "--out", str(out),
               "--repository", _REPO_URL, "--commit", _COMMIT, "--force"])
    report = json.loads(out.read_text(encoding="utf-8"))
    row = next(c for c in report["components"] if c["name"] == "core-inflate")
    assert row["provenance"] == "inferred"
    assert "source" not in row or "open question" in row["source"]
