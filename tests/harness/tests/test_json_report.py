"""The threat-model.json export layer — mini schema validator and projection.

The mutation suite in test_validator.py proves each JSON.* check flips on its
owning defect. It cannot prove that the schema validator actually sees every
keyword class it claims, that the sidecar projection never upgrades provenance,
or that the wiring fails soft when the JSON arrives without a sidecar. That
lives here, against the real schema.json and the golden zlib fixture.
"""
from __future__ import annotations

import copy
import json

import pytest
import yaml

import mutate
from threatmodel_eval import validate
from threatmodel_eval.jsonreport import (
    JSON_DISPOSITIONS,
    _SCHEMA_PATH,
    project_from_sidecar,
    run_json_checks,
)
from threatmodel_eval.jsonschema_mini import validate_instance

SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def _golden_json() -> dict:
    return json.loads(mutate.GOLDEN_JSON.read_text(encoding="utf-8"))


def _golden_sidecar() -> dict:
    return yaml.safe_load(mutate.GOLDEN_SIDECAR.read_text(encoding="utf-8"))


def _project(sidecar: dict) -> dict:
    golden = _golden_json()
    return project_from_sidecar(
        sidecar,
        repository=golden["repository"],
        commit=golden["commit"],
        date=golden["date"],
        description=golden["description"],
    )


# --------------------------------------------------------------------------- #
# Golden trio and wiring
# --------------------------------------------------------------------------- #
def test_golden_trio_validates_clean():
    report = validate(mutate.GOLDEN_MODEL, mutate.GOLDEN_SIDECAR,
                      json_report_path=mutate.GOLDEN_JSON)
    assert report.ok, report.render()
    assert not report.warnings, report.render()


def test_golden_json_satisfies_schema():
    assert validate_instance(_golden_json(), SCHEMA) == []


def test_json_without_sidecar_is_a_finding_not_a_crash():
    report = validate(mutate.GOLDEN_MODEL,
                      json_report_path=mutate.GOLDEN_JSON)
    assert "JSON.requires-sidecar" in {f.check_id for f in report.errors}


def test_unreadable_json_reports_as_schema_invalid(tmp_path):
    bad = tmp_path / "threat-model.json"
    bad.write_text("{not json", encoding="utf-8")
    report = validate(mutate.GOLDEN_MODEL, mutate.GOLDEN_SIDECAR,
                      json_report_path=bad)
    assert "JSON.schema-valid" in {f.check_id for f in report.errors}


def test_non_object_json_reports_as_schema_invalid(tmp_path):
    bad = tmp_path / "threat-model.json"
    bad.write_text("[]", encoding="utf-8")
    report = validate(mutate.GOLDEN_MODEL, mutate.GOLDEN_SIDECAR,
                      json_report_path=bad)
    assert "JSON.schema-valid" in {f.check_id for f in report.errors}


def test_dispositions_constant_matches_schema_enum():
    # If schema.json ever grows a tenth label, the export code must move with it.
    assert JSON_DISPOSITIONS == SCHEMA["$defs"]["disposition"]["enum"]


# --------------------------------------------------------------------------- #
# Mini validator — one probe per keyword class it claims to implement.
# Each probe breaks the golden document in exactly one place and expects a
# pathed error naming that place, so a keyword that silently stops validating
# fails its own probe.
# --------------------------------------------------------------------------- #
def _set(path_keys, value):
    def apply(doc):
        node = doc
        for key in path_keys[:-1]:
            node = node[key]
        node[path_keys[-1]] = value
    return apply


def _delete(key):
    def apply(doc):
        del doc[key]
    return apply


def _dup_disposition(doc):
    doc["dispositions"][8] = doc["dispositions"][0]


def _truncate_dispositions(doc):
    doc["dispositions"] = doc["dispositions"][:8]


_KEYWORD_CASES = [
    ("wrong-type", _set(["description"], 5),
     "$.description", "is not of type 'string'"),
    ("bool-as-integer", _set(["confidence", "documented"], True),
     "$.confidence.documented", "is not of type 'integer'"),
    ("bad-enum", _set(["components", 0, "touches"], ["sockets"]),
     "$.components[0].touches[0]", "is not one of"),
    ("missing-required", _delete("entry_points"),
     "$", "required property 'entry_points' is missing"),
    ("additional-property", _set(["invented"], "x"),
     "$.invented", "unexpected property"),
    ("oneof-miss", _set(["out_of_scope"], {"not_applicable": "yes"}),
     "$.out_of_scope", "matches none of the"),
    ("bad-pattern", _set(["commit"], "HEAD"),
     "$.commit", "does not match"),
    ("bad-date", _set(["date"], "2026-02-30"),
     "$.date", "not a real YYYY-MM-DD date"),
    ("bad-uri", _set(["repository"], "github.com/madler/zlib"),
     "$.repository", "is not a URI"),
    ("min-items", _truncate_dispositions,
     "$.dispositions", "needs at least 9"),
    ("unique-items", _dup_disposition,
     "$.dispositions", "duplicate items"),
    ("const", _set(["spec_version"], 2),
     "$.spec_version", "is not the constant 1"),
    ("minimum", _set(["confidence", "inferred"], -1),
     "$.confidence.inferred", "less than the minimum"),
]


@pytest.mark.parametrize("name,break_doc,path,fragment", _KEYWORD_CASES,
                         ids=[c[0] for c in _KEYWORD_CASES])
def test_mini_validator_catches_keyword_class(name, break_doc, path, fragment):
    doc = _golden_json()
    break_doc(doc)
    errors = validate_instance(doc, SCHEMA)
    assert any(e.startswith(f"{path}:") and fragment in e for e in errors), \
        f"{name}: expected '{path}: ...{fragment}...' in {errors}"


def test_mini_validator_errors_are_capped():
    # A wrong-shaped document must not produce a wall of text.
    doc = {"components": [5] * 100}
    errors = validate_instance(doc, SCHEMA)
    assert len(errors) <= 41
    assert errors[-1].startswith("+") and "not shown" in errors[-1]


# --------------------------------------------------------------------------- #
# Projection — the sidecar-derived starting point.
# --------------------------------------------------------------------------- #
def test_projection_validates_against_schema():
    assert validate_instance(_project(_golden_sidecar()), SCHEMA) == []


def test_projection_passes_json_checks():
    sidecar = _golden_sidecar()
    report = run_json_checks(_project(sidecar), sidecar)
    assert report.ok, report.render()


def test_projection_round_trips_derivable_fields():
    golden = _golden_json()
    doc = _project(_golden_sidecar())
    assert [c["name"] for c in doc["components"]] \
        == [c["name"] for c in golden["components"]]
    assert {(r["entry_point"], r["parameter"]) for r in doc["entry_points"]} \
        == {(r["entry_point"], r["parameter"]) for r in golden["entry_points"]}
    assert [p["property"] for p in doc["properties_provided"]] \
        == [p["property"] for p in golden["properties_provided"]]
    assert [p["property"] for p in doc["properties_not_provided"]] \
        == [p["property"] for p in golden["properties_not_provided"]]
    assert doc["dispositions"] == golden["dispositions"]
    assert doc["confidence"] == golden["confidence"]


def test_projection_collapses_golden_provenance_down():
    doc = _project(_golden_sidecar())
    # contrib-samples is inferred (Q2) in the sidecar; the carve-out must not
    # surface as documented, and its source must point at the open question.
    contrib = next(r for r in doc["out_of_scope"]
                   if r["item"] == "contrib-samples")
    assert contrib["provenance"] == "inferred"
    assert contrib["source"] == "open question Q2"
    # environment and adversaries collapse many records; the golden has
    # inferred contributors (Q5, Q1), so both blocks read inferred.
    assert doc["environment"]["provenance"] == "inferred"
    assert doc["adversaries"]["provenance"] == "inferred"
    # the Q4 caller-trusted rows stay inferred too
    q4 = [r for r in doc["entry_points"]
          if r.get("source") == "open question Q4"]
    assert q4 and all(r["provenance"] == "inferred" for r in q4)
    # documented records keep their authority — the collapse is not gratuitous
    assert all(c["provenance"] == "documented" for c in doc["components"])


def _demote_all(node) -> None:
    """Rewrite every provenance record in place to an assumption."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("provenance", "taint_provenance") \
                    and isinstance(value, dict):
                node[key] = {"kind": "assumption", "question_id": "Q1"}
            else:
                _demote_all(value)
    elif isinstance(node, list):
        for item in node:
            _demote_all(item)


def _provenance_values(node, out: list) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "provenance":
                out.append(value)
            _provenance_values(value, out)
    elif isinstance(node, list):
        for item in node:
            _provenance_values(item, out)


def test_projection_never_emits_documented_for_unratified_records():
    # The hard rule: assumption/inferred must never surface as documented.
    # Demote every record and require the projection to contain not one
    # documented provenance anywhere.
    sidecar = copy.deepcopy(_golden_sidecar())
    _demote_all(sidecar)
    values: list = []
    _provenance_values(_project(sidecar), values)
    assert values and set(values) == {"inferred"}


# --------------------------------------------------------------------------- #
# Mutation materialization — the script output includes the JSON artifact.
# --------------------------------------------------------------------------- #
def test_mutation_materialization_writes_json(tmp_path, monkeypatch):
    monkeypatch.setattr(mutate, "OUT_DIR", tmp_path)
    assert mutate.main() == 0
    golden_text = mutate.GOLDEN_JSON.read_text(encoding="utf-8")
    for case in mutate.build_cases():
        model = tmp_path / case.name / "threat-model.md"
        written = tmp_path / case.name / "threat-model.json"
        assert model.exists(), case.name
        assert not (tmp_path / case.name / "docs").exists(), case.name
        assert written.exists(), case.name
        if case.json_report is None:
            # prose/sidecar-only cases carry the golden export unchanged
            assert written.read_text(encoding="utf-8") == golden_text, case.name
        else:
            assert json.loads(written.read_text(encoding="utf-8")) \
                == case.json_report, case.name
