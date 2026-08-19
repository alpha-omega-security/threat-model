"""Tests for the deterministic validator — 'test the tester'.

Proves two things:
1. the golden zlib fixture passes every check clean; and
2. each single-defect mutation is caught by *exactly* the check that owns it,
   so a check silently breaking would fail this suite.
"""
from __future__ import annotations

import copy
import json

import pytest

import mutate
from threatmodel_eval import (
    Model, load_sidecar, run_json_checks, run_prose_checks,
    run_sidecar_checks, validate,
)
from threatmodel_eval import parse


def _validate(text: str, sidecar: dict, json_report: dict):
    model = Model.from_text(text)
    report = run_prose_checks(model)
    report.extend(run_sidecar_checks(sidecar, model).findings)
    report.extend(run_json_checks(json_report, sidecar, model).findings)
    return report


def _golden_json() -> dict:
    return json.loads(mutate.GOLDEN_JSON.read_text(encoding="utf-8"))


def test_golden_passes_all_checks():
    report = validate(mutate.GOLDEN_MODEL, mutate.GOLDEN_SIDECAR,
                      json_report_path=mutate.GOLDEN_JSON)
    assert report.ok, "golden fixture must have zero error failures:\n" + report.render()
    assert not report.errors


def test_golden_has_no_warnings():
    report = validate(mutate.GOLDEN_MODEL, mutate.GOLDEN_SIDECAR,
                      json_report_path=mutate.GOLDEN_JSON)
    assert not report.warnings, "golden should be warning-clean:\n" + report.render()


def test_stale_prose_digest_is_rejected():
    sidecar = copy.deepcopy(load_sidecar(mutate.GOLDEN_SIDECAR))
    sidecar["prose_version"] = "threat-model.md@sha256:" + "0" * 64
    model = Model.from_file(mutate.GOLDEN_MODEL)
    report = run_sidecar_checks(sidecar, model)
    assert "SC.prose-version" in report.failed_check_ids()


def test_non_root_prose_path_is_rejected():
    sidecar = copy.deepcopy(load_sidecar(mutate.GOLDEN_SIDECAR))
    digest = sidecar["prose_version"].split("@sha256:", 1)[1]
    sidecar["prose_version"] = f"docs/threat-model.md@sha256:{digest}"
    model = Model.from_file(mutate.GOLDEN_MODEL)
    report = run_sidecar_checks(sidecar, model)
    assert "SC.prose-version" in report.failed_check_ids()


def test_prose_must_be_colocated_with_sidecar(tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    model_path = docs / "threat-model.md"
    model_path.write_bytes(mutate.GOLDEN_MODEL.read_bytes())
    sidecar_path = tmp_path / "threat-model.yaml"
    sidecar_path.write_bytes(mutate.GOLDEN_SIDECAR.read_bytes())

    report = validate(model_path, sidecar_path)

    assert "SC.prose-version" in report.failed_check_ids()


def test_adversary_accepts_assumption_provenance():
    """`assumption` is a schema-sanctioned provenance kind for adversaries.

    sidecar-schema.md: kind is documented | maintainer | assumption | inferred;
    an assumption carries a question_id plus an optional rationale. SC.adversaries
    must not reject a well-formed assumption-provenanced adversary.
    """
    sidecar = copy.deepcopy(load_sidecar(mutate.GOLDEN_SIDECAR))
    sidecar["adversaries"][0]["provenance"] = {
        "kind": "assumption",
        "question_id": "Q1",
        "rationale": "Conservative in-process library boundary.",
    }
    model = Model.from_file(mutate.GOLDEN_MODEL)
    report = run_sidecar_checks(sidecar, model)
    assert "SC.adversaries" not in report.failed_check_ids()


def test_responsibility_may_enforce_nothing_for_unsupported_surface():
    """A §1.13 responsibility may target an out-of-scope surface and enforce nothing.

    For a shipped-but-unsupported component (declared scope: out) the
    responsibility is to escalate, not to uphold a named contract, so it may
    both name an out-of-scope component and carry an empty `enforces` list.
    sidecar-schema.md mandates in-scope components only for outputs and contract
    dimensions, not for responsibilities. SC.reference-integrity must accept it.
    """
    sidecar = copy.deepcopy(load_sidecar(mutate.GOLDEN_SIDECAR))
    sidecar["components"].append({"name": "unsupported-surface", "scope": "out"})
    sidecar["downstream_responsibilities"].append({
        "id": "r-escalate-unsupported",
        "component": "unsupported-surface",
        "statement": "Escalate any reliance on the unsupported surface.",
        "enforces": [],
        "provenance": {"kind": "inferred", "question_id": "Q1"},
    })
    model = Model.from_file(mutate.GOLDEN_MODEL)
    report = run_sidecar_checks(sidecar, model)
    assert "SC.reference-integrity" not in report.failed_check_ids()


def test_contract_dimension_matrix_accepts_hyphenated_slugs():
    """The §1.7 matrix may spell the nine dimensions as sidecar-style slugs.

    sidecar-schema.md defines the canonical dimension enum with hyphens
    (``recursive-cyclic-topology``) while the prose reference writes them with
    spaces/slashes (``recursive/cyclic topology``). Both are legitimate, so the
    coverage check must be separator-insensitive.
    """
    import pathlib
    text = pathlib.Path(mutate.GOLDEN_MODEL).read_text(encoding="utf-8")
    slugged = (text
               .replace("numeric domain", "numeric-domain")
               .replace("failure atomicity", "failure-atomicity")
               .replace("recursive/cyclic topology", "recursive-cyclic-topology")
               .replace("callback execution", "callback-execution")
               .replace("serialization/reconstruction", "serialization-reconstruction")
               .replace("reference lifecycle", "reference-lifecycle")
               .replace("concurrency/reentrancy", "concurrency-reentrancy")
               .replace("resource complexity", "resource-complexity")
               .replace("authorization scope", "authorization-scope"))
    report = run_prose_checks(Model.from_text(slugged))
    assert "G2.contract-dimension-matrix" not in report.failed_check_ids()


def test_contract_dimension_matrix_accepts_full_reference_names():
    """The §1.7 matrix may use the reference's fuller dimension names.

    output-structure.md names the dimensions "failure/exception atomicity",
    "callback/collaborator execution", and "reference/object lifecycle"; the
    golden fixture uses shorter forms. Both must satisfy the coverage check.
    """
    import pathlib
    text = pathlib.Path(mutate.GOLDEN_MODEL).read_text(encoding="utf-8")
    full = (text
            .replace("failure atomicity", "failure/exception atomicity")
            .replace("callback execution", "callback/collaborator execution")
            .replace("reference lifecycle", "reference/object lifecycle")
            .replace("numeric domain", "numeric domain and representational limits"))
    report = run_prose_checks(Model.from_text(full))
    assert "G2.contract-dimension-matrix" not in report.failed_check_ids()


@pytest.mark.parametrize("case", mutate.build_cases(), ids=lambda c: c.name)
def test_mutation_is_caught_by_owning_check(case: mutate.MutationCase):
    json_report = (case.json_report if case.json_report is not None
                   else _golden_json())
    report = _validate(case.model_text, case.sidecar, json_report)
    assert not report.ok, f"{case.name}: mutation slipped through validation"
    error_ids = {f.check_id for f in report.errors}
    assert error_ids == case.expected_failures, (
        f"{case.name}: error checks {sorted(error_ids)} "
        f"!= expected {sorted(case.expected_failures)}\n{report.render()}"
    )


def test_all_declared_checks_exist_on_golden():
    """Every expected_failures check_id must be a real check that passes on golden."""
    report = validate(mutate.GOLDEN_MODEL, mutate.GOLDEN_SIDECAR,
                      json_report_path=mutate.GOLDEN_JSON)
    known = {f.check_id for f in report.findings}
    declared = set().union(*(c.expected_failures for c in mutate.build_cases()))
    missing = declared - known
    assert not missing, f"mutations reference unknown check_ids: {sorted(missing)}"


_S18_NUMBERED = (
    "# T\n\n## 1.18 Open questions\n\n"
    "1. Confirm the untrusted surface. Lands in §1.7.\n"
    "2. Confirm scope. Lands in §1.2.\n"
)
_S18_TITLED = (
    "# T\n\n## 1.18 Open questions\n\n"
    "**Q1 — Public scope.** Proposed answer: only documented API. Lands in §1.2.\n\n"
    "**Q2 — Host side effects.** Proposed answer: none beyond §1.5. Lands in §1.5.\n"
)
_S18_BULLET_LABEL = (
    "# T\n\n## 1.18 Open questions\n\n"
    "- [Q1]: Confirm the untrusted surface.\n"
    "- [Q2]: Confirm scope.\n"
)
_S18_BULLET_BOLD = (
    "# T\n\n## 1.18 Open questions\n\n"
    "- **Q1** \u2014 Scope and adversary. Proposed answer: only documented API.\n"
    "- **Q2** \u2014 Host side effects. Proposed answer: none beyond \u00a71.5.\n"
)


@pytest.mark.parametrize(
    "body",
    [_S18_NUMBERED, _S18_TITLED, _S18_BULLET_LABEL, _S18_BULLET_BOLD],
)
def test_open_question_ids_recognizes_all_permitted_formats(body):
    model = Model.from_text(body)
    assert model.open_question_ids() == {"Q1", "Q2"}
    assert model.open_question_count() == 2



# --------------------------------------------------------------------------- #
# Section.is_na — the N/A marker gates the sidecar projection-coverage check,
# so a false positive here silently excuses a whole section from the sidecar.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,body,expected", [
    ("bare marker", "Not applicable — zlib is not a distributed system.", True),
    ("wrapped reason", "Not applicable — zlib is a library, not a\ndistributed system.", True),
    ("bold marker", "**Not applicable** — folded into §1.7.", True),
    ("no trailing period", "Not applicable — no externally consumed output", True),
    ("marker then body", "Not applicable — see §1.7.\n\nThe attacker controls the "
                         "compressed input bytes and crafts arbitrary streams.", False),
    ("marker then prose, one paragraph",
     "Not applicable — see §1.7. The attacker controls the compressed bytes "
     "and crafts arbitrary streams.", False),
    ("buried mention", "The attacker controls the bytes.\n\nByzantine "
                       "participants: not applicable — zlib is not distributed.", False),
    ("first bullet of a list", "- Not applicable to row 3.\n- The attacker "
                               "controls the compressed bytes.", False),
])
def test_section_is_na_only_for_a_whole_body_marker(name, body, expected):
    assert parse.Section("10", "1.10 Adversary model", body).is_na is expected, name
