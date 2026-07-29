"""Mutation generator — negative fixtures that prove the checks bite.

Each :class:`MutationCase` takes the golden zlib fixture and introduces exactly
one defect, declaring the ``check_id`` that MUST flip to FAIL. The pytest suite
asserts (a) the golden passes clean and (b) every mutation is caught by its
declared check — and by that check *specifically* — so a check that silently
stops working is detected.

Run as a script to also materialize the mutated fixtures under
``tests/fixtures/mutations/<name>/`` for manual inspection.
"""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[2]
GOLDEN_DIR = _REPO / "tests" / "fixtures" / "golden" / "zlib"
GOLDEN_MODEL = GOLDEN_DIR / "docs" / "threat-model.md"
GOLDEN_SIDECAR = GOLDEN_DIR / "threat-model.yaml"
OUT_DIR = _REPO / "tests" / "fixtures" / "mutations"


@dataclass
class MutationCase:
    name: str
    description: str
    expected_failures: set[str]
    model_text: str
    sidecar: dict = field(default_factory=dict)


# ---- text helpers ---------------------------------------------------------
def _section_span(text: str, num: str) -> re.Match | None:
    return re.search(
        rf"(^## 1\.{num} .*?$)(.*?)(?=^## 1\.|\Z)",
        text, re.DOTALL | re.MULTILINE,
    )


def _drop_section(text: str, num: str) -> str:
    return re.sub(
        rf"^## 1\.{num} .*?(?=^## 1\.|\Z)", "", text,
        count=1, flags=re.DOTALL | re.MULTILINE,
    )


def _strip_table_lines(text: str, num: str) -> str:
    m = _section_span(text, num)
    assert m, f"section 1.{num} not found"
    body = m.group(2)
    kept = [ln for ln in body.splitlines() if not ln.lstrip().startswith("|")]
    new_body = "\n".join(kept)
    new_body += "\n\nInputs are described in prose only in this mutant.\n"
    return text[: m.start(2)] + new_body + text[m.end(2):]


def _strip_blockquote(text: str, num: str) -> str:
    m = _section_span(text, num)
    assert m, f"section 1.{num} not found"
    body = m.group(2)
    kept = [ln for ln in body.splitlines() if not ln.lstrip().startswith(">")]
    new_body = "\n".join(kept)
    return text[: m.start(2)] + new_body + text[m.end(2):]


# ---- case registry --------------------------------------------------------
def build_cases() -> list[MutationCase]:
    model = GOLDEN_MODEL.read_text(encoding="utf-8")
    sidecar = yaml.safe_load(GOLDEN_SIDECAR.read_text(encoding="utf-8"))
    cases: list[MutationCase] = []

    def add(name, desc, expected, text=None, sc=None):
        cases.append(MutationCase(
            name, desc, set(expected),
            text if text is not None else model,
            copy.deepcopy(sc if sc is not None else sidecar),
        ))

    # --- prose mutations ---
    add("drop-section-1.11",
        "remove the entire §1.11 section (also desyncs the documented count)",
        {"G2.section-1.11", "G1.confidence-matches"},
        text=_drop_section(model, "11"))

    add("inject-hedge-tag",
        "add a forbidden (generally known) hedge-tag without changing counts",
        {"G1.no-hedge-tags"},
        text=model.replace(
            "use a MAC *(documented, zlib manual)*.",
            "use a MAC *(generally known)* *(documented, zlib manual)*.", 1))

    add("mismatch-header-confidence",
        "corrupt the header count (desyncs both the body and the sidecar)",
        {"G1.confidence-matches", "SC.confidence-matches-header"},
        text=model.replace(
            "59 documented / 0 maintainer / 8 inferred",
            "99 documented / 0 maintainer / 8 inferred", 1))

    add("drop-open-questions",
        "delete §1.18 while inferred tags remain (breaks the mapping rule)",
        {"G1.inferred-has-questions"},
        text=_drop_section(model, "18"))

    add("break-input-trust-table",
        "remove the §1.7 trust table and contract-dimension matrix",
        {"G1.confidence-matches", "G2.input-trust-table",
         "G2.contract-dimension-matrix"},
        text=_strip_table_lines(model, "7"))

    add("remove-triager-quickstart",
        "delete the §1.1 triager quick-start block",
        {"G3.triager-quickstart"},
        text=_strip_blockquote(model, "1"))

    add("documented-tag-without-source",
        "a documented body claim loses its source label",
        {"G1.provenance-details"},
        text=model.replace(
            "*(documented, zlib manual)*", "*(documented)*", 1))

    add("inferred-tag-with-unknown-question",
        "an inferred body claim references a nonexistent Q-ID",
        {"G1.inferred-has-questions"},
        text=model.replace("*(inferred, Q3)*", "*(inferred, Q99)*", 1))

    add("input-table-without-provenance-column",
        "the trust table header loses its provenance column",
        {"G2.input-trust-table"},
        text=model.replace(
            "| Entry point | Input operand | Attacker-controllable? | Control kind | Caller must enforce | Provenance |",
            "| Entry point | Input operand | Attacker-controllable? | Control kind | Caller must enforce |",
            1))

    add("matrix-without-provenance-column",
        "the contract-dimension matrix header loses its provenance column",
        {"G2.contract-dimension-matrix"},
        text=model.replace(
            "| Component | Dimension | Status | Conditions / boundary | Routes to | Provenance |",
            "| Component | Dimension | Status | Conditions / boundary | Routes to |",
            1))

    # --- sidecar mutations ---
    sc = copy.deepcopy(sidecar)
    sc["schema"] = "threat-model-sidecar/v1"
    add("sidecar-bad-schema", "unknown sidecar schema tag",
        {"SC.schema"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["dispositions"] = list(sc["dispositions"]) + ["OUT-OF-MODEL: made-up"]
    add("sidecar-invented-disposition",
        "add a disposition outside the closed set",
        {"SC.dispositions"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["confidence"]["inferred"] = 9
    add("sidecar-confidence-drift",
        "sidecar confidence no longer matches the prose header",
        {"SC.confidence-matches-header"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["properties_claimed"][0].pop("violation_symptoms", None)
    add("sidecar-strip-violation-symptom",
        "a claimed property loses its violation symptoms",
        {"SC.claimed-tier-symptom"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    for ep in sc["entry_points"]:
        for p in ep.get("parameters", []):
            if p.get("attacker_controllable"):
                p["caller_must_enforce"] = ""
    add("sidecar-attacker-param-no-enforce",
        "attacker-controllable parameter loses its caller_must_enforce",
        {"SC.param-enforce"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["outputs"][0]["taint"] = "clean"
    add("sidecar-bad-output-taint",
        "output declares an invalid taint value",
        {"SC.output-taint"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["contract_dimensions"].pop()
    add("sidecar-missing-contract-dimension",
        "one in-scope component loses a required contract-dimension row",
        {"SC.contract-dimensions"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["downstream_responsibilities"][0]["enforces"] = ["missing-property-id"]
    add("sidecar-bad-stable-reference",
        "a downstream responsibility references a nonexistent stable ID",
        {"SC.reference-integrity"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["entry_points"][0]["parameters"][0]["control_kinds"] = []
    add("sidecar-missing-control-kind",
        "an input operand loses its required control kind",
        {"SC.param-control-kinds"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["dependency_policy"]["provenance"] = {"kind": "documented"}
    add("sidecar-bad-policy-provenance",
        "dependency policy loses its documented source",
        {"SC.policy-provenance"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["outputs"][0]["invariants"][0]["provenance"] = {"kind": "inferred"}
    add("sidecar-bad-invariant-provenance",
        "an output invariant has incomplete inferred provenance",
        {"SC.output-contract"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["model_status"] = "accepted"
    add("sidecar-accepted-with-inferred",
        "an accepted model retains inferred claims",
        {"SC.accepted-no-inferred"},
        text=model.replace("**Status**: unratified draft", "**Status**: accepted", 1),
        sc=sc)

    sc = copy.deepcopy(sidecar)
    digest = sc["prose_version"].split("@sha256:", 1)[1]
    sc["prose_version"] = f"../docs/threat-model.md@sha256:{digest}"
    add("sidecar-noncanonical-prose-path",
        "the prose binding uses a parent-directory traversal path",
        {"SC.prose-version"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["host_side_effects"][0]["provenance"] = {"kind": "inferred"}
    add("sidecar-bad-side-effect-provenance",
        "a negative host-side-effect claim loses its question ID",
        {"SC.host-side-effects"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["disposition_precedence"] = list(reversed(sc["disposition_precedence"]))
    add("sidecar-bad-disposition-precedence",
        "the deterministic first-match disposition order is reversed",
        {"SC.disposition-precedence"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["model_status"] = "draft"
    add("sidecar-status-drift",
        "sidecar status no longer matches the normalized prose status",
        {"SC.status"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["known_misuses"] = []
    add("sidecar-missing-prose-projection",
        "a substantive prose section has no sidecar records",
        {"SC.prose-projection-coverage"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    row = next(r for r in sc["contract_dimensions"]
               if r["component"] == "core-deflate" and r["dimension"] == "numeric-domain")
    row["property_id"] = "termination"
    add("sidecar-property-wrong-component",
        "a contract row references a claimed property for another component",
        {"SC.contract-dimensions"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["outputs"][0]["component"] = "gzip-file-api"
    sc["outputs"][0]["invariants"][0]["property_id"] = "termination"
    add("sidecar-output-property-wrong-component",
        "an output invariant references a property for another component",
        {"SC.output-contract"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    effect = sc["build_flags"][1]["affects_properties"][0]
    effect["property_id"] = "resource-budgeting"
    add("sidecar-build-affects-disclaimer",
        "a build effect points to a disclaimed rather than claimed property",
        {"SC.reference-integrity"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["dependencies"][0]["violation_disposition"] = "VALID"
    add("sidecar-bad-dependency-disposition",
        "a dependency contract failure invents a non-dependency route",
        {"SC.dependencies"}, sc=sc)

    return cases


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for case in build_cases():
        d = OUT_DIR / case.name
        (d / "docs").mkdir(parents=True, exist_ok=True)
        (d / "docs" / "threat-model.md").write_text(case.model_text, encoding="utf-8")
        (d / "threat-model.yaml").write_text(
            yaml.safe_dump(case.sidecar, sort_keys=False), encoding="utf-8")
        (d / "expected.json").write_text(
            json.dumps({
                "description": case.description,
                "expected_failures": sorted(case.expected_failures),
            }, indent=2), encoding="utf-8")
    print(f"wrote {len(build_cases())} mutation fixtures to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
