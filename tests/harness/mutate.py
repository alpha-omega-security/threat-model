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
GOLDEN_MODEL = GOLDEN_DIR / "threat-model.md"
GOLDEN_SIDECAR = GOLDEN_DIR / "threat-model.yaml"
GOLDEN_JSON = GOLDEN_DIR / "threat-model.json"
OUT_DIR = _REPO / "tests" / "fixtures" / "mutations"


@dataclass
class MutationCase:
    name: str
    description: str
    expected_failures: set[str]
    model_text: str
    sidecar: dict = field(default_factory=dict)
    # None means "golden threat-model.json unchanged" — the consuming suite
    # substitutes the golden export so the JSON checks run on every case.
    json_report: dict | None = None


# ---- text helpers ---------------------------------------------------------
def _section_span(text: str, num: str) -> re.Match | None:
    return re.search(
        rf"(^## 1\.{num} .*?$)(.*?)(?=^## 1\.|\Z)",
        text, re.DOTALL | re.MULTILINE,
    )


def _table_questions(text: str) -> str:
    """Rewrite the whole §1.18 body as a table (yields zero parseable Q-IDs)."""
    m = _section_span(text, "18")
    assert m, "section 1.18 not found"
    rows = "\n".join(
        f"| **Q{n}** | Placeholder question {n} | §1.7 |" for n in range(1, 6))
    body = f"\n\n| ID | Question | Lands in |\n| --- | --- | --- |\n{rows}\n\n"
    return text[:m.start(2)] + body + text[m.end(2):]


def _set_backtest_note(text: str, replacement: str) -> str:
    """Replace the §1.1 backtest-note bullet, or delete it when empty.

    Bounded to the single bullet: an unbounded ``.*?`` lookahead swallows the
    rest of the document the moment §1.1's bullet order changes.
    """
    pat = re.compile(r"^- \*\*Backtest note\*\*:.*?(?=^- \*\*)",
                     re.DOTALL | re.MULTILINE)
    new, n = pat.subn(replacement + "\n" if replacement else "", text, count=1)
    assert n == 1, "backtest note bullet not found"
    assert new != text, "mutation changed nothing"
    return new


def _drop_worked_examples(text: str) -> str:
    """Remove the §1.11 worked-routing-examples block."""
    pat = re.compile(r"^### Worked routing examples.*?(?=^## 1\.)",
                     re.DOTALL | re.MULTILINE)
    new, n = pat.subn("", text, count=1)
    assert n == 1, "worked routing examples block not found"
    return new


def _prefix_section(text: str, num: str, prefix: str) -> str:
    """Insert ``prefix`` at the very start of section 1.<num>'s body."""
    m = _section_span(text, num)
    assert m, f"section 1.{num} not found"
    return text[:m.start(2)] + "\n\n" + prefix + text[m.start(2):]


def _without(sidecar: dict, key: str) -> dict:
    """Sidecar copy with one list key emptied."""
    sc = copy.deepcopy(sidecar)
    sc[key] = []
    return sc


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
    json_report = json.loads(GOLDEN_JSON.read_text(encoding="utf-8"))
    cases: list[MutationCase] = []

    def add(name, desc, expected, text=None, sc=None, jr=None):
        cases.append(MutationCase(
            name, desc, set(expected),
            text if text is not None else model,
            copy.deepcopy(sc if sc is not None else sidecar),
            copy.deepcopy(jr) if jr is not None else None,
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

    # The three backtest mutations together pin the incentive: leaving the
    # placeholder, deleting the note, and faking it must all cost more than
    # running phase 3.6.
    add("backtest-note-still-pending",
        "leave the phase-3.5 drafting placeholder in the §1.1 backtest note, so "
        "the model publishes without the backtest ever having run",
        {"G3.backtest-ran", "G3.backtest-figures"},
        text=_set_backtest_note(model, "- **Backtest note**: _pending phase 3.6_"))

    add("backtest-note-deleted",
        "delete the §1.1 backtest note entirely — the cheapest way to dodge a "
        "check that only looks for the placeholder",
        {"G3.backtest-note"},
        text=_set_backtest_note(model, ""))

    add("backtest-note-contentless",
        "assert the backtest happened without reporting a single figure",
        {"G3.backtest-figures"},
        text=_set_backtest_note(
            model,
            "- **Backtest note**: the backtest was performed and every item "
            "routed to exactly one disposition."))

    add("evidence-column-deleted",
        "strip the provenance tags from the §1.15 table — the shape a citation "
        "crackdown produces when the column is not structurally required",
        {"G2.evidence-columns", "G1.confidence-matches"},
        text=re.sub(r"\*\(documented, zlib (manual|FAQ)[^)]*\)\*(?=\s*\|)", "—",
                    model))

    add("evidence-section-detabled",
        "convert §1.8 back to prose — the shape the defect actually took, since "
        "prose has nowhere to put per-claim evidence",
        {"G2.evidence-columns", "G1.confidence-matches"},
        text=re.sub(r"(^## 1\.8 .*?$)(.*?)(?=^## 1\.9)",
                    lambda m: m.group(1) + "\n\nOutput is as untrusted as the "
                    "input it derives from.\n\n",
                    model, count=1, flags=re.DOTALL | re.MULTILINE))

    add("property-voids-bare-negative",
        "answer every property with 'Voided by: nothing' and name no search — "
        "a negative that costs nothing to write and cannot be reviewed",
        {"G3.property-voids"},
        text=re.sub(r"\*Voided by\*:.*?(?=\*\(documented)",
                    "*Voided by*: nothing. ", model, flags=re.DOTALL))

    add("property-voids-search-as-prose",
        "state the negative's search as prose instead of a command, so no "
        "reader can re-run it — every false negative so far took this shape",
        {"G3.property-voids"},
        text=re.sub(
            r"\*Voided by\*:\n  `inflateBackInit` swaps the bound.*?"
            r"(?=\*\(documented, inflate API contract\)\*)",
            "*Voided by*: nothing — I looked through the public header "
            "carefully and no entry point relaxes it. ",
            model, count=1, flags=re.DOTALL))

    add("memory-symptom-without-write-path",
        "claim an out-of-bounds write as the violation symptom with only a "
        "doc quote behind it — docs promise return codes, not memory outcomes",
        {"G3.symptom-evidence"},
        text=model.replace(
            "buffer overflow — output is clamped by `left`, loaded\n  from "
            "`avail_out` at `inflate.c:331` and written back at `inflate.c:342`.",
            "buffer overflow.", 1))

    add("security-critical-property-without-voids",
        "publish one security-critical guarantee with no off-switches stated, "
        "so a triager reads it as absolute",
        {"G3.property-voids"},
        text=model.replace(
            "*Voided by*:\n  `inflateValidate(strm, 0)`", "*Formerly*:", 1))

    add("worked-examples-missing",
        "drop the §1.11 worked routing examples",
        {"G3.worked-examples"}, text=_drop_worked_examples(model))

    add("worked-examples-all-closes",
        "keep the worked examples but reroute the VALID row to a close, so a "
        "triager's only calibration is how to say no",
        {"G3.worked-examples"},
        text=model.replace("| `VALID` | `output-bound-honored` |",
                           "| `BY-DESIGN: property-disclaimed` | `crc-as-mac` |", 1))

    add("worked-examples-leak-corpus-id",
        "a worked example carries the advisory ID it came from, publishing "
        "producer-side corpus detail",
        {"G3.examples-deidentified"},
        text=model.replace("Crafted stream drives a write",
                           "CVE-2018-25032: crafted stream drives a write", 1))

    add("questions-as-a-table",
        "rewrite §1.18 as a table, which parses to zero Q-IDs and dangles "
        "every inferred/assumption reference in the body at once",
        {"G1.questions-parse", "G1.inferred-has-questions"},
        text=_table_questions(model))

    add("na-marker-then-substantive-body",
        "open §1.10 with an N/A marker but keep the whole substantive body; "
        "a first-line-only check would mark the section N/A and excuse the "
        "sidecar from carrying any adversaries",
        {"SC.prose-projection-coverage"},
        text=_prefix_section(model, "10", "Not applicable — see §1.7.\n"),
        sc=_without(sidecar, "adversaries"))

    add("mid-section-not-applicable",
        "bury 'not applicable' inside a substantive §1.10; a whole-body "
        "substring match would mark the section N/A and excuse the sidecar "
        "from carrying any adversaries at all",
        {"SC.prose-projection-coverage"},
        text=model.replace(
            "The attacker controls the compressed input bytes",
            "Byzantine participants: not applicable — zlib is not distributed.\n\n"
            "The attacker controls the compressed input bytes", 1),
        sc=_without(sidecar, "adversaries"))

    add("mismatch-header-confidence",
        "corrupt the header count (desyncs both the body and the sidecar)",
        {"G1.confidence-matches", "SC.confidence-matches-header"},
        text=model.replace(
            "68 documented / 0 maintainer / 7 inferred",
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
        text=model.replace("*(inferred, Q5)*", "*(inferred, Q99)*", 1))

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
        "sidecar confidence no longer matches the prose header (and so no "
        "longer collapses to the JSON export's counts)",
        {"SC.confidence-matches-header", "JSON.confidence-matches"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["properties_claimed"][0].pop("violation_symptoms", None)
    add("sidecar-strip-violation-symptom",
        "a claimed property loses its violation symptoms",
        {"SC.claimed-tier-symptom"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["properties_disclaimed"][0].pop("tier", None)
    add("sidecar-disclaimer-untiered",
        "a disclaimed property loses its tier; triage fails closed on that, so "
        "the disclaimer silently stops answering the reports it was written for",
        {"SC.disclaimed-tier"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["properties_claimed"][0]["provenance"] = {
        "kind": "inferred", "question_id": "Q1"}
    add("sidecar-inferred-security-critical",
        "a security-critical property is published on inferred provenance — a "
        "guarantee the project never made, at the tier integrators build on; "
        "the JSON export still says documented, which is now an upgrade",
        {"SC.claimed-inferred-tier", "JSON.provenance-fail-safe"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["known_non_findings"][0].pop("symptom", None)
    add("sidecar-non-finding-without-symptom",
        "a known non-finding names only a location; that is a scope question, "
        "an OUT-OF-MODEL route, not a precedence-1 suppression — and the JSON "
        "export's why_safe now has no sidecar symptom to be scoped by",
        {"SC.non-finding-symptom", "JSON.non-finding-scoped"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    _dup = [p for ep in sc["entry_points"] for p in ep.get("parameters", [])
            if p.get("obligation_id")]
    _dup[1]["obligation_id"] = _dup[0]["obligation_id"]
    add("sidecar-duplicate-obligation-id",
        "two entry points reuse one obligation ID for different obligations; "
        "IDs are global, and the wrong repair clones an obligation per entry "
        "point, fragmenting the §1.13 responsibility that enforces[] points at",
        {"SC.obligation-id-unique"}, sc=sc)

    sc = copy.deepcopy(sidecar)
    sc["known_non_findings"][0]["components"] = ["core-deflate"]
    add("sidecar-non-finding-out-of-scope-discharge",
        "a known non-finding matches a component its discharging claim does "
        "not cover, suppressing reports ahead of every other precedence rule; "
        "the JSON export's why_safe no longer names the moved component",
        {"SC.non-finding-discharge-scope", "JSON.non-finding-scoped"}, sc=sc)

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
    sc["prose_version"] = f"../threat-model.md@sha256:{digest}"
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

    # --- JSON export mutations ---
    # The export's provenance axis decides whether a JSON-only consumer may
    # close a report, so the dangerous mutations are the ones that hand out
    # authority the model never granted.
    jr = copy.deepcopy(json_report)
    jr["out_of_scope"][0]["provenance"] = "documented"
    add("json-provenance-upgraded",
        "the contrib/ carve-out is inferred (Q2) in the sidecar but the JSON "
        "says documented — a licence to close that the model never granted",
        {"JSON.provenance-fail-safe"}, jr=jr)

    jr = copy.deepcopy(json_report)
    jr["known_non_findings"][0]["why_safe"] = \
        "This report is a known false positive and can be closed on sight."
    add("json-non-finding-unscoped",
        "a known non-finding's why_safe names neither component nor symptom; "
        "with the structured fields gone from the JSON shape, that entry now "
        "matches every report",
        {"JSON.non-finding-scoped"}, jr=jr)

    jr = copy.deepcopy(json_report)
    jr["dispositions"].remove("model_gap")
    add("json-dispositions-eight",
        "the dispositions array drops model_gap — the escalation route a "
        "JSON-only consumer falls through to (also breaks minItems: 9)",
        {"JSON.dispositions-complete", "JSON.schema-valid"}, jr=jr)

    jr = copy.deepcopy(json_report)
    jr["properties_provided"][0]["severity_tier"] = "correctness"
    add("json-tier-flipped",
        "memory safety demoted from security to correctness in the export, "
        "understating what a violation report means",
        {"JSON.tier-maps"}, jr=jr)

    jr = copy.deepcopy(json_report)
    jr["entry_points"][0]["attacker_controllable"] = "conditional"
    add("json-conditional-without-condition",
        "an entry-point row goes conditional but states no condition; the "
        "schema documents the requirement without enforcing it, so only the "
        "validator stands in the way",
        {"JSON.conditional-has-condition"}, jr=jr)

    jr = copy.deepcopy(json_report)
    jr["components"][0]["touches"].append("network")
    add("json-touches-ungrounded",
        "core-inflate claims a network touch that §1.5 records as absent",
        {"JSON.touches-grounded"}, jr=jr)

    jr = copy.deepcopy(json_report)
    del jr["components"][1]
    add("json-component-vanishes",
        "core-deflate disappears from the JSON component list",
        {"JSON.components-match"}, jr=jr)

    jr = copy.deepcopy(json_report)
    del jr["properties_provided"][-1]
    add("json-property-vanishes",
        "a claimed property disappears from the export",
        {"JSON.properties-match"}, jr=jr)

    jr = copy.deepcopy(json_report)
    del jr["entry_points"][2]
    add("json-entry-point-row-vanishes",
        "the windowBits trust-table row disappears from the export",
        {"JSON.entry-points-match"}, jr=jr)

    jr = copy.deepcopy(json_report)
    jr["commit"] = "0" * 40
    add("json-commit-placeholder",
        "the commit is an all-zeros placeholder, so the export binds to no "
        "tree (and still matches the schema's hex pattern)",
        {"JSON.commit-present"}, jr=jr)

    jr = copy.deepcopy(json_report)
    jr["trust_boundaries"][0]["provenance"] = "documented"
    add("json-boundary-upgraded",
        "a trust-boundary row claims documented while every §1.4 provenance "
        "tag is inferred — the component record it rides on cannot vouch for "
        "the boundary claim",
        {"JSON.provenance-fail-safe"}, jr=jr)

    jr = copy.deepcopy(json_report)
    jr["build_variants"][0]["name"] = "ZLIB-CONST"
    add("json-build-variant-orphan",
        "a documented build variant is renamed so no sidecar flag vouches for "
        "it; with no build-variants match check, only a fail-closed "
        "provenance rule stands in the way",
        {"JSON.provenance-fail-safe"}, jr=jr)

    jr = copy.deepcopy(json_report)
    jr["known_non_findings"][0]["cites"] = "properties_provided[0]"
    add("json-cites-wrong-target",
        "a suppression entry cites a real but unrelated claim — memory "
        "safety instead of the disclaimed bomb resistance that actually "
        "discharges it — handing a JSON-only consumer the wrong licence",
        {"JSON.non-finding-scoped"}, jr=jr)

    jr = copy.deepcopy(json_report)
    jr["confidence"]["documented"] += 1
    add("json-confidence-drift",
        "the JSON confidence block overstates the documented count relative "
        "to the sidecar's collapse",
        {"JSON.confidence-matches"}, jr=jr)

    return cases


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    golden_json_text = GOLDEN_JSON.read_text(encoding="utf-8")
    for case in build_cases():
        d = OUT_DIR / case.name
        d.mkdir(parents=True, exist_ok=True)
        (d / "threat-model.md").write_text(case.model_text, encoding="utf-8")
        (d / "threat-model.yaml").write_text(
            yaml.safe_dump(case.sidecar, sort_keys=False), encoding="utf-8")
        (d / "threat-model.json").write_text(
            json.dumps(case.json_report, indent=2, ensure_ascii=False) + "\n"
            if case.json_report is not None else golden_json_text,
            encoding="utf-8")
        (d / "expected.json").write_text(
            json.dumps({
                "description": case.description,
                "expected_failures": sorted(case.expected_failures),
            }, indent=2), encoding="utf-8")
    print(f"wrote {len(build_cases())} mutation fixtures to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
