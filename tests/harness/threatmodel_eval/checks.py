"""Deterministic checks over a threat-model document and its sidecar.

These operationalize the checkable subset of the four self-check gates in
``.github/skills/threat-model/references/self-check.md`` plus the sidecar schema
in ``sidecar-schema.md``. Judgemental items (is §1.12 "as substantive as"
§1.11? is the prose free of audit output?) are out of scope here — they belong
to the rubric / LLM-judge tier.
"""
from __future__ import annotations

import re
from typing import Iterable

from .parse import Model, markdown_tables
from .report import Finding, Report

# The closed disposition set from output-structure.md §1.17.
DISPOSITIONS = [
    "VALID",
    "VALID-HARDENING",
    "OUT-OF-MODEL: trusted-input",
    "OUT-OF-MODEL: adversary-not-in-scope",
    "OUT-OF-MODEL: unsupported-component",
    "OUT-OF-MODEL: non-default-build",
    "OUT-OF-MODEL: dependency-contract",
    "BY-DESIGN: property-disclaimed",
    "KNOWN-NON-FINDING",
    "MODEL-GAP",
]

# Core sections that must always be present in an orchestrated deliverable.
# 1.18 is required only while inferred claims remain; 1.19 is mandatory.
REQUIRED_SECTIONS = [str(n) for n in range(1, 18)] + ["19"]


def _f(cid, gate, sev, passed, msg, loc="") -> Finding:
    return Finding(cid, gate, sev, passed, msg, loc)


# --------------------------------------------------------------------------
# Gate 1 — provenance and authority
# --------------------------------------------------------------------------
def check_provenance(model: Model) -> Iterable[Finding]:
    hedges = model.hedge_tags()
    yield _f(
        "G1.no-hedge-tags", "G1-provenance", "error", not hedges,
        "no forbidden hedge-tags" if not hedges
        else f"forbidden hedge-tag(s): {', '.join(sorted(set(hedges)))}",
    )

    header = model.header.lower()
    # Accept "provenance" or a plainly-labelled "legend" as the anchor word. The
    # anchor distinguishes a real legend from the bare confidence tally (which
    # always names the three kinds), while not forcing one exact label the
    # guidance does not mandate verbatim.
    legend_ok = ("provenance" in header or "legend" in header) and all(
        t in header for t in ("documented", "maintainer", "inferred")
    )
    yield _f(
        "G1.legend-present", "G1-provenance", "error", legend_ok,
        "provenance legend present in header" if legend_ok
        else "header is missing the (documented/maintainer/inferred) legend",
        "§1.1",
    )

    stated = model.stated_confidence()
    yield _f(
        "G1.confidence-present", "G1-provenance", "error", stated is not None,
        "draft-confidence count present" if stated
        else "header lacks a 'N documented / N maintainer / N inferred' count",
        "§1.1",
    )
    if stated is not None:
        actual = model.tag_counts()
        act = (actual["documented"], actual["maintainer"], actual["inferred"],
               actual["assumption"])
        match = stated == act
        yield _f(
            "G1.confidence-matches", "G1-provenance", "error", match,
            "header confidence matches body tag counts" if match
            else f"header says {stated} but body has {act} "
                 "(documented/maintainer/inferred/assumption)",
            "§1.1",
        )

    details = model.provenance_details()
    bad_details = [
        f"{kind}:{detail or '<missing>'}" for kind, detail in details
        if (kind == "documented" and not detail)
        or (kind == "maintainer" and not re.fullmatch(r"\d{4}-\d{2}", detail))
        or (kind in ("inferred", "assumption")
            and not re.fullmatch(r"Q\d+", detail, re.IGNORECASE))
    ]
    yield _f(
        "G1.provenance-details", "G1-provenance", "error", not bad_details,
        "every body provenance tag carries a source, date, or Q-ID"
        if not bad_details else f"provenance tags with missing/invalid detail: {bad_details}",
    )

    counts = model.tag_counts()
    # Both (inferred, QN) and (assumption, QN) must resolve to a §1.18
    # ratification item (see output-structure.md, "Mapping rule").
    unratified = counts["inferred"] + counts["assumption"]
    if unratified > 0:
        s18 = model.section("18")
        question_ids = model.open_question_ids()
        refs = [detail.upper() for kind, detail in details
                if kind in ("inferred", "assumption") and detail]
        mapped = len(refs) == unratified and set(refs) <= question_ids
        yield _f(
            "G1.inferred-has-questions", "G1-provenance", "error",
            s18 is not None and mapped,
            f"{unratified} inferred/assumption claim(s) map to §1.18 Q-IDs"
            if (s18 and mapped) else
            f"inferred/assumption claim refs {sorted(set(refs))} do not resolve "
            f"within §1.18 IDs {sorted(question_ids)}",
            "§1.18",
        )


# --------------------------------------------------------------------------
# Gate 2 — coverage
# --------------------------------------------------------------------------
def check_coverage(model: Model) -> Iterable[Finding]:
    for num in REQUIRED_SECTIONS:
        s = model.section(num)
        present = s is not None and s.substantive
        yield _f(
            f"G2.section-1.{num}", "G2-coverage", "error", present,
            f"§1.{num} present and substantive" if present else
            (f"§1.{num} present but empty/trivial" if s
             else f"§1.{num} missing"),
        )

    s7 = model.section("7")
    tables = markdown_tables(s7.body) if s7 else []
    trust_tables = [rows for rows in tables
                    if "attacker" in rows[0].lower()
                    and "control kind" in rows[0].lower()]
    table_ok = any(rows[0].count("|") - 1 >= 6
                   and "provenance" in rows[0].lower()
                   for rows in trust_tables)
    yield _f(
        "G2.input-trust-table", "G2-coverage", "error", table_ok,
        "§1.7 has a per-input trust table (>=6 columns)" if table_ok
        else "§1.7 must contain a six-column per-input trust table, not prose",
        "§1.7",
    )
    if s7:
        trust_head = trust_tables[0][0].lower() if trust_tables else ""
        cols_ok = (("parameter" in trust_head or "input operand" in trust_head)
                   and "attacker" in trust_head and "control kind" in trust_head
                   and ("enforce" in trust_head or "must" in trust_head)
                   and "provenance" in trust_head)
        yield _f(
            "G2.input-trust-columns", "G2-coverage", "warn", cols_ok,
            "trust table has the expected columns" if cols_ok
            else "§1.7 table must have Entry point / Input operand / "
                  "Attacker-controllable? / Control kind / Caller must enforce / "
                  "Provenance",
            "§1.7",
        )

        matrix_tables = [rows for rows in tables
                         if "component" in rows[0].lower()
                         and "dimension" in rows[0].lower()
                         and "status" in rows[0].lower()]
        # Coverage is about the eight dimensions being present, not their exact
        # wording. The prose reference names them fully ("failure/exception
        # atomicity", "callback/collaborator execution", "reference/object
        # lifecycle"), the golden fixture uses shorter forms ("failure
        # atomicity"), and sidecar-schema.md uses hyphenated slugs
        # ("failure-atomicity"). Match on each dimension's distinctive invariant
        # token(s) — folding '-', '/', and whitespace to a space — so every
        # legitimate spelling passes while all eight rows are still required.
        def _fold(text: str) -> str:
            return re.sub(r"[-/\s]+", " ", text.lower())
        dimension_tokens = (
            ("numeric", "domain"),      # ...and representational limits
            ("atomicity",),             # failure / failure/exception atomicity
            ("topology",),              # recursive/cyclic topology
            ("callback", "execution"),  # callback/collaborator execution
            ("reconstruction",),        # serialization/reconstruction
            ("lifecycle",),             # reference/object lifecycle
            ("reentrancy",),            # concurrency/reentrancy
            ("complexity",),            # resource complexity
        )
        matrix_text = _fold("\n".join(matrix_tables[0])) if matrix_tables else ""
        matrix_ok = (bool(matrix_tables)
                     and "provenance" in matrix_tables[0][0].lower()
                     and all(all(tok in matrix_text for tok in toks)
                             for toks in dimension_tokens))
        yield _f(
            "G2.contract-dimension-matrix", "G2-coverage", "error", matrix_ok,
            "§1.7 contains all eight required contract dimensions" if matrix_ok
            else "§1.7 must contain a contract-dimension matrix with all eight "
                 "required dimensions",
            "§1.7",
        )

    s8 = model.section("8")
    taint_ok = bool(s8) and "taint" in s8.body.lower() or (
        bool(s8) and "untrusted as the input" in s8.body.lower())
    yield _f(
        "G2.output-taint", "G2-coverage", "error", bool(s8) and taint_ok,
        "§1.8 states output taint" if (s8 and taint_ok)
        else "§1.8 must state the taint of each output channel",
        "§1.8",
    )

    s9 = model.section("9")
    dep_ok = bool(s9) and any(
        k in s9.body.lower()
        for k in ("dependency", "dependencies", "zero-dependency", "no runtime")
    )
    yield _f(
        "G2.dependencies", "G2-coverage", "error", dep_ok,
        "§1.9 states dependency trust (or zero-dependency claim)" if dep_ok
        else "§1.9 must state per-dependency trust or an explicit "
             "zero-dependency claim",
        "§1.9",
    )


# --------------------------------------------------------------------------
# Gate 3 — triage readiness
# --------------------------------------------------------------------------
def check_triage(model: Model) -> Iterable[Finding]:
    header = model.header.lower()
    # Treat hyphens as spaces so "contract-dimension" / "quick-start" satisfy the
    # canonical "contract dimension" / "quick start" wording either way. The term
    # is hyphenated in most of the skills, so agents naturally hyphenate it in the
    # quick-start prose and the literal-substring test would otherwise reject it.
    header_flat = header.replace("-", " ")
    qs_ok = ("quick start" in header_flat and "§1.17" in model.header
             and "contract dimension" in header_flat and "precedence" in header_flat)
    yield _f(
        "G3.triager-quickstart", "G3-triage", "error", qs_ok,
        "header contains a triager quick-start routing to §1.17" if qs_ok
           else "§1.1 must contain the seven-step triager quick-start, including "
               "contract dimensions, precedence, and §1.17",
        "§1.1",
    )

    yield _f(
        "G3.backtest-note", "G3-triage", "warn", "backtest" in header,
        "header records a backtest note" if "backtest" in header
        else "§1.1 should record the phase-3.6 backtest result",
        "§1.1",
    )

    s17 = model.section("17")
    if not s17:
        yield _f("G3.dispositions", "G3-triage", "error", False,
                 "§1.17 (triage dispositions) missing", "§1.17")
    else:
        missing = [d for d in DISPOSITIONS if d not in s17.body]
        yield _f(
            "G3.dispositions", "G3-triage", "error", not missing,
            "§1.17 enumerates the full closed disposition set" if not missing
            else f"§1.17 is missing disposition(s): {', '.join(missing)}",
            "§1.17",
        )

    s11 = model.section("11")
    if s11:
        b = s11.body.lower()
        symptom_ok = "symptom" in b
        tier_ok = ("security-critical" in b or "correctness" in b or "tier" in b)
        yield _f(
            "G3.property-symptom-tier", "G3-triage", "warn",
            symptom_ok and tier_ok,
            "§1.11 properties carry violation symptom + severity tier"
            if (symptom_ok and tier_ok)
            else "§1.11 properties should each carry a violation symptom and a "
                 "severity tier",
            "§1.11",
        )


# --------------------------------------------------------------------------
# Gate 4 — style and scope (soft, deterministic subset only)
# --------------------------------------------------------------------------
def check_style(model: Model) -> Iterable[Finding]:
    words = len(model.text.split())
    # ~3-8 pages ≈ 1200–6000 words. Flag sprawl as a soft signal only.
    ok = 800 <= words <= 7000
    yield _f(
        "G4.length", "G4-style", "warn", ok,
        f"document length {words} words is within one-sitting range" if ok
        else f"document is {words} words — outside the ~800–7000 (3–8 page) "
             "range; sprawl/thinness is a smell",
    )
    # Audit-output smell: "the project should" / "we recommend".
    audit = re.findall(r"\b(the project should|we recommend)\b",
                       model.text, re.IGNORECASE)
    yield _f(
        "G4.no-audit-output", "G4-style", "warn", not audit,
        "no audit-style 'should/recommend' language" if not audit
        else f"found {len(audit)} audit-style phrase(s) ('the project "
             "should…'/'we recommend…') — that is audit output, not a model",
    )


def run_prose_checks(model: Model) -> Report:
    report = Report()
    report.extend(check_provenance(model))
    report.extend(check_coverage(model))
    report.extend(check_triage(model))
    report.extend(check_style(model))
    return report
