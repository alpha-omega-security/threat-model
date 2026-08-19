"""Deterministic checks over a threat-model document and its sidecar.

These operationalize the checkable subset of the four self-check gates in
``skills/threat-model/references/self-check.md`` plus the sidecar schema
in ``sidecar-schema.md``. Judgemental items (is §1.12 "as substantive as"
§1.11? is the prose free of audit output?) are out of scope here — they belong
to the rubric / LLM-judge tier.
"""
from __future__ import annotations

import re
from typing import Iterable

from .parse import _TAG, Model, has_table, markdown_tables
from .report import Finding, Report

# The one honest exit a regex can recognize. Kept verbatim here, in
# threat-model-backtest/SKILL.md, output-structure.md, and the produce prompt.
NO_CORPUS_SENTENCE = (
    "no historical corpus was available; the backtest routed N synthesized "
    "cases only"
)

# Corpus identifiers that must never reach the published §1.11 examples.
_CORPUS_LEAK = re.compile(
    r"CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}"
    r"|\b\d{4}-\d{2}-\d{2}\b")


def _backtest_note(model: Model) -> str:
    """The §1.1 bullet labelled 'Backtest note', or '' when absent."""
    m = re.search(
        r"^\s*[-*]?\s*\*{0,2}Backtest note\*{0,2}[.:]?(.*?)(?=\n\s*[-*]\s|\n\n|\Z)",
        model.header, re.IGNORECASE | re.DOTALL | re.MULTILINE)
    return m.group(0).strip() if m else ""


def _missing_backtest_figures(note: str) -> list[str]:
    """Which required figures the backtest note fails to state."""
    flat = " ".join(note.split())
    missing = []
    if not re.search(r"\b\d+[-\s]item", flat, re.IGNORECASE):
        missing.append("a corpus item count ('12-item corpus')")
    if not re.search(r"synthesi[sz]ed", flat, re.IGNORECASE):
        missing.append("the real-versus-synthesized split")
    if sum(1 for d in DISPOSITIONS if d in flat) < 2:
        missing.append("a disposition histogram")
    if not re.search(r"historically[-\s]fixed|fail[-\s]safe", flat, re.IGNORECASE):
        missing.append("the fail-safe figure")
    return missing


def _worked_example_rows(body: str) -> list[str]:
    """Data rows of the '### Worked routing examples' table in §1.11."""
    m = re.search(r"^#{2,4}\s*Worked routing examples\s*$(.*?)(?=^#{2,4}\s|\Z)",
                  body, re.MULTILINE | re.DOTALL)
    if not m:
        return []
    rows = [r for group in markdown_tables(m.group(1)) for r in group[2:]]
    return [r for r in rows if r.strip().startswith("|")]


# A statement-level source locator: `inflate.c:1393`, not `inflate.c`.
_CODE_LOCATOR = re.compile(r"[\w./-]+\.\w+:\d+")
# Symptoms that assert a memory outcome. Documentation does not establish these.
# Symptoms where a caller-reachable off-switch changes the triage answer: the
# memory outcomes, plus accepting bad data as good and unbounded growth.
_CONSEQUENTIAL_SYMPTOM = re.compile(
    r"\boob[- ]?(?:read|write)\b|\bout[- ]of[- ]bounds\b|\bbuffer[- ]overflow\b"
    r"|\buse[- ]after[- ]free\b|\buninitiali[sz]ed[- ]read\b"
    r"|\bmemory corruption\b|\bheap (?:overflow|corruption)\b"
    r"|\bbad[- ]data[- ]accepted\b|\bintegrity[- ]bypass\b"
    r"|\baccepted as (?:valid|complete|authentic)\b"
    r"|\bunbounded[- ]allocation\b|\bunbounded (?:memory|growth)\b",
    re.IGNORECASE)
_MEMORY_SYMPTOM = re.compile(
    r"\boob[- ]?(?:read|write)\b|\bout[- ]of[- ]bounds\b|\bbuffer[- ]overflow\b"
    r"|\buse[- ]after[- ]free\b|\bheap (?:overflow|corruption)\b"
    r"|\bmemory corruption\b", re.IGNORECASE)
# The permitted negative answer. "Nothing" alone is not enough: a bare negative
# costs nothing to write and cannot be reviewed, so the author must also name
# the search, which a reviewer can then re-run and falsify.
_NO_VOID = re.compile(r"voided by\W+(nothing|none)\b", re.IGNORECASE)
# A command a reader can paste, not a claim about having searched. Prose like
# "searched every ZEXPORT in zlib.h" has been wrong every time it was checked,
# and it cannot be re-run; `grep -rn 'ASMINF' *.c *.h` can.
_SEARCH_COMMAND = re.compile(r"\b(?:grep|rg|ag|git\s+grep)\b[^\n`]*", re.IGNORECASE)


def _property_units(body: str) -> list[tuple[str, str]]:
    """Split §1.11 into (label, text) per property, for bullets or a table."""
    # Stop at the first sub-heading: §1.11 ends with the worked-examples block,
    # and without this the final property absorbs it and inherits its wording.
    body = re.split(r"^#{3,6}\s", body, maxsplit=1, flags=re.MULTILINE)[0]
    units: list[tuple[str, str]] = []
    for group in markdown_tables(body):
        heads = [h.strip().lower() for h in group[0].strip().strip("|").split("|")]
        if not any("propert" in h or h in ("id", "name") for h in heads):
            continue
        for row in group[2:]:
            if row.strip().startswith("|"):
                cells = [c.strip() for c in row.strip().strip("|").split("|")]
                units.append(((cells[0] if cells else "?")[:40], row))
    if units:
        return units
    # Bullet form: a top-level "- " item, continuation lines indented.
    cur: list[str] = []
    for line in body.splitlines():
        if re.match(r"^\s*[-*]\s+\S", line) and not line.startswith((" ", "\t")):
            if cur:
                units.append((_unit_label(cur[0]), "\n".join(cur)))
            cur = [line]
        elif cur:
            cur.append(line)
    if cur:
        units.append((_unit_label(cur[0]), "\n".join(cur)))
    return units


def _unit_label(first_line: str) -> str:
    m = re.search(r"\*\*(.+?)\*\*|`([^`]+)`", first_line)
    return (m.group(1) or m.group(2))[:40] if m else first_line.strip()[:40]


def _voids_required(text: str) -> bool:
    """Does this property have to say what turns it off?

    Keyed on the **violation symptom**, not the tier and not everything.

    Tier does not work: it was tried, and the property whose off-switch mattered
    most (an integrity check a caller can disable) was tiered correctness-only,
    so a tier-scoped rule never reached it — and an author can drop the
    obligation by relabelling the tier.

    Everything does not work either: it was tried, and asking eight properties
    for off-switches produced three false negatives. Volume drove the sloppiness.

    The symptom predicts whether a switch matters, and it is already load-bearing
    for the tier, so dodging the obligation by softening the symptom also
    softens the claim.
    """
    return bool(_CONSEQUENTIAL_SYMPTOM.search(text))


def _memory_symptom_backed(text: str) -> bool:
    """Is every memory-outcome claim in this property backed where it is made?

    The locator has to sit with the symptom, not merely somewhere in the same
    property. A property can cite real code for its off-switches and still
    assert an out-of-bounds write its evidence never establishes -- that is the
    exact shape the overclaim took, so a unit-wide search for any locator
    passes it.
    """
    # Split into cells (table row) or sentences (bullet form) and check each
    # fragment that asserts a memory outcome.
    parts = text.split("|") if text.lstrip().startswith("|") else re.split(
        r"(?<=[.;])\s+", text)
    for part in parts:
        # Only the fragment that *declares* the symptom. A property statement
        # naturally says "must not read or write out of bounds"; that is the
        # guarantee, not the claim about what a violation looks like.
        if not re.search(r"symptom", part, re.IGNORECASE):
            continue
        if _MEMORY_SYMPTOM.search(part) and not _CODE_LOCATOR.search(part):
            return False
    return True


def _states_voids(text: str) -> bool:
    # Read only the voids clause. Judging the whole property lets a locator that
    # belongs to the *symptom* satisfy the voids requirement, so a property can
    # cite real code and still never say what turns it off.
    m = re.search(r"voided by\b(.*)", text, re.IGNORECASE | re.DOTALL)
    if not m:
        return False
    clause = re.split(r"\n\s*\n|^\s*[-*]\s+\*\*", m.group(1),
                      maxsplit=1, flags=re.MULTILINE)[0]
    if _CODE_LOCATOR.search(clause):
        return True
    # A negative answer is only reviewable if the search is a command.
    return bool(_NO_VOID.search("voided by" + clause)
                and _SEARCH_COMMAND.search(clause))


def _tabled_question_ids(section) -> set[str]:
    """Q-IDs that appear inside a §1.18 table, where they do not parse."""
    if not section or not has_table(section.body):
        return set()
    ids: set[str] = set()
    for row in markdown_tables(section.body):
        for line in row:
            ids.update(f"Q{n}" for n in re.findall(r"\bQ(\d+)\b", line))
    return ids


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

# §1.15/§1.14 entries scope to one or more components. The schema spells this
# `components: [...]`; `component: <name>` is the older singular form, still
# accepted so existing sidecars keep validating. Shared by the validator and the
# routing engine: they must agree, or an entry written in one form silently
# escapes the other's component guard.
ALL_IN_SCOPE = "all-in-scope"


def entry_components(item: dict) -> list[str]:
    """Component scope of a §1.15/§1.14 entry, in either schema form."""
    plural = item.get("components")
    if isinstance(plural, list):
        return [c for c in plural if isinstance(c, str) and c.strip()]
    single = item.get("component")
    if isinstance(single, str) and single.strip():
        return [single]
    return []

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

        # A §1.18 written as a *table* yields no Q-IDs: `| **Q1** |` matches
        # none of the recognized entry styles, so every reference above dangles
        # at once. Diagnose that directly -- otherwise the failure reads as "the
        # model invented Q-IDs" and a repair pass edits the body tags instead of
        # the section format. Detect the partial conversion too, which is what a
        # half-applied edit produces: some questions listed, the rest tabled.
        unparsed = _tabled_question_ids(s18) - question_ids if s18 else set()
        yield _f(
            "G1.questions-parse", "G1-provenance", "error", not unparsed,
            "§1.18 questions parse to stable Q-IDs" if not unparsed else
            f"§1.18 carries {sorted(unparsed)} inside a table, where they do "
            "not parse: write one top-level list item per question with the ID "
            "starting the line (`- **Q1** — ...`), never a table row",
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
        # Coverage is about the nine dimensions being present, not their exact
        # wording. The prose reference names them fully ("failure/exception
        # atomicity", "callback/collaborator execution", "reference/object
        # lifecycle"), the golden fixture uses shorter forms ("failure
        # atomicity"), and sidecar-schema.md uses hyphenated slugs
        # ("failure-atomicity"). Match on each dimension's distinctive invariant
        # token(s) — folding '-', '/', and whitespace to a space — so every
        # legitimate spelling passes while all nine rows are still required.
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
            ("authorization",),         # authorization scope
        )
        matrix_text = _fold("\n".join(matrix_tables[0])) if matrix_tables else ""
        matrix_ok = (bool(matrix_tables)
                     and "provenance" in matrix_tables[0][0].lower()
                     and all(all(tok in matrix_text for tok in toks)
                             for toks in dimension_tokens))
        yield _f(
            "G2.contract-dimension-matrix", "G2-coverage", "error", matrix_ok,
            "§1.7 contains all nine required contract dimensions" if matrix_ok
            else "§1.7 must contain a contract-dimension matrix with all nine "
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
           else "§1.1 must contain the triager quick-start, including "
               "contract dimensions, precedence, and §1.17",
        "§1.1",
    )

    # The three backtest checks are deliberately arranged so that *deleting* the
    # note and *faking* it both cost more than running phase 3.6. Keying only on
    # the placeholder would make the honest-but-interrupted path the only failing
    # one, which inverts the incentive the placeholder exists to create.
    note = _backtest_note(model)
    yield _f(
        "G3.backtest-note", "G3-triage", "error", bool(note),
        "§1.1 carries a labelled backtest note" if note
        else "§1.1 must carry a bullet labelled 'Backtest note' recording the "
             "phase-3.6 result; deleting it is not a way to pass",
        "§1.1",
    )

    if note:
        pending = "_pending phase 3.6_" in note
        yield _f(
            "G3.backtest-ran", "G3-triage", "error", not pending,
            "the §1.1 backtest note carries a real result" if not pending else
            "§1.1 still holds the drafting placeholder '_pending phase 3.6_': "
            "run phase 3.6 and replace it with the corpus counts, the real-"
            "versus-synthesized split, the disposition histogram, and the "
            "fail-safe figure",
            "§1.1",
        )

        # A note is either a real result -- which necessarily carries figures --
        # or the verbatim admission that no history was reachable. Prose that
        # merely asserts the backtest happened satisfies neither.
        missing = _missing_backtest_figures(note)
        no_corpus = NO_CORPUS_SENTENCE in " ".join(note.split())
        ok = no_corpus or not missing
        yield _f(
            "G3.backtest-figures", "G3-triage", "error", ok,
            "the backtest note reports its figures" if ok else
            f"§1.1 backtest note is missing {', '.join(missing)}; state the "
            "corpus size, the real-versus-synthesized split, the disposition "
            "histogram, and the fail-safe figure — or, when no history was "
            f'reachable, the exact sentence "{NO_CORPUS_SENTENCE}"',
            "§1.1",
        )

    # §1.7's provenance column survived a citation crackdown because the column
    # is structurally required; §1.8/§1.10/§1.15's did not, and the author
    # satisfied the rule by deleting the column instead of opening the file --
    # which keeps every claim's authority while removing its evidence.
    bad_evidence: list[str] = []
    for num in ("8", "10", "15"):
        sec = model.section(num)
        if not sec or sec.is_na:
            continue
        col = None
        for group in markdown_tables(sec.body):
            heads = [h.strip().lower() for h in group[0].strip().strip("|").split("|")]
            idx = next((i for i, h in enumerate(heads) if "provenance" in h), None)
            if idx is None:
                continue
            col = idx
            for row in group[2:]:
                if not row.strip().startswith("|"):
                    continue
                cells = [c.strip() for c in row.strip().strip("|").split("|")]
                cell = cells[idx] if idx < len(cells) else ""
                if not cell or not _TAG.search(cell):
                    label = (cells[0] if cells else "?")[:40]
                    bad_evidence.append(f"§1.{num} row {label or '?'}")
        if col is None:
            # No table, or a table without the column: the shape itself is the
            # defect. Prose has nowhere to put per-claim evidence, which is how
            # a citation crackdown gets satisfied by deleting the column.
            bad_evidence.append(f"§1.{num} has no table with a Provenance column")
    yield _f(
        "G2.evidence-columns", "G2-coverage", "error", not bad_evidence,
        "§1.8/§1.10/§1.15 carry a Provenance column, tagged in every row"
        if not bad_evidence else
        f"missing per-row evidence: {bad_evidence[:8]}"
        f"{' …' if len(bad_evidence) > 8 else ''}. Fill the cell by opening the "
        "file, or tag the row inferred with a §1.18 question — never drop the "
        "column or fall back to prose",
        "§1.8/§1.10/§1.15",
    )

    s11 = model.section("11")
    if s11:
        # A security-critical guarantee published without its off-switches reads
        # as absolute, so a triager answers VALID to a report whose real first
        # question was "did you disable it?". The switches are found by reading
        # statements, not comments -- hence a file:line locator, or an explicit
        # statement that nothing voids the property.
        # Per property, never a document-wide count: counting lets an author
        # pile every void onto one property and leave the rest bare, which
        # publishes the exact defect while reading as diligent. It also applies
        # to every property regardless of tier -- tier says how bad a violation
        # is, not whether the guarantee can be switched off, and scoping by tier
        # would let an author drop the obligation by relabelling it.
        missing = [name for name, text in _property_units(s11.body)
                   if _voids_required(text) and not _states_voids(text)]
        yield _f(
            "G3.property-voids", "G3-triage", "error", not missing,
            "every §1.11 property states what voids it" if not missing else
            f"§1.11 properties that do not state what voids them: "
            f"{missing[:8]}{' …' if len(missing) > 8 else ''}. Each needs its "
            "off-switches — the API call, flag, or mode that turns the "
            "guarantee off, cited file:line at the implementing statement — or "
            "an explicit 'nothing voids it' naming what you searched",
            "§1.11",
        )

        # An exaggeration squeezed out of the provenance and tier fields
        # relocates to whichever field is not policed, and the symptom is the
        # field that decides whether a report is a vulnerability at all. Docs
        # promise return codes; only code shows memory outcomes, so a
        # memory-class symptom resting on a doc quote is an overclaim by
        # construction.
        unbacked = [name for name, text in _property_units(s11.body)
                    if not _memory_symptom_backed(text)]
        yield _f(
            "G3.symptom-evidence", "G3-triage", "error", not unbacked,
            "memory-safety symptoms are backed by a code citation"
            if not unbacked else
            f"§1.11 properties claiming a memory-safety symptom with no "
            f"file:line evidence: {unbacked[:8]}"
            f"{' …' if len(unbacked) > 8 else ''}. A manual that says 'returns "
            "an error' does not establish an out-of-bounds write — cite the "
            "write path, or state the symptom the evidence actually supports",
            "§1.11",
        )

        rows = _worked_example_rows(s11.body)

        # Scoped to the worked-example rows, not all of §1.11: citing the
        # advisory that documents a property is legitimate provenance and
        # threat-model-recon instructs it. What must stay producer-side is the
        # corpus identity behind an *example*, which is de-identified by rule.
        leaked = sorted({m.group(0) for r in rows
                         for m in _CORPUS_LEAK.finditer(r)})
        yield _f(
            "G3.examples-deidentified", "G3-triage", "error", not leaked,
            "worked routing examples carry no corpus identifiers"
            if not leaked else
            f"§1.11 worked examples leak producer-side corpus detail: {leaked}. "
            "De-identify them — no advisory IDs, no dates",
            "§1.11",
        )
        # 2-4 rows, at least one routing VALID. The VALID row is the point: a
        # triager whose only examples are closes learns the model exists to
        # say no.
        has_valid = any(re.search(r"\bVALID\b(?!-)", r) for r in rows)
        ok = 2 <= len(rows) <= 4 and has_valid
        yield _f(
            "G3.worked-examples", "G3-triage", "error", ok,
            "§1.11 carries 2-4 worked routing examples including a VALID"
            if ok else
            f"§1.11 needs a '### Worked routing examples' table of 2-4 rows "
            f"with at least one routing VALID (found {len(rows)} row(s), "
            f"VALID present: {has_valid})",
            "§1.11",
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
