#!/usr/bin/env python3
"""Export an existing threat model as `threat-model.json` (schema.json shape).

An orchestrated run produces prose (`threat-model.md`, canonical) and a
YAML sidecar (`threat-model.yaml`, a near-lossless derived index). Some
consumers speak only the flat schema in `schema.json`, so this tool projects
the pair into a third artifact. The authority order is prose > yaml > json.

The output is an export, not the model. It drops the triage machinery on
purpose — disposition precedence, disclaimed-property tiers, the dependency
edge model, non-finding component/symptom fields — so a consumer cannot
triage from it; triage keeps reading prose + YAML. The mapping never upgrades
provenance: a claim held as inferred or assumption stays `inferred` here.

The mechanical projection comes from `threatmodel_eval.jsonreport`. On top of
it this tool fills the author-only fields it can honestly pull out of the
prose: description from §1.2, open questions from §1.18, non-finding
reasoning from §1.15, misuse reasoning from §1.14, boundaries from §1.4,
environment from §1.5. Whatever it cannot extract stays empty and is listed
on stderr as needing hand completion. An empty field is recoverable; a
machine-guessed one presented as authored is not.

Usage:
    python export_json.py MODEL.md SIDECAR.yaml --repository URL --commit SHA
    python export_json.py MODEL.md SIDECAR.yaml --source-root ../checkout

Exit codes: 0 clean write; 1 error-severity check failures (file written only
under --force); 2 usage, load, or extraction failure.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

# Allow running as a loose script (python export_json.py ...).
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from threatmodel_eval.checks import entry_components  # type: ignore
    from threatmodel_eval.jsonreport import (  # type: ignore
        project_from_sidecar, run_json_checks)
    from threatmodel_eval.jsonschema_mini import (  # type: ignore
        validate_instance)
    from threatmodel_eval.parse import (  # type: ignore
        _TAG, Model, load_sidecar, markdown_tables)
else:  # pragma: no cover - import style depends on invocation
    from .threatmodel_eval.checks import entry_components
    from .threatmodel_eval.jsonreport import (project_from_sidecar,
                                               run_json_checks)
    from .threatmodel_eval.jsonschema_mini import validate_instance
    from .threatmodel_eval.parse import (_TAG, Model, load_sidecar,
                                         markdown_tables)

_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schema.json"
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
# Same lenient shape jsonschema_mini accepts for format: uri.
_URI_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:\S+$")

# Provenance tags as they appear in prose: *(documented, source)* etc.
# Stripped from extracted text — the JSON rows carry their own provenance
# axis, and a stray tag inside a string would just be noise there.
_TAG_RE = re.compile(
    r"\*?\((?:documented|maintainer|inferred|assumption)\b[^)]*\)\*?",
    re.IGNORECASE)


def _squash(text: str) -> str:
    """Collapse whitespace and drop provenance tags from one prose fragment."""
    text = _TAG_RE.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\s+([.,;:!?])", r"\1", text)   # tag removal leaves " ."
    return text.strip(" -–—")


def _dict_rows(value) -> list[dict]:
    return [v for v in value if isinstance(v, dict)] \
        if isinstance(value, list) else []


# --------------------------------------------------------------------------
# §1.1 header extraction — repository, commit, date
# --------------------------------------------------------------------------
# Real headers vary (surveyed across out/ and out_batch1..3). Supported shapes:
#
# repository (only in bullets labeled Project / Repository / Repo / Target /
# Source, so an advisory URL elsewhere in the header cannot win):
#   - **Project**: Express (`express` on npm) —
#     <https://github.com/expressjs/express>
#   - **Repository**: https://github.com/owner/repo        (plain or <...> URL)
#   - **Project**: Gson ..., the `gson/` Maven module of
#     `github.com/google/gson`.
#     A schemeless well-known host gets https:// prefixed: the header names the
#     repository and only the scheme is implied. Nothing else is invented.
#
# commit (only in bullets labeled Modeled version / Version binding / Commit /
# Modeled ref / Version):
#   - **Modeled version**: `ZLIB_VERSION ...`, commit `e3dc0a85b...`
#   - **Modeled version**: `master` at commit `4f73e74`
#   - **Version binding**: express 5.2.1, repository commit **`a371447`**
#   - wrapped bullets ("at merged commit\n  `a3714...`") — continuation lines
#     are joined onto their bullet before matching.
#   - fallback: "commit <hex>" without backticks; the hex must contain a digit
#     so an unlucky all-[a-f] English word cannot pass as a sha.
#
# date:
#   - **Date**: 2026-08-08        (trailing period or prose tolerated)

_REPO_LABELS = ("project", "repository", "repo", "target", "source")
_COMMIT_LABELS = ("modeled version", "version binding", "commit",
                  "modeled ref", "version")
_URL_IN_TEXT = re.compile(r"<?(https?://[^\s>\)\]]+)>?")
_BARE_REPO = re.compile(
    r"\b((?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)"
    r"/[\w.-]+/[\w.-]+)")
_COMMIT_TICKED = re.compile(r"\bcommit\b[^`\n]{0,40}`([0-9a-f]{7,40})`",
                            re.IGNORECASE)
_COMMIT_BARE = re.compile(
    r"\bcommit\b[\s:*]{0,6}\(?((?=[0-9a-f]*\d)[0-9a-f]{7,40})(?![0-9a-f])",
    re.IGNORECASE)
_DATE_LINE = re.compile(r"\*\*Date\*\*\s*:?\s*(\d{4}-\d{2}-\d{2})")


def _header_bullets(header: str) -> list[tuple[str, str]]:
    """(label, full text) per top-level header bullet, continuations joined."""
    bullets: list[str] = []
    for line in header.splitlines():
        stripped = line.strip()
        if re.match(r"[-*]\s+\*\*", stripped):
            # Strip only the bullet marker; lstrip("-* ") would also eat the
            # bold ** that opens the label.
            bullets.append(re.sub(r"^[-*]\s+", "", stripped))
        elif bullets and stripped and not stripped.startswith(("#", "|", "-",
                                                               "*", ">")):
            bullets[-1] += " " + stripped
    out = []
    for b in bullets:
        m = re.match(r"\*\*([^*]+)\*\*\s*[:–——-]?\s*(.*)", b)
        if m:
            out.append((m.group(1).strip().casefold(), b))
    return out


def extract_repository(model: Model) -> str | None:
    for label, text in _header_bullets(model.header):
        if not label.startswith(_REPO_LABELS):
            continue
        m = _URL_IN_TEXT.search(text)
        if m:
            return m.group(1).rstrip(".,;")
        m = _BARE_REPO.search(text)
        if m:
            return "https://" + m.group(1).rstrip(".,;")
    return None


def extract_commit(model: Model) -> str | None:
    for label, text in _header_bullets(model.header):
        if not label.startswith(_COMMIT_LABELS):
            continue
        m = _COMMIT_TICKED.search(text) or _COMMIT_BARE.search(text)
        if m:
            return m.group(1).lower()
    return None


def extract_date(model: Model) -> str | None:
    m = _DATE_LINE.search(model.header)
    return m.group(1) if m else None


def _git_head(source_root: str) -> tuple[str | None, str]:
    """(sha, "") from the modeled tree, or (None, why it failed)."""
    try:
        proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=source_root,
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    if proc.returncode != 0:
        return None, proc.stderr.strip() or f"git exited {proc.returncode}"
    sha = proc.stdout.strip().lower()
    if not _COMMIT_RE.fullmatch(sha):
        return None, f"git rev-parse returned {sha!r}, not a commit sha"
    return sha, ""


# --------------------------------------------------------------------------
# Prose helpers
# --------------------------------------------------------------------------
def _prose_units(body: str) -> list[str]:
    """Bullets and sentences from a section body.

    Tables, fenced code (diagrams live in fences), and headings are skipped:
    they are structure, not the prose statements this tool quotes. If the
    section carries bullets, only bullets are returned — sectioned bullet
    lists are the deliberate statements, and the surrounding connective
    paragraphs ("These are negative claims found by scanning...") are
    commentary that would pollute an extracted list.
    """
    bullet_units: list[str] = []
    para_lines: list[str] = []
    paras: list[str] = []
    in_fence = False
    mode = ""                      # "bullet" while the last line was one

    def flush_para() -> None:
        if para_lines:
            paras.append(" ".join(para_lines))
            para_lines.clear()

    for line in body.splitlines() + [""]:
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            flush_para()
            mode = ""
            continue
        if in_fence or not stripped or stripped.startswith(("#", "|")):
            flush_para()
            mode = ""
            continue
        # `1.` entries count as bullets: §1.14 lists are often numbered.
        if re.match(r"(?:[-*]|\d+\.)\s+\S", stripped):
            flush_para()
            bullet_units.append(re.sub(r"^(?:[-*]|\d+\.)\s+", "", stripped))
            mode = "bullet"
        elif mode == "bullet" and line[:1] in (" ", "\t"):
            bullet_units[-1] += " " + stripped
        else:
            para_lines.append(stripped)
            mode = "para"

    units = bullet_units if bullet_units else [
        s for p in paras for s in re.split(r"(?<=[.!?])\s+", p)
    ]
    cleaned = [_squash(u) for u in units]
    return [u for u in cleaned if 25 <= len(u)]


def _table_data(body: str) -> list[tuple[list[str], list[str]]]:
    """(header cells, row cells) for every data row of every pipe table."""
    out: list[tuple[list[str], list[str]]] = []
    sep = re.compile(r"^[:\s|-]+$")
    for group in markdown_tables(body):
        rows = [[c.strip() for c in line.strip().strip("|").split("|")]
                for line in group]
        header = rows[0]
        for row in rows[1:]:
            if sep.match("|".join(row)):
                continue
            out.append((header, row))
    return out


def _norm_cell(cell: str) -> str:
    return _squash(cell).strip("`*_ ").casefold()


# --------------------------------------------------------------------------
# Author-only field completion. Each function fills what it honestly can,
# records the source in `completed`, and records what it left empty in
# `needs` — the stderr hand-completion list.
# --------------------------------------------------------------------------
def fill_description(report: dict, model: Model,
                     completed: list[str], needs: list[str]) -> None:
    s = model.section("2")
    blocks: list[str] = []
    if s:
        in_fence = False
        current: list[str] = []
        for line in s.body.splitlines() + [""]:
            stripped = line.strip()
            if stripped.startswith("```"):
                in_fence = not in_fence
                stripped = ""
            if not stripped or in_fence \
                    or stripped.startswith(("#", "|", ">")):
                if current:
                    blocks.append("\n".join(current))
                    current = []
                continue
            current.append(line.rstrip())
        for block in blocks:
            if len(block.strip()) >= 40:
                report["description"] = block.strip()
                completed.append("description: first §1.2 paragraph")
                return
    needs.append("description: no substantive §1.2 paragraph found; "
                 "left empty")


def fill_trust_boundaries(report: dict, model: Model,
                          completed: list[str], needs: list[str]) -> None:
    s = model.section("4")
    tables = _table_data(s.body) if s else []
    units = _prose_units(s.body) if s else []

    def from_tables(name: str) -> str | None:
        for header, cells in tables:
            if not any(name.casefold() in _norm_cell(c) for c in cells):
                continue
            for i, h in enumerate(header):
                if re.search(r"boundary|trust", h, re.IGNORECASE) \
                        and i < len(cells) and _squash(cells[i]):
                    return _squash(cells[i])
        return None

    def from_prose(name: str, entry_points: list[str]) -> str | None:
        for unit in units:
            if name.casefold() in unit.casefold():
                return unit
        # Second chance: a §1.4 sentence naming one of the component's entry
        # points ("bytes handed to `inflate` are attacker-controlled"). Short
        # ids are skipped — a three-letter verb would match everything.
        for ep in entry_points:
            if not isinstance(ep, str) or len(ep) < 4:
                continue
            for unit in units:
                if re.search(rf"\b{re.escape(ep)}\b", unit, re.IGNORECASE):
                    return unit
        return None

    for row in _dict_rows(report.get("trust_boundaries")):
        if row.get("boundary"):
            continue
        name = row.get("component")
        if not isinstance(name, str) or not name:
            continue
        eps = [c.get("entry_points")
               for c in _dict_rows(report.get("components"))
               if c.get("name") == name]
        text = from_tables(name) or from_prose(
            name, eps[0] if eps and isinstance(eps[0], list) else [])
        if text:
            row["boundary"] = text
            completed.append(f"trust_boundaries ({name}): §1.4")
        else:
            needs.append(f"trust_boundaries ({name}): no §1.4 row or sentence "
                         "names this component; boundary left empty")

    # A boundary claim's authority lives in §1.4's own provenance tags, not
    # in the component record. The projection therefore emits every boundary
    # row as bare `inferred`; this is the authoring layer that reads §1.4.
    # When every tag there collapses to inferred/assumption, the rows stay
    # capped and gain the §1.4 question id as their source. When §1.4 is
    # documented-grounded, upgrading is a hand decision — mechanically
    # attributing a tag to one component's boundary is guesswork, and
    # over-conservative `inferred` is the allowed direction.
    tags = [(m.group(1).lower(), (m.group(2) or "").strip())
            for m in _TAG.finditer(s.body)] if s else []
    kinds = {kind for kind, _ in tags}
    rows = _dict_rows(report.get("trust_boundaries"))
    if tags and kinds <= {"inferred", "assumption"}:
        qid = next((d for _, d in tags if re.fullmatch(r"Q\d+", d)), None)
        for row in rows:
            row["provenance"] = "inferred"
            if qid and not row.get("source"):
                row["source"] = f"open question {qid}"
        completed.append(
            "trust_boundaries provenance: inferred per §1.4 tags"
            + (f" (source: open question {qid})" if qid else ""))
    elif tags and kinds <= {"documented", "maintainer"} and rows:
        needs.append("trust_boundaries: §1.4 grounds its boundaries in "
                     "documented/maintainer tags but the rows are left "
                     "inferred; upgrade by hand where the tag covers the row")


_NEGATION = re.compile(r"\b(?:no|not|never|none|nor)\b|n't\b", re.IGNORECASE)


def fill_environment(report: dict, model: Model, sidecar: dict,
                     completed: list[str], needs: list[str]) -> None:
    env = report.get("environment")
    if not isinstance(env, dict):
        return
    s = model.section("5")
    units = _prose_units(s.body) if s and not s.is_na else []
    assumes = [u for u in units if not _NEGATION.search(u)]
    does_not = [u for u in units if _NEGATION.search(u)]
    if assumes:
        env["assumes"] = assumes
        completed.append("environment.assumes: §1.5")
    else:
        needs.append("environment.assumes: nothing extractable from §1.5")
    if does_not:
        env["does_not"] = does_not
        completed.append("environment.does_not: §1.5")
    else:
        # The sidecar's absent-stance §1.5 records are mechanical but true:
        # an `absent` stance is exactly a does-not statement.
        derived = []
        for effect in _dict_rows(sidecar.get("host_side_effects")):
            if effect.get("stance") != "absent" or not effect.get("effect"):
                continue
            comps = [c for c in effect.get("components") or []
                     if isinstance(c, str)]
            derived.append(f"no {effect['effect']}"
                           + (f" ({', '.join(comps)})" if comps else ""))
        if derived:
            env["does_not"] = derived
            completed.append(
                "environment.does_not: sidecar §1.5 absent stances")
        else:
            needs.append("environment.does_not: nothing extractable from §1.5")


# Word-level match so "cap" cannot ride inside "capability".
_MISUSE_STOPWORDS = {
    "a", "an", "the", "and", "or", "of", "for", "to", "in", "on", "with",
    "without", "as", "is", "are", "use", "using", "used", "its", "it",
    "this", "that", "via", "by", "from",
}


def _best_unit(pattern: str, units: list[str]) -> str | None:
    """The §1.14 entry that best matches a sidecar misuse pattern.

    The sidecar pattern and the prose entry paraphrase each other, so exact
    matching finds nothing. Scored token overlap with a floor does: at least
    half the pattern's significant words, and at least two of them, must
    appear in the entry. Below the floor no entry is returned — attaching the
    wrong reasoning would be worse than attaching none.
    """
    tokens = [t.strip(".-_")
              for t in re.findall(r"[\w.-]+", pattern.casefold())]
    tokens = [t for t in tokens
              if len(t) >= 3 and t not in _MISUSE_STOPWORDS]
    if not tokens:
        return None
    best, best_score = None, 0.0
    for unit in units:
        hits = sum(1 for t in tokens
                   if re.search(rf"(?<![\w-]){re.escape(t)}(?![\w-])",
                                unit, re.IGNORECASE))
        score = hits / len(tokens)
        if hits >= min(2, len(tokens)) and score >= 0.5 and score > best_score:
            best, best_score = unit, score
    return best


def _why_unsafe_clause(unit: str) -> str | None:
    """The '*Why unsafe*: ...' clause of a §1.14 entry, when it has one."""
    m = re.search(r"\*+Why unsafe\*+\s*[:–——-]?\s*(.+?)(?=\*+Instead\*+|$)",
                  unit, re.IGNORECASE)
    return m.group(1).strip(" .") + "." if m and m.group(1).strip(" .") \
        else None


def fill_known_misuse(report: dict, model: Model, sidecar: dict,
                      completed: list[str], needs: list[str]) -> None:
    rows = report.get("known_misuse")
    if not isinstance(rows, list):
        return                     # not_applicable — nothing to complete
    s = model.section("14")
    units = _prose_units(s.body) if s and not s.is_na else []
    records = _dict_rows(sidecar.get("known_misuses"))
    for i, row in enumerate(rows):
        if not isinstance(row, dict) or row.get("why_unsafe"):
            continue
        pattern = records[i].get("pattern") if i < len(records) else None
        match = _best_unit(str(pattern or ""), units)
        if match:
            row["why_unsafe"] = _why_unsafe_clause(match) or match
            completed.append(f"known_misuse[{i}] why_unsafe: §1.14")
        else:
            needs.append(f"known_misuse[{i}] ({row.get('pattern')!r}): "
                         "no matching §1.14 entry; why_unsafe left empty")


def fill_known_non_findings(report: dict, model: Model, sidecar: dict,
                            completed: list[str], needs: list[str]) -> None:
    s = model.section("15")
    tables = _table_data(s.body) if s else []
    records = _dict_rows(sidecar.get("known_non_findings"))
    for i, row in enumerate(_dict_rows(report.get("known_non_findings"))):
        record = records[i] if i < len(records) else {}
        # project_from_sidecar emits rows in sidecar order; verify anyway so a
        # drifted pairing cannot attach the wrong reasoning to an entry.
        if record.get("tool_pattern") != row.get("reported_as"):
            record = next((r for r in records
                           if r.get("tool_pattern") == row.get("reported_as")),
                          {})
        comps = entry_components(record)
        symptom = record.get("symptom")
        rid = str(record.get("id") or "").casefold()
        conditions = None
        for header, cells in tables:
            if not rid or not any(_norm_cell(c) == rid for c in cells):
                continue
            for j, h in enumerate(header):
                if "condition" in h.casefold() and j < len(cells) \
                        and _squash(cells[j]):
                    conditions = _squash(cells[j]).rstrip(".")
                    break
            break
        if conditions and comps and isinstance(symptom, str) \
                and symptom.strip():
            # why_safe is the one JSON field left that can carry the §1.15
            # scope (components + symptom), so it names both explicitly.
            row["why_safe"] = (
                f"Covers {', '.join(comps)}; symptom '{symptom}'. "
                f"Exact-match conditions (§1.15): {conditions}.")
            completed.append(
                f"known_non_findings[{i}] why_safe: §1.15 row "
                f"{record.get('id')!r}")
        else:
            needs.append(
                f"known_non_findings[{i}] ({row.get('reported_as')!r}): "
                "why_safe is the mechanical scaffold; replace with the "
                "§1.15 reasoning")


# §1.18 "Lands in: §1.N" → the JSON field the answer lands in. Sections with
# no JSON home stay unmapped on purpose: §1.8 output taint, §1.9 dependency
# edges, §1.16 revision triggers, and §1.17 precedence are all dropped by the
# schema (spec §4), so no field name would be true.
_SECTION_FIELD = {
    "2": "description",
    "3": "out_of_scope",
    "4": "trust_boundaries",
    "5": "environment",
    "6": "build_variants",
    "7": "entry_points",
    "10": "adversaries",
    "11": "properties_provided",
    "12": "properties_not_provided",
    "13": "downstream_responsibilities",
    "14": "known_misuse",
    "15": "known_non_findings",
}

# The three §1.18 entry shapes the harness Q-ID parser recognizes
# (parse.Model.open_question_ids): bulleted labels, titled labels, numbered
# lists. That parser stays the authority on which IDs exist; these only
# locate each ID's text block.
_Q_STARTS = [
    (re.compile(r"^\s{0,3}[-*]\s+[\[*_]{0,3}(Q\d+)[\]*_]{0,3}"
                r"\s*[:.–——-]\s*(.*)$", re.IGNORECASE), "Q"),
    (re.compile(r"^\s{0,3}\*{0,2}(Q\d+)\*{0,2}\s*[:.–——-]\s*(.*)$",
                re.IGNORECASE), "Q"),
    (re.compile(r"^\s{0,3}(\d+)\.\s+(\S.*)$"), "N"),
]
_PROPOSED_MARK = re.compile(
    r"(?:^|\n)\s*[-*]?\s*Proposed answer\s*[:–——-]?\s*",
    re.IGNORECASE)
_LANDS_MARK = re.compile(
    r"(?:^|\n)\s*[-*]?\s*Lands in\s*[:–——-]?\s*", re.IGNORECASE)


def _split_questions(body: str) -> list[tuple[str, str]]:
    """(qid, entry text) per §1.18 entry, in document order."""
    entries: list[tuple[str, list[str]]] = []
    in_fence = False
    for line in body.splitlines():
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or line.strip().startswith("|"):
            continue
        started = False
        for pattern, kind in _Q_STARTS:
            m = pattern.match(line)
            if m:
                qid = m.group(1).upper() if kind == "Q" else f"Q{m.group(1)}"
                entries.append((qid, [m.group(2)]))
                started = True
                break
        if not started and entries and line.strip():
            entries[-1][1].append(line)
    return [(qid, "\n".join(lines)) for qid, lines in entries]


def fill_open_questions(report: dict, model: Model, sidecar: dict,
                        completed: list[str], needs: list[str]) -> None:
    valid_ids = model.open_question_ids()
    questions: list[dict] = []
    seen: set[str] = set()
    s = model.section("18")
    for qid, text in _split_questions(s.body) if s else []:
        if qid not in valid_ids or qid in seen:
            continue
        seen.add(qid)
        marks = sorted(
            [(m.start(), m.end(), "proposed")
             for m in [_PROPOSED_MARK.search(text)] if m]
            + [(m.start(), m.end(), "lands")
               for m in [_LANDS_MARK.search(text)] if m])
        claim = _squash(text[:marks[0][0]] if marks else text)
        parts: dict[str, str] = {}
        for k, (start, end, kind) in enumerate(marks):
            stop = marks[k + 1][0] if k + 1 < len(marks) else len(text)
            parts[kind] = _squash(text[end:stop])
        if not claim:
            needs.append(f"open_questions: §1.18 {qid} has no extractable "
                         "claim text; dropped")
            continue
        entry = {"claim": f"{qid}: {claim}", "field": ""}
        refs = re.findall(r"§\s*1\.(\d+)", parts.get("lands", ""))
        field = next((_SECTION_FIELD[r] for r in refs if r in _SECTION_FIELD),
                     None)
        if field:
            entry["field"] = field
        elif refs:
            # True but unmapped: better to carry the real section number than
            # a field name the schema mapping does not support.
            entry["field"] = f"§1.{refs[0]}"
            needs.append(f"open_questions ({qid}): lands in §1.{refs[0]}, "
                         "which has no JSON field; review by hand")
        else:
            needs.append(f"open_questions ({qid}): no 'Lands in' line; "
                         "field left empty")
        if parts.get("proposed"):
            entry["proposed"] = parts["proposed"]
        questions.append(entry)
    if questions:
        report["open_questions"] = questions
        completed.append(f"open_questions: {len(questions)} §1.18 entries")
        missing = sorted(valid_ids - seen)
        if missing:
            needs.append("open_questions: §1.18 ids without extractable "
                         f"entries: {missing}")
    else:
        # §1.18 is only required while unratified claims remain, so an empty
        # result is a gap only when the sidecar still carries such claims.
        unratified = any(
            isinstance(r, dict) and isinstance(r.get("provenance"), dict)
            and r["provenance"].get("kind") in ("inferred", "assumption")
            for key in ("components", "properties_claimed",
                        "properties_disclaimed", "adversaries",
                        "host_side_effects", "known_non_findings")
            for r in _dict_rows(sidecar.get(key)))
        if unratified:
            needs.append("open_questions: nothing extracted from §1.18 but "
                         "the sidecar carries inferred/assumption claims")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _resolve_inputs(args, model: Model) -> tuple[str, str, str] | str:
    """(repository, commit, date), or an error message.

    Nothing is ever fabricated here. A commit the tool cannot determine is a
    refusal, not a placeholder — a made-up sha would bind the export to a
    tree that never existed.
    """
    repository = args.repository or extract_repository(model)
    if not repository:
        return ("cannot determine the repository URL: the §1.1 header names "
                "none; pass --repository URL")
    if not _URI_RE.match(repository):
        return (f"repository {repository!r} is not a URI (expected "
                "scheme://...); pass the full URL via --repository")

    if args.commit:
        commit = args.commit.strip().lower()
        if not _COMMIT_RE.fullmatch(commit):
            return (f"--commit {args.commit!r} does not match "
                    "^[0-9a-f]{7,40}$; pass a real sha")
    elif args.source_root:
        commit, why = _git_head(args.source_root)
        if not commit:
            return (f"git rev-parse HEAD failed in {args.source_root}: {why}; "
                    "pass --commit SHA instead")
    else:
        commit = extract_commit(model)
        if not commit:
            return ("cannot determine the modeled commit: the §1.1 header "
                    "records none; pass --commit SHA or --source-root DIR")

    date = args.date or extract_date(model) \
        or datetime.date.today().isoformat()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        return f"--date {date!r} is not YYYY-MM-DD"
    try:
        datetime.date.fromisoformat(date)
    except ValueError:
        return f"--date {date!r} is not a real calendar date"
    return repository, commit, date


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Export a threat model (prose + sidecar) as "
                    "threat-model.json per schema.json.")
    ap.add_argument("model", help="path to the prose threat-model markdown")
    ap.add_argument("sidecar", help="path to the threat-model.yaml sidecar")
    ap.add_argument("--out", default=None,
                    help="output path (default: threat-model.json beside "
                         "the sidecar)")
    ap.add_argument("--repository", default=None,
                    help="repository URL; default: extracted from the §1.1 "
                         "header")
    ap.add_argument("--commit", default=None,
                    help="modeled commit sha; default: extracted from the "
                         "§1.1 header")
    ap.add_argument("--source-root", default=None,
                    help="modeled checkout; runs `git rev-parse HEAD` there "
                         "instead of --commit")
    ap.add_argument("--date", default=None,
                    help="model date YYYY-MM-DD; default: §1.1 Date line, "
                         "else today")
    ap.add_argument("--scope-subpath", default=None,
                    help="subdirectory the run was scoped to, if any")
    ap.add_argument("--force", action="store_true",
                    help="write even when error-severity checks fail "
                         "(the exit code stays 1)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="also print passing checks")
    args = ap.parse_args(argv)

    try:
        model = Model.from_file(args.model)
    except OSError as exc:
        print(f"cannot read {args.model}: {exc}", file=sys.stderr)
        return 2
    try:
        sidecar = load_sidecar(args.sidecar)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"cannot load sidecar {args.sidecar}: {exc}", file=sys.stderr)
        return 2

    resolved = _resolve_inputs(args, model)
    if isinstance(resolved, str):
        print(resolved, file=sys.stderr)
        return 2
    repository, commit, date = resolved

    report = project_from_sidecar(
        sidecar, repository=repository, commit=commit, date=date,
        description="", scope_subpath=args.scope_subpath)

    # project_from_sidecar always emits the optional entry-point `component`
    # key; a sidecar row without one yields None, which schema.json rejects.
    # Dropping the key is faithful; inventing a component name is not.
    for row in _dict_rows(report.get("entry_points")):
        if row.get("component") is None:
            row.pop("component", None)

    completed: list[str] = []
    needs: list[str] = []
    fill_description(report, model, completed, needs)
    fill_trust_boundaries(report, model, completed, needs)
    fill_environment(report, model, sidecar, completed, needs)
    fill_known_misuse(report, model, sidecar, completed, needs)
    fill_known_non_findings(report, model, sidecar, completed, needs)
    fill_open_questions(report, model, sidecar, completed, needs)

    try:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"cannot load {_SCHEMA_PATH}: {exc}", file=sys.stderr)
        return 2
    schema_errors = validate_instance(report, schema)
    try:
        checks = run_json_checks(report, sidecar, model)
    except Exception as exc:      # noqa: BLE001 — refuse, never mask
        # A gate that cannot run must block the write, exactly like a gate
        # that fails. Continuing without the cross-checks would let an
        # unchecked export through on the strength of a checker outage.
        print("run_json_checks raised "
              f"{type(exc).__name__}: {exc} — the JSON gate itself is "
              "broken (threatmodel_eval.jsonreport); refusing to write",
              file=sys.stderr)
        return 2

    print(f"Converting {args.model} + {args.sidecar}")
    if schema_errors:
        print("schema.json violations:")
        for err in schema_errors:
            print(f"  {err}")
    print(checks.render(verbose=args.verbose))

    ok = checks.ok and not schema_errors
    out_path = Path(args.out) if args.out \
        else Path(args.sidecar).resolve().parent / "threat-model.json"
    if not ok and not args.force:
        print(f"\nnot written: {len(checks.errors)} error-severity check "
              "failure(s); fix them or pass --force", file=sys.stderr)
        return 1
    if not ok:
        print("\nWARNING: writing despite error-severity failures — this "
              "export FAILS its own gates and must not be published as-is",
              file=sys.stderr)

    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False)
                        + "\n", encoding="utf-8")
    print(f"wrote {out_path}")

    if completed:
        print("\ncompleted from prose (verify against the canonical "
              "sections):", file=sys.stderr)
        for note in completed:
            print(f"  - {note}", file=sys.stderr)
    if needs:
        print("\nneeds hand completion before this export is publishable:",
              file=sys.stderr)
        for note in needs:
            print(f"  - {note}", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
