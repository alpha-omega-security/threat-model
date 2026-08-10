"""Resolve a model's code citations against the source it was written from.

Every other check in this harness inspects the document's *shape*: a tag is
present, a column exists, a figure is stated. Shape is cheap to satisfy without
doing the work, and repeatedly has been — a citation that looks like
``inflate.c:1393`` costs nothing to invent, and the rest of the validator cannot
tell an invented one from a real one.

These checks close that gap when the source tree is available, which it is at
generation time: the runner is holding the clone. They answer two questions a
regex over the document can never answer.

  1. Does the cited line exist, and is it *code*? A blank line, a comment, a
     bare ``#endif`` or a lone closing brace resolves to nothing a reader can
     check, so it is evidence of nothing.
  2. Does text the model quotes from a file actually appear in that file?

Neither proves the citation supports the claim — that stays a human judgement.
Both catch the failure that keeps recurring: citation-shaped text pointing
somewhere plausible and wrong.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .parse import Model
from .report import Finding, Report

# `inflate.c:1393` or `deflate.c:856-931`, normally inside backticks.
_CITATION = re.compile(r"`([\w./-]+\.[A-Za-z]\w*):(\d+)(?:\s*[-–]\s*(\d+))?`")

# Text the model quotes and attributes to a named file in the same breath:
#   "…some quoted sentence…" *(documented, `zlib.h` `deflateBound`)*
_ATTRIBUTED_QUOTE = re.compile(
    r"[\"“]([^\"”\n]{25,240})[\"”][^\n]{0,120}?`([\w./-]+\.[A-Za-z]\w*)`")

_SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".hpp", ".py", ".rs", ".go",
                    ".js", ".ts", ".java", ".s", ".asm"}


def _f(cid: str, passed: bool, msg: str, loc: str = "") -> Finding:
    return Finding(cid, "citations", "error", passed, msg, loc)


def _comment_lines(lines: list[str]) -> set[int]:
    """1-based line numbers that are entirely inside a comment.

    A line-prefix test is not enough: continuation prose inside a ``/* … */``
    block often starts with an ordinary word, and that is exactly where a
    mis-resolved citation lands -- documentation text that reads like a
    statement about behaviour but is not the behaviour.
    """
    inside, out = False, set()
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        started_inside = inside
        code = []
        j = 0
        while j < len(s):
            if not inside and s.startswith("/*", j):
                inside, j = True, j + 2
            elif inside and s.startswith("*/", j):
                inside, j = False, j + 2
            else:
                if not inside:
                    code.append(s[j])
                j += 1
        rest = "".join(code).strip()
        if (started_inside or not rest) and not rest.split("//")[0].strip():
            out.add(i)
    return out


def _classify(line: str, in_comment: bool) -> str:
    """What kind of thing is at this line? '' means real code."""
    s = line.strip()
    if not s:
        return "a blank line"
    if in_comment or s.startswith(("/*", "*/", "*", "//")):
        return "comment text"
    if s in ("#endif", "#else", "{", "}", "};"):
        return "a bare " + s
    return ""


def _norm(text: str) -> str:
    return " ".join(text.split())


def _probe(quote: str) -> str | None:
    """The longest run of a quotation that should appear verbatim in the source.

    A published quote is rarely a clean substring of the file: authors elide
    with an ellipsis, and the quoted text may itself contain quotes or
    backticks that truncate any naive capture. Matching on the longest
    uninterrupted fragment keeps the check honest without inventing failures --
    a fabricated quotation has no long fragment in the file either.
    """
    parts = re.split(r"…|\.\.\.|[`\"“”]", quote)
    best = max((_norm(p) for p in parts), key=len, default="")
    return best if len(best) >= 40 else None


def check_citations(model: Model, source_root: Path) -> Iterable[Finding]:
    """Resolve `file:line` citations and attributed quotes against the tree."""
    root = Path(source_root)
    text = model.text

    unresolved: list[str] = []
    seen: set[tuple[str, str]] = set()
    for match in _CITATION.finditer(text):
        path, line_no = match.group(1), match.group(2)
        if (path, line_no) in seen:
            continue
        seen.add((path, line_no))
        if Path(path).suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        target = root / path
        if not target.is_file():
            # Fall back to a unique basename match: models cite `inflate.c`
            # where the tree may nest it under a subdirectory.
            matches = [p for p in root.rglob(Path(path).name) if p.is_file()]
            if len(matches) != 1:
                unresolved.append(f"{path}:{line_no} (no such file under the source root)")
                continue
            target = matches[0]
        try:
            lines = target.read_text(errors="replace").splitlines()
        except OSError as exc:                       # pragma: no cover - unreadable file
            unresolved.append(f"{path}:{line_no} ({exc})")
            continue
        n = int(line_no)
        if n < 1 or n > len(lines):
            unresolved.append(
                f"{path}:{line_no} (file has {len(lines)} lines)")
            continue
        kind = _classify(lines[n - 1], n in _comment_lines(lines))
        if kind:
            unresolved.append(f"{path}:{line_no} is {kind}: {lines[n - 1].strip()[:60]!r}")

    yield _f(
        "CITE.resolves", not unresolved,
        f"all {len(seen)} code citations resolve to real source lines"
        if not unresolved else
        f"citations that do not resolve to code: {unresolved[:10]}"
        f"{' …' if len(unresolved) > 10 else ''}. A citation is evidence only "
        "if a reader can open it and see the behaviour — point at the statement",
    )

    missing_quotes: list[str] = []
    for quote, path in _ATTRIBUTED_QUOTE.findall(text):
        if Path(path).suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        candidates = [root / path]
        if not candidates[0].is_file():
            candidates = [p for p in root.rglob(Path(path).name) if p.is_file()]
        if len(candidates) != 1:
            continue                                  # unresolvable, CITE.resolves owns it
        probe = _probe(quote)
        if probe is None:
            continue      # nothing long enough to match on without false alarms
        body = _norm(candidates[0].read_text(errors="replace"))
        if probe not in body:
            missing_quotes.append(f"{path}: {probe[:70]!r}")

    yield _f(
        "CITE.quotes", not missing_quotes,
        "every quotation attributed to a source file appears in it"
        if not missing_quotes else
        f"quotations not found in the file they are attributed to: "
        f"{missing_quotes[:6]}{' …' if len(missing_quotes) > 6 else ''}",
    )


def run_citation_checks(model: Model, source_root: str | Path) -> Report:
    return Report(list(check_citations(model, Path(source_root))))
