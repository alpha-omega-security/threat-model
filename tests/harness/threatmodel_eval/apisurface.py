"""Check the §1.7 coverage claim against the header it names.

A model that says "every public entry point in `zlib.h` is covered" has made a
claim about a set, and that set is sitting right there in the source. Left
unchecked it is the most misleading sentence a model can carry: it converts
every omission into an apparent scoping decision, so a triager who cannot find
an entry point concludes the author considered it and left it out.

The check is deliberately narrow. It fires only when the model names a header
and asserts completeness over it, because that is the one case where the claim
is precise enough to be wrong. A model that instead states a denominator --
"38 of 94 exported functions tabled; the rest are accessors" -- is doing what
the spec asks and is checked on the number, not the adjective.

Nothing here guesses at what "public" means for a project that did not say. A
check that invents its own denominator produces arguments, not findings.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .parse import Model
from .report import Finding, Report

# "every public entry point in `zlib.h`", "all exported functions in `api.h`".
_COMPLETENESS = re.compile(
    r"\b(?:every|all|each)\b[^.\n]{0,60}?"
    r"(?:entry point|exported function|export|public function|API function)s?"
    r"[^.\n]{0,40}?\bin\b\s*`([\w./-]+\.[hH]\w*)`", re.IGNORECASE)

# "38 of 94 exported functions", "27 of the 41 entry points"
_DENOMINATOR = re.compile(
    r"\b(\d+)\s+of\s+(?:the\s+)?(\d+)\b[^.\n]{0,50}?"
    r"(?:entry point|export|public function)", re.IGNORECASE)

# A C declaration in a public header: returns something, names something, opens
# a paren, and is a declaration rather than a definition or a macro.
_C_DECL = re.compile(
    r"^[A-Za-z_][\w \t\*]*?\b(\w+)\s*\([^;{]*\)\s*;", re.MULTILINE)


def _f(cid: str, passed: bool, msg: str, loc: str = "") -> Finding:
    return Finding(cid, "citations", "error", passed, msg, loc)


def _exports(header: Path) -> set[str]:
    """Function names a C header declares. Empty when we cannot tell."""
    try:
        text = header.read_text(errors="replace")
    except OSError:                            # pragma: no cover - unreadable
        return set()
    # Strip comments so prose examples do not read as declarations.
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", " ", text)
    names = set(_C_DECL.findall(text))
    # Macro-generated aliases (zlib's `deflateInit(a,b)` style) are declared as
    # #define, not as prototypes; count them too, since callers use them. No
    # space before the paren -- `#define Z_ERRNO (-1)` is a constant, not a
    # callable, and counting those inflates the denominator with names no
    # trust table would ever have a row for.
    names |= set(re.findall(r"^#\s*define\s+(\w+)\(", text, re.MULTILINE))
    return {n for n in names if not n.startswith("_")}


def _named_in(section_body: str) -> set[str]:
    return set(re.findall(r"`(\w+)\(?\)?`", section_body))


def check_api_coverage(model: Model, source_root: Path) -> Iterable[Finding]:
    root = Path(source_root)
    s7 = model.section("7")
    if s7 is None:
        yield _f("API.coverage-claim", True, "no §1.7 to check")
        return

    problems: list[str] = []
    for header_name in set(_COMPLETENESS.findall(s7.body)):
        candidates = [root / header_name]
        if not candidates[0].is_file():
            candidates = [p for p in root.rglob(Path(header_name).name)
                          if p.is_file()]
        if len(candidates) != 1:
            continue                            # cannot resolve; say nothing
        exports = _exports(candidates[0])
        if len(exports) < 5:
            continue                            # not a header we can read
        missing = sorted(exports - _named_in(s7.body))
        if missing:
            problems.append(
                f"§1.7 claims complete coverage of {header_name}, but "
                f"{len(missing)} of {len(exports)} declared functions have no "
                f"row: {missing[:12]}{' …' if len(missing) > 12 else ''}")

    yield _f(
        "API.coverage-claim", not problems,
        "§1.7 coverage claims match the header they name" if not problems
        else " | ".join(problems) + ". Either table them, or drop the "
        "completeness claim and state the count you did cover — an unqualified "
        "claim makes every omission look deliberate",
        "§1.7",
    )

    # A stated denominator is the shape the spec asks for. Check the number.
    wrong: list[str] = []
    for stated_num, stated_total in _DENOMINATOR.findall(s7.body):
        for header in {p for p in root.glob("*.h")}:
            exports = _exports(header)
            if len(exports) < 5:
                continue
            if abs(len(exports) - int(stated_total)) <= 2:
                break                           # matches a real header: fine
        else:
            if root.glob("*.h"):
                wrong.append(
                    f"§1.7 says {stated_num} of {stated_total}, which matches "
                    "no header in the tree")
    yield _f(
        "API.coverage-count", not wrong,
        "§1.7 coverage denominators match a real header" if not wrong
        else " | ".join(wrong[:4]),
        "§1.7",
    )


def run_api_checks(model: Model, source_root: str | Path) -> Report:
    return Report(list(check_api_coverage(model, Path(source_root))))
