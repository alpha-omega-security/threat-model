"""Check the model's scope claims against what the build actually compiles.

Scope is normally decided from the directory layout: `contrib/` and `examples/`
look like samples, so they get marked out of scope and the source scan skips
them. Directory names are a convention. The build system is the truth, and the
two disagree more often than they look like they would -- a default-on,
platform-conditional option can compile a "samples" directory straight into the
shipped library.

When that happens the model fails *open*: §1.17's precedence puts
`OUT-OF-MODEL: unsupported-component` second, so a memory-safety report in code
that really does ship closes as out of scope.

This check needs the source tree, so it only runs with ``--source-root``. It
looks for build rules that compile a path the model placed out of scope. It does
not try to understand the build -- it flags the contradiction and leaves the
judgement to a human, because the answer is usually "and it is default-on for
one platform", which no heuristic is going to work out.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .parse import Model
from .report import Finding, Report

_BUILD_FILES = (
    "configure", "Makefile", "Makefile.in", "Makefile.am", "makefile",
    "CMakeLists.txt", "meson.build", "BUILD", "BUILD.bazel", "setup.py",
    "pyproject.toml", "Cargo.toml", "package.json", "build.gradle",
)
_BUILD_SUFFIXES = {".mk", ".cmake", ".bzl"}

# A line that builds something, as opposed to merely mentioning a path (a test
# target that recurses into a sample directory is not the library shipping it).
_COMPILES = re.compile(
    r"\.o\b|\.lo\b|\.obj\b|\$\(CC\)|\$\(CXX\)|add_library|target_sources"
    r"|add_executable|_SOURCES\b|\bSRCS\b|\bsources\s*[:=]", re.IGNORECASE)

# `clean` targets name every object they delete, including ones no default
# build ever produces. Removing a file is not shipping it.
_DESTROYS = re.compile(r"\brm\s+-|\$\(RM\)|\bdel\s+/|\bunlink\b", re.IGNORECASE)

# Paths the model names as out of scope: `contrib/`, `examples/`, `third_party/`.
_OUT_OF_SCOPE_PATH = re.compile(r"`([\w.\-]+(?:/[\w.\-]*)+)`")

# Test directories are expected to compile -- into test binaries, not into the
# shipped artifact. Flagging them buries the finding that matters, and a project
# that really does link its test code into its library is rare enough to accept
# missing.
_TEST_DIRS = {"test", "tests", "t", "spec", "specs", "bench", "benchmarks",
              "testing", "fuzz", "fuzzing"}


def _f(cid: str, passed: bool, msg: str, loc: str = "") -> Finding:
    return Finding(cid, "citations", "error", passed, msg, loc)


def _logical_lines(lines: list[str]) -> list[tuple[int, str]]:
    """(start line, whole command) for each backslash-continued block.

    A ``rm -f`` in a clean target wraps over several lines, so a physical line
    holding only ``contrib/infback9/*.o`` looks like a build rule until you can
    see the verb that owns it.
    """
    out: list[tuple[int, str]] = []
    buf, start = "", 0
    for n, raw in enumerate(lines, 1):
        if not buf:
            start = n
        buf = f"{buf} {raw.strip().rstrip(chr(92))}" if buf else raw.rstrip(chr(92))
        if raw.rstrip().endswith("\\"):
            continue
        out.append((start, buf))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


def _acknowledged(model: Model, built_path: str) -> bool:
    """Does the model name the specific path the build reaches into?

    ``contrib/`` out of scope while ``contrib/crc32vx/`` is compiled in on one
    platform is a legitimate, and common, shape. What is not legitimate is
    saying the first without the second.
    """
    text = model.text
    parts = [p for p in built_path.split("/") if p]
    # Any prefix deeper than the top directory counts as naming the carve-out.
    for depth in range(len(parts), 1, -1):
        if "/".join(parts[:depth]) in text:
            return True
    return False


def _build_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.name in _BUILD_FILES or p.suffix in _BUILD_SUFFIXES:
            out.append(p)
        if len(out) > 400:                    # pragma: no cover - runaway guard
            break
    return out


def check_scope_against_build(model: Model, source_root: Path) -> Iterable[Finding]:
    root = Path(source_root)
    scope_section = model.section("3")
    if scope_section is None:
        yield _f("BUILD.scope-matches", True, "no §1.3 to check")
        return

    # Directory-ish tokens the out-of-scope section names.
    claimed_out = {
        m.rstrip("/").split("/")[0]
        for m in _OUT_OF_SCOPE_PATH.findall(scope_section.body)
        if "/" in m
    }
    claimed_out = {d for d in claimed_out
                   if (root / d).is_dir() and d.lower() not in _TEST_DIRS}

    compiled: list[str] = []
    for build in _build_files(root):
        try:
            lines = build.read_text(errors="replace").splitlines()
        except OSError:                        # pragma: no cover - unreadable
            continue
        rel = build.relative_to(root)
        for n, line in _logical_lines(lines):
            if not _COMPILES.search(line) or _DESTROYS.search(line):
                continue
            for d in sorted(claimed_out):
                hit = re.search(rf"\b({re.escape(d)}/[\w.\-/]*)", line)
                if not hit:
                    continue
                # A model that names the exact path the build reaches into has
                # done the work: it knows the carve-out exists and has said so.
                # Only the silent contradiction is a finding.
                if _acknowledged(model, hit.group(1)):
                    break
                compiled.append(f"{rel}:{n} builds from {d}/")
                break

    # De-duplicate by directory so one over-eager Makefile does not bury the list.
    seen, unique = set(), []
    for item in compiled:
        key = item.split("builds from ")[-1]
        if key not in seen:
            seen.add(key)
            unique.append(item)

    yield _f(
        "BUILD.scope-matches", not unique,
        "no out-of-scope directory is compiled by the build"
        if not unique else
        f"§1.3 places these out of scope but the build compiles from them: "
        f"{unique[:6]}{' …' if len(unique) > 6 else ''}. A directory the "
        "shipped artifact is built from is in scope wherever it lives — or "
        "§1.3 must say which platform or flag pulls it in, and §1.6 must carry "
        "that flag",
        "§1.3",
    )


def run_buildscope_checks(model: Model, source_root: str | Path) -> Report:
    return Report(list(check_scope_against_build(model, Path(source_root))))
