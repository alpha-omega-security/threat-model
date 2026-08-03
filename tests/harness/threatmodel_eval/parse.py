"""Parsers for a threat-model prose document and its YAML sidecar.

The prose document follows the canonical section structure in
``skills/threat-model/references/output-structure.md`` (headings like
``## 1.7 Assumptions about inputs``). The sidecar follows
``sidecar-schema.md`` (``schema: threat-model-sidecar/v2``).

Parsing is intentionally forgiving about house-style variations (heading level
2 vs 3, section titles) but strict about the section *numbers*, which are the
stable anchors the triager quick-start and the checks rely on.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_HEADING = re.compile(r"^(#{1,6})[ \t]+(.*?)[ \t]*#*$")
_SECTION_NO = re.compile(r"^1\.(\d+[a-z]?)\b")
# A provenance tag: (documented, source) / (maintainer, 2025-03) /
# (inferred, Q7) / (assumption, Q7). Detail is mandatory for body claims and
# validated separately.
_TAG = re.compile(
    r"\((documented|maintainer|inferred|assumption)(?:,\s*([^)]*?))?\)",
    re.IGNORECASE,
)
# Hedge tags the skill explicitly forbids.
_HEDGE = re.compile(
    r"\((implicit|documented in purpose|generally known)\)", re.IGNORECASE
)
# The §1.1 draft-confidence tally. The fourth "/ N assumption" term is appended
# only when the model uses (assumption) tags (see output-structure.md §1.1).
_CONFIDENCE = re.compile(
    r"(\d+)\s*documented\s*/\s*(\d+)\s*maintainer\s*/\s*(\d+)\s*inferred"
    r"(?:\s*/\s*(\d+)\s*assumption)?",
    re.IGNORECASE,
)


@dataclass
class Section:
    number: str          # "1", "7", "11", "5a" ...
    title: str
    body: str

    @property
    def is_na(self) -> bool:
        return bool(re.search(r"not applicable", self.body, re.IGNORECASE))

    @property
    def substantive(self) -> bool:
        # A section counts as substantive if it has real content beyond the
        # heading, or is explicitly marked N/A with a reason.
        stripped = self.body.strip()
        if self.is_na:
            return True
        return len(stripped) >= 40


@dataclass
class Model:
    path: Path
    text: str
    sections: dict[str, Section] = field(default_factory=dict)

    # ---- construction -------------------------------------------------
    @classmethod
    def from_file(cls, path: str | Path) -> "Model":
        p = Path(path)
        return cls.from_text(p.read_text(encoding="utf-8"), p)

    @classmethod
    def from_text(cls, text: str, path: str | Path = "<memory>") -> "Model":
        m = cls(path=Path(path), text=text)
        m._parse_sections()
        return m

    def _parse_sections(self) -> None:
        lines = self.text.splitlines()
        headings: list[tuple[int, int, str]] = []  # (line_idx, level, title)
        for i, line in enumerate(lines):
            hm = _HEADING.match(line)
            if hm:
                headings.append((i, len(hm.group(1)), hm.group(2).strip()))
        for idx, (line_i, level, title) in enumerate(headings):
            sm = _SECTION_NO.match(title)
            if not sm:
                continue
            # Section body runs until the next heading of same or higher level.
            end = len(lines)
            for later_i, later_level, _ in headings[idx + 1:]:
                if later_level <= level:
                    end = later_i
                    break
            body = "\n".join(lines[line_i + 1:end])
            self.sections[sm.group(1)] = Section(sm.group(1), title, body)

    # ---- accessors ----------------------------------------------------
    def section(self, number: str) -> Section | None:
        return self.sections.get(number)

    @property
    def header(self) -> str:
        s = self.section("1")
        return s.body if s else ""

    def tag_counts(self, exclude_header: bool = True) -> dict[str, int]:
        """Count parenthesized provenance tags across the body.

        The §1.1 header carries the *summary* count and the legend, so it is
        excluded by default to compare stated vs. actual body claims.
        """
        text = self.text
        if exclude_header and self.section("1"):
            text = text.replace(self.section("1").body, "")
        counts = {"documented": 0, "maintainer": 0, "inferred": 0,
                  "assumption": 0}
        for m in _TAG.finditer(text):
            counts[m.group(1).lower()] += 1
        return counts

    def provenance_details(self) -> list[tuple[str, str]]:
        """Return body provenance tags as ``(kind, detail)`` pairs."""
        text = self.text
        if self.section("1"):
            text = text.replace(self.section("1").body, "")
        return [
            (match.group(1).lower(), (match.group(2) or "").strip())
            for match in _TAG.finditer(text)
        ]

    def stated_confidence(self) -> tuple[int, int, int, int] | None:
        """Return ``(documented, maintainer, inferred, assumption)`` from §1.1.

        The trailing "/ N assumption" term is optional; it reads as 0 when the
        model states no assumption tally.
        """
        m = _CONFIDENCE.search(self.header)
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)),
                int(m.group(4) or 0))

    def stated_status(self) -> str | None:
        """Normalize the §1.1 status line to the sidecar enum."""
        match = re.search(r"\*\*Status\*\*\s*:\s*([^\n]+)", self.header,
                          re.IGNORECASE)
        if not match:
            return None
        value = re.split(r"[,.;]", match.group(1), maxsplit=1)[0].strip().lower()
        if "unratified" in value:
            return "unratified-draft"
        if "under" in value and "review" in value:
            return "under-review"
        if "accepted" in value:
            return "accepted"
        if "draft" in value:
            return "draft"
        return None

    def hedge_tags(self) -> list[str]:
        return [m.group(0) for m in _HEDGE.finditer(self.text)]

    def open_question_count(self) -> int:
        s = self.section("18")
        if not s:
            return 0
        # Count numbered, bulleted, or Q-labeled question entries.
        return len(re.findall(
            r"^\s*(?:\d+\.\s+\S|[-*]\s+\S|\*{0,2}Q\d+\*{0,2}\s*[:.\u2013\u2014-])",
            s.body, re.MULTILINE | re.IGNORECASE))

    def open_question_ids(self) -> set[str]:
        """Return canonical Q-IDs from numbered or explicitly labeled entries.

        Three §1.18 entry styles are recognized, all permitted by the spec,
        which mandates a stable ``QN`` per question but not a fixed list format:
        numbered lists (``1.`` -> ``Q1``), bulleted labels (``- [Q1]:``), and
        inline bold/plain labels (``**Q1 — ...**``, ``Q1: ...``).
        """
        s = self.section("18")
        if not s:
            return set()
        numbered = {
            f"Q{match}" for match in re.findall(r"^\s*(\d+)\.\s+\S", s.body, re.MULTILINE)
        }
        labeled = {
            match.upper() for match in re.findall(
                r"^\s*[-*]\s+[*_]{0,2}\[?(Q\d+)\]?[*_]{0,2}\s*[:\u2013\u2014-]", s.body,
                re.MULTILINE | re.IGNORECASE,
            )
        }
        titled = {
            match.upper() for match in re.findall(
                r"^\s*\*{0,2}(Q\d+)\*{0,2}\s*[:.\u2013\u2014-]", s.body,
                re.MULTILINE | re.IGNORECASE,
            )
        }
        return numbered | labeled | titled


def markdown_tables(body: str) -> list[list[str]]:
    """Return well-formed pipe-table row groups from Markdown text."""
    groups: list[list[str]] = []
    current: list[str] = []
    for line in body.splitlines() + [""]:
        if line.strip().startswith("|"):
            current.append(line)
        elif current:
            groups.append(current)
            current = []
    sep = re.compile(r"^\s*\|?[\s:|-]+\|[\s:|-]+$")
    return [rows for rows in groups if len(rows) >= 2 and any(sep.match(r) for r in rows)]


def has_table(body: str, min_cols: int = 2) -> bool:
    return any(rows[0].count("|") - 1 >= min_cols for rows in markdown_tables(body))


def load_sidecar(path: str | Path) -> dict:
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"sidecar {p} did not parse to a mapping")
    return data
