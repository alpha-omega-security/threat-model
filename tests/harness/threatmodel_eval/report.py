"""Result and report types for the threat-model validator.

A `Finding` is one check outcome. `severity` distinguishes hard requirements
(``error`` — must pass, gates the exit code) from soft signals (``warn``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Literal

Severity = Literal["error", "warn"]
Gate = Literal[
    "G1-provenance", "G2-coverage", "G3-triage", "G4-style", "sidecar", "compat"
]


@dataclass(frozen=True)
class Finding:
    check_id: str
    gate: Gate
    severity: Severity
    passed: bool
    message: str
    location: str = ""

    def marker(self) -> str:
        if self.passed:
            return "PASS"
        return "FAIL" if self.severity == "error" else "WARN"


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def extend(self, fs: Iterable[Finding]) -> None:
        self.findings.extend(fs)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if not f.passed and f.severity == "error"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if not f.passed and f.severity == "warn"]

    @property
    def ok(self) -> bool:
        """True when no error-severity check failed."""
        return len(self.errors) == 0

    def failed_check_ids(self) -> set[str]:
        return {f.check_id for f in self.findings if not f.passed}

    def render(self, verbose: bool = False) -> str:
        lines: list[str] = []
        for f in self.findings:
            if f.passed and not verbose:
                continue
            loc = f" [{f.location}]" if f.location else ""
            lines.append(f"  {f.marker():4} {f.check_id:28} {f.message}{loc}")
        n_err, n_warn = len(self.errors), len(self.warnings)
        n_pass = sum(1 for f in self.findings if f.passed)
        status = "OK" if self.ok else "FAILED"
        lines.append("")
        lines.append(
            f"  => {status}: {n_pass} passed, {n_err} error(s), {n_warn} warning(s)"
        )
        return "\n".join(lines)
