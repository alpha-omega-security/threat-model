---
title: zlib threat model
slug: zlib
description: In-process compression and decompression where compressed bytes are untrusted, the caller owns buffers and budgets, and checksums do not provide authenticity.
status: Unratified draft
project_kind: Native compression library
target_name: madler/zlib
target_repository: https://github.com/madler/zlib
modeled_commit: 51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf
modeled_date: 2026-08-07
languages:
  - C
confidence_documented: 68
confidence_inferred: 7
claimed_properties: 7
entry_point_rows: 4
open_question_count: 5
source_directory: https://github.com/alpha-omega-security/threat-model/tree/main/tests/fixtures/golden/zlib
artifacts:
  - label: Prose
    path: tests/fixtures/golden/zlib/threat-model.md
  - label: YAML
    path: tests/fixtures/golden/zlib/threat-model.yaml
  - label: JSON
    path: tests/fixtures/golden/zlib/threat-model.json
---

## Why this example matters

zlib has a compact API and a deceptively simple data flow, which makes it a
useful demonstration of operand-level trust. The compressed stream can be
attacker-controlled while the calling process, destination buffer, lengths,
allocator callbacks, file paths, and resource budget remain caller-owned.

Treating all of those inputs as equally hostile would make the model noisy.
Treating all of them as trusted would hide the project’s central security
guarantee.

## Contract at a glance

| Dimension | Model decision |
| --- | --- |
| Untrusted surface | Compressed input bytes supplied to inflate and gzip read paths |
| Trusted party | The in-process caller and the buffers, lengths, callbacks, and configuration it supplies |
| Claimed core property | Memory safety for attacker-controlled compressed input on supported platforms |
| Explicit non-goal | Authenticity or cryptographic integrity from Adler-32/CRC-32 |
| Downstream duty | Bound total decompressed output and treat decoded content as untrusted |
| Host effects | Core APIs are computational; the gzip convenience API touches caller-selected files |

## The key trust boundary

The primary boundary sits at the compressed byte stream. A report is in-model
only when attacker-controlled bytes can reach the affected path without first
requiring control of a caller-trusted operand.

That distinction drives several different outcomes:

- an out-of-bounds write reached from crafted compressed bytes can be `VALID`;
- path traversal through a caller-selected `gzopen` path is a trusted-input
  question;
- unlimited decompression without a caller budget concerns a disclaimed
  resource property;
- a checksum-forgery report confuses error detection with authentication.

## What the backtest exercises

The golden fixture routes historical and synthetic findings across memory
safety, resource exhaustion, checksum misuse, unsupported sample code, caller
obligations, and recurring sanitizer noise. It checks that historically fixed
vulnerabilities remain open while documented non-findings and explicit
non-goals route consistently.

## What the artifacts demonstrate

The prose is canonical and contains the reasoning. The YAML sidecar preserves
the richer provenance and precedence needed for triage. The JSON export is
intentionally lossy and conservative: when it cannot carry a closure rule, the
consumer should escalate rather than guess.

## Open questions
{: #open-questions }

This fixture remains an **unratified draft**. Five proposed maintainer decisions
remain, including the exact caller-trusted operand set, the support status of
`contrib/`, downstream output well-formedness, and the completeness of the host
side-effect inventory.

Until those claims are confirmed, an inferred fact can identify a likely route
but cannot close a report.
