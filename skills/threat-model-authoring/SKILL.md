---
name: threat-model-authoring
description: >-
  Draft phase 3.5 of a threat model from the orientation brief, surface
  analysis, and maintainer answers. USE WHEN writing docs/threat-model.md to the
  canonical §1.1–§1.19 structure. Combines concise prose with the §1.7 trust
  table and contract matrix, §1.8 output statements, §1.17 disposition table,
  §1.1 triager quick-start, and any prior-policy back-map. Tags every non-trivial
  claim as documented, maintainer, or inferred; maps inferred claims to §1.18;
  and maintains confidence counts. DO NOT USE FOR: sidecar generation,
  backtesting, or triage.
argument-hint: '<target path for the threat-model document>'
---

# Threat Model — Authoring (draft the document)

Phase 3.5. Write the deliverable to the section structure in
[output-structure.md](../threat-model/references/output-structure.md). Read
[principles.md](../threat-model/references/principles.md) first — the style bar
is "describe the project as it *is*, not as it should be," and "write so a human
can read it": short, direct sentences (one idea each), plain words, active voice,
real verbs over nominalizations, and short bulleted lists or table rows instead
of piled-up noun stacks. Target the reading level of good developer
documentation, not a research paper — accuracy first, but never at the cost of
plain prose.

The deliverable deliberately mixes **both kinds of content in one document**:

- **Unstructured** — plain prose and short bulleted lists carrying the reasoning
  (scope, adversary model, properties provided / not provided, false friends,
  downstream responsibilities, known misuses).
- **Structured** — meaningful tables embedded inline: the §1.7 per-input-operand
  input-trust table and contract-dimension matrix, the §1.8 output-taint
  statements, the §1.17 closed disposition set, and the §1.1 boxed triager
  quick-start. (The separate
  machine-readable `threat-model.yaml` is `threat-model-sidecar`'s job.)

## Assemble from the upstream artifacts

- **§1.2/§1.3** from the recon component-family carve and out-of-scope inventory.
- **§1.4/§1.5/§1.7/§1.8** from the surface analysis (reachability preconditions,
  side-effects inventory, per-input-operand table, contract-dimension matrix,
  output taint).
- **§1.6/§1.9/§1.10/§1.11/§1.12/§1.13/§1.14/§1.15** seeded from recon's mined
  maintainer positions and promoted as interview answers arrive.
- **§1.1 header, §1.16, §1.17, §1.18** authored here to bind the whole together.
- **Prior-policy back-map appendix** from recon whenever `SECURITY.md` or an
  equivalent authoritative model existed; retain every source claim until a
  maintainer explicitly approves removing the map.

## Provenance discipline (non-negotiable)

- Every non-trivial claim carries exactly one of *(documented, source)*,
  *(maintainer, YYYY-MM)*, *(assumption, QN)*, *(inferred, QN)*. The `QN` on an
  assumption or inferred tag resolves to §1.18. **No hedge-tags** ("implicit",
  "documented in purpose", "generally known").
- **Prefer documented disclaimers to open questions.** When code + docs show a
  guarantee is simply not made (no thread-safety, no resource bound, no failure
  atomicity), record it as a *(documented)* §1.12 disclaimer — the absence is
  verifiable. Reserve `unresolved` / *(inferred)* for dimensions where a
  guarantee plausibly exists but was not confirmed. This is the main lever for
  cutting `MODEL-GAP` without weakening closure safety.
- **Assumption vs inferred.** Use *(assumption, QN)* for a conservative default
  you are willing to act on now (it may close low-blast-radius reports under the
  `relaxed` policy); use *(inferred, QN)* when the question is genuinely open
  (escalate-only under every policy). Do not relabel a guess as *(documented)* to
  make it close — that launders the author's inference into the project's
  authority and is forbidden.
- Every *(inferred)* and *(assumption)* tag has a matching §1.18 item that
  **states a proposed answer**. Mapping is one-directional: inferred/assumption →
  question required; extra edge-case/meta questions are allowed.
- Keep the header's **draft-confidence count** (documented / maintainer /
  inferred, plus assumption when used) current, and declare the **triage
  policy** (`strict` default, or `relaxed`). A draft with no *(inferred)* /
  *(assumption)* is fully reviewed or overclaiming; mostly unratified is not
  ready to publish.
- **Retain tags in the published version** — a closed report cites *(maintainer,
  2025-03)*, and bare prose is not defensible. Footnotes are fine; keep the chain
  of authority intact.

## Section-specific must-dos

- **§1.1** — version binding, reporting cross-reference, status (incl.
  `unratified draft` when §3.7 applies), triage-policy declaration (`strict`
  default / `relaxed`), provenance legend, draft-confidence count, backtest note,
  sibling models, and the boxed **triager quick-start** whose steps reference
  sections that actually exist.
- **§1.7** — a *table*, not prose; mark any untabled remainder from the surface
  timebox. Include control kinds and the per-family contract-dimension matrix.
  Every matrix row is claimed, disclaimed, N/A with reason, or unresolved.
- **§1.7-§1.12 contract closure** — promote claimed rows to §1.11 (or their owning
  environment/output section), disclaimed rows to §1.3/§1.12, and unresolved rows
  to proposed-answer §1.18 questions. No row may remain implicit.
- **§1.8** — state the taint of *every* output channel, including the "output is
  as untrusted as input" one-liner where it applies; promote structural output
  invariants to §1.11.
- **§1.11** — each property carries a **violation symptom** and a **severity
  tier**; resource properties state a **threshold**, not just a direction.
- **§1.12** — at least as substantive as §1.11; call out **false friends**
  (CRC≠MAC, hash≠collision-resistant, PRNG≠CSPRNG, sandbox≠isolation) and name
  the **well-known attack classes** for this category (compression bombs, XXE,
  ReDoS, billion-laughs) — one sentence each.
- **§1.13** — at least as substantive as §1.11; fold in every §1.6 dev-only knob
  and every risky §1.8 "must not assume" as a positive obligation.
- **Stateful APIs** — state failure postconditions where relevant, including
  callback/collaborator exceptions and partial mutation.
- **§1.17** — the closed disposition set, each citing its licensing section,
  including `dependency-contract`; add the all-status closure constraint.
- **Closure safety** — an *(inferred)* claim never licenses a closing
  disposition, regardless of status. An *(assumption)* closes only what the
  declared triage policy permits (`strict`: never; `relaxed`: low-blast-radius
  provisional closes only), and never a security-critical `property-disclaimed`,
  `KNOWN-NON-FINDING`, or `dependency-contract`. An accepted model has no
  inferred or assumption claims; retain review/draft status while any §1.18
  item remains.

## Style rules

- Plain prose and short lists. Tables only when **every cell is meaningful** —
  no templated tables with empty cells.
- When a property is **not** guaranteed, say so plainly ("Constant-time
  comparison is not provided" beats silence).
- Do not hedge into uselessness ("may or may not be safe depending on usage"). If
  you cannot get a clear answer, record an `unresolved` matrix row and a
  proposed-answer §1.18 question.
- Cut anything that belongs in a code review/audit, restates the README, or is a
  generic platitude. Every section is substantive or marked `Not applicable —
  <reason>`.

## Output

`docs/threat-model.md` (or the project's house path), ready for the
`threat-model-backtest` gate and the `threat-model-sidecar` derivation. Keep it
to one sitting (3–8 pages) — sprawl is a smell.
