---
name: threat-model-backtest
description: >-
   Backtest phase 3.6 of threat-model production against historical findings
   before sign-off. USE WHEN a draft model must prove it can uniquely route real
   reports. Builds a stratified producer-side corpus across components and
   contract dimensions, clusters large corpora by sink and attack class, and
   routes each item blind to one §1.17 disposition. Reports MODEL-GAP,
   contradictory or ambiguous routing, coverage, qualified §1.15 candidates,
   and §1.18 questions. The corpus is not published. DO NOT USE FOR: drafting,
   sidecar generation, or triaging one new finding.
argument-hint: '<path to the draft threat-model document>'
---

# Threat Model — Backtest (validate against history)

Phase 3.6. **A draft that has never been backtested is untested software.** The
project's own history is a free test suite; use it before presenting the draft
for sign-off. This is a **producer-side quality gate** — the corpus does not go
into the published document (per the leave-out list: CVE history is not the
threat model).

## Procedure

1. **Assemble a stratified corpus** — start with the last 10–30 inbound security
   findings: published advisories, reports closed as "not a bug" / "by design",
   issues labeled `security`, and scanner/fuzzer/AI-analysis output. If a
   vendored `security-context.md` is present in the working directory (a
   runner's pre-fetch of exactly this material), seed the corpus from it before
   searching elsewhere. Prefer
   contested items, but do not let recency or controversy leave component
   families or contract dimensions untested.
   - Cover every in-scope component family.
   - Cover every applicable contract-dimension row: numeric limits, failure
     atomicity, topology, callbacks, serialization, lifecycle, concurrency, and
     resource complexity.
   - For a large corpus, cluster by `(component, sink, attack class, required
     attacker capability)` and route at least one representative from every
     cluster. Increase the corpus beyond 30 when necessary to avoid an untested
     cluster; report both item count and cluster count.
2. **Route each item blind** — using only the draft (not hindsight knowledge of
   how it was actually resolved), apply the §1.1 triager quick-start and assign
   **exactly one** §1.17 disposition, citing the licensing section. Routing rules
   and the closed disposition set are in
   [output-structure.md](../threat-model/references/output-structure.md).
3. **Score the routing** — three failure signatures, each with a fix:

   | Signature | Meaning | Fix |
   | --- | --- | --- |
   | Routes to `MODEL-GAP` | the model is missing a decision | propose one of: a conditional §1.11 guarantee, an explicit §1.12 disclaimer, or an `unresolved` matrix row plus proposed-answer §1.18 question |
   | Routes plausibly to **two or more** dispositions | two sections overlap or contradict | sharpen them until the routing is unique |
   | Routes to a disposition that **contradicts** how the maintainer actually resolved it | the model is wrong, or the historical call was | high-value §1.18 question — do not paper over it |

4. **Feed §1.15** — a recurring pattern is a candidate known non-finding only
   when its final outcome closes as `OUT-OF-MODEL:*`,
   `BY-DESIGN: property-disclaimed`, or an already-established
   `KNOWN-NON-FINDING`. Never promote `VALID-HARDENING` or `MODEL-GAP` into a
   non-finding. Require documented/maintainer provenance and record the exact
   component or sink, symptom/attack class, preconditions, and stable claim or
   obligation IDs that discharge it; textual resemblance alone is not a match.
   That is the only backtest corpus content that may enter the document.
5. **Close the coverage loop** — update the contract-dimension matrix after
   every revision, then reroute the affected cluster. An accepted model has no
   unexplained applicable cell and no unowned `MODEL-GAP`; an unratified draft
   may retain gaps only when each is represented by an `unresolved` row and §1.18
   question.

## Record the result

Note in the §1.1 header that the backtest was performed, the item and cluster
counts, contract-dimension coverage, and routing results — e.g., *"backtested
against 22 findings in 14 clusters across all 8 applicable contract dimensions;
20 routed uniquely, 2 produced model revisions."* Do **not** publish the corpus
itself.

## Output

Hand back to the orchestrator: the routing table (item → cluster → contract
dimension → disposition → pass/fail signature), the coverage report, the model
decisions/revisions triggered (for `threat-model-authoring` to apply), the §1.18
questions for unresolved gaps, the §1.15 candidates, and the header backtest note.
