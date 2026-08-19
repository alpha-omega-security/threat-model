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
   - **Record each item's actual historical outcome** where one exists — `fixed`,
     `wontfix`, `by-design`, `out-of-scope`, or `unknown` — with the advisory or
     issue URL it came from. That label is the ground truth step 3 scores
     against, and without it the backtest cannot fail. Set the outcome aside
     while routing (step 2 is blind); compare only afterwards.
   - **When no historical record is reachable**, say so rather than inventing
     one. Synthesize cases to exercise the matrix, mark every one `synthesized`,
     and write the §1.1 note verbatim: *"no historical corpus was available; the
     backtest routed N synthesized cases only."* A self-invented corpus reported
     as history is worse than no backtest, because it reads as evidence.
2. **Route each item blind** — using only the draft (not hindsight knowledge of
   how it was actually resolved), apply the §1.1 triager quick-start and assign
   **exactly one** §1.17 disposition, citing the licensing section. Routing rules
   and the closed disposition set are in
   [output-structure.md](../threat-model/references/output-structure.md).
3. **Score the routing.** The two directions of error are **not** symmetric.
   Wrongly closing a real vulnerability is far worse than wrongly escalating a
   non-finding: an over-escalating model wastes maintainer time, an
   over-closing one hands a reporter a "not a bug" on a live issue. Score
   accordingly — this asymmetry decides every fix below.

   | Signature | Meaning | Fix |
   | --- | --- | --- |
   | **Closes an item the project actually fixed** | the model closes a true positive — the one disqualifying outcome | **Blocking. Fix before sign-off.** Narrow the licensing §1.12 disclaimer, §1.7 trusted marking, or §1.3 scope line until the item routes `VALID` or escalates. **Never widen a disclaimer to reach a close.** |
   | Routes to `MODEL-GAP` | the model is missing a decision | propose, in this order: an `unresolved` matrix row plus a proposed-answer §1.18 question; a conditional §1.11 guarantee; or an explicit §1.12 disclaimer. Prefer the option that leaves the report **escalating** over the option that closes it |
   | Routes plausibly to **two or more** dispositions | two sections overlap or contradict | sharpen them until the routing is unique |
   | Routes to a disposition that **contradicts** how the maintainer actually resolved it | the model is wrong, or the historical call was | high-value §1.18 question — do not paper over it |

   Disclaiming is the cheapest way to make a `MODEL-GAP` disappear, which makes
   it the easiest way to pass this gate while making the model worse. A
   disclaimer added *because a corpus item routed badly* is reverse-engineered
   from the answer: it must still be true of the project as it is, cite a real
   source, and stay inside the scope that source covers.

4. **Feed §1.15** — a recurring pattern is a candidate known non-finding only
   when its final outcome closes as `BY-DESIGN: property-disclaimed` or an
   already-established `KNOWN-NON-FINDING`. Never promote `VALID-HARDENING` or
   `MODEL-GAP` into a non-finding, and never promote an `OUT-OF-MODEL:*` route:
   a pattern that closes because the code is out of scope, the build is
   unsupported, or the root cause sits in a dependency keeps that disposition.
   `KNOWN-NON-FINDING` is first in the precedence order, so relabelling one of
   those routes promotes it above the very checks that decided it. Require
   documented/maintainer provenance and record the exact component or sink,
   symptom/attack class, preconditions, and stable claim or obligation IDs that
   discharge it; textual resemblance alone is not a match. Every candidate must
   satisfy the four §1.15 rules in `output-structure.md` — in particular, no
   entry may match on the reporter's evidence (no reproducer, no demonstrated
   reachability) rather than on the behaviour of the code.
5. **Export 2–4 worked routing examples** (§1.11) — the second and last thing
   the corpus may contribute to the document. Pick items that show the routing
   algorithm working, de-identify them, and give each one line: sink, required
   attacker capability, symptom, disposition, licensing claim. **At least one
   must route `VALID`.** A triager who only ever sees closes learns that the
   model's job is to say no; one worked `VALID` shows where the project takes
   responsibility, and it is the example that makes the rest credible. Budget
   about 15 lines. No CVE IDs, no reporter names, no dates — those are corpus
   content and stay on the producer side per the leave-out list.

   Steps 4 and 5 are the only backtest corpus *items* that may enter the
   document. The §1.1 note carries aggregate figures only, never an item.
6. **Close the coverage loop** — update the contract-dimension matrix after
   every revision, then reroute the affected cluster. An accepted model has no
   unexplained applicable cell and no unowned `MODEL-GAP`; an unratified draft
   may retain gaps only when each is represented by an `unresolved` row and §1.18
   question.

## Record the result

The §1.1 note is the only part a reader sees, so it must state what the backtest
actually proved rather than that it happened. Report, in one short paragraph:

- **Corpus size and shape** — item count, cluster count, and contract-dimension
  coverage.
- **Provenance split** — how many items carry a real historical outcome versus
  how many were synthesized. When none are real, use the verbatim sentence from
  step 1. "Routed 22 findings" reads as history; say which of them was.
- **Disposition histogram** — how many items landed on each §1.17 disposition.
- **The fail-safe figure** — how many historically-fixed items route to a
  **closing** disposition. The target is zero, and a shortfall is the one
  number that blocks sign-off.
- **How much the model closes** — the share of the corpus that closes outright.
  A model that closes nearly everything is either exceptionally well documented
  or quietly over-disclaiming; say which.
- **Contradictions**, with pointers to the §1.18 questions they raised.

Example: *"Backtested 22 findings (14 clusters, all 9 applicable dimensions); 17
carry a real historical outcome, 5 synthesized. Routed 9 VALID, 6
BY-DESIGN: property-disclaimed, 5 OUT-OF-MODEL, 2 escalated, 0 MODEL-GAP. All 11
historically-fixed items routed VALID. 50% of the corpus closes. Two
contradictions raised Q7 and Q9."*

Do **not** publish the corpus itself.

## Output

Write the routing table to **`.threat-model/backtest.md`** — a producer-side
artifact, deliberately in a dot-directory rather than beside
`threat-model.md`. Every row carries a real advisory or issue URL, which
the leave-out list keeps out of the published model, so a table sitting next to
the deliverable gets published by the first `git add -A`. Add
`.threat-model/` to the project's `.gitignore` if it is not already covered.
One row per item:

`id | source | component | cluster | dimension | disposition | licensing § | historical outcome | pass/fail`

where `source` is a real advisory or issue URL, or the literal `synthesized`.
Handing the table back only in conversation materializes nothing a reviewer can
check afterwards, which is how a backtest comes to self-certify.

Also hand back to the orchestrator: the coverage report, the model
decisions/revisions triggered (for `threat-model-authoring` to apply), the §1.18
questions for unresolved gaps, the §1.15 candidates, the §1.11 worked routing
examples, and the header backtest note.
