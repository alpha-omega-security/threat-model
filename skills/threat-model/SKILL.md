---
name: threat-model
description: >
  Produce a high-quality threat model for a targeted open-source repository or
  package — the implicit security contract between a project and its downstream
  users (assumptions, guarantees, disclaimed properties, misuses), NOT an audit,
  pentest, CVE list, or build-hygiene checklist. USE WHEN asked to
  "produce/write/generate a threat model", "model the security contract", or
  "what threats does this library take on". This is the ORCHESTRATOR: it drives
  the canonical 3.1–3.7 procedure (orient → mine → surface → interview → draft
  → backtest → iterate/sign off) and delegates to the threat-model-* specialists,
  then runs sidecar and finalize publication gates. The deliverable
  is a prose document (docs/threat-model.md) plus a structured machine-readable
  companion (threat-model.yaml). To classify one inbound finding against a
  finished model, use threat-model-triage. DO NOT USE FOR: bug hunting, code
  review, CVE enumeration, or supply-chain/SDLC hygiene.
argument-hint: '<path or name of the repo/package to model>'
---

# Threat Model (orchestrator)

Produce the **implicit contract** between a project and its downstream users.
This skill owns the end-to-end procedure and delegates each phase to a
specialist. The deliverable is **two artifacts**:

- **Unstructured** — a prose document (`docs/threat-model.md`) written to the
  canonical section structure, with embedded structured tables (per-input-operand
  trust table, contract-dimension matrix, disposition set).
- **Structured** — a machine-readable companion (`threat-model.yaml`) that a
  triage pipeline can consume.

**Read first:** [principles.md](./references/principles.md) — what a threat
model is and is not, the four-question framework, and what to leave out. Do not
start producing before internalizing it.

## When to use

- Someone asks to produce, write, refresh, or ratify a threat model for a
  specific open-source library, component, service, or package.
- You need a project's security assumptions written down so a downstream
  integrator knows what they own and a triager can route findings.

## When NOT to use

- Bug hunting, code review, pentest, or CVE enumeration → those are audit
  outputs; a threat model describes the project as it *is*, not its bugs.
- Supply-chain / SDLC / build hygiene (action pinning, signing, dep freshness).
- You already have a finished model and want to classify one inbound finding →
  use **threat-model-triage**.

## Specialist roster and delegation map

| Phase | Specialist instructions | Produces (artifact handed back) |
| --- | --- | --- |
| 3.1 Orient | [threat-model-recon](../threat-model-recon/SKILL.md) | Project classification, component-family carve, in/out scope |
| 3.2 Mine existing policy | [threat-model-recon](../threat-model-recon/SKILL.md) | Mined maintainer positions and prior-policy back-map |
| 3.3 Deep surface pass | [threat-model-surface](../threat-model-surface/SKILL.md) | §1.7 trust table/matrix, §1.5 side effects, §1.4 reachability, §1.8 taint |
| 3.4 Question waves | [threat-model-interview](../threat-model-interview/SKILL.md) | Answered/queued waves and provenance promotions |
| 3.5 Draft | [threat-model-authoring](../threat-model-authoring/SKILL.md) | `docs/threat-model.md` with tagged prose and embedded tables |
| 3.6 Backtest | [threat-model-backtest](../threat-model-backtest/SKILL.md) | Routing/coverage report, revisions, qualified §1.15 feed |
| 3.7 Iterate/sign off | **threat-model orchestrator** | Accepted model or unratified draft under the termination policy |
| Publication: §1.19 | [threat-model-sidecar](../threat-model-sidecar/SKILL.md) | Validated `threat-model.yaml` derived index |
| Downstream | [threat-model-triage](../threat-model-triage/SKILL.md) | One §1.17 disposition for an inbound finding |

Specialists can also be invoked standalone. When orchestrating, invoke each in
turn, pass it the prior artifacts, and fold its output into the running draft.

## Workflow

Seven canonical phases. Budgets are stated so you notice when a phase
over/under-runs — that usually signals a scoping problem. Phases 3.4–3.7 form a
revision loop; sidecar generation and final validation are publication gates.

1. **3.1 Orient** *(minutes, cheap reading)* — delegate to
  **threat-model-recon**. Read README/top-level docs, carve component families,
  mark shipped-but-unsupported code, and classify the project type (in-process
  library / CLI / daemon / service / distributed system).
2. **3.2 Mine existing policy** — continue with **threat-model-recon**. Mine
  maintainer-authored docs, FAQ/header rationale, and "wontfix"/"by design"
  rulings. Absorb existing `SECURITY.md` threat-model content as a strict
  superset and build the prior-policy back-map.
3. **3.3 Deep surface pass** *(hours — the deliberate code-reading investment)*
   — delegate to **threat-model-surface**, scoped to the in-model families from
   phase 1. Read entry points for *contract, not bugs* to build the
  per-input-operand trust table, the contract-dimension matrix, and the no-surprise
   side-effects inventory. The matrix forces an explicit claimed / disclaimed /
   N/A / unresolved decision for numeric limits, failure atomicity, recursive or
   cyclic topology, callback execution, serialization, reference lifecycle,
   concurrency, and resource complexity. Timebox per family; mark any untabled
   remainder *(inferred)*, but do not silently generalize high-risk dimensions.
4. **3.4 Question waves** *(iterative)* — delegate to **threat-model-interview**.
   Ask in waves of 3–7, framed as proposed answers. **Wave 1 is always scope +
  intended use**, plus configuration support (especially any insecure default)
  and side-effects questions. Prefer
   **draft-first** mode when maintainer time is scarce: write v1 from public
   artifacts, tag every claim, and collect open questions in §1.18.
5. **3.5 Draft** — delegate to **threat-model-authoring**. Write to the section
   structure in [output-structure.md](./references/output-structure.md). Every
  non-trivial claim carries a *(documented, source)* / *(maintainer, YYYY-MM)* /
  *(assumption, QN)* / *(inferred, QN)* tag; every inferred/assumption Q-ID
  resolves in §1.18. Prefer *(documented)* by mining the docs, and record
  demonstrably-absent guarantees as *(documented)* §1.12 disclaimers rather than
  `unresolved` questions. Declare the **triage policy** in the §1.1 header.
  **Write it plainly** — short one-idea sentences, plain words, active voice,
  and short bullets or table rows instead of piled-up noun stacks; target the
  reading level of good developer docs, not a research paper (see principles.md).
6. **3.6 Backtest** — delegate to **threat-model-backtest**. Assemble a stratified
   historical corpus covering every component family and applicable contract
   dimension; cluster large scanner/fuzzer corpora by sink and attack class,
   then sample every cluster. Route each item *blind* to exactly one §1.17
   disposition. `MODEL-GAP` → formulate a proposed §1.11 guarantee, §1.12
   disclaimer, or explicit §1.18 decision question; ambiguous routing → sharpen
   sections; contradiction with the historical call → §1.18 question. Record
  corpus and cluster coverage in the §1.1 header. Only recurring closing
  non-findings (`OUT-OF-MODEL:*`, `BY-DESIGN:*`, established
  `KNOWN-NON-FINDING`) feed §1.15.
7. **3.7 Iterate, sign off, or terminate** — own this phase. Apply revisions,
  rerun affected backtest clusters, and seek maintainer sign-off. If the
  maintainer goes silent under the declared waiting policy, publish as an
  **unratified draft** with confidence/open questions intact. Never let an
  *(inferred)* claim license a closing disposition; an *(assumption)* may close
  only under the declared `relaxed` policy, only a low-blast-radius route, and
  never a security-critical property.

**Publication gate A — Sidecar.** Delegate to **threat-model-sidecar** to emit
`threat-model.yaml` per [sidecar-schema.md](./references/sidecar-schema.md).
The prose stays canonical; the sidecar is a derived index.

**Publication gate B — Finalize.** Run every gate in
[self-check.md](./references/self-check.md). If any check fails, loop back to
the owning phase; publish only when both prose and sidecar pass.

## Provenance is the backbone

Four tags, used everywhere: *(documented, source)*, *(maintainer, YYYY-MM)*,
*(assumption, QN)*, and *(inferred, QN)* where `QN` resolves in §1.18. No
hedge-tag variants. A draft with **no** *(inferred)* / *(assumption)* tags is
either fully reviewed or overclaiming; a draft that is **mostly** unratified is
not ready to publish. Under the default `strict` triage policy an *(assumption)*
escalates like *(inferred)*; under `relaxed` it may license low-blast-radius
provisional closes but never crosses the security-critical floor. See
[output-structure.md](./references/output-structure.md) for the full legend and
the closed disposition set.

## References

- [principles.md](./references/principles.md) — is/is-not, four questions, leave-out list.
- [output-structure.md](./references/output-structure.md) — the §1.1–§1.19 document spec.
- [question-bank.md](./references/question-bank.md) — reference questions, by wave.
- [sidecar-schema.md](./references/sidecar-schema.md) — the `threat-model.yaml` schema.
- [self-check.md](./references/self-check.md) — the four finalize gates.
- [glossary.md](./references/glossary.md) — plain-language definitions of the jargon for non-expert readers.
- [worked-example.md](./references/worked-example.md) — a zlib flavor sketch.
