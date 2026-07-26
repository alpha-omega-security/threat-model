# Principles — what a threat model is, and is not

Shared context for every threat-model specialist. Read this before drafting or
triaging.

## What it IS

A description of the **implicit contract** between the project and its downstream
users: the assumptions it makes about its environment, inputs, and callers; the
security properties it tries to uphold; the properties it explicitly does *not*
uphold; and the misuses that, while syntactically possible, fall outside intended
use.

It serves **two consumers**, and every section must be usable by both without
re-deriving the reasoning:

- the **downstream integrator** — "which threats do I now own, and which does
  the project own?"
- the **triager** (maintainer / security team / automated pipeline) — "is the
  violated property one the project claims, is the attacker in scope, is the
  affected code in scope?" — citing the section that justifies the call.

## What it IS NOT

- A vulnerability assessment, audit, or pentest. Do not hunt for bugs. Do not
  enumerate CVE-style findings.
- A supply-chain or build-hygiene checklist (action pinning, signing,
  reproducible builds, dependency freshness, whether a `SECURITY.md` exists).
- A restatement of what the source or public API docs already say. The model
  captures the **unwritten** assumptions.
- A coding-standards or secure-coding guide.
- A list of every theoretical attack. Focus on threats the design has an opinion
  about — by addressing them or by declining to.

> If you write "the project should…" or "we recommend…", stop — that is audit
> output. The model describes the project as it **is**, not as it should be.

> **Conservative defaults, not silent gaps.** Where the docs are silent, prefer
> a *documented disclaimer* of the safe (no-guarantee) direction over an open
> question: "no thread-safety is guaranteed" is a verifiable statement about the
> project as it is. Where you must reason past what is verifiable, record a
> *(assumption, QN)* (a conservative default you are willing to act on) rather
> than an *(inferred, QN)* open question — but never let either silence a
> security-critical property. An assumption can, at most and only under the
> `relaxed` triage policy, close a *low-blast-radius* report provisionally; it
> can never carry the project's authority to dismiss a memory-safety or
> RCE-class report. See the provenance and §1.17 rules in output-structure.md.

## Write so a human can read it

The model is read by a tired on-call engineer and an integrator under deadline,
not a thesis committee. **Accuracy comes first, but plain, direct prose is a
requirement, not a nicety.** You earn nothing by sounding academic; a claim you
cannot state plainly is usually one you have not finished thinking through.

Aim for the reading level of good developer documentation — a general
professional audience, roughly grade 9–11 — not a research paper. Concretely:

- **One idea per sentence.** If a sentence chains three "and"s or joins two full
  clauses with a semicolon, split it. Long, comma-spliced sentences are the
  single biggest readability problem in these models.
- **Short, common words.** "uses" not "utilizes", "before" not "prior to",
  "runs" not "is executed", "about" not "with respect to".
- **Verbs, not nominalizations.** "the caller validates input", not
  "caller-side input validation is performed".
- **Active voice with a real subject** — say who does what. "The library copies
  the buffer", not "the buffer is copied".
- **Unpack noun stacks and piled-up inline lists.** A sentence naming a dozen
  collaborators in a row belongs in a short bulleted list or a table, not in
  prose.
- **Define a term once, in plain words, the first time it appears**, then reuse
  it. Do not make the reader decode jargon mid-sentence.
- **Keep the tags and §-cross-references, but don't let a citation stand in for
  a sentence.** The reader should get the point without following the link.

This is not a licence to be vague: keep every operand, capability, and provenance
tag. Say the same precise thing in fewer, plainer words.

## The four-question framework

Every section answers one of:

1. **What does the project assume?** (Environment, callers, inputs,
   dependencies, threat actors in/out of scope.)
2. **What does it guarantee** *given those assumptions*? (Memory safety on valid
   input, deterministic output, bounded resource use, structural output
   invariants.)
3. **What does it explicitly leave to the downstream user?** (Input validation
   at the boundary, output sanitization, transport security, key management,
   rate limiting.)
4. **What known misuses/anti-patterns** look reasonable but violate (1)?

Use the contract-dimension matrix to make these answers complete, not to turn
the model into an audit. The matrix asks whether the project claims, disclaims,
or has not decided edge semantics such as overflow, callback failure, cycles,
serialization, lifecycle, and resource bounds; it does not test the
implementation for defects.

## One model or several?

A repo with multiple component families is usually one model — that is what the
§1.2 component-family table is for. **Split** into separate documents when
families do not share a release cadence, a maintainer set, or an adversary model
(e.g., a core library plus an independently versioned GUI tool or hosted
service). A model that must constantly say "except for component X" is a sign to
split. When splitting, each document names its siblings in its header.

## What to leave out (recurring temptations)

- **CVE history.** Past bugs are not the model. (A *pattern* across past bugs may
  be — "historically, integer overflow on 32-bit systems, so the assumption that
  `size_t` does not wrap is load-bearing." That is a model claim, not a CVE
  list. Using past findings as backtest vectors per phase 3.6 is different from
  listing them — the corpus stays on the producer's side.)
- **Code-level findings.** "Function X ignores the return of Y" is a code review
  finding.
- **Build / release / SDLC hygiene.** (Dependency *trust* assumptions per §1.9
  are model content; dependency *update* hygiene is not.)
- **Things the README already says.**
- **Generic platitudes** ("use defense in depth", "keep dependencies up to
  date"). Cut on sight.
- **Speculation about future features.** Model what exists.
