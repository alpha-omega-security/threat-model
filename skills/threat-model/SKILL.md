---
name: threat-model
description: Produce a threat model for an open-source project - the implicit security contract between the project and its downstream users, structured for both integrators (which threats are theirs vs the project's) and vulnerability triagers (is a report valid, out-of-model, or by-design). Use when asked to write, draft, review, or update a threat model, security model, or trust-boundary document for a library, service, or component; when triaging whether a reported vulnerability is in scope; or when a project needs to define what counts as a security bug.
license: MIT
metadata:
  version: "1.0.0"
  homepage: https://github.com/alpha-omega-security/threat-model
---

# Threat Model

This skill is an instruction set for producing a threat model for an
open-source project, followable by a human reviewer, a coding assistant,
or an automated pipeline. The deliverable is a separate document
(typically `docs/threat-model.md`); this file is the recipe, not the
output. Adapt the questions and sections to the project; do not omit them
silently.

Section numbers (§1-§8) are shared across this file and the reference
files so cross-references resolve. Read
[references/output-structure.md](references/output-structure.md) before
drafting; it defines every §4.x section the procedure below refers to.

---

## 1. What this threat model is — and is not

**It IS** a description of the *implicit contract* between the project and its
downstream users: the assumptions the project makes about its environment,
inputs, and callers; the security properties it tries to uphold; the
properties it explicitly does *not* uphold; and the misuses that, while
syntactically possible, fall outside the intended use of the project.

The document serves **two consumers**:

- The **downstream integrator**, who needs to know which threats the project
  has taken on and which are left to them.
- The **triager** — maintainer, security team, or automated pipeline — who
  must classify an inbound vulnerability report, static-analysis finding, or
  AI-generated analysis as *valid*, *out of model*, or *disclaimed by
  design*, and cite the section that justifies the call.

Write every section so that both consumers can use it without re-deriving
the reasoning.

**It IS NOT**:

- A vulnerability assessment, audit, or pentest report. Do not hunt for bugs.
  Do not enumerate CVE-style findings.
- A supply-chain or build-hygiene checklist. Whether GitHub Actions are
  pinned, whether releases are signed, whether dependencies are up to date,
  whether there is a `SECURITY.md` — none of that belongs here. (§4.6b
  covers the threat-model half of the dependency question, namely which
  dependency surfaces are reachable from attacker input; patch status and
  pinning remain hygiene and stay out.)
- A restatement of what the source code already says. If a reader can see the
  fact by skimming the code or the public API docs, it does not belong here;
  the threat model captures *unwritten* assumptions.
- A coding-standards or secure-coding guide.
- A list of every theoretical attack. Focus on the threats the project's
  design actually has an opinion about (whether by addressing them or by
  declining to address them).

If you find yourself writing "the project should..." or "we recommend...", stop —
that is audit output, not threat model output. The threat model describes the
project as it *is*, not as it should be.


---

## 2. The core question framework

Every section of the resulting threat model should answer one of four
questions:

1. **What does the project assume?** (Environment, callers, inputs, threat
   actors in and out of scope.)
2. **What does the project guarantee** *given those assumptions*? (Memory
   safety on valid input, deterministic output, bounded resource use, etc.)
3. **What does the project explicitly leave to the downstream user?** (Input
   validation at the trust boundary, transport security, key management, rate
   limiting, etc.)
4. **What known misuses or anti-patterns exist** that look reasonable but
   violate the assumptions in (1)?


---

## 3. Procedure

### Step 3.1 — Orient

Before asking any questions, do a *light* pass over the project to form
hypotheses:

- Read `README`, top-level docs, and any existing `SECURITY*`, `THREAT*`, or
  `docs/` content. If an existing document is *titled* "threat model" but
  is structurally an audit, risk register, or findings list (symptoms:
  likelihood×impact scoring, "recommended mitigations", owner/due-date
  columns), do not silently supersede it — mine it as a *(documented)*
  source for §4.8/§4.9/§4.11 and add a §4.14 meta question proposing how
  the two documents should coexist (replace / merge / sit alongside).
- **Mine for maintainer positions already on the record.** The
  highest-yield sources are places where maintainers have already explained
  a design decision or declined to do something: `FAQ` files, header-file
  commentary, `NOTES`/`CAVEATS`/`LIMITATIONS` docs, issue-tracker
  closures labeled "wontfix" / "by design" / "not a bug", and changelog
  entries that explain *why* a behavior is the way it is. These often
  answer threat-model questions before they need to be asked.
- **Mine `SECURITY.md` and any other maintainer-voiced policy artifact**
  (RFC security-considerations sections, bounty scope pages, wiki pages
  the tracker cites when closing reports) for embedded threat-model
  content. Every trust statement, vuln/non-vuln example, and threshold
  there is *(documented)*, not *(inferred)*; lift it into the matching
  §4.x with a citation, keep a short back-map appendix ("`SECURITY.md`
  claim → §") so nothing is silently dropped, and raise in wave 1
  whether the new document replaces, is linked from, or sits alongside
  the existing one.
- Identify the primary public API surface (entry points, exported symbols,
  CLI commands, network protocols, file formats consumed/produced,
  **persisted state read back on startup**).
- **Carve the project into component families** that may have different
  threat profiles. A single library often exposes a pure-computation core,
  a convenience layer that touches the OS (files, sockets, env vars),
  a **plugin or extension loader**, and one or more ancillary utilities.
  Model each at its own trust level rather than averaging them.
- **Identify code that ships but is not supported.** `contrib/`,
  `examples/`, `vendor/`, `third_party/`, `test/`, demo apps, generated bindings.
  Decide explicitly whether each is in or out of threat model.
- Identify the language(s), runtime(s), and obvious trust boundaries (process
  boundary, FFI boundary, network boundary, file-system boundary).
- Note what the project clearly *is not* (e.g., "this is a parser, not a
  network service" — that shapes the threat model).

Keep this pass proportional to the project's size. For a human, that is
usually minutes to an hour; an automated pipeline can afford a deeper read.
Either way the goal is to ask *informed questions* in the next step, not to
produce findings.

### Step 3.2 — Ask clarifying questions, in waves

Iteration is mandatory. There are two viable modes; choose based on
maintainer availability:

- **Interview-first.** Ask questions, then draft. Best when a maintainer is
  actively engaged and answers come back quickly.
- **Draft-first.** Write a v1 entirely from public artifacts (per §3.1),
  tag every claim with its provenance (see §3.3), and collect the
  unresolved questions in a dedicated "Open questions" section at the end
  of the draft. Hand the maintainer a document to *react to* rather than a
  questionnaire to fill in. Best when maintainer time is scarce or
  asynchronous. This is usually the more efficient mode.

Either way, do **not** dump every question at once; the maintainer will not
answer 30 questions in one go and the answers will be shallow if they do.
Ask in **waves of 3–7 questions**, prioritized by which answers most shape
the rest of the model.

The first wave should always cover **scope and intended use**, because
everything else depends on it. Subsequent waves drill into trust boundaries,
adversary model, and known misuses.

A reference question bank is in §6. Pull from it; do not read it verbatim.
Reword for the specific project.

**Frame each question as a proposed answer.** Maintainers respond faster
to "we believe X — confirm or correct" than to an open-ended "what is X?",
so wherever the orient pass yielded a plausible answer, state it as the
hypothesis. Reserve genuinely open questions for cases where no reasonable
default exists.

After each wave:

- Record the answers (in the threat model draft, not just in chat).
- State which next-wave questions the answers unlock or render moot.
- Stop asking once the marginal value of another question is low — a good
  threat model is *finite*. Better a tight 3-page document than a sprawling
  20-page one.

### Step 3.3 — Draft

Write the threat model in the structure given in §4. Each section must
either contain substantive content or be explicitly marked
`Not applicable — <reason>`. Empty headings with no commentary are a smell.

**Provenance tagging.** Every non-trivial claim in the draft must carry one
of these inline tags so readers (and the next iteration) know how much
weight it carries:

| Tag | Meaning |
| --- | --- |
| *(documented)* | Stated in the project's own docs (README, header comments, FAQ, manpage). Cite the source. |
| *(maintainer)* | Stated by a maintainer in response to a question from this process. |
| *(inferred)*   | Reasoned from code structure, absence of a feature, or general domain knowledge — not yet confirmed. Must have a matching entry in the open-questions section. |

Use exactly these three tags. **Do not invent hedge-tags** such as
"*(implicit)*", "*(documented in purpose)*", or "*(generally known)*" —
they leak uncertainty without making it actionable. If a claim is not
clearly *(documented)* or *(maintainer)*, it is *(inferred)* and gets an
open question.

A draft with no *(inferred)* tags has either been fully reviewed or is
overclaiming; a draft that is mostly *(inferred)* is not ready to publish.
As maintainer answers come in, promote *(inferred)* → *(maintainer)* and
retire the corresponding open question.

**Retain provenance in the published version.** When the document is used
to close a report the reporter will push back, and *(maintainer, 2025-03)*
is a defensible citation where bare prose is not; convert to footnotes if
house style prefers.

**Style rules for the output:**

- Plain prose and short bulleted lists. Tables are fine when every cell is
  meaningful (e.g., a trust-transition table or an input-trust matrix);
  avoid templated tables with empty cells.
- When a property is *not* guaranteed, say so plainly. "Constant-time
  comparison is not provided" is more useful than silence.
- Do not hedge into uselessness. "May or may not be safe depending on usage"
  tells the reader nothing. If you cannot get a clear answer, name the
  ambiguity as the finding.

### Step 3.4 — Iterate

Present the draft to the maintainer. Solicit corrections and new threats
they think of *while reading*. Update. Repeat until the maintainer signs off
or the marginal change rate falls to near zero.

**When maintainers disagree.** Many projects have more than one maintainer,
and threat-model questions ("is DoS a bug?", "is the config file trusted?")
are exactly the kind on which they hold different views. Do not average the
answers or pick the one you prefer. Record the disagreement *as* the claim:
"Maintainers are split on whether super-linear CPU on adversarial input is
in scope; the project has no settled position *(maintainer, contested)*."
Add a §4.14 entry flagging it as a governance question the project must
resolve before the model can be cited to close reports on that property,
because a papered-over split resurfaces the first time two maintainers
triage the same class of report to opposite outcomes.

Treat the threat model as a living document: note in its header the date,
the version/commit it was written against, and a pointer to §4.12 for
revision triggers.


---

## 4. Structure of the output document

See [references/output-structure.md](references/output-structure.md) for
the full §4.1-§4.15 section definitions (header, scope, trust
boundaries, inputs/outputs, delegated surface, adversary model,
properties provided and disclaimed, downstream responsibilities, misuse
patterns, non-findings, revision triggers, triage dispositions, open
questions, machine-readable sidecar). Read it before drafting; the
procedure in §3 and the self-check in §8 both reference §4.x numbers.

---

## 5. What to leave out (recurring temptations)

- **CVE history.** Past bugs are not the threat model. (A *pattern* across
  past bugs may be — e.g., "historically the project has had bugs around
  integer overflow on 32-bit systems, so the assumption that `size_t` does
  not wrap is load-bearing." That is a model claim, not a CVE list.)
- **Code-level findings.** "Function X does not check the return value of Y"
  is a code review finding. Out of scope.
- **Build / release / SDLC hygiene.** Action pinning, signing, reproducible
  builds, branch protection, 2FA — all important, none belong here.
- **Dependency inventory.** Listing every transitive package is SBOM
  territory. §4.6b lists only the handful reachable from attacker input.
- **Things the README already says.** Do not paraphrase the project tagline
  back at the reader.
- **Generic platitudes.** "Use defense in depth." "Keep dependencies up to
  date." Cut these on sight.
- **Speculation about future features.** Model what exists.


---

## 6. Reference question bank

See [references/question-bank.md](references/question-bank.md). Pull
questions in waves of 3-7 per §3.2; the first wave should come from §6.1
(scope and intended use).

---

## 7. Worked sketches

See [references/worked-sketches.md](references/worked-sketches.md) for
two illustrative partial models: an in-process C library (zlib) and a
network service (identity-aware reverse proxy).

---

## 8. Self-check before finalizing

See [references/self-check.md](references/self-check.md). Run every item
before publishing; if any fails, iterate.
