---
name: threat-model-recon
description: >-
  Orient and mine an open-source repository for threat-model production phases
  3.1–3.2. USE WHEN starting a threat model or surveying security posture before
  modeling. Reads README, top-level docs, SECURITY/THREAT docs, maintainer issue
  rulings, and changelog rationale; carves component families; flags
  shipped-but-unsupported code; classifies project type; and absorbs an existing
  embedded threat model as a strict superset with a prior-policy back-map.
  Produces an orientation brief. Read-only. DO NOT USE FOR: deep code-surface
  analysis (use threat-model-surface), drafting, bug hunting, code fixes, or
  triage.
argument-hint: '<path or name of the repo/package to orient on>'
---

# Threat Model — Recon (orient + mine)

Phases 3.1–3.2. The **cheap reading** that lets every later phase ask informed
questions. Minutes, not hours — the detailed code reading is
`threat-model-surface`'s job. This is **read-only**: form hypotheses, do not
produce findings, do not edit code.

Read [principles.md](../threat-model/references/principles.md) first.

## Step 1 — Orient (3.1)

**Scope to the published, committed state.** Orient on a released tag or merged
commit — the code, docs, and rulings a downstream reader can actually see. Do
not pull in uncommitted local edits, unmerged branches, draft PRs, or stashes;
they are invisible to anyone the shipped model is written for. Note the exact
ref you modeled for the §1.1 version binding.

Do a light pass and record hypotheses:

- Read `README`, top-level docs, and any existing `SECURITY*`, `THREAT*`, or
  `docs/` content. If a document *titled* "threat model" is structurally an
  audit/risk-register/findings-list (likelihood×impact scoring, "recommended
  mitigations", owner/due-date columns), do **not** silently supersede it. Mine
  only statements explicitly presented as maintainer policy or contract;
  findings and recommendations are not contract evidence. Raise a coexistence
  question for §1.18.
- **Mine for maintainer positions already on the record** — the highest-yield
  sources are where maintainers explained a decision or declined to do
  something: FAQ files, header-file commentary, `NOTES`/`CAVEATS`/`LIMITATIONS`
  docs, issue closures labeled "wontfix"/"by design"/"not a bug", changelog
  entries explaining *why*. These often answer threat-model questions before
  they are asked. Tag what you find *(documented, exact source)*.
- **Check for a vendored `security-context.md`** in the working directory. A
  runner may pre-fetch the repository's off-repo public record into this file
  (via `fetch_security_context.py`): published advisories, OSV.dev records,
  security-related issues (labeled or mentioning security), issues maintainers
  closed as not-planned/wontfix/invalid, security/audit links discovered on
  the project homepage, and optionally the vendored text of named external
  documents (e.g. a commissioned audit report). Treat its entries as
  point-in-time copies of maintainer-authored or maintainer-acknowledged
  public record — mine rulings and advisory text exactly like on-repo sources,
  citing *(documented, \<url\>)* with the original issue or advisory URL;
  follow homepage references and read them (a maintainer-linked audit is on
  the record); and hand the vulnerability history to phase 3.6 as backtest
  corpus seed material. It is mining input, not project source: per the
  leave-out list, never copy its CVE list or individual findings into the
  model, and never cite the file itself as the source.
- Mine for **contract edge decisions**, not bug lists: release-note or issue
  rationale about overflow boundaries, partial mutation after exceptions,
  cyclic inputs, callback trust, deserialization reconstruction, weak-reference
  lifecycle, recursion depth, and complexity expectations. Record the
  maintainer's general rule and route it to the contract-dimension matrix; do
  not copy individual findings into the model.
- Identify the primary public API surface (entry points, exported symbols, CLI
  commands, network protocols, file formats consumed/produced).
- **Carve component families** that may have different threat profiles — a pure-
  computation core, a convenience layer that touches the OS (files, sockets,
  env), ancillary utilities. Model each at its own trust level, not averaged.
- **Identify shipped-but-unsupported code** (`contrib/`, `examples/`, `vendor/`,
  `third_party/`, `test/`, demos, generated bindings). Decide in/out explicitly.
- Identify languages, runtimes, and obvious trust boundaries (process, FFI,
  network, filesystem).
- Note what the project clearly *is not* ("a parser, not a network service") —
  it shapes the model.
- Apply the **split rule** (see principles): if a family does not share the
  release cadence, maintainer set, or adversary model of the rest, flag it for a
  sibling model rather than one averaged document.

## Step 2 — Mine the existing SECURITY.md / embedded model (3.2)

Many projects ship a `SECURITY.md` that is part disclosure process (out of
scope) and part **embedded threat model** — the single highest-authority
*(documented)* source, since it is maintainer policy that already survived
public review. When such content exists:

- **Do not re-derive it.** Lift every trust statement, vuln/non-vuln example,
  and resource threshold directly into the matching section with a citation, tagged
  *(documented)*. Tagging something *(inferred)* that `SECURITY.md` already
  states means the orient pass was skipped.
- **The output must be a strict superset.** Nothing the existing document
  asserts about scope may be silently dropped, weakened, or contradicted. A
  claim you believe is wrong or stale becomes a §1.18 question, not a unilateral
  edit.
- **Build a back-map** — an appendix table "`SECURITY.md` statement →
  threat-model §", one row per claim, proving coverage.
- **Raise the coexistence question in wave 1** — does the new document (a)
  replace that section, (b) become the canonical model `SECURITY.md` links to,
  or (c) sit alongside? Resolve before publishing.

The same treatment applies to any artifact stating maintainer security policy in
the project's own voice: `docs/security-model.md`, a "Security Considerations"
section of an implemented RFC, a bug-bounty scope page, or a wiki page the issue
tracker cites when closing reports.

## Output — orientation brief

Hand back to the orchestrator:

1. **Project-type classification** — in-process library / CLI / daemon / network
   service / distributed system (drives whether roles split and whether §1.4
   needs a diagram and §1.10 a Byzantine actor).
2. **Component-family table** (draft of §1.2) — family, representative entry
   point, touches-outside-process?, in/out of model.
3. **Out-of-scope inventory** (draft of §1.3) — shipped-but-unsupported code +
   reason.
4. **Mined maintainer positions** — each tagged *(documented, exact source)*,
   routed to its target section.
5. **`SECURITY.md` back-map** + the coexistence question for wave 1.
6. **Split recommendation** — one model or several, with reason.

Everything not lifted from a document is a hypothesis for the surface pass and
interview to confirm — leave it *(inferred, QN)* with the matching question ID,
or *(assumption, QN)* where a conservative default is clearly safe.

**Mine before you infer.** Every fact you can attribute to a maintainer-authored
source (README, Javadoc/`package-info`, header comments, manpage, FAQ, changelog
rationale, issue rulings) is *(documented)* and does not escalate. The recon
pass is the cheapest place to convert would-be inferences into documented
claims; a draft that is mostly *(inferred)* usually means this mining was thin,
not that the project is genuinely undocumented. Where the docs verifiably make
**no** guarantee (no thread-safety statement, no resource bound), that absence is
itself *(documented)* — carry it forward as a §1.12 disclaimer, not an open
question.
