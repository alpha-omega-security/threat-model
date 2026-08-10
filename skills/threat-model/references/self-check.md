# Self-check before finalizing

Four gates. Every item in every gate must pass; if any check fails, iterate
before publishing. The orchestrator runs this gate after the authoring +
sidecar + backtest specialists have reported.

## Gate 1 — Provenance and authority

- [ ] Every non-trivial claim carries a *(documented, source)* /
      *(maintainer, YYYY-MM)* / *(assumption, QN)* / *(inferred, QN)* tag; the
      header explains the legend; every source/Q-ID resolves; **no hedge-tag
      variants** ("implicit", "documented in purpose", "generally known").
- [ ] The header reports a draft-confidence count and the correct status,
      including `unratified draft` where the §3.7 termination policy applied, and
      declares the **triage policy** (`strict` default / `relaxed`).
- [ ] The header records **generation metadata** — producing model/agent +
      version, effort level, and the plugins/skills actually used — or marks the
      model human-authored; the sidecar's `generation` block matches.
- [ ] Every **inferred** and **assumption** tag has a matching item in §1.18,
      and every item states a proposed answer. (Edge-case probes of
      **documented** claims and meta/ownership questions without an
      inferred/assumption backing are permitted.)
- [ ] §1.18 is a **list**, not a table, and every `QN` referenced in the body
      resolves to a question here. A tabled §1.18 parses to zero Q-IDs and
      dangles every body reference at once. Prefer the explicit
      `- **Q1** — …` form.
- [ ] No prose names a tag kind in tag syntax. Kinds mentioned as vocabulary are
      **bold**; every parenthesized tag carries a source, date, or `QN`.
- [ ] A section marked `Not applicable` says so on its first line and nowhere
      else; substantive sections state what is absent in plain words.
- [ ] Demonstrably-absent guarantees are recorded as **documented** §1.12
      disclaimers, not `unresolved` rows; `unresolved` is reserved for
      dimensions where a guarantee plausibly exists but was not confirmed.
- [ ] Every **documented** tag cites a **locator**, not a bare filename — file
      plus function/macro, a named doc section, or a short quoted phrase.
- [ ] Absence claims are bounded: an absent *guarantee* is a §1.12 disclaimer,
      but an absent *behaviour* found by scanning is a §1.5 **assumption** (or
      **inferred** where the scan could not be exhaustive, naming the hole). No
      disclaimer generalizes past the component, family, or dimension its cited
      source actually names.
- [ ] No unratified §1.11 property — **inferred** or **assumption** — carries a
      `security-critical` tier; any such candidate is an `unresolved` matrix row
      plus a §1.18 choice question.
- [ ] No closing disposition is licensed by an **inferred** claim, regardless
      of model status. An **assumption** licenses a close only under `relaxed`
      policy, only for a low-blast-radius route, and never a security-critical
      `property-disclaimed`, `KNOWN-NON-FINDING`, or `dependency-contract`. An
      accepted model has zero inferred and zero assumption claims; any remaining
      one requires `under maintainer review` or `unratified draft` status.
- [ ] Any pre-existing `SECURITY.md` (or equivalent) threat-model content is
      fully absorbed: the new model is a strict superset, the back-map appendix
      exists, and the coexistence question was asked.

## Gate 2 — Coverage

- [ ] Every section is substantive or marked N/A with a reason.
- [ ] Distinct component families (core vs OS-touching convenience layer vs
      shipped-but-unsupported) are each modeled at their own trust level or
      explicitly placed out of scope; if the split rule applied, sibling models
      are cross-linked.
- [ ] Build/config variants that change the envelope are enumerated (§1.6) or
      the section states there are none; for each insecure-default knob, the
      maintainer's ruling (supported vs dev-only) is recorded.
- [ ] §1.7 contains a per-input-operand trust *table*, not just prose; a partial
      table (per the §3.3 timebox) has its uncovered portion explicitly marked.
- [ ] Every parameter records its control kind; executable callbacks, concrete
      types/classes, object topology, collaborator implementations, sizes, and
      serialized state are not collapsed into a single attacker-control boolean.
- [ ] Every in-scope component family has a complete contract-dimension matrix.
      Every applicable row is claimed, disclaimed, N/A with reason, or
      unresolved; no cell is blank.
- [ ] Stateful families state postconditions for validation, allocation,
      callback, and collaborator failures, or explicitly disclaim atomicity.
- [ ] §1.8 states the taint of every output channel — including the "output is
      as untrusted as input" one-liner where it applies — and structural output
      invariants are promoted to §1.11.
- [ ] §1.9 states per-dependency trust assumptions and the vendored-code policy,
      or makes the explicit zero-dependency claim.
- [ ] §1.12 (NOT provided) and §1.13 (downstream responsibilities) are at least
      as substantive as §1.11 (provided). If not, the model is under-specified.
- [ ] §1.12 names at least the obvious false-friend properties and the
      well-known attack classes for this category of project.

## Gate 3 — Triage readiness

- [ ] The §1.1 header contains the triager quick-start, and its steps reference
      sections that actually exist in this document.
- [ ] Every §1.11 property carries a violation symptom and a severity tier;
      resource properties state a threshold.
- [ ] §1.15 (known non-findings) is populated or marked N/A with a reason.
- [ ] Every §1.15 entry obeys the four §1.15 rules: discharged by a stable claim
      ID in this document (never by a process or reporting-etiquette statement);
      matched on the behaviour of the code and **never** on the reporter's
      evidence (no reproducer, no demonstrated reachability); naming a symptom
      or attack class alongside its component, with no entry scoped to "any
      in-scope family"; and discharged by a claim whose own component set covers
      the entry. An entry that reduces to "out of scope", "unsupported build",
      or "dependency root cause" carries that `OUT-OF-MODEL` label instead.
- [ ] Every §1.12 disclaimer states its conditions/boundary and a tier; no tier
      cell is blank. Triage fails closed on a blank, so an untiered disclaimer
      escalates every report it should have answered.
- [ ] The §1.1 quick-start ends with the provenance gate, and the model uses the
      `closed` / `provisional` / `escalated` status vocabulary. An escalated
      finding keeps its disposition and is not recorded as a `MODEL-GAP`.
- [ ] §1.17 enumerates the closed disposition set, each citing its licensing
      section, including `dependency-contract`; the all-status closure
      constraint (inferred escalates; assumption governed by the triage policy;
      security-critical floor) is present.
- [ ] §1.17 states deterministic precedence, including exact §1.15 matches, so
      multiple failed preconditions still route to one disposition.
- [ ] The phase-3.6 backtest was performed: the historical corpus routed with
      each item landing on exactly one disposition, and the results (corpus size,
      revisions triggered) are recorded in the header.
- [ ] The §1.1 backtest placeholder `_pending phase 3.6_` is gone, replaced by
      real figures — corpus and cluster counts, the real-versus-synthesized
      split, the disposition histogram, and the fail-safe figure (how many
      historically-fixed items route to a closing disposition — target zero). A corpus with
      no real historical items says so in phase 3.6's verbatim wording rather
      than presenting synthesized cases as history.
- [ ] **No corpus item that the project actually fixed routes to a closing
      disposition.** This is the one blocking backtest outcome: an
      over-escalating model wastes maintainer time, an over-closing one answers
      a live vulnerability with "not a bug".
- [ ] Any §1.12 disclaimer or §1.3 scope line added *in response to* a backtest
      routing is still true of the project as it is, cites a real source, and
      stays inside the scope that source covers. Widening a disclaimer to clear
      a `MODEL-GAP` is the cheapest way to pass this gate and the surest way to
      make the model worse.
- [ ] §1.11 carries 2–4 de-identified worked routing examples, **at least one
      routing `VALID`**, and they carry no CVE IDs, reporter names, or dates.
- [ ] Backtest coverage is stratified across every in-scope component family and
      applicable contract dimension; large corpora were clustered by sink and
      attack class, with every cluster represented.
- [ ] Every `MODEL-GAP` produced a proposed §1.11 guarantee, §1.12 disclaimer, or
      unresolved matrix row plus §1.18 question, and the affected cluster was
      rerouted after revision.
- [ ] An accepted model has no unexplained applicable matrix row and no unowned
      `MODEL-GAP`. An unratified draft identifies each remaining gap explicitly.
- [ ] A triager handed an arbitrary new finding — tool, human, or AI — can route
      it to exactly one §1.17 disposition, citing a section, without consulting
      the maintainer.
- [ ] An orchestrated run emits a sidecar that conforms to schema v2, identifies
      the exact prose content it derives from, and was regenerated after the
      last prose change. Prose-only output is permitted only for standalone
      authoring.
- [ ] A sidecar used for automated closure carries provenance for every
      closure-driving parameter, output invariant, component, adversary,
      host-side-effect claim, dependency, build condition, property, and known
      non-finding, plus the canonical first-match disposition order.
- [ ] An orchestrated run also emits `threat-model.json` conforming to
      `schema.json`, regenerated alongside the sidecar after the last prose
      change. Authority order: prose > yaml > json; the JSON is an export, not
      a triage input.
- [ ] The JSON validates against `schema.json`, its `dispositions` array is
      exactly the nine schema values verbatim, and its `commit` is the real sha
      of the modeled tree, not a placeholder.
- [ ] No JSON record upgrades provenance: nothing whose sidecar provenance is
      **inferred** or **assumption** surfaces as `documented`, and `confidence`
      is the collapsed sidecar count (documented + maintainer,
      inferred + assumption).
- [ ] Every JSON known non-finding names its in-scope components and discharged
      symptom in `why_safe`, and its `cites` resolves to a real entry in the
      same document. The JSON drops the sidecar's scoping fields; either
      `why_safe` carries them or the entry can suppress everything.

## Gate 4 — Style and scope

- [ ] No bullet would be more at home in a code review or audit report.
- [ ] No bullet restates what the README/API docs already say.
- [ ] A reader who has never seen the project can answer: "what threats has the
      library taken responsibility for, and which have been left to me?"
- [ ] The document fits comfortably in one sitting (typically 3–8 pages).
      Sprawl is a smell.
- [ ] **Reads at the level of good developer docs, not a research paper.** Spot-
      check the densest paragraphs: sentences carry one idea each (no three-`and`
      chains or semicolon-joined clauses), words are plain ("uses", not
      "utilizes"), voice is active with a real subject, and piled-up noun stacks
      or long inline lists have been broken into short bullets or table rows.
- [ ] No sentence relies on a §-cross-reference to be understood — the citation
      supports the point, it does not replace the sentence.
