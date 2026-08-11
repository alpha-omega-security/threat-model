---
name: threat-model-sidecar
description: >-
  Emit and validate the §1.19 machine-readable companions: threat-model.yaml
  using schema threat-model-sidecar/v2, and the flat threat-model.json export
  conforming to schema.json. USE WHEN an orchestrated threat model is ready
  for publication, automated or AI-assisted triage, dependency compatibility
  analysis, or companion regeneration after prose changes. Projects provenance-
  backed components, input obligations, contract dimensions, outputs,
  adversaries, dependencies, configurations, properties, misuses, non-findings,
  and the closed disposition enum. Prose remains canonical; authority order is
  prose > yaml > json. DO NOT USE FOR: writing prose or routing a finding.
argument-hint: '<path to the prose threat-model document>'
---

# Threat Model — Sidecar (machine-readable companions)

Owns §1.19: emit `threat-model.yaml` and `threat-model.json` alongside the
prose document so shared triage tooling can consume the model without parsing
prose. Follow the schema in
[sidecar-schema.md](../threat-model/references/sidecar-schema.md) for the YAML
and the mapping in
[json-report-schema.md](../threat-model/references/json-report-schema.md) for
the JSON exactly — companions are only useful to tooling if they are
**structurally uniform across projects**. Authority order: **prose > yaml >
json**. The JSON is a flat, lossy export for consumers of `schema.json`; it is
never a triage input.

## Principles

- **Prose is canonical; the sidecar is a derived index.** Do not put anything in
  the sidecar that is not already asserted in the prose. If the two disagree, the
  sidecar is wrong.
- **Record provenance of derivation** — set `prose_version` to the canonical
  relative prose path plus SHA-256 of its exact UTF-8 bytes, and regenerate
  whenever the prose changes.
- **Uniform shape only** — use the `schema: threat-model-sidecar/v2` fields as
  given; extend with project-specific keys **only** under an `x-` prefix. The
  JSON schema forbids extensions entirely; what does not fit stays in the YAML.
- **Never upgrade provenance.** The JSON collapses four provenance kinds into
  two: `documented` and `maintainer` become `documented`; `inferred` and
  `assumption` become `inferred`. The collapse only goes down — a record whose
  sidecar provenance is `inferred` or `assumption` must never surface in the
  JSON as `documented`. That direction hands a JSON-only consumer a licence the
  model never granted.

## Procedure

1. Confirm the prose document is at least a complete draft (all sections
   substantive or N/A). If §1.7/§1.8/§1.11/§1.17 are incomplete, stop and hand
   back — the sidecar cannot be faithfully derived from a partial model.
2. Project each prose section into its sidecar block:
   - §1.2/§1.3/§1.4 → `components` (`scope: in|out`, out-reason, and per-
     component reachability precondition).
   - §1.5 → `host_side_effects[]` — explicit present/absent/conditional host
     effects with components, conditions, and provenance.
   - §1.7 → `entry_points[].parameters[]` — every attacker-controllable
     parameter must have a non-empty `caller_must_enforce` and at least one
     value in its `control_kinds` array.
   - §1.7-§1.12 → `contract_dimensions[]` — all eight required dimensions for
     every in-scope component, including explicit `not-applicable` rows;
     claimed/disclaimed rows reference stable property IDs and unresolved rows
     reference §1.18 question IDs.
   - §1.8 → `outputs[]` (`taint: same-as-input | sanitized | constrained`,
     in-scope component, separately provenanced invariants, and downstream
     must-not-assume records).
   - §1.10 → `adversaries[]` (in/out of scope, capabilities, excluded
     capabilities, goals, provenance).
   - §1.9 → `dependency_policy` + `dependencies[]`, including stable
     `relied_on_properties`, acknowledged obligation IDs, adversary capabilities
     actually forwarded, and output channels/taint handling; an **empty list plus
     `zero_runtime_dependencies: true` is the explicit zero-dependency claim**,
     not an omission. **Leave `outputs_consumed: []` unless the project holds an
     `output-sanitization`-kind property about a dependency's output** — each
     entry's `supports_property_id` must reference such a property. If the
     project passes a dependency's output straight through and disclaims
     sanitization (the common case), the list stays empty; the passthrough taint
     is already recorded in §1.8 `outputs[]` and the §1.12 disclaimers. Do **not**
     point `supports_property_id` at a behavioral, atomicity, or probabilistic
     property.
   - §1.6 → `build_policy` + `build_flags[]` (`default`, `security_relevant`,
     support stance, affected property IDs/effects, provenance).
   - §1.11 → `properties_claimed[]` (kind, components, tier, conditions,
     violation symptoms, provenance).
   - §1.12 → `properties_disclaimed[]` (components, conditions,
     `false_friend: true|false`, provenance).
   - §1.13 → `downstream_responsibilities[]` linked to obligation/property IDs.
   - §1.14 → `known_misuses[]`, the structured basis for `VALID-HARDENING`.
   - §1.15 → `known_non_findings[]`, with component/sink, conditions, and
     `discharged_by` stable IDs sufficient for exact (not fuzzy) matching.
   - §1.17 → `dispositions` plus `disposition_precedence` — the fixed closed
     enum and first-match order, verbatim.
3. Normalize the prose status to the schema enum (`draft`, `unratified-draft`,
   `under-review`, `accepted`) using the mapping in `sidecar-schema.md`; set
   `confidence` to match the §1.1 counts exactly. Project the header's **triage
   policy** to the top-level `triage_policy` (`strict` default / `relaxed`).
   Carry `tier` (`security-critical | correctness-only`) on every
   `properties_disclaimed[]` entry so a consumer can enforce the assumption
   security-critical floor. Project the §1.1 **generation metadata** to the
   top-level `generation` block (`model`, `effort`, `plugins[]`); omit the block
   only when the prose header records a fully human-authored model.
4. Project the validated YAML to `threat-model.json` per
   [json-report-schema.md](../threat-model/references/json-report-schema.md):
   - Collapse provenance downward: `documented`/`maintainer` → `documented`,
     `inferred`/`assumption` → `inferred`. A JSON block built from many sidecar
     records takes the weakest of the set. Collapse `confidence` the same way:
     `documented` + `maintainer`, `inferred` + `assumption`.
   - Emit all nine schema disposition values, verbatim.
     `OUT-OF-MODEL: dependency-contract` has no JSON value; a JSON-only
     consumer falls through to `model_gap`, which escalates. Do not invent a
     label for it.
   - Flatten `entry_points` to one row per (entry point × parameter). An
     `attacker_controllable: conditional` row must carry a non-empty
     `condition`.
   - For each known non-finding, name the covered in-scope components and the
     discharged symptom in `why_safe`, and point `cites` at the discharging
     entry in the same document (`properties_provided[3]` style). The JSON
     drops the sidecar's `components` and `symptom` fields, so `why_safe` is
     the only place left to carry the scope.
   - Record `repository`, `commit` (`git rev-parse HEAD` in the modeled tree),
     `date`, `scope_subpath`, and a short §1.2 `description`.

## Validation gate

Reject (and hand back) if any of these fail:

- [ ] `confidence` equals the header's draft-confidence count.
- [ ] `model_status` is the normalized schema value for the prose status.
- [ ] `prose_version` has the required path-plus-SHA-256 form and its digest
  matches the prose bytes.
- [ ] Every attacker-controllable input operand has a non-empty
  `caller_must_enforce`; explicit `none — <property ID>` means safe handling is
  project-owned, while every actual caller obligation has a stable ID.
- [ ] Every parameter has a non-empty `control_kinds` array containing only
      valid values.
- [ ] Every in-scope component × each required contract dimension is present
  exactly once, claimed/disclaimed property IDs resolve, and every
  unresolved row cites a §1.18 question ID.
- [ ] Every closure-driving component, parameter trust decision, output
      invariant, adversary, dependency, build policy/flag, property,
      responsibility, misuse, and non-finding has provenance sufficient to
      enforce the closure constraint for every model status and triage policy.
- [ ] `dispositions` is exactly the closed enum — **no project-specific
      dispositions invented** (a finding fitting none is `MODEL-GAP`, a prose
      revision, not a new label).
- [ ] `disposition_precedence` equals §1.17's canonical first-match order.
- [ ] Every `properties_claimed[]` entry has a `tier` and at least one
      `violation_symptom`; every claimed/disclaimed property and contract row
      has provenance.
- [ ] Every dependency reliance, caller-obligation acknowledgement, output
  invariant, configuration effect, responsibility, and non-finding
  discharge reference resolves to a stable ID.
- [ ] An accepted model has zero inferred and zero assumption claims; a model
  with any inferred or assumption record remains `under-review` or
  `unratified-draft`.
- [ ] `triage_policy` is `strict` or `relaxed` (defaulting to `strict` when the
  header is silent); every `assumption` provenance record carries a
  `question_id`, and every `properties_disclaimed[]` entry carries a `tier`.
- [ ] The `generation` block matches the §1.1 generation metadata (`model`,
  `effort`, and the `plugins[]` actually used), or is absent only when the prose
  records a fully human-authored model.
- [ ] No key outside the schema except under an `x-` prefix.

For `threat-model.json`:

- [ ] Validates against `schema.json`.
- [ ] `dispositions` is exactly the nine schema values, verbatim.
- [ ] Provenance is never upgraded — no record whose sidecar provenance is
      `inferred` or `assumption` appears as `documented`.
- [ ] `confidence` is the collapsed sidecar count: `documented` + `maintainer`
      and `inferred` + `assumption`.
- [ ] Every `known_non_findings[]` entry's `why_safe` names the in-scope
      components it covers and the symptom it discharges, and its `cites`
      resolves to the row of the claim that discharges it — a real but
      unrelated index does not pass.
- [ ] `commit` is the real sha of the modeled tree, not a placeholder.

## Output

`threat-model.yaml` and `threat-model.json` in the repo root (inside the
subdirectory for a scoped run), one level above the prose in `docs/`, plus a
one-line note of the `prose_version` the YAML was derived from for the
orchestrator's finalize gate. The JSON carries no prose binding — only `commit`
and `date` — one more reason it is an export, not the model.
