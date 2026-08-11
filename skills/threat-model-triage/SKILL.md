---
name: threat-model-triage
description: >-
  Triage one inbound vulnerability report, scanner hit, fuzzer artifact, or AI
  finding against a finished threat model. USE WHEN asked whether a finding is
  valid or in scope. Applies the §1.1 routing algorithm and §1.17 precedence to
  assign exactly one closed disposition with section and provenance citations;
  inferred claims may escalate but never close, and assumptions close only what
  the model's declared triage policy permits. A finding with no supported
  route is MODEL-GAP and triggers §1.16. DO NOT USE FOR: producing a model from
  scratch or backtesting a corpus.
argument-hint: '<the finding to triage> + <path to the threat model>'
---

# Threat Model — Triage (route one finding)

The **consumer** side of the model. Given an inbound finding and a finished (or
drafted) threat model, assign **exactly one** disposition from the closed §1.17
set, citing the section that licenses it. The response is "see threat model §X",
not ad-hoc prose.

Requires a threat model produced by the `threat-model` orchestrator (or an
equivalent document following
[output-structure.md](../threat-model/references/output-structure.md)). If no
such model exists, stop and recommend producing one first.

Route from the prose and the `threat-model.yaml` sidecar, never from the
`threat-model.json` export. The JSON drops `disposition_precedence`,
disclaimed-property tiers, and known-non-finding component/symptom scope, so a
consumer holding only the JSON cannot apply §1.17 first-match ordering or the
security-critical floor. It states the contract; it cannot route a report
against it.

## Routing algorithm (the §1.1 triager quick-start)

1. **Locate the sink** → look up its row in the **§1.7** input-trust table (or the
   **§1.8** output statement, for findings about what downstream consumers may
   assume).
2. **Locate the contract dimension** → for state corruption, overflow,
   recursion, callback execution, deserialization, lifecycle, concurrency, or
   complexity findings, consult the component's contract-dimension row and its
   routed owning claim in §1.3/§1.5/§1.7/§1.10/§1.11/§1.12 or unresolved question in §1.18.
   Do not infer failure semantics from the parameter trust row alone.
3. **Check the attacker capability and control kind** the finding requires
   against **§1.7/§1.10**. Distinguish control of data from control of size,
   type/class, callback code, object topology, collaborator implementation, or
   serialized state.
4. **Check the affected component** against **§1.2/§1.3**, and any required build
   flag against **§1.6**.
5. If the root cause lies in a **dependency**, apply **§1.9**.
6. Check **§1.15** for an exact **known non-finding** match: same component or
  sink, symptom/attack class, and required conditions, with a current stable
  discharge reference. Textual resemblance is insufficient.
7. Apply §1.17's first-match precedence and assign exactly one disposition,
  citing the licensing section and provenance. If none
   fits, assign `MODEL-GAP` and trigger **§1.16** — **do not improvise**.

## The closed disposition set (§1.17)

| Disposition | When | Licensed by |
| --- | --- | --- |
| `VALID` | Violates a claimed property via an in-scope adversary and input. | §1.11, §1.7, §1.10 |
| `VALID-HARDENING` | No §1.11 property violated, but a §1.14 misuse is easy enough to harden. Private; maintainer discretion; usually no CVE. | §1.14 |
| `OUT-OF-MODEL: trusted-input` | Needs attacker control of a parameter marked trusted. | §1.7 |
| `OUT-OF-MODEL: adversary-not-in-scope` | Needs an excluded attacker capability. | §1.10 |
| `OUT-OF-MODEL: unsupported-component` | Lands in out-of-scope code. | §1.3 |
| `OUT-OF-MODEL: non-default-build` | Requires a configuration explicitly marked dev-only, discouraged for the modeled use, or unsupported; non-default alone is insufficient. | §1.6 |
| `OUT-OF-MODEL: dependency-contract` | Root cause is a dependency failing its own contract; usage conformant. **Forward upstream**, don't just close. | §1.9 |
| `BY-DESIGN: property-disclaimed` | Concerns a property explicitly not provided. | §1.12 |
| `KNOWN-NON-FINDING` | Matches a documented recurring false positive. | §1.15 |
| `MODEL-GAP` | Fits none of the above → revise the model. | triggers §1.16 |

## Guardrails

- **Exactly one disposition.** Apply §1.17's precedence when multiple
  preconditions fail. Report `MODEL-GAP` only when the model is silent or
  genuinely contradictory, not merely because two predicates are true.
- **`MODEL-GAP` is not "other".** It means the model is incomplete: the correct
  response is to add the property to §1.11/§1.12 (via `threat-model-authoring`),
  not to make an ad-hoc call on the report.
- **Closure constraint (all statuses), governed by the declared triage policy.**
  Any disposition that closes a report against the reporter (`OUT-OF-MODEL: *`,
  `BY-DESIGN: *`, `KNOWN-NON-FINDING`) must be licensed by a **documented** or
  **maintainer** claim, with one policy-scoped exception for **assumption**:
  - An **inferred** licensing claim always **escalates** instead of closing.
  - Read the header's **triage policy**. Under **`strict`** (default) an
    **assumption** also escalates only. Under **`relaxed`** an **assumption**
    may close the **low-blast-radius** routes — `trusted-input`,
    `adversary-not-in-scope`, `unsupported-component`, `non-default-build`, and a
    *non*-security-critical `property-disclaimed` — as a **provisional** close:
    cite the `QN`, note it re-opens on challenge, and leave the §1.18 item open.
  - **Security-critical floor (both policies).** An **assumption** never licenses
    `KNOWN-NON-FINDING`, a `property-disclaimed` whose property is
    `security-critical`, or `dependency-contract`; those escalate unless
    **documented** / **maintainer**.
  - **Silence floor (both policies, every provenance).** A §1.12 disclaimer that
    rests on the *absence* of a statement rather than on a stated limit never
    closes a `security-critical` report, a `KNOWN-NON-FINDING`, or
    `dependency-contract` — even tagged **documented**. Escalate instead.
  - An untiered §1.12 disclaimer is treated as `security-critical`, not as the
    weaker case. Do not read a blank tier as permission.
  - `VALID` routings are unaffected. A model marked `accepted` while retaining
    **inferred** or **assumption** claims is invalid; return it for status/model
    correction.
- **An escalated finding is not a `MODEL-GAP`.** Escalation means the route is
  right and the authority to use it is missing; `MODEL-GAP` means there is no
  route. Keep the disposition, mark it `escalated`, and name the §1.18 question
  that would unblock it. Do not feed it into the §1.16 revision loop — that loop
  is for genuine gaps, and filling it with escalations manufactures phantom
  model defects.
- **Cite provenance.** When a disposition closes a report, cite the tagged claim
  (e.g., "not a bug — §1.12 disclaims this property *(maintainer, 2025-03)*", or
  "provisionally out of model — §1.7 *(assumption, Q6)* under relaxed policy;
  re-open on challenge").

## Output

The disposition **and its status**, written as `DISPOSITION (status)` — for
example `OUT-OF-MODEL: trusted-input (escalated)`. The status is one of:

| Status | Meaning |
| --- | --- |
| `closed` | Licensed by a **documented** or **maintainer** claim. The report is answered. |
| `provisional` | A `relaxed`-policy **assumption** close. Cite the `QN`; re-opens on challenge. |
| `escalated` | The route is right but its license cannot close it. Name the blocking `QN`. |

`VALID` and `MODEL-GAP` are not closes and take no status qualifier.

Also report the citing section(s), the provenance of the licensing claim, and —
for `MODEL-GAP` or a two-way route — the model-revision or sharpening
recommendation to hand back to the orchestrator.
