# Output structure — the threat-model document

This is the canonical section-by-section specification for the **deliverable**
(typically `docs/threat-model.md`). The `threat-model-authoring` specialist
writes to this structure; every other specialist feeds one or more sections.

Use these sections, in this order. Rename to fit a project's house style, but
cover the same ground. Each section is either substantive or explicitly marked
`Not applicable — <reason>`. Empty headings are a smell.

Two consumers must be able to use every section without re-deriving the
reasoning:

- the **downstream integrator**, deciding which threats they now own; and
- the **triager**, classifying an inbound report/finding as valid, out of
  model, or disclaimed — and citing the section that justifies the call.

**Write it plainly.** Both readers are busy professionals, not an academic
audience. Use short, direct sentences (one idea each), plain words, active voice,
and real verbs instead of nominalizations; break piled-up noun stacks and long
inline lists into short bullets or table rows. Target the reading level of good
developer documentation, not a research paper. Precision and readability are not
in tension — keep every operand and provenance tag, just say it in fewer, plainer
words. See "Write so a human can read it" in
[principles.md](principles.md).

---

## Provenance tags (used throughout)

Every non-trivial claim carries exactly one inline tag:

| Tag | Meaning |
| --- | --- |
| *(documented, source)* | Stated in a maintainer-authored public source: project docs, headers, FAQ/manpage, `SECURITY.md`, release rationale, or an issue ruling. Name or link the exact source in the tag. |
| *(maintainer)* | Stated by a maintainer in response to a question from this process. Date it, e.g. *(maintainer, 2025-03)*. |
| *(assumption, QN)* | A **reasonable default the model author is willing to act on now**, chosen conservatively where docs are silent and no maintainer answer exists — e.g. "no thread-safety is guaranteed for a mutable view" when the Javadoc states none. Still unratified: `QN` **must** resolve to a §1.18 ratification item, and review promotes it to *(maintainer)*. Distinct from *(inferred)* only in that the author has committed to a default rather than left the question open. |
| *(inferred, QN)*   | Reasoned from code structure, absence of a feature, or domain knowledge, **without** a committed default — genuinely open. `QN` **must** resolve to the matching open question in §1.18. |

Do **not** invent hedge-tags ("*(implicit)*", "*(documented in purpose)*",
"*(generally known)*"). If a claim is not clearly *(documented)* or
*(maintainer)*, it is *(assumption)* (author commits to a conservative default)
or *(inferred)* (question left open). Retain tags in the published version — a
disposition that closes a report cites *(maintainer, 2025-03)*, and bare prose
is not defensible.

**Assumptions vs inferences — the routing difference.** Both are unratified and
both register a §1.18 item. They differ only in what the **triage policy** lets
them do (see §1.1 and §1.17): under `strict` an *(assumption)* behaves exactly
like an *(inferred)* claim — it may escalate but never close. Under `relaxed` an
*(assumption)* may additionally license the **low-blast-radius** closes
(`trusted-input`, `adversary-not-in-scope`, `unsupported-component`,
`non-default-build`, and a *non*-security-critical `property-disclaimed`), each
emitted as a **provisional** close that a reporter can re-open on challenge. An
*(assumption)* **never** licenses `KNOWN-NON-FINDING`, a security-critical
`property-disclaimed`, or `dependency-contract`, and *(inferred)* never closes
under either policy. Prefer *(assumption)* over *(inferred)* only when the safe
default is genuinely clear; when a real guarantee might exist, leave it
*(inferred)*.

**Disclaim-by-default for demonstrably-absent guarantees.** When the code and
docs show a family-wide guarantee is simply *not made* (no stated thread-safety,
no resource bound, no failure-atomicity guarantee), record that as a
*documented* **disclaimer** in §1.12 — the absence is verifiable in the public
API, so it is *(documented, source)*, not an open question. Reserve `unresolved`
/ *(inferred)* for dimensions where a guarantee **plausibly exists** but could
not be confirmed. Disclaiming the safe (no-guarantee) direction pushes the
responsibility to the caller and is the primary lever for reducing `MODEL-GAP`
without weakening the closure-safety rule.

Implementation and tests may support an inference, but do not by themselves
turn an unwritten contract into *(documented)* provenance. A conformance test is
documented evidence only when the project publicly identifies it as normative.

---

## 1.1 Header

- Project name, version/commit, date, author(s) of the threat model.
- **Version binding** — the model is versioned alongside the project. A report
  against version *N* is triaged against the model as it stood at *N*, not HEAD.
- **Reporting cross-reference** — one line: §1.11 (claimed-property) findings
  are reported per the project's disclosure channel; §1.3 / §1.12 findings are
  closed citing this document.
- **Status** — draft / unratified draft / under maintainer review / accepted,
  with date. For every status, restate the closure constraint in one line: an
  *(inferred)* claim may escalate a report but never close it, and an
  *(assumption)* closes only what the declared triage policy permits.
- **Triage policy** — one line declaring `strict` or `relaxed` (default
  `strict`), so a triager knows what an *(assumption)* is allowed to do. Under
  `strict`, assumptions escalate only; under `relaxed`, they may license the
  low-blast-radius closes provisionally (see §1.17). The security-critical floor
  holds under both policies.
- **Provenance legend** — the one-line key for the four tags above.
- **Draft confidence** — a count of *(documented)* / *(maintainer)* /
  *(inferred)* claims (e.g., "29 documented / 0 maintainer / 30 inferred"). When
  the model uses *(assumption)* tags, append "/ N assumption".
- **Backtest note** — corpus size and routing result from phase 3.6.
- **Sibling models** — if the repo is covered by more than one model, name the
  others and their scope.
- One-paragraph plain-language description of the project's purpose.
- **Triager quick-start** — a boxed routing algorithm:

  > Given an inbound finding:
  > 1. Locate the sink → look up its row in the §1.7 input-trust table (or the
  >    §1.8 output statement, for "downstream may assume X" findings).
  > 2. Locate the contract dimension → for state corruption, overflow,
  >    recursion, callbacks, serialization, lifecycle, concurrency, or
  >    complexity, follow the component's matrix row to its owning claim.
  > 3. Check the required attacker capability and control kind against §1.7/§1.10;
  >    distinguish data from size, type/class, callback code, topology,
  >    collaborator implementation, and serialized state.
  > 4. Check the affected component against §1.2/§1.3, and any required build
  >    flag against §1.6.
  > 5. If the root cause is in a dependency, apply §1.9.
  > 6. Apply §1.17's precedence order, beginning with an exact §1.15 known-
  >    non-finding match.
  > 7. Assign exactly one §1.17 disposition, citing the licensing section and
  >    its provenance. If
  >    none fits, assign `MODEL-GAP` and trigger §1.16 — do not improvise.

## 1.2 Scope and intended use

- Primary intended use cases — concrete ("in-process compression of application
  data" beats "general compression library").
- Deployment contexts (in-process library? CLI? daemon? embedded? kernel?).
- Caller expectations and trust level. For a **network service/daemon**, split
  the role into *client* (untrusted), *operator/admin* (trusted for the
  instance), and *peer* (authenticated but adversarial); each gets rows in §1.7
  and actors in §1.10.
- **Component-family table** (lead with it): family name, representative
  entry point, whether it touches anything outside the process (fs, network,
  env, child processes), and in/out of this model. Anything out here reappears
  in §1.3 with the reason.

## 1.3 Out of scope (explicit non-goals)

- Use cases the project does not aim to support (state even the obvious ones).
- Threats not defended against, each with a reason ("not a security boundary",
  "out of layer", "unsolvable at this layer").
- Shipped-but-unsupported code (`contrib/`, `examples/`, `vendor/`,
  `third_party/`, demos, generated bindings) with an explicit policy.

## 1.4 Trust boundaries and data flow

- Where the trust boundary sits.
- The path data takes, expressed as trust transitions. Skip (say so) if purely
  computational with no meaningful transitions.
- **Diagram when roles multiply** (≥3 roles): a simple boxes-and-arrows
  data-flow diagram (ASCII or Mermaid) with boundaries drawn on it. A single-
  boundary in-process library needs only prose.
- **Reachability precondition per component** — the condition a finding must
  meet to matter (e.g., "a finding in `inflate.c` is in-model only if reachable
  from the compressed input bytes").

## 1.5 Assumptions about the environment

- OS, runtime, hardware; concurrency (thread-safety, reentrancy, signal-safety);
  memory model (allocator, alignment); time/clock; filesystem/network/peripheral.
- **No-surprise side-effects inventory** — what the project does *not* do to its
  host (sockets? child processes? signal handlers? env reads? stdout/stderr?
  global locale/FPU state? process-wide mutation?). These are **negative
  claims**, rarely documented — predominantly *(inferred)* in a first draft, so
  a **wave-1/2 confirmation target**.

## 1.6 Build-time and configuration variants

- Compile-time defines, feature flags, runtime knobs that **change which
  security properties hold**: default, effect on the model, whether discouraged.
  If none, say so.
- **Support posture, not defaultness, controls routing.** For every security-
  relevant configuration, record whether it is supported for the modeled use.
  A defect in a supported configuration is in-model even when that
  configuration is non-default. `OUT-OF-MODEL: non-default-build` applies only
  when §1.6 explicitly marks the required configuration dev-only, discouraged
  for the modeled exposure, or otherwise unsupported. (The disposition name is
  retained for compatibility; its meaning is **unsupported configuration**.)
- **The insecure-default case** — when the shipped default voids a §1.11
  property, the maintainer must rule whether that default is a supported
  production posture (`VALID`) or explicitly dev-only/unsupported
  (`OUT-OF-MODEL: non-default-build`, with the required production setting in
  §1.13). This is a **wave-1** question.

## 1.7 Assumptions about inputs

- What inputs are accepted and from where.
- **Per-input-operand trust table** — one row per direct parameter and each
  security-relevant indirect input (stream contents, inherited handle state,
  connection metadata) of every public entry point: `Entry point | Input
  operand | Attacker-controllable? | Control kind | Caller
  must enforce | Provenance`. `Control kind` distinguishes data, size/rate, type/class,
  callback/code, object-graph topology, collaborator implementation,
  resource-name, and serialized state. Project-specific kinds use an `x-`
  prefix.
  For a network service the first column is the route/endpoint or protocol
  message, and rows cover headers/connection metadata as well as bodies. Prose
  is not sufficient — findings are reported against specific sinks. If the
  surface was too large to table fully (per the phase-3.3 timebox), say which
  portion is covered and mark the remainder *(inferred)*.
- Size/shape/rate assumptions (bounded? streaming? memory-mapped?).
- **Contract-dimension matrix** — one row per applicable dimension for every
  in-scope component family. Required dimensions are numeric domain and
  representational limits; failure/exception atomicity; recursive/cyclic
  topology; callback/collaborator execution; serialization/reconstruction;
  reference/object lifecycle; concurrency/reentrancy; and resource complexity.
  Each row is `Component | Dimension | Status | Conditions / boundary |
  Routes to | Provenance`; status is `claimed`, `disclaimed`, `N/A — reason`,
  or `unresolved`. Each row routes to the owning §1.3/§1.5/§1.7/§1.10/§1.11/§1.12
  claim or a proposed-answer §1.18 question. Add domain-specific rows such as
  Unicode normalization or probabilistic-result semantics where applicable.
- For stateful APIs, state the postcondition after validation, allocation,
  callback, or collaborator failure: unchanged, partially committed,
  best-effort cleanup, or unspecified.

## 1.8 Assumptions and guarantees about outputs

The mirror of §1.7 — the project's output is somebody else's input. Per output
channel (return values, filled buffers, files, network responses, callbacks):

- **Taint** — the default one-liner for parsers/decoders/decompressors, worth
  stating verbatim: *"Output is exactly as untrusted as the input it derives
  from; no sanitization, normalization, or encoding is performed."*
- **Structural invariants that ARE guaranteed** (valid UTF-8, depth/size caps,
  matching length fields, round-trip) — promote each to §1.11 with a symptom
  and tier, and reference from here.
- **What downstream must NOT assume** (canonical form, dedup, ordering, no NUL
  bytes, safety for HTML/SQL/shell). One-line disclaimers that pre-empt misuse.
- If there is genuinely no externally consumed output, mark N/A with reason.

## 1.9 Assumptions about dependencies

- **Per-dependency trust statements** — one per direct runtime dependency: the
  property relied on, and whether a violation is triaged here or upstream.
- **Vendored/bundled copies** compiled into supported artifacts: covered at the
  pinned version or deferred upstream? Who ships the fix?
- **Routing rule** — a dependency failing its own documented contract (this
  project's usage conformant) → `OUT-OF-MODEL: dependency-contract`, forwarded
  upstream. This project misusing a dependency contract → in-model.
- **Zero-dependency claim** — if none beyond libc/runtime, say so explicitly (a
  strong negative claim; usually *(inferred)* at first — early question wave).

## 1.10 Adversary model

- Who the attacker is; capabilities they have and lack; what they are trying to
  do; which actors are explicitly out ("a caller controlling the process has
  already won").
- For **distributed/replicated/consensus** systems, include the
  *authenticated-but-Byzantine participant* as a distinct actor and state the
  honest-fraction threshold (`< n/3`, `< ½ stake`); put the threshold in the
  §1.11 conditions and its complement in §1.3.

## 1.11 Security properties the project provides

For each property state **four things**: (1) the property + conditions;
(2) **violation symptom** (crash, OOB r/w, info leak, hang, wrong output,
unbounded allocation); (3) **severity tier** (security-critical → CVE, vs
correctness-only); (4) provenance tag. Cover memory/safety, correctness,
promoted structural output invariants, distributed-system properties (with the
honest bound), and resource properties — **state the threshold** ("super-linear
in input is a bug; constant-factor blowup is not"; "a hang is a bug; slow is
not"; or "no resource guarantee at all"). A property counts only if the project
committed to it (normative docs,
maintainer-authored public rulings, explicitly normative conformance tests, or a
maintainer answer). Implementation/tests that merely suggest a contract remain
*(inferred)*. Do not invent properties.
Promote every `claimed` contract-dimension row here or to the environment/output
section that owns it; no claimed row may exist only in the matrix.

## 1.12 Security properties the project does *not* provide

The companion to §1.11 and the highest-value section for an integrator. State
each plainly. Call out **"false-friend" properties** separately — features that
look like a security property but are not ("X is provided for A; sometimes
mistaken for B, which it does not satisfy": CRC≠MAC, non-crypto hash≠collision-
resistant, PRNG≠CSPRNG, resource-"sandbox"≠isolation). Name the **well-known
attack classes** for this category the project leaves to the caller (compression
bombs, XXE, ReDoS, billion-laughs) — one sentence each.
Promote every `disclaimed` contract-dimension row here or to §1.3. State
unsupported edge semantics plainly: for example, whether oversized cardinality,
cyclic object graphs, callback exceptions, reconstructed polymorphic state, or
weak-reference clearing are caller-owned.
**Disclaim demonstrably-absent guarantees here rather than leaving them
`unresolved`.** If the public API makes no thread-safety, resource-bound, or
failure-atomicity guarantee, say so as a *(documented)* disclaimer — the absence
is verifiable, and a disclaimer lets a matching report close as
`BY-DESIGN: property-disclaimed` instead of routing to `MODEL-GAP`. Keep
`unresolved` only for dimensions where a guarantee plausibly exists but was not
confirmed.

## 1.13 Downstream responsibilities

Action-oriented contract of what the *user* (embedding app, or operator for a
service) must do for §1.5–§1.10 to hold. Every §1.6 dev-only knob reappears as
"set X before exposing the service"; every risky §1.8 "must not assume" becomes
a positive obligation ("sanitize decompressed output before rendering").

## 1.14 Known misuse patterns

Common misuses the API permits. In a draft, one-liners; before publishing,
expand each to *what it looks like / why unsafe / what to do instead*.

## 1.15 Known non-findings (recurring false positives)

The mirror of §1.14: patterns tools/fuzzers/AI/humans repeatedly flag that are
**not** bugs under the model. Per entry: what is reported, why it is safe (cite
the §1.7 assumption or §1.11 invariant that discharges it), and the suppression
pattern where helpful. The phase-3.6 backtest feeds this section. Highest-
leverage input for automated triage — can be fed back verbatim as a negative
prompt.

Each entry has a stable ID and cites the specific assumption, disclaimer, or
claimed-property ID that discharges it. This makes an exact match deterministic
without erasing the underlying disposition. Define the component or sink,
symptom/attack class, and required conditions. An "exact" match satisfies all
of those fields and the current discharging claim; text similarity alone never
licenses `KNOWN-NON-FINDING`.

## 1.16 Conditions that would change this model

Kinds of change that trigger a revision (new public API, new input format, new
network surface, new deployment context, a §1.6 default change, a new/changed
dependency, a shipped-but-unsupported component promoted to core). Also: a
report that cannot be cleanly routed to a §1.17 disposition is itself a trigger —
revise the model, don't make an ad-hoc call.

## 1.17 Triage dispositions

The **closed set** of outcomes, each citing the licensing section:

| Disposition | Meaning | Licensed by |
| --- | --- | --- |
| `VALID` | Violates a claimed property, via in-scope adversary and input. | §1.11, §1.7, §1.10 |
| `VALID-HARDENING` | No §1.11 property violated, but the API makes a §1.14 misuse easy enough to harden. Private; maintainer discretion; usually no CVE. | §1.14 |
| `OUT-OF-MODEL: trusted-input` | Requires attacker control of a parameter marked trusted. | §1.7 |
| `OUT-OF-MODEL: adversary-not-in-scope` | Requires an excluded attacker capability. | §1.10 |
| `OUT-OF-MODEL: unsupported-component` | Lands in out-of-scope code. | §1.3 |
| `OUT-OF-MODEL: non-default-build` | Requires a §1.6 configuration explicitly marked dev-only, discouraged for the modeled use, or unsupported. Non-default alone is insufficient. | §1.6 |
| `OUT-OF-MODEL: dependency-contract` | Root cause is a dependency failing its own contract; usage conformant. Forward upstream. | §1.9 |
| `BY-DESIGN: property-disclaimed` | Concerns a property explicitly not provided. | §1.12 |
| `KNOWN-NON-FINDING` | Matches a documented recurring false positive. | §1.15 |
| `MODEL-GAP` | Fits none of the above. | triggers §1.16 |

**Precedence (first matching rule wins):**

1. An exact §1.15 pattern → `KNOWN-NON-FINDING`.
2. Unsupported component → `OUT-OF-MODEL: unsupported-component`.
3. Unsupported configuration → `OUT-OF-MODEL: non-default-build`.
4. Conformant use of a dependency that violated its own contract →
  `OUT-OF-MODEL: dependency-contract`.
5. Required control of a trusted input → `OUT-OF-MODEL: trusted-input`.
6. Required excluded attacker capability →
  `OUT-OF-MODEL: adversary-not-in-scope`.
7. Explicitly disclaimed property → `BY-DESIGN: property-disclaimed`.
8. Violated claimed property → `VALID`; otherwise an easy-to-prevent §1.14
  misuse may be `VALID-HARDENING`.
9. No unique supported conclusion → `MODEL-GAP`.

Multiple failed preconditions do not by themselves create a `MODEL-GAP`; this
order resolves them. Use `MODEL-GAP` when the model is silent or genuinely
contradictory.

**Closure constraint — all statuses.** Any disposition that closes a report
against the reporter (`OUT-OF-MODEL: *`, `BY-DESIGN: *`, `KNOWN-NON-FINDING`)
must be licensed by a *(documented)* or *(maintainer)* claim, **except** as the
declared triage policy permits for *(assumption)* claims:

- An *(inferred)* licensing claim can only **escalate** the report to the
  maintainer, under every policy.
- Under **`strict`** (default) an *(assumption)* behaves like *(inferred)*:
  escalate only.
- Under **`relaxed`** an *(assumption)* may license the **low-blast-radius**
  closes — `trusted-input`, `adversary-not-in-scope`, `unsupported-component`,
  `non-default-build`, and a *non*-security-critical `property-disclaimed` — as
  a **provisional** close (tag the licensing `QN`, keep the §1.18 item open, and
  re-open on a reporter challenge without new evidence).
- **Security-critical floor (both policies).** An *(assumption)* never licenses
  `KNOWN-NON-FINDING`, a `property-disclaimed` whose property is
  `security-critical`, or `dependency-contract`. Those still require
  *(documented)* / *(maintainer)* or they escalate.

`VALID` and `MODEL-GAP` remain fail-safe under every policy. An accepted model
has zero inferred **and** zero assumption claims; if any *(inferred)* or
*(assumption)* remains, use `under maintainer review` or `unratified draft`
rather than `accepted`.

## 1.18 Open questions for the maintainers

Required while any *(inferred, QN)* or *(assumption, QN)* tag remains. Per
question: state the **proposed answer**, note which section the answer lands in,
group into waves of 3–7. For an *(assumption)*, the proposed answer is the
default the author is already applying — mark it "applied under relaxed policy"
when relevant so review either ratifies it to *(maintainer)* or overturns it.
**Mapping rule** — every inferred or assumption tag carries the stable `QN` of a
question here; one question may ratify multiple claims. Also permitted: edge-case
probes of documented claims and
meta questions (ownership, revision policy, venue). When answered, promote the
body tag(s) and delete the question.
Every `unresolved` contract-dimension row must have a question that offers the
maintainer an explicit choice between a §1.11 guarantee, a §1.12 disclaimer, or a
narrower set of conditions. Do not use "please clarify" as the proposed answer.

## 1.19 Machine-readable companion

An orchestrated threat-model run emits a `threat-model.yaml` sidecar with the
triage-relevant facts, per the schema in
[sidecar-schema.md](./sidecar-schema.md). The prose document remains canonical;
the sidecar is a derived index. Regenerate it whenever the prose changes and
record the prose version it derives from. Owned by the `threat-model-sidecar`
specialist. A prose-only draft is permitted only when
`threat-model-authoring` is invoked standalone; it is not a complete
orchestrated deliverable.

## Appendix: prior security-policy back-map (when applicable)

When the project already had authoritative threat-model content in
`SECURITY.md` or equivalent policy, append a one-row-per-claim back-map from the
prior statement to its destination in §1.1–§1.19. Keep it until maintainers
explicitly approve removal; it proves the new model is a strict superset.
