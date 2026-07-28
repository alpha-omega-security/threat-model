# Reference sidecar schema — `threat-model.yaml`

The machine-readable companion (§1.19) must be **structurally uniform across
projects**, or shared triage tooling cannot consume it. Use this shape; extend
with project-specific keys only under an `x-` prefix. All section references
point at the prose document, which remains **canonical**. Owned by the
`threat-model-sidecar` specialist; regenerate whenever the prose changes and
record the prose version it derives from.

**Provenance `kind`** is one of `documented` (carries `source`), `maintainer`
(carries `date`), `assumption` (carries `question_id` plus an optional
`rationale`), or `inferred` (carries `question_id`). A closing route may be
licensed by `documented`/`maintainer` under any policy; by `assumption` only
under `triage_policy: relaxed`, only for a low-blast-radius route, and never for
a `security-critical` disclaimed property, `KNOWN-NON-FINDING`, or
`dependency-contract`; `inferred` never closes. `triage_policy` defaults to
`strict` when omitted.

```yaml
# threat-model.yaml — derived index; the prose threat model is canonical.
schema: threat-model-sidecar/v2
project: zlib
# Canonical relative path plus SHA-256 of the exact prose bytes.
prose_version: "docs/threat-model.md@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
model_status: unratified-draft # draft | unratified-draft | under-review | accepted
triage_policy: strict          # strict (default) | relaxed
confidence: {documented: 29, maintainer: 24, inferred: 6, assumption: 0}

generation:                   # from §1.1 generation metadata; omit for a fully human-authored model
  model: "Claude Opus 4.8"    # producing model/agent, name + version ("human-authored" if none)
  effort: high                # reasoning/effort level: low | medium | high | <provider label>
  plugins:                    # skills / plugins / MCP servers that drove production; only those used
    - threat-model
    - threat-model-recon
    - threat-model-surface
    - threat-model-sidecar

components:                   # from §1.2 / §1.3
  - name: core-inflate
    scope: in                 # in | out
    reachability_precondition: "reachable from compressed input bytes"
    provenance: {kind: documented, source: "zlib manual"}
  - name: examples
    scope: out
    reason: "unsupported, per §1.3"
    provenance: {kind: maintainer, date: "2025-03"}

host_side_effects:            # from §1.5
  - effect: network-sockets
    stance: absent            # absent | present | conditional
    components: [core-inflate, gz-convenience]
    conditions: "all supported library entry points"
    provenance: {kind: inferred, question_id: Q8}
  - effect: filesystem
    stance: conditional
    components: [gz-convenience]
    conditions: "only the gz* file API touches caller-named paths"
    provenance: {kind: documented, source: "gzopen API contract"}

entry_points:                 # from §1.7; id is a function, route, or protocol message
  - id: gzread
    component: gz-convenience
    parameters:
      - name: file_contents
        attacker_controllable: true
        control_kinds: [data, size]
        obligation_id: cap-output-buffer
        caller_must_enforce: "output buffer >= len"
        provenance: {kind: documented, source: "gzread API contract"}
      - name: path            # inherited from gzopen handle
        attacker_controllable: false
        control_kinds: [resource-name]
        caller_must_enforce: "path sanitization"
        provenance: {kind: maintainer, date: "2025-03"}

contract_dimensions:           # from the §1.7-§1.12 coverage matrix
  - component: core-inflate
    dimension: numeric-domain   # enum listed below
    status: claimed             # claimed | disclaimed | not-applicable | unresolved
    conditions: "supported stream and platform sizes"
    property_id: memory-safety-untrusted-input
    provenance:
      kind: documented          # documented | maintainer | assumption | inferred
      source: "zlib manual: inflate contract"
  - component: core-inflate
    dimension: callback-execution
    status: not-applicable
    conditions: "API accepts no executable callbacks"
    provenance:
      kind: inferred
      question_id: Q4

outputs:                      # from §1.8
  - component: core-inflate
    channel: inflate-output-buffer
    taint: same-as-input      # same-as-input | sanitized | constrained
    taint_provenance: {kind: documented, source: "inflate API contract"}
    invariants:
      - id: output-bound-honored
        statement: "writes bounded by caller-supplied length"
        property_id: output-bound-honored
        provenance: {kind: documented, source: "inflate API contract"}
    downstream_must_not_assume:
      - id: output-is-text-safe
        statement: "output is safe for a text or command grammar"
        provenance: {kind: inferred, question_id: Q7}

adversaries:                  # from §1.10
  - name: compressed-input-author
    scope: in                 # in | out
    capabilities: [supply-input-bytes, choose-input-size]
    excluded_capabilities: [execute-in-host-process]
    goals: [memory-corruption, resource-exhaustion]
    provenance: {kind: documented, source: "zlib security considerations"}
  - name: in-process-caller
    scope: out
    capabilities: [choose-callback-code, mutate-process-state]
    excluded_capabilities: []
    goals: []
    provenance: {kind: inferred, question_id: Q2}

dependency_policy:            # from §1.9
  zero_runtime_dependencies: false
  provenance: {kind: documented, source: "build manifest"}

dependencies:
  - name: caller-supplied-allocator
    relied_on_for: "standard allocator contract"
    relied_on_properties: [allocator-size-correctness]
    caller_obligations_acknowledged: []
    adversary_capabilities_forwarded: []
    outputs_consumed: []
    covered_here: false
    violation_disposition: "OUT-OF-MODEL: dependency-contract"
    provenance: {kind: documented, source: "allocator API contract"}

build_policy:                 # from §1.6
  security_relevant_flags_present: true
  provenance: {kind: documented, source: "build configuration"}

build_flags:
  - name: ZLIB_INSECURE
    default: "off"
    security_relevant: true
    maintainer_stance: discouraged   # supported | dev-only | discouraged | unsupported
    affects_properties:
      - property_id: format-string-bounds
        effect: voids
    provenance: {kind: documented, source: "zlib build documentation"}

properties_claimed:           # from §1.11
  - id: memory-safety-untrusted-input
    kind: memory-safety       # enum listed below
    components: [core-inflate]
    tier: security-critical   # security-critical | correctness-only
    conditions: "well-formed stream init; supported platform"
    violation_symptoms: [crash, oob-read, oob-write]
    provenance: {kind: documented, source: "zlib manual"}
  - id: output-bound-honored
    kind: resource-bound
    components: [core-inflate]
    tier: security-critical
    conditions: "caller supplies a valid output buffer and length"
    violation_symptoms: [oob-write]
    provenance: {kind: documented, source: "inflate API contract"}
  - id: format-string-bounds
    kind: memory-safety
    components: [gz-convenience]
    tier: security-critical
    conditions: "ZLIB_INSECURE is disabled"
    violation_symptoms: [buffer-overflow]
    provenance: {kind: documented, source: "zlib build documentation"}

properties_disclaimed:        # from §1.12
  - id: decompression-bomb-resistance
    components: [core-inflate]
    conditions: "no caller-enforced output budget"
    tier: correctness-only    # security-critical | correctness-only (gates assumption closes)
    false_friend: false
    provenance: {kind: documented, source: "zlib manual"}
  - id: crc-as-mac
    components: [gz-convenience]
    conditions: "all builds"
    tier: correctness-only
    false_friend: true
    provenance: {kind: maintainer, date: "2025-03"}

downstream_responsibilities:  # from §1.13
  - id: cap-decompressed-output
    component: core-inflate
    statement: "cap total decompressed output before allocation"
    enforces: [cap-output-buffer]
    provenance: {kind: documented, source: "inflate API contract"}

known_misuses:                # from §1.14
  - id: crc-used-as-mac
    component: gz-convenience
    pattern: "using CRC-32 to authenticate attacker-controlled data"
    safer_alternative: "authenticate the framed data with a MAC"
    provenance: {kind: maintainer, date: "2025-03"}

known_non_findings:           # from §1.15
  - id: bounded-output-write
    component: core-inflate
    tool_pattern: "write past the inflate output buffer"
    conditions: "valid caller buffer; report shows no write beyond supplied length"
    discharged_by: [output-bound-honored]
    provenance: {kind: maintainer, date: "2025-03"}

dispositions:                 # from §1.17; the closed set
  - VALID
  - VALID-HARDENING
  - "OUT-OF-MODEL: trusted-input"
  - "OUT-OF-MODEL: adversary-not-in-scope"
  - "OUT-OF-MODEL: unsupported-component"
  - "OUT-OF-MODEL: non-default-build"
  - "OUT-OF-MODEL: dependency-contract"
  - "BY-DESIGN: property-disclaimed"
  - KNOWN-NON-FINDING
  - MODEL-GAP

disposition_precedence:       # from §1.17; first matching rule wins
  - KNOWN-NON-FINDING
  - "OUT-OF-MODEL: unsupported-component"
  - "OUT-OF-MODEL: non-default-build"
  - "OUT-OF-MODEL: dependency-contract"
  - "OUT-OF-MODEL: trusted-input"
  - "OUT-OF-MODEL: adversary-not-in-scope"
  - "BY-DESIGN: property-disclaimed"
  - VALID
  - VALID-HARDENING
  - MODEL-GAP
```

## Field notes

- Required top-level keys are `schema`, `project`, `prose_version`,
  `model_status`, `confidence`, `components`, `host_side_effects`, `entry_points`,
  `contract_dimensions`, `outputs`, `adversaries`, `dependency_policy`,
  `dependencies`, `build_policy`, `build_flags`, `properties_claimed`,
  `properties_disclaimed`, `downstream_responsibilities`, `known_misuses`,
  `known_non_findings`, `dispositions`, and `disposition_precedence`. Lists may be empty only when the
  prose explicitly supports that absence. Unknown keys require an `x-` prefix.
- Normalize prose status as follows: `draft` → `draft`, `unratified draft` →
  `unratified-draft`, `under maintainer review` → `under-review`, and `accepted`
  → `accepted`. The sidecar value is normalized; it need not textually equal the
  prose label.
- `prose_version` is `<canonical-relative-path>@sha256:<64 lowercase hex>` for
  the exact UTF-8 prose bytes. Validators recompute the digest when the prose
  file is available; a label such as `draft` or `v1` is not sufficient.
- `confidence` must equal the header's draft-confidence count (§1.1). If they
  disagree, the sidecar is stale — regenerate.
- `entry_points[].parameters[]` is the structured form of the §1.7 input-
  operand table; `name` may identify a direct parameter or a documented
  indirect input. Every attacker-controllable operand has a non-empty
  `caller_must_enforce`. When no caller obligation exists because safe handling
  is a claimed property, use `none — <property ID>` and omit `obligation_id`;
  otherwise every non-trivial obligation has a stable `obligation_id`. Every
  operand has one or more `control_kinds` from `data`, `size`,
  `rate`, `type-class`, `callback-code`, `object-topology`,
  `collaborator-implementation`, `resource-name`, or `serialized-state`.
  Project-specific values use an `x-` prefix. IDs are unique within their list.
- `contract_dimensions[].dimension` is one of `numeric-domain`,
  `failure-atomicity`, `recursive-cyclic-topology`, `callback-execution`,
  `serialization-reconstruction`, `reference-lifecycle`,
  `concurrency-reentrancy`, or `resource-complexity`. Domain-specific values
  use an `x-` prefix.
- Every **in-scope component × each of the eight required dimensions** appears
  exactly once; use `not-applicable` with a reason rather than omitting a row.
  Domain-specific `x-` dimensions are additional. `claimed` and `disclaimed`
  rows require a `property_id` resolving to the corresponding property list.
  `unresolved` requires inferred provenance and `question_id`; `not-applicable`
  requires a reason in `conditions` and no property reference.
- Provenance is `{kind: documented, source: ...}`,
  `{kind: maintainer, date: YYYY-MM}`, or
  `{kind: inferred, question_id: QN}`. Use the canonical evidence mapping:
  maintainer-authored public policy/rulings are documented; implementation or
  tests suggesting an unwritten contract are inferred unless explicitly
  normative. Every closure-driving record and each output taint/invariant has
  its own provenance.
- `host_side_effects[]` is the §1.5 no-surprise inventory. Each effect has an
  `absent`, `present`, or `conditional` stance, applicable in-scope components,
  conditions, and provenance. Negative claims are usually inferred until
  confirmed; do not encode absence as an empty list.
- Every output record names its in-scope `component`.
  `outputs[].invariants[]` link to a claimed `property_id`.
  `downstream_must_not_assume[]` records separately provenanced disclaimers.
- `adversaries[]` is the structured §1.10 actor model required to evaluate
  attacker capability and `OUT-OF-MODEL: adversary-not-in-scope`.
- `dependency_policy` and `build_policy` preserve provenance even when
  `dependencies` or `build_flags` is empty. A zero-dependency closure requires
  `zero_runtime_dependencies: true`; an empty list alone is not a claim.
- `dependencies[].relied_on_properties[]` contains stable property IDs expected
  from that dependency; compatibility analysis matches IDs exactly.
  `caller_obligations_acknowledged[]` contains obligation IDs from the
  dependency's entry points. `adversary_capabilities_forwarded[]` lists only
  in-scope capabilities actually exposed across that edge. `outputs_consumed[]`
  records dependency output channel, `taint_handling: passthrough | sanitized |
  constrained`, and the consumer's output-sanitization
  `supports_property_id`. Each entry's `supports_property_id` **must** reference a
  `kind: output-sanitization` property in `properties_claimed`; if the project
  holds no such property about a dependency's output (the common case — it passes
  the output through and disclaims sanitization), leave `outputs_consumed: []`
  rather than pointing the entry at a behavioral, atomicity, or probabilistic
  property. These relation fields prevent unrelated global model
  facts from creating compatibility findings. Free-text `relied_on_for`
  explains the relationship but is not a matching key.
- `dependencies[].violation_disposition` is always
  `OUT-OF-MODEL: dependency-contract`; misuse of the dependency API is a
  consumer property violation, not an alternative dependency disposition.
- Every build flag records `default`, boolean `security_relevant`, and
  `maintainer_stance: supported | dev-only | discouraged | unsupported`.
  Every security-relevant flag identifies non-empty `affects_properties[]` with a
  claimed property ID and `effect: preserves | narrows | voids`. Defaultness alone
  never determines scope; `maintainer_stance` does.
- Claimed properties require `kind`, non-empty `components`, `conditions`,
  `tier`, symptoms, and provenance. `kind` is one of `memory-safety`,
  `output-sanitization`, `resource-bound`, `availability`, `confidentiality`,
  `integrity`, `authentication`, `correctness`, or an `x-` value. Disclaimed
  properties require components, conditions, `false_friend`, and provenance.
- `downstream_responsibilities[].enforces[]` references stable obligation,
  property, invariant, or must-not-assume IDs.
  `known_non_findings[]` records component, optional sink, tool pattern,
  conditions, and `discharged_by[]` stable IDs; all fields must match for an
  exact route, so it is never unstructured or fuzzy prose. `known_misuses[]`
  supplies the structured basis for `VALID-HARDENING`.
- Automated triage must enforce provenance: an inferred record may suggest
  escalation but may never authorize a closing disposition, regardless of
  `model_status`. An accepted model must have `confidence.inferred: 0` and no
  inferred records; otherwise use `under-review` or `unratified-draft`.
- `outputs[].taint: same-as-input` is the machine form of the §1.8 default
  one-liner.
- `dependencies: []` is meaningful only with `dependency_policy:
  {zero_runtime_dependencies: true, provenance: ...}`.
- `dispositions` is a fixed enum — do not add project-specific dispositions;
  a finding that fits none is `MODEL-GAP` and triggers a prose revision (§1.16).
- `disposition_precedence` is the fixed §1.17 first-match order shown above;
  tooling must not use the presentation order of `dispositions` as precedence.
