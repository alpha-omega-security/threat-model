# Reference JSON report schema — `threat-model.json`

An orchestrated run publishes three artifacts, in strict order of authority:

1. `docs/threat-model.md` — the prose model. **Canonical.**
2. `threat-model.yaml` — the `threat-model-sidecar/v2` index. Near-lossless.
3. `threat-model.json` — a flat export conforming to the repo-root
   `schema.json` (draft 2020-12, `spec_version: 1`). **Lossy.**

**Prose > yaml > json.** The JSON is an export for external consumers that
speak `schema.json`, not a replacement for either sibling. A JSON-only
consumer holds strictly less information, and the mapping below is built so
that everything the JSON loses pushes that consumer toward *escalating*,
never toward *closing*. That asymmetry is the point of every rule on this
page.

The file lives at `threat-model.json` in the repo root, beside
`threat-model.yaml` (inside `subdir` when the run is scoped to a
subdirectory, exactly like the YAML). Regenerate it whenever the prose or
the sidecar changes. Unlike the sidecar it carries no `prose_version` hash —
it is bound to the modeled tree only by `repository` + `commit` + `date`, so
record the commit with `git rev-parse HEAD` in the tree the model describes.

## Provenance collapse — the safety-critical rule

`schema.json` has two provenance values (`documented` | `inferred`). The
model has four. The collapse is not cosmetic: in this system provenance
decides whether a claim may close a report.

| sidecar `provenance.kind` | → JSON `provenance` | JSON `source` |
| --- | --- | --- |
| `documented` | `documented` | the documented source (`file:line` or URL) |
| `maintainer` | `documented` | `maintainer ruling, YYYY-MM` |
| `assumption` | `inferred` | the question id, e.g. `open question Q4` |
| `inferred` | `inferred` | the question id, e.g. `open question Q4` |

The reasoning: JSON's binary axis really asks *"does this claim carry
authority to close a report?"* `documented` and `maintainer` do, under every
policy. `assumption` closes only under a `relaxed` triage policy, only for a
low-blast-radius route, and never above the security-critical floor — and
the JSON has no field for any of those three conditions. So it collapses
**down**, to `inferred`.

> **Hard rule, validator-enforced** (`JSON.provenance-fail-safe`): a record
> whose sidecar provenance is `assumption` or `inferred` must never appear
> in the JSON as `documented`. That direction hands a JSON-only consumer a
> licence the model never granted. The reverse — a `documented`/`maintainer`
> claim appearing as `inferred` — is merely over-conservative and is
> allowed, though do not do it gratuitously.

**Many records, one object.** `environment` and `adversaries` are single
objects in `schema.json` but collapse many sidecar records, each with its
own provenance. The object takes the **weakest of the set**: if any
contributing record is `inferred` or `assumption`, the whole block is
`inferred`.

**`confidence`.** The JSON block is `{documented, inferred}` only. Collapse
the same way: `documented` = sidecar `documented` + `maintainer`;
`inferred` = sidecar `inferred` + `assumption`. It must equal the §1.1
header counts collapsed identically. Golden zlib: sidecar
`{documented: 68, maintainer: 0, inferred: 7}` → JSON
`{documented: 68, inferred: 7}`. The block is optional in the schema —
emit it anyway; it is how a consumer sees how much of the model is
unratified.

## Nine JSON labels for ten dispositions

`schema.json`'s `dispositions` array must hold exactly nine values
(`minItems: 9, maxItems: 9, uniqueItems`), verbatim. The model's closed set
has ten.

| §1.17 disposition | JSON value |
| --- | --- |
| `VALID` | `valid` |
| `VALID-HARDENING` | `valid_hardening` |
| `OUT-OF-MODEL: trusted-input` | `out_of_model_trusted_input` |
| `OUT-OF-MODEL: adversary-not-in-scope` | `out_of_model_adversary` |
| `OUT-OF-MODEL: unsupported-component` | `out_of_model_unsupported_component` |
| `OUT-OF-MODEL: non-default-build` | `out_of_model_non_default_build` |
| `OUT-OF-MODEL: dependency-contract` | *(no JSON value)* |
| `BY-DESIGN: property-disclaimed` | `by_design_disclaimed` |
| `KNOWN-NON-FINDING` | `known_non_finding` |
| `MODEL-GAP` | `model_gap` |

**`OUT-OF-MODEL: dependency-contract` has no JSON label.** A JSON-only
consumer that meets such a finding matches no disposition and falls through
to `model_gap`, which escalates. That is the safe direction: a dropped route
that escalates costs a human a look; a dropped route that closed would
silence a real report. So the export complies with the schema as written
instead of extending it, and the prose and YAML stay canonical for that
route. This gap is deliberate and stated here because silently dropping it
is what would make it dangerous.

## Field mapping

Top-level `additionalProperties: false` — no `x-` extensions are possible.

Authored fields, no sidecar source:

| JSON field | Source | Notes |
| --- | --- | --- |
| `spec_version` | constant | always integer `1` |
| `repository` | the run's target URL | `format: uri` |
| `commit` | `git rev-parse HEAD` in the modeled tree | `^[0-9a-f]{7,40}$`; never a placeholder |
| `date` | date the model was written | `YYYY-MM-DD` |
| `scope_subpath` | the run's `subdir`, else `null` | |
| `description` | §1.2 intended use | markdown; a short paragraph, not the whole model |

Required fields projected from the sidecar:

| JSON field | Sidecar source | Mapping |
| --- | --- | --- |
| `components` | `components[]` where `scope: in` | see below |
| `out_of_scope` | `components[]` where `scope: out` | `{item, reason, provenance}`; or `{not_applicable: true, reason}` when nothing is carved out |
| `trust_boundaries` | §1.4 + `components[].reachability_precondition` | `{component, boundary, reachability_precondition, provenance}`; `minItems: 1`. The boundary's provenance is §1.4's, not the component's — a row may claim `documented` only when §1.4 itself carries a documented or maintainer tag |
| `entry_points` | `entry_points[].parameters[]` | flattened, see below |
| `environment` | §1.5 + §1.10 | `{assumes[], does_not[], provenance}`; weakest provenance of the contributing claims |
| `adversaries` | `adversaries[]` | `{in_scope: names, out_of_scope: names, provenance}`; `threshold` only for replicated/quorum systems |
| `properties_provided` | `properties_claimed[]` | see below |
| `properties_not_provided` | `properties_disclaimed[]` | `{property: id, reason: conditions, false_friend, provenance}` |
| `downstream_responsibilities` | `downstream_responsibilities[].statement` | plain strings; IDs and `enforces[]` are lost |
| `known_misuse` | `known_misuses[]` | `{pattern, why_unsafe, instead: safer_alternative}`; `why_unsafe` is authored from the §1.14 prose; or `not_applicable` |
| `known_non_findings` | `known_non_findings[]` | see below — the dangerous one |
| `dispositions` | fixed | all nine values above |
| `open_questions` | §1.18 | `{claim, field, proposed}`; `field` names the **JSON field** the answer lands in (the JSON echo of §1.18's "Lands in: §1.11") |

Optional fields:

| JSON field | Sidecar source | Mapping |
| --- | --- | --- |
| `confidence` | `confidence` | collapsed as above; emit it |
| `build_variants` | `build_flags[]` | `{name, default, effect, discouraged, provenance}`; `effect` is prose derived from `affects_properties[]` (e.g. `"narrows configured-window-memory-bound"`); `discouraged: true` iff `maintainer_stance` is `discouraged` or `unsupported`; or `not_applicable` |
| `attack_classes` | §1.10 goals / attack classes | array of strings, or `not_applicable` |
| `scan_config` | §1.3 / §1.7 / §1.15 | scanner-steering hints; emit only when the model actually supports them |

### `components[]` and `touches`

```
{name, entry_points: [ids], touches: [enum], in_scope: true, reason?, provenance, source?}
```

Only `scope: in` components go here; `scope: out` goes to `out_of_scope`.
The schema would let an out-of-scope component sit in `components` with
`in_scope: false` — do not do that. `out_of_scope` is required, and
splitting the list makes the same fact appear twice with no rule for which
wins.

`entry_points` lists the `entry_points[].id` values whose `component` is
this one.

`touches` maps from the §1.5 `host_side_effects[]` inventory. Emit a value
only for effects whose `stance` is `present` or `conditional` for that
component. **`absent` produces nothing** — that is the whole point of the
§1.5 inventory.

| sidecar `effect` | JSON `touches` |
| --- | --- |
| `filesystem` | `filesystem` |
| `network-sockets`, `network` | `network` |
| `environment-reads`, `env` | `env` |
| `child-processes`, `subprocess` | `child_processes` |
| `signal-handlers`, `signals` | `signals` |
| `global-state`, `process-state` | `global_state` |

A `present`/`conditional` effect that maps to none of the six enum values
has no JSON home; it stays in the YAML. Do not force it into a near-miss
bucket.

### `entry_points[]` — flattened

The sidecar nests parameters under entry points. The JSON is one row per
**(entry point × parameter)**:

```
{entry_point, parameter, attacker_controllable, condition?, caller_must_enforce?, component, provenance, source?}
```

`attacker_controllable` is `no` (sidecar `false`), `yes` (sidecar `true`,
unconditionally), or `conditional` (controllability depends on a stated
condition — then `condition` is **required**). `schema.json` states the
`condition` requirement only in a `description`, with no `if`/`then`, so the
validator enforces it (`JSON.conditional-has-condition`).

`caller_must_enforce` carries over verbatim, including the
`none — <property ID>` form. `control_kinds` and `obligation_id` have no
JSON home.

### `properties_provided[]`

```
{property: id, conditions?, violation_symptom, severity_tier, provenance, source?}
```

- `violation_symptom` is singular; join the sidecar's
  `violation_symptoms[]` with `", "`.
- `severity_tier`: `security-critical` → `security`;
  `correctness-only` → `correctness`.
- The sidecar's `kind` (memory-safety / integrity / …) has no JSON home.

### `known_non_findings[]` — the dangerous loss, and the rule that contains it

```
{reported_as, why_safe, cites?, suppression?}
```

The JSON non-finding drops `components` and `symptom` — exactly the two
fields §1.15 requires so that a known non-finding cannot suppress
everything. A precedence-rule-1 entry that matches anywhere matches every
report. This is the one place where the lossy direction is *unsafe*, so it
gets a containment rule, validator-enforced (`JSON.non-finding-scoped`):

- `reported_as` = the sidecar `tool_pattern` — what the tool says.
- `why_safe` **must name, in text, both (a) the in-scope components it
  covers and (b) the violation symptom it discharges.** It is the only
  field left that can carry the scope.
- `cites` **must** point at the discharging claim inside this document, in
  the schema's "JSON pointer-ish" style: `properties_provided[3]`,
  `properties_not_provided[1]`, or `out_of_scope[0]`. It must resolve to a
  real index in this document.
- `suppression` = the sidecar `conditions` — when the suppression applies.

## What the JSON does not carry

The JSON is not the model. It drops:

- `triage_policy` and `model_status`
- `prose_version` — the JSON has no binding to the prose bytes it came
  from, only `commit` + `date`
- `generation` metadata
- `contract_dimensions` — all eight, per component
- disclaimed-property **tiers** — so the assumption security-critical floor
  is invisible
- `obligation_id` and `control_kinds`
- the entire `dependencies[]` / `dependency_policy` edge model
- `disposition_precedence` — so a consumer cannot even apply first-match
  ordering
- `known_non_findings[].components` and `.symptom` (contained as above)

The consequence: **a consumer cannot triage from `threat-model.json`
alone.** It can tell you what the contract says; it cannot tell you how to
route a report against it. `threat-model-triage` keeps reading the prose
and the YAML.

## Worked example — zlib golden fixture

Derived from `tests/fixtures/golden/zlib/threat-model.yaml` and its prose.
Note the collapses at work: `environment` and `adversaries` are `inferred`
because their weakest contributor is; `touches` is empty for the pure
in-memory components because §1.5 records those effects `absent`; every
`why_safe` names its components and symptom; every `cites` resolves to the
claim that actually discharges its entry.

```json
{
  "spec_version": 1,
  "repository": "https://github.com/madler/zlib",
  "commit": "51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf",
  "date": "2026-08-07",
  "scope_subpath": null,
  "description": "In-process compression and decompression of application data, linked directly into a host program. zlib ships as a library with no daemon or privileged mode. The caller is trusted for the process; the compressed input bytes are the untrusted surface.",
  "confidence": {"documented": 68, "inferred": 7},

  "components": [
    {"name": "core-inflate", "entry_points": ["inflate", "inflateInit2"], "touches": [], "in_scope": true, "provenance": "documented", "source": "zlib manual"},
    {"name": "core-deflate", "entry_points": [], "touches": [], "in_scope": true, "provenance": "documented", "source": "zlib manual"},
    {"name": "gzip-file-api", "entry_points": ["gzopen"], "touches": ["filesystem"], "in_scope": true, "provenance": "documented", "source": "zlib manual"}
  ],
  "out_of_scope": [
    {"item": "contrib-samples", "reason": "third-party samples, unsupported per §1.3", "provenance": "inferred", "source": "open question Q2"},
    {"item": "examples-demos", "reason": "examples/ demonstration programs, not the supported library surface per §1.3", "provenance": "documented", "source": "zlib source layout"}
  ],
  "trust_boundaries": [
    {"component": "core-inflate", "boundary": "compressed input bytes are attacker-controlled; caller buffers, lengths, and window arguments are trusted", "reachability_precondition": "reachable from compressed input bytes", "provenance": "inferred", "source": "open question Q1"},
    {"component": "core-deflate", "boundary": "input is caller-supplied plaintext; the caller is trusted for the process", "reachability_precondition": "reachable from caller-supplied plaintext", "provenance": "inferred", "source": "open question Q1"},
    {"component": "gzip-file-api", "boundary": "compressed bytes cross the boundary through a gz* handle over a caller-named file", "reachability_precondition": "reachable from gz* handle over caller-named file", "provenance": "inferred", "source": "open question Q1"}
  ],
  "entry_points": [
    {"entry_point": "inflate", "parameter": "next_in/avail_in", "attacker_controllable": "yes", "caller_must_enforce": "none — memory-safety-untrusted-input", "component": "core-inflate", "provenance": "documented", "source": "inflate API contract"},
    {"entry_point": "inflate", "parameter": "next_out/avail_out", "attacker_controllable": "no", "caller_must_enforce": "buffer >= claimed size; honor avail_out", "component": "core-inflate", "provenance": "inferred", "source": "open question Q4"},
    {"entry_point": "inflateInit2", "parameter": "windowBits", "attacker_controllable": "no", "caller_must_enforce": "within documented range", "component": "core-inflate", "provenance": "inferred", "source": "open question Q4"},
    {"entry_point": "gzopen", "parameter": "path", "attacker_controllable": "no", "caller_must_enforce": "validate/sanitize path before passing", "component": "gzip-file-api", "provenance": "documented", "source": "gzopen API contract"}
  ],
  "environment": {
    "assumes": [
      "hosted C runtime with a caller-provided allocator (zalloc/zfree)",
      "external synchronization for a shared z_stream"
    ],
    "does_not": [
      "open sockets",
      "spawn child processes",
      "install signal handlers",
      "touch the filesystem outside the gzip file API"
    ],
    "provenance": "inferred",
    "source": "open question Q5"
  },
  "build_variants": [
    {"name": "ZLIB_CONST", "default": "off", "effect": "changes API shape only; no effect on the security model", "discouraged": false, "provenance": "documented", "source": "zlib build documentation"},
    {"name": "custom-MAX_WBITS", "default": "shipped default", "effect": "narrows configured-window-memory-bound", "discouraged": false, "provenance": "documented", "source": "zlib build documentation"}
  ],
  "adversaries": {
    "in_scope": ["compressed-input-author"],
    "out_of_scope": ["in-process-caller"],
    "provenance": "inferred",
    "source": "open question Q1"
  },

  "properties_provided": [
    {"property": "memory-safety-untrusted-input", "conditions": "any input on a supported platform", "violation_symptom": "crash, oob-read, oob-write", "severity_tier": "security", "provenance": "documented", "source": "zlib manual"},
    {"property": "integrity-check-on-decode", "conditions": "caller has not called inflateValidate(strm, 0)", "violation_symptom": "wrong-output", "severity_tier": "security", "provenance": "documented", "source": "zlib manual, inflate check-value description"},
    {"property": "output-bound-honored", "conditions": "single call with valid output buffer", "violation_symptom": "buffer-overflow", "severity_tier": "security", "provenance": "documented", "source": "inflate API contract"},
    {"property": "termination", "conditions": "valid or invalid input", "violation_symptom": "hang, infinite-loop", "severity_tier": "security", "provenance": "documented", "source": "zlib manual"},
    {"property": "stream-lifecycle", "conditions": "documented init/end or open/close sequence", "violation_symptom": "invalid-state", "severity_tier": "correctness", "provenance": "documented", "source": "zlib manual"},
    {"property": "independent-stream-thread-safety", "conditions": "streams are independent", "violation_symptom": "data-race", "severity_tier": "correctness", "provenance": "documented", "source": "zlib FAQ"},
    {"property": "configured-window-memory-bound", "conditions": "internal window allocation is bounded by configured MAX_WBITS", "violation_symptom": "allocation-exceeds-configured-bound", "severity_tier": "correctness", "provenance": "documented", "source": "zlib build documentation"}
  ],
  "properties_not_provided": [
    {"property": "confidentiality-integrity-authenticity", "reason": "all supported configurations", "false_friend": false, "provenance": "documented", "source": "zlib manual"},
    {"property": "crc-as-mac", "reason": "all supported configurations", "false_friend": true, "provenance": "documented", "source": "zlib manual"},
    {"property": "decompression-bomb-resistance", "reason": "no caller output budget", "false_friend": false, "provenance": "documented", "source": "zlib manual"},
    {"property": "failure-state-atomicity", "reason": "operation returns failure", "false_friend": false, "provenance": "documented", "source": "zlib manual"},
    {"property": "trusted-callback-safety", "reason": "caller allocator violates its contract", "false_friend": false, "provenance": "documented", "source": "zlib manual"},
    {"property": "resource-budgeting", "reason": "caller-selected memory level", "false_friend": false, "provenance": "documented", "source": "zlib manual"},
    {"property": "shared-stream-thread-safety", "reason": "shared handle without synchronization", "false_friend": false, "provenance": "documented", "source": "zlib FAQ"}
  ],
  "attack_classes": ["memory-corruption", "resource-exhaustion"],

  "downstream_responsibilities": [
    "cap total decompressed output",
    "treat output as untrusted",
    "synchronize shared stream access"
  ],
  "known_misuse": [
    {"pattern": "using CRC-32 for authentication", "why_unsafe": "Adler-32 and CRC-32 detect accidental corruption, not tampering", "instead": "use a MAC"},
    {"pattern": "decompressing without an output cap", "why_unsafe": "bounding decompressed size is the caller's responsibility", "instead": "enforce an output budget"}
  ],
  "known_non_findings": [
    {"reported_as": "OOM on crafted stream without an output cap", "why_safe": "Against core-inflate, unbounded-allocation is the disclaimed decompression-bomb-resistance property: capping decompressed output is the caller's job.", "cites": "properties_not_provided[2]", "suppression": "no output budget and no memory-safety violation"},
    {"reported_as": "CRC/Adler collision or forgery report", "why_safe": "Against gzip-file-api, integrity-bypass is the disclaimed crc-as-mac property: the checksums detect corruption, not tampering.", "cites": "properties_not_provided[1]", "suppression": "report assumes checksum authenticity rather than memory corruption"},
    {"reported_as": "MSan/Valgrind use-of-uninitialized-value in the deflate match loop", "why_safe": "Against core-deflate, an uninitialized-read that stays inside a zlib allocation does not breach the claimed memory-safety-untrusted-input property.", "cites": "properties_provided[0]", "suppression": "the value never affects deflate output and the read stays inside a zlib allocation"}
  ],

  "dispositions": [
    "valid",
    "valid_hardening",
    "out_of_model_trusted_input",
    "out_of_model_adversary",
    "out_of_model_unsupported_component",
    "out_of_model_non_default_build",
    "by_design_disclaimed",
    "known_non_finding",
    "model_gap"
  ],
  "open_questions": [
    {"claim": "the untrusted surface is exactly the compressed input bytes, with every sizing argument caller-trusted", "field": "trust_boundaries", "proposed": "yes"},
    {"claim": "contrib/ is unsupported for security purposes", "field": "out_of_scope", "proposed": "yes; reports there close as out_of_model_unsupported_component"},
    {"claim": "downstream well-formedness is disclaimed for every output grammar", "field": "properties_not_provided", "proposed": "yes; output is exactly as untrusted as its input"},
    {"claim": "the caller-trusted classification of next_out and windowBits is complete", "field": "entry_points", "proposed": "yes; the caller owns both"},
    {"claim": "there are no host side-effects beyond those listed", "field": "environment", "proposed": "no — no sockets, child processes, or signal handlers, and no filesystem access outside the gzip file API"}
  ]
}
```

Two dispositions from the sidecar do not survive the export:
`OUT-OF-MODEL: dependency-contract` (no JSON label; falls through to
`model_gap`, which escalates) and the caller-supplied-allocator dependency
edge that licensed it. Both stay in the YAML and the prose, which remain
canonical.
