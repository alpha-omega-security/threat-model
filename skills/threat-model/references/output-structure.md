# Output document structure (§4)

Referenced from [SKILL.md](../SKILL.md). Section numbers are shared across all files so cross-references (e.g., "see §4.8") resolve here.

---

## 4. Structure of the output document

Use these sections, in this order. Rename if the project has a strong house
style, but cover the same ground.

### 4.1 Header
- Project name, version/commit, date, author(s) of the threat model.
- **Version binding and reporting** — the model is versioned with the
  project (a report against version *N* is triaged against the model at
  *N*); §4.8 findings go to the project's disclosure channel, §4.3/§4.9
  findings are closed citing this document.
- **Status** — draft / under maintainer review / accepted, with the date.
- **Provenance legend** — a one-line key for the *(documented)* /
  *(maintainer)* / *(inferred)* tags used throughout.
- **Draft confidence** — a rough tag count, e.g., "29 documented / 0
  maintainer / 30 inferred", updated as questions are resolved.
- One-paragraph description of the project's purpose, written for someone who
  has never seen it.

### 4.2 Scope and intended use
- **Production intent.** State whether the project is intended for
  production use at all, or is a reference/educational/research
  implementation. If the maintainers say "reference only, use a hardened
  fork in production", the rest of the model is short: §4.8 collapses to
  correctness properties and everything else routes to §4.9.
- Primary intended use cases. Be concrete — "in-process compression of
  application data" beats "general compression library".
- Deployment contexts the project was designed for (in-process library? CLI
  tool? server? embedded? kernel?).
- Caller expectations: who is expected to call this, and at what trust level?
  For a **network service or daemon** (as opposed to an in-process
  library), there is rarely a single "caller" — typically the role
  splits into *client* (untrusted), *operator/admin* (trusted for the
  instance), and *peer* (authenticated but adversarial). Name each role
  here; they get separate rows in §4.6 and separate actors in §4.7.
- **Component-family table.** Carve the public surface into families with
  distinct threat profiles, one row each: family name, representative
  API/entry point, whether it touches anything outside the process
  (filesystem, network, env, child processes), and whether it is in or out
  of this model. Include a row for any **plugin/extension/hook loader**
  (loadable modules, user-defined functions, script hooks, webhooks); its
  trust ruling ("plugins are trusted-as-core" vs "plugin isolation is a
  claimed property") drives more triage disputes than any other single
  line. Lead with this table; anything marked out of model must reappear
  in §4.3 with the reason.

### 4.3 Out of scope (explicit non-goals)
- Use cases the project does *not* aim to support. State them, even if they
  seem obvious — they are obvious to the maintainer, not to a new integrator.
- Threats the project does not attempt to defend against, with the reason
  ("not a security boundary", "out of layer", "unsolvable at this layer", etc.).
- **Code that ships in the repository but is not covered by the model.**
  `contrib/`, `examples/`, `vendor/`, `third_party/`, demo apps, generated
  bindings. State the policy explicitly ("unsupported, separately
  authored, threat-model separately") so integrators do not extend the
  core's guarantees to them by association.

### 4.4 Trust boundaries and data flow
- Where the trust boundary sits (e.g., "API surface is the boundary; all
  bytes inside the library are assumed already-authenticated").
- The path data takes through the project, expressed as the trust transitions
  it crosses. Skip this section if the project is purely computational with
  no meaningful trust transitions; say so.
- **Reachability preconditions per component.** For each component family
  in the §4.2 table, state the condition a finding must meet to matter:
  *"a finding in `inflate.c` is in-model only if reachable from the
  compressed input bytes; a finding in `deflate.c` is in-model only if
  reachable from a caller-supplied dictionary."* This is the test a
  triager applies to a static-analysis or AI-reported hit before anything
  else.

### 4.5 Assumptions about the environment
Cover, where applicable:
- Operating system, runtime, hardware assumptions.
- Concurrency assumptions (thread-safety guarantees, reentrancy, signal-safety).
- Memory model assumptions (allocator behavior, alignment, sizeof guarantees).
- Time/clock assumptions.
- Filesystem, network, or peripheral assumptions.
- **What the project does *not* do to its host.** This is the
  "no-surprise side effects" inventory: does it open sockets? spawn
  processes? install signal handlers? read environment variables? write
  to stdout/stderr? touch global locale or FPU state? mutate process-wide
  state? An integrator embedding the project into a larger system needs
  this list as much as the positive assumptions.

  These are **negative claims**, rarely written down and hard to cite, so
  the inventory will be mostly *(inferred)* in a first draft; confirm it
  in wave 1 or 2.

### 4.5a Build-time and configuration variants
List the compile-time defines, feature flags, build options, or runtime
configuration knobs that **change which security properties hold.** For
each: the default, the effect on the model, and whether the maintainers
discourage it. (Examples from the zlib trial: `ZLIB_INSECURE` removes
`gzprintf` overflow protection; `BUILDFIXED` / `DYNAMIC_CRC_TABLE` remove
thread safety on pre-C11 toolchains.) If no such knobs exist, say so.

This is distinct from build hygiene (§1): "the project" is a family of
binaries or deployment modes, and the model must say which member it
describes.

**The insecure-default case.** When a knob's *default* is the value that
voids a §4.8 property (e.g., an auth gate shipping `enabled = false`),
ask in **wave 1** whether that default is the supported production
posture (reports against it are `VALID`) or a dev convenience operators
must flip (reports are `OUT-OF-MODEL: non-default-build`, and the flip
requirement appears in §4.10). Record the ruling here.

### 4.6 Assumptions about inputs
- What inputs the project accepts and from where it expects them to come.
- **Per-parameter trust table.** For every public entry point that accepts
  external data, one row per parameter:

  | Function | Parameter | Attacker-controllable? | Caller must enforce |
  | --- | --- | --- | --- |
  | `gzopen` | `path` | no — trusted caller string | path sanitization |
  | `gzread` | file contents | **yes** | output buffer ≥ `len` |
  | `gzprintf` | `format` | no — trusted literal | never source from input |

  For a **network service**, the first column is the route/endpoint or
  protocol message (e.g., `POST /v1/configuration`, `Handshake` frame)
  rather than a function name, and rows should cover headers and
  connection metadata as well as bodies — header-presence checks
  (`X-Forwarded-*`, auth tokens) are common false friends.

  Prose ("file contents may be attacker-controlled; format strings may
  not") is not sufficient for triage: tool and AI findings are reported
  against specific sinks, and the triager needs to look up the exact
  parameter.

  **Scaling rule.** For projects with hundreds of exported symbols, a
  per-parameter table is impractical. State the *default* trust level for
  the whole surface ("all parameters are trusted caller data unless listed
  below" or the reverse) and then tabulate only the exceptions. A one-line
  default plus a 12-row exception list is more useful for triage than an
  incomplete 400-row table.

- **Persisted state as input.** For any project that reads back its own
  data directory, cache, index, project file, or serialized session on
  startup or `open()`, add a row for that on-disk format. The question is
  whether an attacker who can write to that location (but has no other
  foothold) is in the model. This is where "opening a `.foo` file executes
  code" reports land (pickle, `yaml.load`, embedded macros, SQLite
  loadable extensions, editor project settings). If the on-disk format is
  trusted, say so here and add "do not open project files from untrusted
  sources" to §4.10.
- Size, shape, and rate assumptions (bounded? streaming? memory-mapped?).

### 4.6a Outputs and expected sinks
For projects whose *output* is consumed by another interpreter (template
engines, serializers, ORMs/query builders, shell wrappers, code
generators, structured loggers, header/URL builders), whether the emitted
data is safe for its sink is as much a security property as anything in
§4.6. For each such output:

| Output | Expected sink | Sink-safety guaranteed? | If not, caller must |
| --- | --- | --- | --- |
| rendered template | browser HTML context | **yes**, autoescaped | mark raw with `\|safe` deliberately |
| `.to_sql()` string | DB driver | no | use `.execute()` which parameterizes |
| log line | line-oriented log collector | no CR/LF stripping | sanitize user fields before logging |

A "no" in column 3 is a §4.9 disclaimed property and a §4.10 downstream
responsibility. A "yes" is a §4.8 claimed property with the usual
violation-symptom and severity fields. Omit this section for projects
whose output is opaque data with no downstream interpreter (e.g., a
compressor); say so.

### 4.6b Delegated and inherited surface
List the dependencies (linked, vendored, or shelled-out-to) that are
**reachable from a §4.6 attacker-controllable input**. Patch status,
provenance, and pinning stay out of scope per §1; the only fact recorded
here is, when this project hands attacker bytes to libfoo, whose bug a
crash in libfoo is.

For each reachable dependency, one line:

- which §4.6 input reaches it,
- whether the project **re-exports** the dependency's surface (findings
  are `VALID` here; the project owns the CVE and coordinates upstream) or
  **delegates** it (findings are `OUT-OF-MODEL: report-upstream`; this
  project ships the fix by bumping the dependency),
- which of the dependency's own disclaimed properties (its §4.9, if it
  has a model) become this project's §4.9 by inheritance.

Dependencies with no path from an attacker-controllable input are
omitted; if none are reachable, say so in one line.

### 4.7 Adversary model
- Who is the assumed attacker? (Network peer? User of the embedding app?
  Local process? Co-tenant?)
- What capabilities does the attacker have, and what do they not have?
- What is the attacker assumed to be trying to do? (Crash the host? Read
  memory? Smuggle data? Cause CPU exhaustion? Simply send malformed input?)
- Which actors are explicitly *not* in the model? ("Attackers with control
  over the calling process are out of scope — they have already won.")
- For projects with a **plugin or extension surface** (per the §4.2
  table), place "malicious plugin author" explicitly in or out. If
  plugins are trusted-as-core, a malicious plugin is out of scope for the
  same reason a malicious caller is; if plugin isolation is a claimed
  property, the plugin author is an in-scope adversary and the isolation
  boundary appears in §4.8.
- For projects commonly deployed **multi-tenant** (databases, queues,
  runners, notebook servers), place "authenticated co-tenant" explicitly
  in or out. Tenant-to-tenant isolation is either a §4.8 property or a
  §4.9 disclaimer; silence here is the source of most disputed reports
  against this class of project.
- For **distributed / replicated / consensus systems**, include the
  *authenticated-but-Byzantine participant* as a distinct actor: a peer
  who holds a legitimate identity, passes the handshake, and then
  behaves arbitrarily. State the honest-fraction threshold (e.g.,
  `< n/3`, `< ½ stake`) under which the model holds; put the threshold
  in the §4.8 "conditions" column and its complement ("≥ threshold
  Byzantine") in §4.3 as out of scope.

### 4.8 Security properties the project provides
For each property, state **four things**:

1. **The property** and the conditions under which it holds.
2. **Violation symptom** — what a break looks like in practice (crash,
   OOB read/write, information leak, hang, wrong output, unbounded
   allocation). This lets a triager map a fuzzer artifact or report
   symptom back to the property it violates.
3. **Severity tier** — one of:
   - `critical` (memory corruption, RCE, auth bypass, sandbox escape),
   - `high` (information disclosure: reading memory/files/secrets the
     adversary should not reach),
   - `moderate` (denial of service: hang, crash, unbounded resource use
     without further consequence),
   - `low` (correctness/quality only; ordinary bug tracker, no CVE).
   Adapt the labels to house style but keep at least these four bands so
   that "arbitrary write" and "uninitialized-read of padding bytes" do not
   land in the same bucket.
4. **Provenance tag**, as everywhere else.

**Language/runtime baseline.** State properties as the *delta* from what
the language and runtime already guarantee. "No out-of-bounds reads on
untrusted input" is a load-bearing §4.8 claim for a C library and is
noise for a pure-Python or safe-Rust project, where the runtime provides
it. Restating the runtime's guarantees as the project's pads the section
without informing triage. For memory-safe languages the section still has
work to do: the interesting §4.8 claims for a Rust crate concern panics
on adversarial input, `unsafe` blocks, FFI edges, and resource bounds
rather than the borrow checker.

Cover, where applicable:
- Memory/safety properties (no OOB reads/writes given size invariants from
  the API contract, etc.).
- Correctness properties (deterministic output, idempotency, round-trip
  fidelity).
- **Distributed-system properties** (safety, liveness, finality,
  ordering, replica consistency) where applicable. These are
  *network-wide* rather than single-process; the "conditions" field
  carries the honest-participant bound from §4.7, and the violation
  symptom is typically observable across nodes (fork, indefinite
  stall, divergent state hash) rather than on one host.
- Resource properties (bounded memory given bounded input, bounded CPU,
  no unbounded recursion). **State the threshold, not just the
  direction.** DoS reports are the most contested triage category;
  "bounded" is not actionable. Push the maintainer for a categorical or
  quantitative line — e.g., "super-linear in input size is a bug;
  constant-factor blowup is not", "a hang is a bug; slow is not", or "no
  resource guarantee is made at all".
- **Error and observability channel.** Whether error messages, stack
  traces, or timing of failure paths returned to an untrusted caller are
  considered information disclosure. For a library this is usually N/A
  (errors go to the trusted caller); for a service it is a recurring
  dispute and needs a ruling.
- Confidentiality / integrity / availability properties, if any.

A property only counts if the project has actually committed to it — either
in docs, in tests, or in maintainer statement. Do not invent properties.

### 4.9 Security properties the project does *not* provide
The companion to §4.8. State each plainly. Examples (project-dependent):
- "No constant-time guarantees; do not use for secret comparison."
- "Not safe against adversarially-crafted inputs designed to maximize
  CPU/memory cost (no compression-bomb defense)."
- "No authentication of input data; the caller must verify integrity before
  calling."
- "Not designed for use across a security boundary within a single process."
- "Error responses may include stack traces / input echoes; deploy behind a
  layer that strips them if that matters."

Within this section, **call out "false-friend" properties separately** —
features that *look like* a security property but are not one. The
canonical shape is "X is provided for purpose A; it is sometimes mistaken
for purpose B, which it does not satisfy." (Examples: a CRC that looks
like an integrity guarantee but is not a MAC; a non-cryptographic hash
that looks collision-resistant; a PRNG that looks like a CSPRNG; a
"sandbox" mode that isolates resources but not security.) These are the
single highest-value statements for a downstream integrator, because they
correct an assumption the integrator is likely to bring with them.

Also name **well-known attack classes against this category of project**
that the project itself cannot defend against and leaves to the caller
(e.g., compression-oracle attacks for compression libraries, XXE for XML
parsers, ReDoS for regex engines, billion-laughs for recursive-format
parsers). One sentence per class is enough to put the integrator on
notice.

### 4.10 Downstream responsibilities
A short, action-oriented list of what the *user* of the project must do in
order for the assumptions in §4.5–§4.7 to hold. For a library, "user"
means the embedding application; for a service/daemon, it means the
**operator/deployer** (and, if SDKs ship, separately the SDK
integrator). Every §4.5a knob whose default the maintainer has
designated dev-only must reappear here as "set X before exposing the
service." This is not a how-to guide; it is a contract. ("Validate that input length fits the documented bounds
before calling X." "Do not expose the API surface directly to untrusted
network peers." "Re-key on a schedule appropriate to the data lifetime.")

### 4.11 Known misuse patterns
Common ways the project is or has been misused, even though the API permits
them. Examples:
- Passing untrusted data to an interface intended for trusted data.
- Using the project as a security boundary when it is not one.
- Exceeding documented size or recursion limits.
- Mixing modes/contexts that the project does not synchronize.

**In a draft**, one-liners are acceptable — capture the inventory first.
**Before publishing**, expand each entry to *what the misuse looks like*,
*why it is unsafe*, *what to do instead*. No need to attribute or shame;
just describe.

### 4.11a Known non-findings (recurring false positives)
The mirror of §4.11: patterns that scanners, fuzzers, AI analyzers, or
human reviewers repeatedly flag against this project that are **not**
bugs given the model. For each: what the tool reports, why it is safe
under the model (cite the §4.6 trust assumption or §4.8 invariant that
discharges it), and — where helpful — the suppression pattern.

Examples of the shape:
- "`strcpy` at `foo.c:NN` — length is bounded by the 4-byte header field
  parsed at `foo.c:MM`; per §4.8 the header is validated before this
  point."
- "Unchecked `malloc` return in `examples/` — out of scope per §4.3."
- "Integer overflow on `len * 2` — `len` is capped to 2^28 by the API
  contract per §4.6."
- "Prototype pollution on the options object — the object never reaches a
  property lookup on attacker-chosen keys; per §4.6 `options` is trusted
  caller data."
- "ReDoS in the config-file parser — config is operator-trusted per §4.6;
  adversary cannot supply it."

This section is the highest-leverage input for automated or AI-assisted
triage: it can be fed back verbatim as a suppression list or negative
prompt. Keep it current as new tools produce new noise.

### 4.12 Conditions that would change this model
List the kinds of changes that should trigger a revision: e.g., a new public
API, accepting a new input format, gaining a network surface, taking on a
new deployment context, a change in default for a §4.5a build knob, a
shipped-but-unsupported component being promoted into core, or a §4.6b
dependency changing its own threat model (a property this project
inherits being newly disclaimed upstream).

Also list **evidence that the model is incomplete** as a trigger: a
report that cannot be routed to a §4.13 disposition is a `MODEL-GAP`, and
the response is to add the property to §4.8 or §4.9 rather than make an
ad-hoc call, so future maintainers do not drift from the model unnoticed.

### 4.13 Triage dispositions
Enumerate the **closed set of outcomes** a vulnerability report, tool
finding, or AI analysis can receive when judged against this model. Each
disposition cites the section that licenses it, so the triager's response
is "see threat model §X" rather than ad-hoc prose.

| Disposition | Meaning | Licensed by |
| --- | --- | --- |
| `VALID` | Violates a property the project claims, via an in-scope adversary and input. | §4.8, §4.6, §4.7 |
| `VALID-HARDENING` | No §4.8 property is violated, but the API makes a §4.11 misuse easy enough that the project elects to harden it. Reported privately; fixed at maintainer discretion; typically no CVE. | §4.11 |
| `OUT-OF-MODEL: trusted-input` | Requires attacker control of a parameter the model marks trusted. | §4.6 |
| `OUT-OF-MODEL: adversary-not-in-scope` | Requires an attacker capability the model excludes. | §4.7 |
| `OUT-OF-MODEL: unsupported-component` | Lands in `contrib/`, `examples/`, or other code placed out of scope. | §4.3 |
| `OUT-OF-MODEL: non-default-build` | Only manifests under a discouraged or non-default §4.5a flag. | §4.5a |
| `OUT-OF-MODEL: report-upstream` | Lands in a §4.6b dependency whose surface this project delegates rather than re-exports. Reporter is redirected; this project ships the fix by updating the dependency. | §4.6b |
| `BY-DESIGN: property-disclaimed` | Concerns a property the project explicitly does not provide. | §4.9 |
| `KNOWN-NON-FINDING` | Matches a documented recurring false positive. | §4.11a |
| `MODEL-GAP` | Cannot be cleanly routed to any of the above. | triggers §4.12 |

Adapt the labels to house style, but keep the set closed and the section
citations intact: a finding that fits nowhere is `MODEL-GAP`, not
"other".

### 4.14 Open questions for the maintainers
Required while any *(inferred)* tags remain; may be dropped once the model
is fully ratified. For each question:

- State the **proposed answer** alongside the question, so the maintainer
  can confirm, correct, or strike it rather than compose from scratch.
- Note which section of the model the answer will land in.
- Group into waves of 3–7 (per §3.2) so the maintainer can respond to one
  wave at a time.

**Mapping rule.** Every *(inferred)* tag in the body **must** route to a
question here. The reverse is not required: questions probing the edges
of a *(documented)* claim, or meta questions about ownership and
publication, are also allowed. When a question is answered, promote the
matching body tag(s) and delete the question.

### 4.15 Optional: machine-readable companion
Where triage will be automated or AI-assisted, emit a sidecar (e.g.
`threat-model.yaml`) alongside the prose document containing only the
triage-relevant facts in structured form. The prose document remains
canonical; the sidecar is a derived index for tooling. Regenerate it
whenever the prose changes.

Minimal shape (adapt field names to house style, keep the top-level keys
so sidecars are comparable across projects):

```yaml
project: <name>
model_version: <commit-or-tag>
components:
  - {name: core, in_scope: true}
  - {name: contrib/, in_scope: false, reason: §4.3}
inputs:
  default_trust: trusted        # or 'untrusted'; §4.6 scaling rule
  exceptions:
    - {entry: gzread, param: file_contents, attacker_controllable: true}
delegated_surface:
  - {dependency: libxml2, reached_from: [parse], ownership: report-upstream}
build_flags:
  - {name: ZLIB_INSECURE, default: off, discouraged: true}
properties_claimed:
  - {id: mem-safety-untrusted-decode, severity: critical}
properties_disclaimed: [decompression-bomb-defense, constant-time]
non_findings:
  - {pattern: strcpy in gzlib.c, discharged_by: §4.6}
```

