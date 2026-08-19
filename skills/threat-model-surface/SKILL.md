---
name: threat-model-surface
description: >-
  Perform phase 3.3 deep analysis of an in-scope attack surface for a threat
  model. USE WHEN the orientation brief is ready and code must be read to derive
  the §1.7 per-input trust table and contract-dimension matrix, §1.5
  no-surprise side-effects inventory, §1.4 reachability preconditions, and §1.8
  output taint. Reads public entry points for contract rather than defects,
  timeboxes each component family, and marks uncovered surface inferred.
  Produces a surface analysis. Read-only. DO NOT USE FOR: bug hunting, code
  review, orientation, or drafting the prose model.
argument-hint: '<in-scope component families to read>'
---

# Threat Model — Surface (deep pass on the in-scope surface)

Phase 3.3. The orient pass was minutes; this is **hours, and that is expected**.
Three of the output's most valuable artifacts cannot be produced any other way:

- the **per-input-operand trust table** (§1.7), which requires reading each
  in-scope entry point far enough to say which direct parameters and indirect
  inputs an attacker can reach and what the caller must enforce; and
- the **contract-dimension matrix** (§1.7-§1.12), which prevents silence about
  failure behavior, representational limits, executable collaborators, object
  topology, and lifecycle edge cases from becoming downstream `MODEL-GAP`
  findings; and
- the **no-surprise side-effects inventory** (§1.5) — negative claims about what
  the project does to its host that cannot be established by reading docs.

Read [principles.md](../threat-model/references/principles.md) and the §1.5 /
§1.7 / §1.8 specs in
[output-structure.md](../threat-model/references/output-structure.md) first.

## Rules for keeping the cost bounded

- **Scope by the recon carve.** Read only the entry points of in-model families.
  Do not read `contrib/`, examples, or out-of-scope families beyond confirming
  they are separable.
- **Read for contract, not for bugs.** At each entry point the question is
  *"which of these parameters can an attacker control, what kind of control is
  it, and what contract applies at edge conditions?"* — not *"is this code
  correct?"* Record whether behavior is guaranteed, disclaimed, or unresolved;
  do not test whether the implementation satisfies it. The moment the reading
  turns into review, **stop** and move on.
- **Timebox per family.** If a family's surface is too large to table in budget
  (e.g., a service with 100+ routes), table the highest-exposure subset, mark the
  remainder *(inferred, QN)* with a coverage note, and raise completing the table as
  an open question / follow-up — do **not** silently generalize.
- **Record hypotheses as you go**, in draft form with provenance tags. Preserve
  **documented** provenance for explicit normative public contracts. Code,
  implementation comments, and tests that merely suggest an unwritten contract
  remain *(inferred, QN)* until a maintainer ratifies them.
- **Read code as a behavioural oracle, not just as a second-class doc.** Mining
  comments and headers tells you what the project *says*; it cannot tell you
  where a guarantee stops. Every `security-critical` property needs its
  **off-switches** found by reading statements: the API call that relaxes a
  check, the flag that removes one, the mode that trades it for speed. Cite each
  as `<file>:<line>` at the statement that implements it. A comment describing
  the function does not qualify — the check that matters may have no comment at
  all, which is exactly why comment-harvesting misses it.
  These are easy to walk past because they are **not input operands**: no
  attacker-controlled parameter appears, so an input-shaped reading of the API
  sees nothing. They are property switches. Grep for names built on *validate*,
  *undermine*, *relax*, *skip*, *permit*, *trust*, *unsafe*, *strict*, and
  *sane*, then read what each one assigns.
- **Search the whole shipped build, not the files you happen to have open.**
  Scope every switch hunt to the source set the supported build compiles —
  including the build scripts, which is where platform-conditional and
  default-on options live. A search restricted to the public header and one
  implementation file will miss a compile-time switch that replaces an entire
  function, and it will miss it silently.
- **Report a negative as a command plus its result**, so the next reader can
  re-run it in one paste: `grep -rn 'PATTERN' <file set>` — *N hits, all in X*.
  "I searched and found nothing" is not reviewable and has been wrong every
  time it has been checked.
- **Cite harder before tagging inferred.** Before marking a row **inferred**,
  check the API docs, header comments, Javadoc/`package-info`, manpage, and
  `README` — a fact stated there is *(documented, source)*, not inferred. Turning
  a false-inferred into a true-documented row is pure accuracy and directly
  reduces the escalation count.
- **Disclaim demonstrably-absent guarantees rather than leaving them open.** When
  the reading shows a family makes **no** thread-safety, resource-bound, or
  failure-atomicity guarantee, that absence is verifiable — record the matrix row
  as `disclaimed` with *(documented, source)*, routing to §1.12, not as
  `unresolved`. Reserve `unresolved` / **inferred** for dimensions where a
  guarantee **plausibly exists** but you could not confirm it. Where you must
  reason past the verifiable to a clear safe default, tag *(assumption, QN)*
  rather than *(inferred, QN)*.

## Build the per-input-operand trust table (§1.7)

One row per direct parameter and each security-relevant indirect input of every
public entry point:

| Function | Input operand | Attacker-controllable? | Control kind | Caller must enforce | Provenance |
| --- | --- | --- | --- | --- | --- |
| `gzopen` | `path` | no — trusted caller string | data, resource-name | path sanitization | *(documented, gzopen contract)* |
| `gzread` | file contents | **yes** | data, size | output buffer >= `len` | *(inferred, Q4)* |
| `gzprintf` | `format` | no — trusted literal | x-format-string | never source from input | *(inferred, Q5)* |

For a **network service**, the first column is the route/endpoint or protocol
message (`POST /v1/configuration`, `Handshake` frame), and rows must cover
**headers and connection metadata** as well as bodies — header-presence checks
(`X-Forwarded-*`, auth tokens) are common false friends. Group rows by component
family if the table grows large. Prose is not sufficient: tool/AI findings are
reported against specific sinks, and the triager must look up the exact parameter.

Do not collapse all control into a boolean. Use one or more **control kinds**:
`data`, `size/rate`, `type/class`, `callback/code`, `object-graph topology`,
`collaborator implementation`, `resource-name`, `serialized state`,
`credential` (a secret presented to authenticate), `principal` (an identity,
tenant, or role an authorization decision reads), or a project-specific `x-`
kind. Distinguish an attacker choosing data passed through a trusted callback
from an attacker choosing the callback itself — and an attacker supplying a
record ID or role name from one merely supplying data, because the former is
what an authorization guard has to evaluate.

Also capture size/shape/rate assumptions (bounded? streaming? memory-mapped?),
and flag any input whose magnitude drives resource allocation (memory, threads,
file handles) — that feeds the §1.11 resource-property threshold.

## Build the contract-dimension matrix (§1.7-§1.12)

For every in-scope component family, fill every applicable row. A blank cell is
not allowed:

| Dimension | Status | Conditions / boundary | Routes to | Provenance |
| --- | --- | --- | --- | --- |
| numeric domain and representational limits | claimed / disclaimed / N/A / unresolved | maximum size, overflow behavior, normalization domain | §1.11 / §1.12 / §1.18 | *(inferred, QN)* or cited documented/maintainer source |
| failure and exception atomicity | claimed / disclaimed / N/A / unresolved | state after validation or callback failure | §1.11 / §1.12 / §1.18 | *(inferred, QN)* or cited source |
| recursive or cyclic topology | claimed / disclaimed / N/A / unresolved | self-reference, graph depth, reentrancy | §1.11 / §1.12 / §1.18 | *(inferred, QN)* or cited source |
| callback and collaborator execution | claimed / disclaimed / N/A / unresolved | comparator, predicate, factory, virtual dispatch | §1.7 / §1.10 / §1.11 / §1.12 / §1.18 | *(inferred, QN)* or cited source |
| serialization and reconstruction | claimed / disclaimed / N/A / unresolved | restored types, callbacks, invariant rebuilding | §1.3 / §1.7 / §1.10 / §1.11 / §1.12 / §1.18 | *(inferred, QN)* or cited source |
| reference and object lifecycle | claimed / disclaimed / N/A / unresolved | weak/soft references, GC clearing, invalidation | §1.5 / §1.11 / §1.12 / §1.18 | *(inferred, QN)* or cited source |
| concurrency and reentrancy | claimed / disclaimed / N/A / unresolved | shared mutation, callback reentry | §1.5 / §1.11 / §1.12 / §1.18 | *(inferred, QN)* or cited source |
| resource complexity | claimed / disclaimed / N/A / unresolved | CPU, heap, stack, I/O as a function of input/state | §1.7 / §1.11 / §1.12 / §1.18 | *(inferred, QN)* or cited source |
| authorization scope | claimed / disclaimed / N/A / unresolved | who may invoke which operations; which side owns the check | §1.7 / §1.10 / §1.11 / §1.12 / §1.18 | *(inferred, QN)* or cited source |

Add project-type rows when needed, such as Unicode/canonicalization,
probabilistic-result semantics, protocol state transitions, clock behavior, or
distributed consistency. The matrix is a contract inventory, not a bug list.
A demonstrably-absent guarantee is a `disclaimed` row with **documented**
provenance; only a dimension where a guarantee might exist stays `unresolved`
and becomes a proposed-answer question for the interview. A guarantee "might
exist" when the project has historically fixed reports of that class, or when a
documented guarantee already implies it — in that case narrow the `claimed` row
rather than disclaiming. Record the disclaimer's **conditions and tier** (see
§1.12): a disclaimer with no boundary is the one that over-closes, and the tier
is the worst impact of a report the disclaimer would close.

For stateful APIs, explicitly record the **postcondition on failure**: unchanged,
partially committed, best-effort cleanup, or unspecified. Cover failures from
validation, allocation, caller callbacks, and delegated collaborator methods.

## Build the no-surprise side-effects inventory (§1.5)

Scan for what the project does to its host, then state the **negative** claims:
does it open sockets? spawn processes? install signal handlers? read environment
variables? write to stdout/stderr? touch global locale or FPU state? mutate
process-wide state?

**Tag these by how good your scan was, not by a default.** A negative here says
no such behaviour was *observed*; the project has not promised to keep it that
way, so it is a §1.5 inventory row rather than a documented contract:

- *(assumption, QN)* when you scanned the shipped sources of the supported build
  exhaustively and found nothing. Name what you searched.
- *(inferred, QN)* when the scan could not be exhaustive — hand-written
  assembly, generated code, `dlopen` or another dynamic dispatch, an `#ifdef`
  branch you did not read, or a dependency that could do it on the project's
  behalf. Name the specific hole in the question, so the maintainer knows what
  you could not see.

Do not pre-label the whole inventory **inferred** before scanning. A negative
you actually verified across the supported build is worth more to a triager than
a blanket hedge, and the difference is exactly what the maintainer is being
asked to ratify.

## Derive reachability preconditions (§1.4) and output taint (§1.8)

- Per in-model family, state the condition a finding must meet to matter ("a
  finding in `inflate.c` is in-model only if reachable from the compressed input
  bytes"). This is the first test a triager applies to a tool/AI hit.
- Per output channel, state taint. The default for parsers/decoders/decompressors
  is one line worth stating verbatim: *"Output is exactly as untrusted as the
  input it derives from; no sanitization, normalization, or encoding is
  performed."* Note any structural invariant the code actually upholds (bounded
  writes, valid encoding, matching length fields) — each is a candidate §1.11
  property.

## Output — surface analysis

Hand back: the §1.7 table (with coverage note if partial), the completed
contract-dimension matrix, the §1.5 side-effects inventory, per-family §1.4
reachability preconditions, and §1.8 output-taint statements — each tagged with
its actual provenance. Mark code-derived contract hypotheses *(inferred, QN)* and
call out unresolved dimensions and wave-1/2 confirmation targets for
`threat-model-interview`.
