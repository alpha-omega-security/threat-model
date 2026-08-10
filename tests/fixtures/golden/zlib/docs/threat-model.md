# Threat model — zlib

## 1.1 Header

- **Project**: zlib (general-purpose lossless data-compression library).
- **Version binding**: this model is versioned with the source. A report
  against version *N* is triaged against the model as it stood at *N*, not HEAD.
- **Reporting cross-reference**: §1.11 (claimed-property) findings are reported
  through the project's private disclosure channel; §1.3 / §1.12 findings are
  closed by citing this document.
- **Status**: unratified draft, 2025-03. While unratified, any disposition that
  closes a report against the reporter must be licensed by a **documented** or
  **maintainer** claim (see §1.17); **inferred** licensing escalates instead.
- **Provenance legend**: *(documented, source)* = stated in the named public
  source; *(maintainer, YYYY-MM)* = confirmed by a maintainer on that date;
  *(inferred, QN)* = reasoned from code and mapped to question `QN` in §1.18.
- **Draft confidence**: 68 documented / 0 maintainer / 7 inferred.
- **Backtest note**: routed a 12-item corpus in 6 clusters across all 8
  applicable contract dimensions; 9 items carry a real historical outcome, 3 are
  synthesized. Dispositions: 4 `VALID`, 3 `BY-DESIGN: property-disclaimed`, 1
  `KNOWN-NON-FINDING`, 4 `OUT-OF-MODEL: unsupported-component`, 0
  `MODEL-GAP`. All 4 historically-fixed
  items routed `VALID`, so nothing the project fixed was closed. 7 of 12 close
  outright; one `unsupported-component` route escalates instead, because §1.3's
  `contrib/` exclusion is still unratified (Q2). One contradiction with the
  historical call raised Q3.
- **Sibling models**: none; this model covers the core library only.

zlib is an in-process C library that compresses and decompresses byte streams
using DEFLATE (raw, zlib, and gzip framing). It performs no I/O of its own and
holds no ambient authority; the calling application owns all buffers and files.

> **Triager quick-start.** Given an inbound finding:
> 0. Read the triage policy above (`strict` here). It decides what an
>    **assumption** may do in step 8.
> 1. Locate the sink → look up its row in the §1.7 input-trust table (or the
>    §1.8 output statement, for "downstream may assume X" findings).
> 2. Locate the contract dimension and follow its matrix row to the owning claim.
> 3. Check attacker capability and control kind against §1.7/§1.10.
> 4. Check the affected component against §1.2/§1.3 and any required build flag
>    against §1.6.
> 5. If the root cause is in a dependency, apply §1.9.
> 6. Apply §1.17 precedence, beginning with an exact §1.15 match.
> 7. Assign exactly one §1.17 disposition, citing its licensing section. If none
>    fits, assign `MODEL-GAP` and trigger §1.16 — do not improvise.
> 8. **Before closing, check the provenance of the licensing claim.** Applies to
>    every `OUT-OF-MODEL: *`, `BY-DESIGN: *`, and `KNOWN-NON-FINDING`; `VALID`
>    and `MODEL-GAP` are unaffected.
>    - **documented** / **maintainer** → close.
>    - **inferred** → **escalate, never close**, under either policy.
>    - **assumption** → escalate under `strict` (this model). Under `relaxed` it
>      may provisionally close a low-blast-radius route, never
>      `KNOWN-NON-FINDING`, a security-critical `property-disclaimed`, or
>      `dependency-contract`.
>    - A disclaimer resting only on the docs being **silent** never closes a
>      security-critical report.
>    Record the outcome as `closed`, `provisional`, or `escalated`. An escalated
>    finding keeps its disposition — it is not a `MODEL-GAP`.

## 1.2 Scope and intended use

Primary intended use is in-process compression and decompression of application
data, linked directly into a host program *(documented, zlib manual)*. zlib ships as a
library with no daemon or privileged mode *(documented, zlib manual)*. The caller is trusted
for the process; the *compressed input bytes* are the untrusted surface
*(inferred, Q1)*.

| Component family | Entry point | Touches outside process? | In model? | Provenance |
| --- | --- | --- | --- | --- |
| Inflate (decompression) | `inflate` | no | in | *(documented, zlib manual)* |
| Deflate (compression) | `deflate` | no | in | *(documented, zlib manual)* |
| gzip file API | `gzread`/`gzwrite` | yes (fs) | in | *(documented, zlib manual)* |
| `contrib/` samples | various | varies | out (see §1.3) | *(inferred, Q2)* |
| `examples/` demos | `gun`/`gzappend`/… | varies | out (see §1.3) | *(documented, zlib source layout)* |

## 1.3 Out of scope (explicit non-goals)

- zlib is not an authentication, integrity, or encryption library; the Adler-32
  and CRC-32 checks detect accidental corruption, not tampering *(documented, zlib manual)*.
- Compression-ratio attacks ("zip bombs") are not defended against — bounding
  decompressed size is the caller's responsibility *(documented, zlib manual)*.
- Shipped-but-unsupported: `contrib/` holds third-party samples and is not part
  of the supported library; findings there are `OUT-OF-MODEL: unsupported-component`
  *(inferred, Q2)* — **except `contrib/crc32vx/`**, which the build compiles
  into libz on s390x: `configure` defaults `enable_crcvx=1` and enables it when
  the host is s390x, `Makefile.in:164` builds `crc32_vx.o` from it, and the
  public `crc32()` dispatches there under `HAVE_S390X_VX` (`crc32.c:947`). That
  file is **in scope** on s390x builds; a report against it routes on its merits,
  not as an unsupported component *(documented, `Makefile.in` crc32_vx rule)*.
- Demonstration code: `examples/` programs (e.g. `gun`, `gzappend`) are teaching
  samples, not the supported library surface; findings there are
  `OUT-OF-MODEL: unsupported-component` *(documented, zlib source layout)*.

## 1.4 Trust boundaries and data flow

The single trust boundary sits at the compressed-input byte stream: bytes handed
to `inflate`/`gzread` are attacker-controlled; the caller's buffers, lengths,
and window-size arguments are trusted *(inferred, Q1)*. Data flow is purely
computational (bytes in → bytes out) with no privilege transition, so no diagram
is needed. Reachability precondition: a finding in `inflate.c` is in-model only
if it is reachable from the compressed input bytes.

## 1.5 Assumptions about the environment

zlib targets a hosted C runtime with a caller-provided allocator (`zalloc`/
`zfree`), is thread-safe across independent streams, and requires external
synchronization for a shared `z_stream` *(documented, zlib FAQ)*. No-surprise
side-effects: zlib opens no sockets, spawns no child processes, installs no
signal handlers, and (outside the gzip file API) performs no filesystem access
*(inferred, Q5)*.

## 1.6 Build-time and configuration variants

- `ZLIB_CONST` and windowBits framing selectors change API shape but not the
  security model *(documented, zlib manual)*.
- Custom `MAX_WBITS`/memory-level builds change resource bounds; the shipped
  defaults are the supported production posture, so a report against defaults is
  `VALID`, not `OUT-OF-MODEL: non-default-build` *(documented, zlib build documentation)*.

## 1.7 Assumptions about inputs

Inputs are the compressed byte stream plus caller-supplied buffers and sizing
arguments. Per-parameter trust table (one row per public entry-point parameter):

| Entry point | Input operand | Attacker-controllable? | Control kind | Caller must enforce | Provenance |
| --- | --- | --- | --- | --- | --- |
| `inflate` | `next_in`/`avail_in` (compressed bytes) | yes | data, size | nothing — must be safe on arbitrary input | *(documented, inflate API contract)* |
| `inflate` | `next_out`/`avail_out` (output buffer) | no | data, size | buffer >= claimed size; honor `avail_out` | *(inferred, Q4)* |
| `inflateInit2` | `windowBits` | no | size | in documented range | *(inferred, Q4)* |
| `gzopen` | `path` | no (trusted) | resource-name | validate before passing | *(documented, gzopen API contract)* |

Size/shape: input is streaming and unbounded; the caller must cap total
decompressed output to defend against compression bombs *(documented, zlib manual)*.

Contract-dimension matrix (every required dimension appears once per in-scope
component family):

| Component | Dimension | Status | Conditions / boundary | Routes to | Provenance |
| --- | --- | --- | --- | --- | --- |
| core-inflate | numeric domain | claimed | documented size types/ranges | §1.11 memory-safety-untrusted-input | *(documented, zlib manual)* |
| core-inflate | failure atomicity | disclaimed | failed stream may require reset/end | §1.12 failure-state-atomicity | *(documented, zlib manual)* |
| core-inflate | recursive/cyclic topology | N/A | byte streams are not object graphs | §1.7 | *(documented, zlib API shape)* |
| core-inflate | callback execution | disclaimed | caller allocator is trusted | §1.10 trusted-caller | *(documented, zlib manual)* |
| core-inflate | serialization/reconstruction | N/A | no object reconstruction | §1.7 | *(documented, zlib API shape)* |
| core-inflate | reference lifecycle | claimed | stream lifetime follows init/end | §1.11 stream-lifecycle | *(documented, zlib manual)* |
| core-inflate | concurrency/reentrancy | claimed | independent streams only | §1.5 thread-safety | *(documented, zlib FAQ)* |
| core-inflate | resource complexity | disclaimed | caller caps expanded output | §1.12 decompression-bomb-resistance | *(documented, zlib manual)* |
| core-deflate | numeric domain | claimed | documented size types/ranges | §1.11 memory-safety-untrusted-input | *(documented, zlib manual)* |
| core-deflate | failure atomicity | disclaimed | failed stream may require reset/end | §1.12 failure-state-atomicity | *(documented, zlib manual)* |
| core-deflate | recursive/cyclic topology | N/A | byte streams are not object graphs | §1.7 | *(documented, zlib API shape)* |
| core-deflate | callback execution | disclaimed | caller allocator is trusted | §1.10 trusted-caller | *(documented, zlib manual)* |
| core-deflate | serialization/reconstruction | N/A | no object reconstruction | §1.7 | *(documented, zlib API shape)* |
| core-deflate | reference lifecycle | claimed | stream lifetime follows init/end | §1.11 stream-lifecycle | *(documented, zlib manual)* |
| core-deflate | concurrency/reentrancy | claimed | independent streams only | §1.5 thread-safety | *(documented, zlib FAQ)* |
| core-deflate | resource complexity | disclaimed | caller selects memory level | §1.12 resource-budgeting | *(documented, zlib manual)* |
| gzip-file-api | numeric domain | claimed | documented lengths and offsets | §1.11 output-bound-honored | *(documented, zlib manual)* |
| gzip-file-api | failure atomicity | disclaimed | I/O may partially advance file state | §1.12 failure-state-atomicity | *(documented, zlib manual)* |
| gzip-file-api | recursive/cyclic topology | N/A | handles are not object graphs | §1.7 | *(documented, zlib API shape)* |
| gzip-file-api | callback execution | N/A | no caller executable callback | §1.7 | *(documented, zlib API shape)* |
| gzip-file-api | serialization/reconstruction | N/A | no object reconstruction | §1.7 | *(documented, zlib API shape)* |
| gzip-file-api | reference lifecycle | claimed | handle valid until `gzclose` | §1.11 stream-lifecycle | *(documented, zlib manual)* |
| gzip-file-api | concurrency/reentrancy | disclaimed | shared handles need synchronization | §1.5 thread-safety | *(documented, zlib FAQ)* |
| gzip-file-api | resource complexity | disclaimed | caller caps output and I/O | §1.12 decompression-bomb-resistance | *(documented, zlib manual)* |

## 1.8 Assumptions and guarantees about outputs

| Output channel | Component | Taint | Downstream must not assume | Provenance |
| --- | --- | --- | --- | --- |
| `next_out` decompressed bytes | `core-inflate` | Exactly as untrusted as the compressed input; no sanitization, normalization, or encoding | Well-formed for any higher-layer grammar — UTF-8, HTML, SQL, shell | *(documented, zlib manual, `inflate` description)* |
| `out()` callback buffer | `core-inflate` | Same as above; the window is the caller's own buffer | That writes stay within `avail_out` — the `inflateBack` bound is the window size, not `avail_out` | *(documented, zlib.h `inflateBack`, "at most the window size")* |
| `strm->msg` / `gzerror` string | `core-inflate`, `gzip-file-api` | **Assembled**, not constant: the `gz*` layer builds it from the caller-supplied path | That it is safe to render — it embeds a path the caller chose | *(documented, `gzlib.c` `gz_error`, `"%s%s%s"` with `state->path`)* |

Output never exceeds `avail_out` per `inflate` call — promoted to §1.11 as
`output-bound-honored` with a symptom and tier.

## 1.9 Assumptions about dependencies

Zero-dependency claim: zlib depends on nothing beyond the C runtime and the
caller-provided allocator *(documented, zlib build manifest)*. There are no vendored third-party
libraries in the supported build. Routing rule: a defect rooted in the host
libc failing its own contract is `OUT-OF-MODEL: dependency-contract`; zlib
misusing the runtime is in-model. The platform libc allocator/`malloc` is the
one runtime dependency the model names explicitly *(documented, zlib manual)*.

## 1.10 Adversary model

Actors assume the baseline deployment context: zlib linked in-process into a
host program that owns its own memory (§1.2).

| Actor | In scope? | Capabilities held | Capabilities excluded | Goals | Provenance |
| --- | --- | --- | --- | --- | --- |
| Compressed-input author | **yes** | Supply arbitrary, malformed, or maximally expanding stream bytes; choose input size | Cannot choose buffer pointers, lengths, the allocator, `windowBits`, or build flags; cannot run code in the host process | Memory corruption, resource exhaustion | *(documented, zlib manual, "never crash even on corrupted input")* |
| In-process caller | no | Chooses every buffer, the allocator, and the build | — (excluded wholesale) | — | *(documented, zlib manual — a caller controlling the process has already won)* |

## 1.11 Security properties the project provides

- **Memory safety on untrusted input** (`core-inflate`, `core-deflate`): for any
  input, `inflate` and `deflate` must not read or write out of bounds.
  *Violation symptom*: OOB read/write or crash — the write path is bounded by
  the distance test at `inflate.c:1026` (`if (state->sane)`) and by the fast
  loop's output limit at `inffast.c:83` (`end = out + (strm->avail_out - 257)`).
  *Tier*: security-critical (CVE-class). *Voided by*: `inflateUndermine(strm, 1)` relaxes the
  distance-too-far check — `inflate.c:1376` sets `state->sane = !subvert`, but
  only in a build defining `INFLATE_ALLOW_INVALID_DISTANCE_TOOFAR_ARRR`; the
  default build returns `Z_DATA_ERROR` and leaves the check on (§1.6).
  *(documented, zlib manual)*
- **Output bound honored**: a single call writes no more than `avail_out` bytes.
  *Violation symptom*: buffer overflow — output is clamped by `left`, loaded
  from `avail_out` at `inflate.c:331` and written back at `inflate.c:342`.
  *Tier*: security-critical.
  *Voided by*:
  `inflateBackInit` swaps the bound — it stores a caller-supplied window at
  `infback.c:59` (`state->window = window;`) which `inflateBack` writes through
  at `infback.c:222`, so for that entry point the limit is the window size, not
  `avail_out` (`zlib.h`, `inflateBack`: "The length written by out() will be at
  most the window size"). No other `ZEXPORT` in `zlib.h` assigns to the output
  or window state. *(documented, inflate API contract)*
- **Termination**: `inflate` makes forward progress and does not hang on valid
  or invalid input. *Violation symptom*: infinite loop / hang. *Tier*:
  security-critical. *Voided by*: nothing.
  Search: `grep -rn 'sane\|_STRICT\|ASMINF\|undermine' *.c *.h configure` —
  hits only in `inflate.c`/`inffast.c` for the distance check, none touching
  loop progress. *(documented, zlib manual)*
- **Integrity check on decode**: `inflate` returns `Z_STREAM_END` only when the
  trailing Adler-32 or CRC-32 matches. *Violation symptom*: corrupted data
  accepted as valid. *Tier*: security-critical. *Voided by*:
  `inflateValidate(strm, 0)` — `inflate.c:1393` clears the check-value bit with
  `state->wrap &= ~4`, and every check-value comparison in the file is gated on
  that bit. A report that inflate accepted a bad CRC must first establish that
  the caller did not call it. *(documented, zlib manual)*
- **Configured window-memory bound**: internal sliding-window allocation is
  bounded by the build's configured `MAX_WBITS`; the configured maximum is the
  threshold. *Violation symptom*: allocation exceeding that configured bound.
  *Tier*: correctness-only. *Voided by*: nothing at run time — the ceiling is
  set at build time by `MAX_WBITS` (`zconf.h:287`, `15`) and `MAX_MEM_LEVEL`
  (`zconf.h:277`), and `deflateInit2`/`inflateInit2` only select within it.
  A build redefining either moves the bound, which is why §1.6 carries it.
  *(documented, zlib build documentation)*

### Worked routing examples

De-identified from the phase-3.6 backtest, to show the §1.1 algorithm in use.

| Reported | Sink | Attacker needs | Symptom | Routes to | Licensed by |
| --- | --- | --- | --- | --- | --- |
| Crafted stream drives a write past the caller's output buffer | `inflate` | the compressed bytes only | OOB write | `VALID` | `output-bound-honored` |
| Fuzzer OOM: a few KB expands to gigabytes with no output cap | `inflate` | the compressed bytes only | Unbounded allocation, OOM | `KNOWN-NON-FINDING` **(closed)** | `fuzzer-unbounded-memory` |
| Data race corrupts state when two threads share one handle | `gzread` | nothing — a caller threading error | Data race, state corruption | `BY-DESIGN: property-disclaimed` **(closed)** | `shared-stream-thread-safety` |
| Scanner hit in a bundled sample program | `contrib-samples` (`contrib/minizip`) | n/a | any | `OUT-OF-MODEL: unsupported-component` **(escalated)** | §1.3, still **inferred** (Q2) |

Two of these are worth reading twice.

Row 2 shows the precedence subtlety: the §1.12 bomb disclaimer would also close
it, but an exact §1.15 match is rule 1 and fires first, so the disposition is
`KNOWN-NON-FINDING` citing the entry — which in turn cites the disclaimer.

Row 4 shows the provenance gate. The route is right, but §1.3's `contrib/`
exclusion is still **inferred** (Q2), and an inferred claim may escalate and
never close. So the finding keeps its disposition and goes to the maintainer
rather than being answered. Ratifying Q2 turns this row from `escalated` into
`closed` — which is what the open questions are for.

## 1.12 Security properties the project does *not* provide

Tier is the worst impact of a report the disclaimer would close, not how the
project feels about the property.

| ID | zlib does not provide | Conditions / boundary | Tier | False friend? | Provenance |
| --- | --- | --- | --- | --- | --- |
| `confidentiality-integrity-authenticity` | Confidentiality, integrity, or authenticity of data. | All supported configurations. | security-critical | no | *(documented, zlib manual, "not a secure protocol" note)* |
| `crc-as-mac` | Tamper detection. CRC-32/Adler-32 detect accidental corruption only. | All supported configurations. | security-critical | **yes** | *(documented, zlib manual, `crc32` description)* |
| `decompression-bomb-resistance` | Any bound on how much output a given input produces. | Caller sets no output budget. | security-critical | no | *(documented, zlib manual, `uncompress` note on caller-supplied size)* |
| `shared-stream-thread-safety` | Safe concurrent use of one `z_stream` from several threads. | A handle shared without caller synchronization. | security-critical | no | *(documented, zlib FAQ #21)* |
| `trusted-callback-safety` | Defence against a caller allocator that breaks its own contract. | `zalloc`/`zfree` violate their documented contract. | security-critical | no | *(documented, zlib manual, `zalloc` contract)* |
| `failure-state-atomicity` | A defined stream state after a failed call. | The operation returned an error code. | correctness-only | no | *(documented, zlib manual, return-code section)* |
| `resource-budgeting` | A memory budget below the caller's chosen level. | Caller-selected `memLevel`/`windowBits`. | correctness-only | no | *(documented, zlib manual, `deflateInit2`)* |

Well-known attack classes left to the caller: **compression bombs** (bound the
output), and untrusted-output injection (sanitize before rendering)
*(documented, zlib manual)*.

## 1.13 Downstream responsibilities

- Cap total decompressed size / ratio before trusting a stream *(documented, zlib manual)*.
- Treat decompressed bytes as untrusted input to the next layer *(documented, zlib manual)*.
- Serialize access to a shared `z_stream` *(documented, zlib FAQ)*.

## 1.14 Known misuse patterns

- Using CRC-32 as an integrity/authentication check — looks like tamper
  detection, is not; use a MAC *(documented, zlib manual)*.
- Decompressing without an output cap — enables memory-exhaustion via bombs
  *(documented, zlib manual)*.

## 1.15 Known non-findings (recurring false positives)

An exact match satisfies every field *and* the discharging claim. Conditions
describe what the code does, never how well the report was written: an
unreproduced report is not a non-finding, it stays open pending a reproducer.

| ID | Components | Symptom / attack class | What gets reported | Conditions for an exact match | Discharged by | Provenance |
| --- | --- | --- | --- | --- | --- | --- |
| `fuzzer-unbounded-memory` | `core-inflate` | Unbounded allocation | Fuzzer "unbounded memory" on a crafted stream | The caller set no output budget, and the run shows no out-of-bounds access or bound violation | `decompression-bomb-resistance` | *(documented, zlib manual, `uncompress` note on caller-supplied size)* |
| `crc-forgery` | `gzip-file-api` | Integrity bypass | CRC/Adler "collision" or "forgery" | The report treats the checksum as authentication rather than error detection | `crc-as-mac` | *(documented, zlib manual, `crc32` description)* |
| `msan-uninitialized-value` | `core-deflate` | Uninitialized read | MSan/Valgrind "use of uninitialized value" in the match loop | The value never affects deflate's output and the read stays inside a zlib allocation | `memory-safety-untrusted-input` | *(documented, zlib FAQ #36)* |

## 1.16 Conditions that would change this model

A new public API, a new input framing, a network-facing wrapper, a change to a
shipped default that voids a §1.11 property, or the promotion of a `contrib/`
component into the core library. Also: any report that cannot be cleanly routed
to a §1.17 disposition is itself a trigger to revise the model.

## 1.17 Triage dispositions

| Disposition | Meaning | Licensed by |
| --- | --- | --- |
| `VALID` | Violates a claimed §1.11 property via in-scope adversary and input. | §1.11, §1.7, §1.10 |
| `VALID-HARDENING` | No §1.11 property violated, but a §1.14 misuse is easy enough to harden. | §1.14 |
| `OUT-OF-MODEL: trusted-input` | Requires attacker control of a parameter marked trusted. | §1.7 |
| `OUT-OF-MODEL: adversary-not-in-scope` | Requires an excluded attacker capability. | §1.10 |
| `OUT-OF-MODEL: unsupported-component` | Lands in out-of-scope code (`contrib/`). | §1.3 |
| `OUT-OF-MODEL: non-default-build` | Only under a discouraged/non-default §1.6 flag. | §1.6 |
| `OUT-OF-MODEL: dependency-contract` | Root cause is a dependency failing its own contract. | §1.9 |
| `BY-DESIGN: property-disclaimed` | Concerns a property explicitly not provided (§1.12). | §1.12 |
| `KNOWN-NON-FINDING` | Matches a documented recurring false positive. | §1.15 |
| `MODEL-GAP` | Fits none of the above; triggers §1.16. | §1.16 |

**Precedence — first matching rule wins.** Multiple failed preconditions do not
create a `MODEL-GAP`; this order resolves them.

1. Exact §1.15 known non-finding → `KNOWN-NON-FINDING`.
2. Out-of-scope §1.3 component → `OUT-OF-MODEL: unsupported-component`.
3. Unsupported §1.6 configuration → `OUT-OF-MODEL: non-default-build`.
4. Conformant use of a dependency that broke its own §1.9 contract →
   `OUT-OF-MODEL: dependency-contract`.
5. Requires control of a §1.7 trusted operand → `OUT-OF-MODEL: trusted-input`.
6. Requires an excluded §1.10 capability →
   `OUT-OF-MODEL: adversary-not-in-scope`.
7. Concerns a §1.12 disclaimed property → `BY-DESIGN: property-disclaimed`.
8. Violates a §1.11 claimed property → `VALID`; otherwise an easy-to-prevent
   §1.14 misuse may be `VALID-HARDENING`.
9. No unique supported conclusion → `MODEL-GAP`, triggering §1.16.

**Closure constraint.** Any disposition that closes a report against the
reporter (`OUT-OF-MODEL: *`, `BY-DESIGN: *`, `KNOWN-NON-FINDING`) must be
licensed by a **documented** or **maintainer** claim.

- An **inferred** licensing claim only **escalates**, under either policy.
- This model declares the `strict` triage policy, so an **assumption** also
  escalates only. Under `relaxed` it could provisionally close a
  low-blast-radius route, citing the `QN` and re-opening on challenge.
- **Security-critical floor (both policies).** An **assumption** never licenses
  `KNOWN-NON-FINDING`, a `security-critical` `property-disclaimed`, or
  `dependency-contract`.
- **Silence floor (both policies).** A §1.12 disclaimer resting only on the docs
  being *silent*, rather than on a stated limit, never closes a
  `security-critical` report.
- `VALID` and `MODEL-GAP` are fail-safe and are not closes.

Record each outcome as `closed`, `provisional`, or `escalated`. An escalated
finding keeps its disposition and goes to the maintainer; it is **not** a
`MODEL-GAP`.

## 1.18 Open questions for the maintainers

- **Q1** — Is the untrusted surface exactly the compressed input bytes, with
  every sizing argument caller-trusted?
  - Proposed answer: yes.
  - Lands in: §1.4 and the §1.7 trust table.
- **Q2** — Is `contrib/` unsupported for security purposes?
  - Proposed answer: yes; reports there close as
    `OUT-OF-MODEL: unsupported-component`.
  - Lands in: §1.3.
- **Q3** — Is downstream well-formedness disclaimed for every output grammar?
  - Proposed answer: yes; output is exactly as untrusted as its input.
  - Lands in: §1.8, and as a §1.12 disclaimer.
- **Q4** — Is the caller-trusted classification of `next_out` and `windowBits`
  complete?
  - Proposed answer: yes; the caller owns both.
  - Lands in: §1.7.
- **Q5** — Are there host side-effects beyond those listed in §1.5?
  - Proposed answer: no — no sockets, child processes, or signal handlers, and
    no filesystem access outside the gzip file API.
  - Lands in: §1.5.

## 1.19 Machine-readable companions

The repository-root `threat-model.yaml` is a schema-v2 derived index bound to
the SHA-256 of this prose. Beside it, `threat-model.json` is a flat export of
the same model for consumers of the repository report schema; it is lossy by
design and carries no triage precedence. The prose remains canonical and both
companions are regenerated after every prose change. Authority order: prose,
then YAML, then JSON.
