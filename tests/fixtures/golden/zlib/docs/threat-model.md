# Threat model — zlib

## 1.1 Header

- **Project**: zlib (general-purpose lossless data-compression library).
- **Version binding**: this model is versioned with the source. A report
  against version *N* is triaged against the model as it stood at *N*, not HEAD.
- **Reporting cross-reference**: §1.11 (claimed-property) findings are reported
  through the project's private disclosure channel; §1.3 / §1.12 findings are
  closed by citing this document.
- **Status**: unratified draft, 2025-03. While unratified, any disposition that
  closes a report against the reporter must be licensed by a *(documented)* or
  *(maintainer)* claim (see §1.17); *(inferred)* licensing escalates instead.
- **Provenance legend**: *(documented, source)* = stated in the named public
  source; *(maintainer, YYYY-MM)* = confirmed by a maintainer on that date;
  *(inferred, QN)* = reasoned from code and mapped to question `QN` in §1.18.
- **Draft confidence**: 59 documented / 0 maintainer / 8 inferred.
- **Backtest note**: routed a 4-item historical corpus (CVE-2018-25032,
  CVE-2022-37434, one fuzzer OOM, one CRC "MAC" report); all four landed on a
  single disposition with no MODEL-GAP.
- **Sibling models**: none; this model covers the core library only.

zlib is an in-process C library that compresses and decompresses byte streams
using DEFLATE (raw, zlib, and gzip framing). It performs no I/O of its own and
holds no ambient authority; the calling application owns all buffers and files.

> **Triager quick-start.** Given an inbound finding:
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
  *(inferred, Q2)*.
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

Output taint: the decompressed bytes are exactly as untrusted as the compressed
input they derive from; no sanitization, normalization, or encoding is performed
*(documented, inflate API contract)*. Guaranteed structural invariant: output never exceeds the
caller's supplied `avail_out` per call — promoted to §1.11 with a symptom and
tier. Downstream must NOT assume the output is well-formed for any higher-layer
grammar (UTF-8, HTML, SQL, shell) *(inferred, Q3)*.

## 1.9 Assumptions about dependencies

Zero-dependency claim: zlib depends on nothing beyond the C runtime and the
caller-provided allocator *(documented, zlib build manifest)*. There are no vendored third-party
libraries in the supported build. Routing rule: a defect rooted in the host
libc failing its own contract is `OUT-OF-MODEL: dependency-contract`; zlib
misusing the runtime is in-model. The platform libc allocator/`malloc` is the
one runtime dependency the model names explicitly *(documented, zlib manual)*.

## 1.10 Adversary model

The attacker controls the compressed input bytes and can craft arbitrary,
malformed, or maximally expanding streams *(documented, zlib manual)*. They cannot control
the caller's buffer pointers, lengths, allocator, or build flags. A caller who
already controls the process or its memory has won and is out of scope
*(documented, zlib manual)*.

## 1.11 Security properties the project provides

- **Memory safety on decompression**: for any input, `inflate` must not read or
  write out of bounds. *Violation symptom*: OOB read/write or crash. *Tier*:
  security-critical (CVE-class). *(documented, zlib manual)*
- **Output bound honored**: a single call writes no more than `avail_out` bytes.
  *Violation symptom*: buffer overflow. *Tier*: security-critical. *(documented, inflate API contract)*
- **Termination**: `inflate` makes forward progress and does not hang on valid
  or invalid input. *Violation symptom*: infinite loop / hang. *Tier*:
  security-critical. *(documented, zlib manual)*
- **Configured window-memory bound**: internal sliding-window allocation is
  bounded by the build's configured `MAX_WBITS`; the configured maximum is the
  threshold. *Violation symptom*: allocation exceeding that configured bound.
  *Tier*: correctness-only. *(documented, zlib build documentation)*

## 1.12 Security properties the project does *not* provide

- No confidentiality, integrity, or authenticity of data *(documented, zlib manual)*.
- **False-friend**: CRC-32/Adler-32 are error-detection checksums, frequently
  mistaken for a MAC; they provide no protection against deliberate tampering
  *(documented, zlib manual)*.
- Well-known attack classes left to the caller: **compression bombs** (bound the
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

- Fuzzer report of "unbounded memory" on a crafted stream: safe under the model
  because §1.7 makes the caller responsible for capping output; suppress unless
  an actual OOB or bound violation is shown *(documented, zlib manual)*.
- CRC "collision"/"forgery" report: discharged by §1.12 — the checksum is not a
  MAC *(documented, zlib manual)*.
- MSan/Valgrind "use of uninitialized value" inside `deflate`'s match loop:
  intentional for performance and never observable in the output, so it is a
  false positive rather than a memory-safety break *(documented, zlib FAQ)*.

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

## 1.18 Open questions for the maintainers

1. Confirm the untrusted surface is exactly the compressed input bytes and that
   all sizing arguments are caller-trusted (lands in §1.4/§1.7). *(maps inferred:
   trust boundary)*
2. Confirm `contrib/` is unsupported for security purposes and reports there are
   `OUT-OF-MODEL: unsupported-component` (lands in §1.3).
3. Confirm downstream-well-formedness is explicitly disclaimed for all output
   grammars (lands in §1.8).
4. Confirm the caller-trusted classification of `next_out`/`windowBits` in the
   §1.7 table is complete (lands in §1.7).
5. Confirm no additional side-effects beyond those listed in §1.5 (lands in §1.5).

## 1.19 Machine-readable companion

The repository-root `threat-model.yaml` is a schema-v2 derived index bound to
the SHA-256 of this prose. The prose remains canonical and the sidecar is
regenerated after every prose change.
