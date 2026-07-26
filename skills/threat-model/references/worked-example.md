# Worked sketch (zlib as a sounding board)

A few illustrative entries — **not** a complete threat model, just the flavor. A
real run goes deeper and is driven by maintainer answers, not producer guesses.
When running this skill against a real project, do **not** fabricate maintainer
positions — ask (phase 3.4 / `threat-model-interview`).

- **Intended use** *(documented, zlib manual)* — In-process DEFLATE/gzip/zlib
  (de)compression invoked by a host application. Not a network service; not a
  sandbox.
- **Trust boundary** *(inferred, Q1)* — The API surface. Once data is inside the
  library it is treated as authenticated by virtue of the caller having
  presented it. Authentication of compressed data (e.g., HMAC) is the caller's
  problem.
- **Adversary out of scope** *(inferred, Q2)* — A caller already running in the host
  process; it has trivially full control and is not a meaningful adversary at
  this layer.
- **Property provided (conditional)** *(inferred, Q3)* — Memory safety for
  well-formed, size-bounded inputs and correctly-initialized streams, on
  supported platforms with a conformant C runtime. *Violation symptom:* crash /
  OOB read-write. *Tier:* security-critical.
- **Property not provided** *(inferred, Q4)* — No defense against adversarially
  constructed inputs that maximize CPU/memory cost ("decompression bombs"). The
  caller caps output size or wall-clock budget.
- **Output trust** *(inferred, Q5)* — Decompressed bytes are exactly as untrusted as
  the compressed input; no sanitization, encoding validation, or normalization.
  The only structural guarantee is that no more than the caller-supplied buffer
  length is written.
- **Dependency trust** *(inferred, Q6)* — No runtime dependencies beyond a conformant
  C runtime and the caller-replaceable allocator; a caller-supplied `zalloc` is
  assumed to honor the standard allocator contract.
- **Downstream responsibility** *(inferred, Q7)* — Bounding decompressed-output size;
  not feeding `gz*` file APIs filenames sourced from untrusted users without
  sanitization (path is interpreted by the OS, not the library).
- **Known misuse** *(inferred, Q8)* — Treating the gzip CRC as an integrity guarantee
  against a malicious sender. CRC-32 is an error-detection code, not a MAC.
- **False friend** *(inferred, Q9)* — CRC-32 looks like an integrity guarantee; it
  is not a MAC and provides no protection against a chosen-input adversary.
- **Build variant** *(inferred, Q10)* — `ZLIB_INSECURE` removes `gzprintf` overflow
  protection; `BUILDFIXED` / `DYNAMIC_CRC_TABLE` remove thread safety on
  pre-C11 toolchains. Default off / discouraged.

An abbreviated contract-dimension matrix for the same sketch would make the
remaining decisions explicit:

| Component | Dimension | Status | Boundary / destination | Provenance |
| --- | --- | --- | --- | --- |
| core inflate | numeric domain | unresolved | Proposed §1.18 answer: supported sizes fail before integer wrap; if confirmed, promote to §1.11 | *(inferred, Q11)* |
| core inflate | failure atomicity | unresolved | Proposed §1.18 answer: a failed stream operation may leave the stream unusable; if confirmed, disclaim in §1.12 | *(inferred, Q12)* |
| core inflate | callback execution | claimed | Caller allocators are trusted collaborators; route to §1.7/§1.10 | *(inferred, Q13)* |
| core inflate | recursive/cyclic topology | N/A | No caller-supplied object graph; confirm in §1.18 | *(inferred, Q14)* |
| core inflate | resource complexity | disclaimed | No decompression-bomb resistance; route the disclaimer to §1.12 and derive the caller obligation in §1.13 | *(inferred, Q15)* |

These bullets are deliberately the kind of thing **not** visible from reading
`inflate.c`. They are statements about *contract*, not *code* — and every one is
*(inferred, QN)* until a maintainer ratifies it. Each illustrative Q-ID would
have a matching proposed-answer entry in §1.18 of a complete model.
