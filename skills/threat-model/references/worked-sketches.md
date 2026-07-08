# Worked sketches (§7)

Referenced from [SKILL.md](../SKILL.md).

---

## 7. Worked sketches

These are illustrative entries, not complete threat models; a real run
goes deeper and is driven by maintainer answers rather than the
producer's guesses. (When using this skill against a real project, do not fabricate
maintainer positions; ask.)

### 7.1 In-process C library (zlib)

- **Intended use** — In-process DEFLATE/gzip/zlib (de)compression invoked by
  a host application. Not a network service; not a sandbox.
- **Trust boundary** — The API surface. Once data is inside the library, it
  is treated as authenticated by virtue of the caller having presented it.
  Authentication of compressed data (e.g., HMAC) is the caller's problem.
- **Adversary out of scope** — A caller already running in the host process.
  Such a caller has trivially full control and is not a meaningful adversary
  to model at this layer.
- **Property provided (conditional)** — Memory safety for well-formed,
  size-bounded inputs and correctly-initialized streams, on supported
  platforms with a conformant C runtime.
- **Property not provided** — No defense against adversarially constructed
  inputs that maximize CPU/memory cost (a.k.a. "decompression bombs"). The
  caller is responsible for capping the output size or wall-clock budget.
- **Downstream responsibility** — Bounding decompressed-output size; not
  feeding `gz*` file APIs filenames sourced from untrusted users without
  sanitization (path is interpreted by the OS, not the library).
- **Known misuse** — Treating the gzip CRC as an integrity guarantee against
  a malicious sender. CRC-32 is an error-detection code, not a MAC.

### 7.2 Network service (identity-aware reverse proxy)

- **Intended use** — Terminates TLS, authenticates the client, and forwards
  the request to an upstream application with identity headers attached.
  Production intent; single-tenant per instance. Client is the untrusted
  network peer; the operator (who supplies config and the upstream list)
  is trusted; upstreams are operator-chosen and semi-trusted.
- **§4.6 default trust** — All request bytes from the client are
  attacker-controllable. All config-file fields are operator-trusted. The
  exception list is short: `X-Forwarded-*` headers on the *inbound* request
  are stripped, not trusted, because the client can set them.
- **§4.6a output** — Forwarded request to upstream. Sink-safety claimed:
  identity headers (`X-Auth-User` etc.) are guaranteed set by the proxy
  and never passed through from the client; a client-supplied identity
  header reaching the upstream is a `critical` §4.8 violation (auth
  bypass). In the return direction, 4xx/5xx bodies are fixed strings and
  upstream error bodies are not relayed; a verbose upstream error
  reaching the client is a `high` §4.8 violation (info disclosure).
- **§4.6b delegated surface** — TLS handling delegated to the platform TLS
  library; findings there are `report-upstream`. JWT validation via a
  vendored library reachable from the client's `Authorization` header;
  findings there are re-exported (`VALID` here).
- **Property not provided** — No rate limiting, no WAF, no request-body
  inspection. DoS via request volume is the operator's problem (§4.10:
  "deploy behind a load balancer / set connection limits").
- **Known non-finding** — "Open redirect via the `?next=` parameter": the
  redirect target is constrained to the operator-configured allowlist per
  §4.6; scanners flag the parameter shape without checking the allowlist.

None of these bullets are visible from reading `inflate.c` or a proxy's
`handler.go`; they are statements about contract, not code.

