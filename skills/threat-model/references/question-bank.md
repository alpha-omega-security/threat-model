# Reference question bank

Pull from these in waves of 3–7, reworded for the specific project. Owned by the
`threat-model-interview` specialist; the orchestrator and recon specialists also
draw wave-1 questions from §Scope.

**Framing rule.** Frame every question as a *proposed answer* for the maintainer
to confirm, correct, or strike — not an open "what is X?". Reserve genuinely open
questions for cases where no reasonable default exists.

> *Instead of:* "What is the adversary model?"
> *Ask:* "We believe the only adversary in scope is whoever supplies the
> compressed input; in-process callers and side-channel observers are out of
> scope. Is that right, and is anything missing?"

The **first wave** must cover scope and intended use — everything depends on it
— plus the **configuration-support** question (§Build, last item) and the
**side-effects inventory** (§Environment, last item). Combine related prompts as
needed to keep the wave within 3–7 questions; do not defer either required topic.

---

## Scope and intended use (ask first → §1.2/§1.3/§1.4)

1. Who is the intended caller, and at what trust level do you assume they
   operate?
2. What deployment shapes did you design for (in-process library, CLI, daemon,
   embedded, kernel)?
3. What use cases are clearly out of scope — uses people attempt that you do not
   support?
4. Is there a security boundary *inside* the project, or is the entire API
   surface the boundary?

## Inputs, outputs, and trust (→ §1.7/§1.8)

5. Of the public-API inputs, which do you assume attacker-controllable and which
   trusted?
6. Are there documented or undocumented size/shape/rate limits beyond which
   behavior is undefined or degraded?
7. Does any input flow into resource allocation (memory, threads, file handles)
   in a way whose magnitude the input controls?
8. Does the output carry any guarantee — sanitization, normalization, structural
   invariants (valid encoding, bounded depth, matching length fields) — or is it
   exactly as untrusted as the input it derives from? What do integrators most
   often wrongly assume about it?

## Dependencies (→ §1.9)

9. Which runtime dependencies do you rely on for security-relevant behavior, and
   for what property in each case? If "none beyond libc/the runtime," can we
   state that as a guarantee?
10. For vendored/bundled third-party code that ships in supported artifacts: is
    it covered by your security process at the pinned version, or deferred to
    upstream? Who ships the fix when upstream patches?

## Adversary model (→ §1.10)

11. Who is the adversary you most cared about? Who is explicitly out of scope?
12. What capabilities does the assumed adversary have — observe timing? memory?
    influence inputs? inject inputs? cause restarts?
13. Are there adversaries users sometimes assume that you do *not* defend against
    (side-channel, co-tenant, malicious caller)?

## Properties provided (→ §1.11)

14. What properties do you believe the project provides given valid input, and
    where are they documented or tested?
15. Are any of those properties conditional (certain platforms only, certain
    features compiled in only)?
16. Where is the line on resource consumption — is super-linear CPU/memory in
    input size a bug? Is a hang on pathological input a bug? Or is no resource
    guarantee made at all?

## Properties NOT provided (→ §1.12)

17. What security properties have you deliberately decided are not this
    project's job?
18. Are there functions that look general-purpose but are unsafe for a
    particular use (comparison not constant-time, RNG not cryptographic, hash
    not collision-resistant)?

## Misuse and downstream responsibility (→ §1.13/§1.14/§1.15)

19. What is the most common way you have seen this project misused?
20. What single thing do you wish every integrator did before calling the API,
    that they often do not?
21. Are there configurations or modes that should never be combined?
22. Does the project expose anything that *looks like* a security primitive but
    is not (checksum≠MAC, hash≠collision-resistant, PRNG≠CSPRNG,
    sandbox≠isolation)?
23. What do scanners/fuzzers/researchers most often report that you consider a
    non-finding, and why? (Feeds §1.15.)

## Environmental assumptions (→ §1.5)

24. What does the project assume about its host (OS, allocator, threading,
    signal handling, byte order, integer width)?
25. Are there platforms nominally supported but not first-class for security?
26. What does the project *refrain* from doing to its host — no signal handlers,
    no spawning, no sockets, no env-var reads, no global state? Which are
    deliberate guarantees vs. incidental? (Highest-priority negative claim.)

## Build and configuration variants (→ §1.6)

27. Which compile-time defines, feature flags, or runtime knobs change the
    security envelope? Default for each, and which do you actively discourage?
28. Is there shipped code (`contrib/`, `examples/`, bindings, demos) you do not
    consider part of the project for security purposes?
29. We believe support posture, not defaultness, controls scope: every supported
    configuration is in-model, while only configurations explicitly marked
    dev-only, discouraged for the modeled exposure, or unsupported route to
    `OUT-OF-MODEL: non-default-build`. Confirm the stance for each security-
    relevant knob, especially any less-secure default. (Wave 1 — reshapes
    §1.6/§1.11/§1.13/§1.17.)

## Stability and revision (→ §1.16)

30. What kind of change to the project would invalidate the answers you have
    just given?

## Contract edge conditions (→ §1.7/§1.10/§1.11/§1.12)

31. We believe operations are required to preserve documented state invariants
    if validation, allocation, a caller callback, or a delegated collaborator
    throws; alternatively, partial mutation is explicitly permitted. Which is
    the intended contract?
32. We believe supported numeric behavior ends at `<project-specific limit>`;
    above it the API must fail before mutation rather than wrap, truncate, or
    return an incorrect result. Confirm or provide the actual boundary.
33. We believe self-referential or cyclic object graphs are unsupported inputs,
    and recursive operations need not detect them. Confirm, or identify the
    operations that promise cycle-safe behavior.
34. We believe callback-bearing inputs (comparators, predicates, factories,
    transformers, virtual collaborators) are trusted code even when the data
    passed through them is attacker-controlled. Confirm and identify exceptions.
35. We believe native deserialization is supported only for trusted streams and
    does not promise to sanitize restored concrete types or suppress their
    callbacks. Confirm, and identify any classes with stronger reconstruction
    guarantees.
36. We believe weak/soft-reference and cache-like components must tolerate
    lifecycle events such as GC clearing or invalidation without violating
    their public return/exception contract. Confirm or disclaim that behavior.
37. We believe stack use, heap use, and CPU time have separate thresholds:
    `<proposed thresholds>`. Confirm which forms of super-linear work, deep
    recursion, or proportional allocation count as bugs.
38. We believe normalization/canonicalization and probabilistic-result semantics
    are provided only where explicitly documented; otherwise downstream users
    must not infer them. Confirm and name any stronger guarantees.

## Authorization and privilege (→ §1.7/§1.10/§1.12)

Substantive for daemons, network services, and anything with roles; usually a
single confirmation of question 39 for an in-process library.

39. We believe every caller that can reach the API operates at a single trust
    level, and the project performs no authorization of its own — any caller
    may invoke any operation. Confirm, or name the operations that are
    restricted and to whom. (For a library this one confirmation usually
    settles the authorization-scope rows.)
40. For each interface with roles (user/admin, per-tenant, read-only), we
    propose this role table: `<roles and the operations each may invoke>`.
    Confirm which operations require which role, and whether the check is this
    project's job or the deployment's.
41. Is any operation *intentionally* reachable by any authenticated caller,
    where a reporter might expect a narrower check? A confirmed "yes, that is
    intended" becomes a §1.12 disclaimer — the statement that closes that
    entire class of reports as by-design instead of escalating each one.

## Coexistence (meta — ask in wave 1 when a prior model exists)

42. A prior `SECURITY.md` / doc titled "threat model" already states model
    content. Should the new document (a) replace that section, (b) become the
    canonical model it links to, or (c) sit alongside as an expansion?
