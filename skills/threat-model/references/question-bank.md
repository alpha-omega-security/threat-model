# Reference question bank (§6)

Referenced from [SKILL.md](../SKILL.md) §3.2.

---

## 6. Reference question bank

Pull from these in waves. Reword for the specific project. The first wave
should be drawn from §6.1.

### 6.1 Scope and intended use (ask first)
0. Is this project intended for production use, or is it a
   reference/research/educational implementation? If the latter, is there
   a hardened fork you point people at?
1. Who is the intended caller of this project, and at what trust level do you
   assume they operate?
2. What deployment shapes did you have in mind when designing it
   (in-process library, CLI, daemon, embedded, etc.)?
3. What use cases do you consider clearly *out of scope* — uses people
   sometimes attempt that you do not support?
4. Is there a security boundary inside the project, or is the entire API
   surface the boundary?

### 6.2 Inputs and trust
5. Of the inputs accepted by the public API, which do you assume are
   attacker-controllable, and which do you assume are trusted?
6. Are there documented or undocumented size/shape/rate limits on inputs
   beyond which behavior is undefined or degraded?
7. Does any input flow into resource allocation (memory, threads, file
   handles) in a way whose magnitude is controlled by the input?
7a. Does the project read back its own persisted state (data directory,
    cache, project file, serialized session)? If someone can write to
    that location and nothing else, are they in your adversary model?
7b. Where the project *emits* something another interpreter consumes
    (HTML, SQL, shell, headers, log lines), do you guarantee the output
    is safe for that sink, or is escaping the caller's job?

### 6.3 Adversary model
8. Who is the adversary you most cared about when designing this? Who is
   explicitly out of scope?
9. What capabilities does the assumed adversary have — can they observe
   timing? Memory? Influence inputs? Inject inputs? Cause restarts?
10. Are there adversaries sometimes assumed by users that you do *not* defend
    against (e.g., side-channel adversaries, co-tenant adversaries, malicious
    callers)?
10a. If the project is deployed multi-tenant, is one authenticated tenant
    attacking another in scope, or is tenant isolation the operator's
    problem?

### 6.4 Properties the project tries to uphold
11. What properties do you believe the project provides given valid input,
    and where are those properties documented or tested?
12. Are any of those properties only conditional (e.g., only on certain
    platforms, only when certain features are compiled in)?
12a. Where is the line on resource consumption — is super-linear CPU or
    memory in input size a bug? Is a hang on pathological input a bug?
    Or do you make no resource guarantee at all?

### 6.5 Properties the project does *not* uphold
13. What security properties have you deliberately decided are *not* this
    project's job?
14. Are there functions that look general-purpose but are unsafe for a
    particular use (e.g., comparison functions that are not constant-time,
    RNG that is not cryptographic, hash that is not collision-resistant)?
14a. Do error responses, log lines, or stack traces returned to an
    untrusted caller count as information disclosure, or is scrubbing
    them the deployer's job?

### 6.6 Misuse and downstream responsibility
15. What is the most common way you have seen this project misused?
16. What single thing do you wish every integrator did before calling the
    API, that they often do not?
17. Are there configurations or modes that should never be combined?
18. Does the project expose anything that *looks like* a security
    primitive but is not one (a checksum mistaken for a MAC, a hash
    mistaken for collision-resistant, a PRNG mistaken for a CSPRNG, a
    sandbox mistaken for an isolation boundary)?
18a. What do scanners, fuzzers, or security researchers most often
    report against this project that you consider a non-finding, and
    why? (Feeds §4.11a.)

### 6.7 Environmental assumptions
19. What does the project assume about its host (OS, allocator, threading,
    signal handling, byte order, integer width)?
20. Are there platforms that are nominally supported but not really first
    class for security purposes?
21. What does the project *refrain* from doing to its host — no signal
    handlers, no spawning, no sockets, no env-var reads, no global state?
    Which of these are deliberate guarantees vs. incidental?

### 6.8 Build and configuration variants
22. Which compile-time defines, feature flags, or runtime configuration
    knobs change the security envelope? What is the default for each, and
    which do you actively discourage?
23. Is there code shipped in the repository (`contrib/`, `examples/`,
    bindings, demos) that you do not consider part of the project for
    security purposes?
23a. For each §4.5a knob whose *default* is the less-secure value: is
    that default the supported production posture (so a report against
    it is `VALID`), or a dev-convenience that operators are expected to
    flip (so it is `OUT-OF-MODEL: non-default-build`)?

### 6.9 Stability and revision
24. What kind of change to the project would invalidate the answers you have
    just given?

### 6.10 Delegated surface and extension points
25. Which of your linked or vendored dependencies receive bytes that
    originated from an attacker-controllable input? For each: if a
    researcher finds a crash there via your entry point, do you own the
    report or do you redirect them upstream?
26. If the project loads plugins, extensions, or user-defined functions:
    are plugin authors trusted at the same level as core contributors, or
    do you claim any isolation between a plugin and the host?

