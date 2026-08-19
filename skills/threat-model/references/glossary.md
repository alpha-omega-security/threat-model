# Glossary — plain-language terms for reading a threat model

For maintainers and integrators who are new to security threat modeling. A
threat model uses a handful of specialized words so that findings route the same
way every time. This page defines them in plain language, in the order you are
likely to meet them when reading a model or reacting to a finding. Keep the
model open alongside this page — every term maps to a section of the document.

If you only read one thing: a threat model is a **contract**. It writes down what
the project promises about security, what it deliberately does *not* promise, and
who is responsible for the gap. When someone reports a problem, you compare it to
the contract and put it in exactly one bucket (a **disposition**).

---

## The big picture

| Term | Plain meaning |
| --- | --- |
| **Threat model** | The written security contract between a project and the people who use it. Not a bug list, audit, or pentest — it describes the project *as it is*. |
| **In scope / out of scope** | Whether the model takes responsibility for something. In-scope threats are the project's problem; out-of-scope ones are explicitly someone else's. |
| **Downstream / integrator** | The person or app that uses this project. The model tells them which risks they now own. |
| **Triager** | Whoever decides if an incoming report is a real problem for this project — a maintainer, a security team, or an automated pipeline. |
| **Disposition** | The single bucket a finding lands in after triage (see the table below). The model defines a fixed, closed set — you never invent a new one. |

---

## Provenance tags — "who said so?"

Every claim in the model carries one tag showing where it came from. This matters
because only some tags are trusted enough to *close* a report against a reporter.

| Tag | Plain meaning | Can it close a report? |
| --- | --- | --- |
| *(documented, source)* | Stated in the project's own public docs, headers, `SECURITY.md`, or an issue ruling. Names the exact source — file plus function, a named doc section, or a short quote, not just a filename. | Yes — except a disclaimer that rests only on the docs being *silent*, which never closes a serious issue. |
| *(maintainer, date)* | A maintainer confirmed it in answer to a modeling question. | Yes. |
| *(assumption, QN)* | A cautious default the author is willing to act on where the docs are silent — still needs a maintainer to confirm (question `QN`). | Only under the `relaxed` policy, and only for low-risk cases. Never for a serious (memory-safety / RCE-class) issue. |
| *(inferred, QN)* | An educated guess from reading the code — genuinely unconfirmed (question `QN`). | No. It can only **escalate** a report to a human. |

The `QN` in an assumption or inferred tag points to an open question in §1.18. A
finished (`accepted`) model has no inferred or assumption tags left.

---

## Triage dispositions — the buckets a finding lands in

When a report arrives, you route it to exactly one of these. The model cites the
section that justifies the call. (Full precedence order is in §1.17.)

| Disposition | Plain meaning |
| --- | --- |
| `VALID` | A real problem: it breaks a security property the project promised, using an attacker and input the model considers in scope. Fix it. |
| `VALID-HARDENING` | Not a broken promise, but the API makes an easy mistake easy. Worth improving; usually not a CVE. |
| `OUT-OF-MODEL: trusted-input` | Only works if the attacker controls something the project trusts by design (e.g., a value the calling app is supposed to supply). |
| `OUT-OF-MODEL: adversary-not-in-scope` | Requires powers the model's attacker is not assumed to have (e.g., already running inside your process). |
| `OUT-OF-MODEL: unsupported-component` | Lands in code the project ships but does not support (examples, demos, `contrib/`). |
| `OUT-OF-MODEL: non-default-build` | Requires a configuration the project marks dev-only or unsupported. (Just being non-default is *not* enough.) |
| `OUT-OF-MODEL: dependency-contract` | The real fault is in a dependency breaking its own promises, while this project used it correctly. Forward it upstream. |
| `BY-DESIGN: property-disclaimed` | Concerns something the model openly says it does *not* protect against (e.g., "we do not resist decompression bombs"). |
| `KNOWN-NON-FINDING` | A false alarm scanners/fuzzers raise repeatedly that the model already explains away. |
| `MODEL-GAP` | Fits none of the above — the model is silent or contradictory. This is a signal to *update the model*, not to make an ad-hoc call. |

**Close vs. escalate.** *Closing* a report tells the reporter "this is not a
problem for us," and needs a trusted (*documented* / *maintainer*) claim behind
it. If only an *inferred* claim applies, you don't close — you **escalate** to a
maintainer. `VALID` and `MODEL-GAP` always fail safe.

---

## Inputs, outputs, and attackers

| Term | Plain meaning |
| --- | --- |
| **Sink** | A specific place data flows *into* — a function parameter, an endpoint, a protocol message. Findings are reported against a specific sink, not "the library" in general. |
| **Source** | Where data comes *from*. Attacker-controlled sources are the interesting ones. |
| **Attacker-controllable** | Whether an attacker can choose this input. If yes, the project has to defend against it; if no, it's the caller's job to keep it clean. |
| **Control kind** | *What* an attacker controls, not just whether they do: the raw data, its size/rate, its type/class, callback code, object-graph shape, or serialized state. These get defended differently, so the model keeps them apart. |
| **Taint** | How untrusted the output is. The common rule for parsers/decoders: "output is exactly as untrusted as the input it came from — we do not sanitize it." |
| **Trust boundary** | The line where data crosses from untrusted to trusted (or vice versa). Usually the public API surface. |
| **Reachability precondition** | The condition a finding must meet to matter (e.g., "only counts if reachable from the compressed input bytes"). |

---

## Properties and promises

| Term | Plain meaning |
| --- | --- |
| **Security property** | Something the project promises to uphold — memory safety, correct output, a size bound. Each has a *violation symptom* (what breaks) and a *tier*. |
| **Violation symptom** | What you'd actually see if the property broke: a crash, out-of-bounds read/write, info leak, hang, wrong output, or runaway allocation. |
| **Tier** | How serious a violation is: `security-critical` (a real vulnerability → CVE) or `correctness-only` (a bug, but not a security hole). |
| **Disclaimed property** | Something the project deliberately does *not* promise, stated plainly so a report about it can be closed `BY-DESIGN`. Disclaiming the safe direction ("no thread-safety guaranteed") is a feature, not a cop-out — it tells integrators what they own. |
| **False friend** | A feature that looks like a security guarantee but isn't: CRC ≠ MAC, a fast hash ≠ collision-resistant, a PRNG ≠ a secure RNG, a resource "sandbox" ≠ isolation, authenticated ≠ authorized. Called out so users don't lean on them. |
| **Contract dimension** | A standard checklist axis the model forces a decision on for each component — numeric limits, failure atomicity, recursion/cycles, callbacks, serialization, object lifecycle, concurrency, resource cost, and authorization scope. Each is marked claimed, disclaimed, N/A, or unresolved so nothing is left implicit. |
| **Authorization scope** | Who is allowed to invoke which operations, and which side of the API owns that check. Distinct from authentication: authentication verifies who the caller is, authorization decides what that caller may do. A library usually disclaims it ("any caller that can reach the API may use all of it"); a service with roles has to say which operations need which role. |

---

## Adversary and system terms

| Term | Plain meaning |
| --- | --- |
| **Adversary model** | Who the attacker is, what they can and can't do, and what they're trying to achieve. A report requiring powers outside this model is out of scope. |
| **Blast radius** | How much damage a wrong call could do. "Low-blast-radius" closes are the only ones a cautious *assumption* is allowed to make provisionally. |
| **Principal** | The identity an operation is performed *as* — a user, tenant, role, or service account. An authorization decision reads a principal; if no code path does, the project has a single trust level. |
| **Byzantine participant / honest fraction** | For distributed systems only: a participant who is authenticated but may act maliciously, and the threshold of honest participants the guarantees need (e.g., "fewer than 1/3 malicious"). |

---

## Process and workflow terms

| Term | Plain meaning |
| --- | --- |
| **Provenance** | The chain of "who said so" behind each claim — the tags above. Kept in the published model so any closed report is defensible. |
| **Triage policy** | How cautiously the model closes reports. `strict` (default): only firmly documented claims close anything. `relaxed`: cautious assumptions may close low-risk reports provisionally, and a reporter can reopen them. |
| **Escalate** | Hand a report to a maintainer instead of closing it, because the supporting claim isn't confirmed enough. |
| **Disposition status** | What a triager may *do* with a route, recorded next to the disposition: `closed` (the claim behind it is confirmed), `provisional` (a cautious assumption closed it under `relaxed`; a reporter can reopen it), or `escalated` (the route is right but the claim behind it isn't confirmed enough to close). An escalated report is **not** a model gap — the model had an answer, it just lacks the authority to give it yet. |
| **Absence-based disclaimer** | A "we don't promise that" written because nothing in the docs promises it, rather than because the project stated a limit. Useful, but weaker: it never closes a serious report on its own, because silence is not the same as a decision. |
| **Backtest** | A validation step: route past real findings through the draft model and compare each result against what the project actually did. Landing in exactly one bucket is necessary but not sufficient — the test it must pass is that nothing the project actually fixed gets closed. |
| **Fail-safe figure** | The number the backtest reports that matters most: how many items the project actually fixed the model would have *closed*. The target is zero. Over-escalating wastes maintainer time; over-closing answers a live vulnerability with "not a bug". |
| **Worked routing example** | A one-line worked case in §1.11 — what was reported, the sink, what the attacker needed, the symptom, the disposition, and the claim that licensed it. At least one shows a report the project *accepts* as valid. |
| **Sidecar** | The machine-readable `threat-model.yaml` companion to the prose model, for tools and automated triage. The prose stays the source of truth. |
| **Version binding** | The model is tied to a specific released/committed version. A report against version *N* is judged against the model as it stood at *N*. |
| **Unratified draft** | A model published while some claims are still unconfirmed (maintainer went quiet). Usable, but it escalates rather than closes on the unconfirmed parts. |

---

## Where each term lives in the document

The model uses fixed section numbers, so a finding can cite exactly where a call
came from:

| Section | What it holds |
| --- | --- |
| §1.1 | Header: version, status, provenance legend, and the triager quick-start. |
| §1.2 / §1.3 | In-scope use and out-of-scope non-goals. |
| §1.4 / §1.5 | Trust boundaries, data flow, and environment assumptions. |
| §1.6 | Build/config variants that change security. |
| §1.7 / §1.8 | Input trust table and output taint. |
| §1.9 / §1.10 | Dependency trust and the adversary model. |
| §1.11 / §1.12 | Properties provided vs. deliberately not provided. |
| §1.13 / §1.14 | Downstream responsibilities and known misuses. |
| §1.15 | Known non-findings (recurring false positives). |
| §1.16 | What would trigger a model update. |
| §1.17 | The closed set of dispositions and their precedence. |
| §1.18 | Open questions for the maintainers. |
| §1.19 | The machine-readable sidecar. |
