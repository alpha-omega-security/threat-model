---
name: threat-model-interview
description: >-
  Run phase 3.4 maintainer question waves for threat-model production. USE WHEN
  inferred claims need ratification or interview-first versus draft-first mode
  must be chosen. Asks 3–7 prioritized proposed-answer questions per wave; wave
  1 always covers scope, intended use, configuration support, and host side
  effects. Records answers, promotes inferred provenance to dated maintainer
  provenance, and retires matching §1.18 questions. Supports the phase 3.7
  termination policy. DO NOT USE FOR: fabricating maintainer positions, drafting
  the whole model, or triage.
argument-hint: '<the inferred claims / open questions needing ratification>'
---

# Threat Model — Interview (question waves)

Phase 3.4. Iteration is mandatory and the model is *finite* — better a tight
3-page document than a sprawling 20-page one. Pull questions from the
[question bank](../threat-model/references/question-bank.md); reword for the
project — do not read them verbatim.

## Choose a mode

- **Interview-first** — ask, then draft. Best when a maintainer is actively
  engaged and answers return quickly.
- **Draft-first** *(usually more efficient)* — write v1 entirely from public
  artifacts (recon + surface), tag every claim, and collect the unresolved
  questions in §1.18. Hand the maintainer a document to *react to* rather than a
  questionnaire to fill in. Best when maintainer time is scarce or asynchronous.

## Wave discipline

- **Never dump every question at once** — a maintainer will not answer 30 in one
  go, and the answers will be shallow if they do. Ask in **waves of 3–7**,
  prioritized by which answers most shape the rest of the model.
- **Wave 1 is always scope + intended use** — everything depends on it — plus the
  two questions that reshape multiple sections and are almost never documented:
  - the **configuration-support** question (support posture for every security-
    relevant knob, especially a default that voids a §1.11 property, reshaping
    §1.6/§1.11/§1.13/§1.17);
  - the **no-surprise side-effects** question (the negative claims from the
    surface pass — sockets, spawning, signal handlers, env reads, global state).
  If a prior `SECURITY.md`/"threat model" doc exists, also ask the **coexistence**
  question in wave 1.
- Subsequent waves drill into trust boundaries, adversary model, dependencies,
  properties provided/not-provided, and known misuses/non-findings. Prioritize
  any `unresolved` rows in the surface contract-dimension matrix by expected
  triage volume and impact; numeric boundaries, callback trust, serialization,
  and failure atomicity commonly outrank low-volume edge cases.

## Frame every question as a proposed answer

Maintainers respond faster and more precisely to "we believe X — confirm or
correct" than to an open "what is X?". Wherever recon/surface yielded a plausible
answer, state it as the working hypothesis and ask the maintainer to ratify or
override. Reserve genuinely open questions for cases with no reasonable default.
For a contract-dimension gap, propose an explicit routing decision: a §1.11
guarantee with conditions, a §1.12 disclaimer, or a narrower supported domain.
Do not ask only "what happens here?"

> *Instead of:* "What is the adversary model?"
> *Ask:* "We believe the only adversary in scope is whoever supplies the
> compressed input; in-process callers and side-channel observers are out of
> scope. Is that right, and is anything missing?"

## After each wave

- **Record answers in the draft**, not just in chat.
- **Promote provenance** — *(inferred, QN)* or *(assumption, QN)* →
  *(maintainer, YYYY-MM)* — and delete the matching §1.18 open question.
- State which next-wave questions the answers **unlock or render moot**.
- Update the contract-dimension row from `unresolved` to `claimed`,
  `disclaimed`, or `N/A`, and route the resulting claim to its prose section.
- **Stop** once the marginal value of another question is low.

## Termination policy (§3.7) — the maintainer goes silent

Adopt a waiting policy up front (e.g., two unanswered waves, or 30–60 days —
whatever the project's cadence suggests). When it expires:

- Publish with status **unratified draft**, the draft-confidence count shown
  prominently, and §1.18 intact.
- **Closure constraint (all statuses):** a disposition that closes a report against the
  reporter (`OUT-OF-MODEL: *`, `BY-DESIGN: *`, `KNOWN-NON-FINDING`) may **not**
  rest on *(inferred)* claims. An *(assumption)* closes only under the declared
  `relaxed` triage policy, only a low-blast-radius route, and never a
  security-critical property, `KNOWN-NON-FINDING`, or `dependency-contract`. A
  report that would otherwise be closed on inferred or ungoverned-assumption
  grounds is **escalated** to the maintainer instead, and the claim moves to the
  top of the next wave. `VALID` routings are unaffected (they fail safe).

## Never fabricate

If a question is unanswered, its claim **stays *(inferred, QN)*** — or
*(assumption, QN)* where a conservative default is clearly safe — with an open
§1.18 item; do not invent a maintainer position. Answering a wave **promotes**
both *(inferred)* and *(assumption)* claims to *(maintainer, YYYY-MM)*. A draft
that is mostly unratified is not ready to publish; a draft with none is fully
reviewed or overclaiming.
