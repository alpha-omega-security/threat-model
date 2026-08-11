# Threat-model quality rubric (Tier 3 — LLM judge)

The deterministic validator (Tiers 0–1) proves a model is *well-formed* and
*internally consistent*. It cannot judge whether the content is *good*. This
rubric is scored by a blind LLM judge to catch the judgemental failures the
regex checks miss — vague scope, laundered provenance, audit-style prose,
padding.

## Protocol

- **Blind.** The judge sees the threat-model document (and optionally the
  project's own README/docs), never the golden fixture, the corpus labels, or
  which agent produced it. Strip authorship and run metadata first.
- **Calibrated.** Before scoring a candidate, the judge scores the golden zlib
  fixture ([../fixtures/golden/zlib/threat-model.md](../fixtures/golden/zlib/threat-model.md))
  to anchor the scale. A candidate is graded relative to that anchor.
- **Structured output.** The judge emits one JSON object (schema below) so runs
  aggregate. Prose justification is required per dimension — a bare score is
  rejected.
- **Two-judge minimum for gating.** For a pass/fail gate, use two independent
  judge passes (or two models); disagreement of ≥2 points on any dimension is
  escalated to a human.

## Dimensions (score each 0–3)

| # | Dimension | 0 (fail) | 3 (exemplary) |
| --- | --- | --- | --- |
| D1 | **Provenance discipline** | Claims untagged, or `(documented)` with no citation, or `(inferred)` used to launder guesses as facts. | Every non-trivial claim tagged; documented claims cite a source; inferred claims are genuinely uncertain and each maps to a §1.18 question. |
| D2 | **Scope crispness** | "General-purpose X"; no component families; in/out boundary fuzzy. | §1.2 concrete intended use + component-family table; §1.3 states even the obvious non-goals with reasons. |
| D3 | **Adversary realism** | One vague "attacker"; capabilities unstated; service roles not split. | §1.10 names capabilities the adversary has *and* lacks; distributed/service roles split (client/operator/peer); excluded actors called out. |
| D4 | **Property precision** | Properties are aspirations ("is secure"); no symptoms or tiers; thresholds missing. | §1.11 entries carry property + condition + violation symptom + severity tier; resource thresholds stated ("super-linear is a bug; constant-factor is not"). |
| D5 | **Disclaimer & false-friend coverage** | §1.12 empty or generic; no named attack classes. | §1.12 names the real attack classes left to the caller (bombs/XXE/ReDoS) and separates false-friends (CRC≠MAC). |
| D6 | **Triage operability** | A triager cannot route a real finding using only the doc; §1.15/§1.17 thin. | Every corpus finding routes to exactly one §1.17 disposition citing a section; §1.15 usable as a negative prompt. |
| D7 | **Model-not-audit discipline** | Reads like an audit report: "the project should…", findings, recommendations. | Reads like a model: states properties and boundaries; no remediation advice, no vuln hunting. |
| D8 | **Right-sizing** | Padding, repetition, or so thin whole sections are stubs. | One-sitting length; every section substantive or explicitly `Not applicable — <reason>`. |

## Gate

- **Hard-fail** if D1, D6, or D7 scores 0 — these are the load-bearing
  properties (defensible provenance, usable triage, correct genre).
- **Pass** requires total ≥ 17/24 with no dimension below 1.
- Report the golden's own score alongside; a candidate scoring at or above the
  golden on every dimension is a strong pass.

## Judge output schema

```json
{
  "candidate_id": "zlib@run-2025-...",
  "calibration_golden_total": 22,
  "scores": {
    "D1": {"score": 3, "why": "..."},
    "D2": {"score": 2, "why": "..."},
    "D3": {"score": 3, "why": "..."},
    "D4": {"score": 2, "why": "..."},
    "D5": {"score": 3, "why": "..."},
    "D6": {"score": 3, "why": "..."},
    "D7": {"score": 3, "why": "..."},
    "D8": {"score": 2, "why": "..."}
  },
  "total": 21,
  "hard_fail": false,
  "verdict": "pass",
  "notes": "escalate D4 threshold wording to a human"
}
```

## Why this tier exists

Gate 4 in [self-check.md](../../skills/threat-model/references/self-check.md)
is explicitly judgemental ("reads like a model, not an audit"; "as substantive
as"). Those cannot be regex-checked without being gamed. The judge closes that
gap, and calibrating on the golden keeps the scale stable across runs and
models.
