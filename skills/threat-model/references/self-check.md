# Self-check before finalizing (§8)

Referenced from [SKILL.md](../SKILL.md) §3.4.

---

## 8. Self-check before finalizing

Before declaring the threat model done, verify:

- [ ] Every section is either substantive or marked N/A with a reason.
- [ ] No bullet would be more at home in a code review or audit report.
- [ ] No bullet restates what the README/API docs already say.
- [ ] Every non-trivial claim carries a *(documented)* / *(maintainer)* /
      *(inferred)* tag, the header explains the legend, and **no hedge-tag
      variants** ("implicit", "documented in purpose", "generally known")
      have crept in.
- [ ] The header reports a draft-confidence tag count.
- [ ] Every *(inferred)* tag has a matching open question in §4.14, and
      every open question states a proposed answer.
- [ ] If the project has distinct component families (core vs.
      OS-touching convenience layer vs. plugin loader vs.
      shipped-but-unsupported), each is modeled at its own trust level or
      explicitly placed out of scope.
- [ ] §4.5a, §4.6a, §4.6b, and §4.11a are each populated or marked N/A
      with a reason; for each §4.5a knob whose default is the less-secure
      value, the maintainer's ruling is recorded.
- [ ] §4.6 either has a per-parameter trust table or states a default
      trust level plus an exception list. Persisted state read on startup
      has a row.
- [ ] §4.8 properties are stated as a delta from the language/runtime
      baseline, not as a restatement of it.
- [ ] §4.9 (properties NOT provided) and §4.10 (downstream responsibilities)
      are at least as substantive as §4.8 (properties provided). If they
      aren't, the model is probably under-specified.
- [ ] §4.9 names at least the obvious "false-friend" properties and the
      well-known attack classes for this category of project.
- [ ] Every §4.8 property carries a violation symptom and a severity
      tier (critical/high/moderate/low), and resource properties state a
      threshold.
- [ ] §4.13 enumerates the triage dispositions and each cites the
      section that licenses it; the set covers dependency findings
      (`report-upstream`).
- [ ] Any contested maintainer position is recorded as contested, not
      averaged, and has a §4.14 governance entry.
- [ ] A reader who has never seen the project can answer: "what threats has
      the library taken responsibility for, and which have been left to me?"
- [ ] A triager handed an arbitrary finding — from a tool, a human, or
      an AI — can route it to exactly one §4.13 disposition, citing a
      section, without consulting the maintainer.
- [ ] The document fits comfortably in one sitting (typically 3–8 pages).
      Sprawl is a smell.

If any check fails, iterate before publishing.
