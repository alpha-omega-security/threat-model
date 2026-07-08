# threat-model

An [agent skill](https://agentskills.io/) for producing threat models for open-source projects.

The output is a document describing the implicit security contract between a project and its downstream users: what the project assumes about its environment and inputs, which security properties it claims, which it explicitly disclaims, and which threats are left to the integrator. It is written to serve two readers at once: the downstream integrator deciding what they are now responsible for, and the maintainer or triager deciding whether an inbound vulnerability report is valid, out of model, or by design.

This is not a vulnerability scanner or audit tool. It produces a contract, not findings.

## Install

### Claude Code

```
/plugin marketplace add alpha-omega-security/threat-model
/plugin install threat-model@threat-model
```

### Other agents

Any [agentskills.io-compatible](https://agentskills.io/clients) agent can load the skill directly from `skills/threat-model/`. Clone the repo and point your agent's skill path at that directory, or copy it into your project's `.claude/skills/` (or equivalent).

## Usage

Point the agent at a project checkout and invoke the skill:

```
/threat-model:threat-model
```

or ask naturally:

```
Produce a threat model for this project.
Is this vulnerability report in scope for our threat model?
Draft a SECURITY.md scope section.
```

The skill runs draft-first by default: it orients on the codebase and existing docs, writes a provisional model with every claim tagged `(documented)` / `(maintainer)` / `(inferred)`, and collects open questions for the maintainers into waves. Answering a wave promotes the matching claims and retires the questions.

## What you get

A `docs/threat-model.md` (or similar) with:

- scope, intended use, and out-of-scope components
- per-parameter input trust table (or default + exceptions for large APIs)
- outputs and their expected sinks
- dependencies reachable from attacker input, and whether findings there are owned or redirected upstream
- adversary model, including plugin authors, co-tenants, and Byzantine peers where relevant
- security properties claimed (with violation symptom and severity tier) and disclaimed (with false-friend callouts)
- downstream responsibilities and known misuse patterns
- recurring false positives that scanners report against the project
- a closed set of triage dispositions, each citing the section that licenses it
- an optional machine-readable YAML sidecar for automated triage

## Structure

```
skills/threat-model/
├── SKILL.md                          # procedure (§1-§3, §5) + pointers
└── references/
    ├── output-structure.md           # §4: every section of the output document
    ├── question-bank.md              # §6: maintainer questions, grouped by wave
    ├── worked-sketches.md            # §7: zlib and reverse-proxy examples
    └── self-check.md                 # §8: pre-publish checklist
```

Section numbers are shared across all files so cross-references (`see §4.8`) resolve regardless of which file you are reading.

## Related

Part of the [Alpha-Omega](https://alpha-omega.dev/) tooling family alongside [scrutineer](https://github.com/alpha-omega-security/scrutineer).

## License

MIT
