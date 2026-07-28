# threat-model

A set of [agent skills](https://agentskills.io/) for producing threat models for open-source projects — an orchestrator plus independently invocable specialists.

The output is a document describing the implicit security contract between a project and its downstream users: what the project assumes about its environment and inputs, which security properties it claims, which it explicitly disclaims, and which threats are left to the integrator. It is written to serve two readers at once: the downstream integrator deciding what they are now responsible for, and the maintainer or triager deciding whether an inbound vulnerability report is valid, out of model, or by design.

This is not a vulnerability scanner or audit tool. It produces a contract, not findings.

## Install

### Claude Code

```
/plugin marketplace add alpha-omega-security/threat-model
/plugin install threat-model@threat-model
```

### Other agents

Any [agentskills.io-compatible](https://agentskills.io/clients) agent can load these skills directly from `skills/`. Clone the repo and point your agent's skill path at that directory, or copy its contents into your project's `.claude/skills/` (or equivalent). Keep the skill folders as siblings — the specialists share the references under `threat-model/references/` via relative paths.

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

### Answering the open questions

The open questions live **inside the model itself**, in the `§1.18 Open questions for the maintainers` section — that section *is* the working scratchpad, so you do not need a separate document. Each question states a proposed answer and names the section its answer lands in, so you (or a maintainer) can react to a draft rather than fill in a blank questionnaire.

To resolve them, hand the answers back to the agent and ask it to continue — for example:

```
Here are answers to the §1.18 open questions: Q3 yes, Q4 no (we never spawn processes), Q7 confirmed. Update the threat model.
```

The agent re-runs the interview/authoring loop: it promotes each answered claim from `(inferred)` / `(assumption)` to `(maintainer, YYYY-MM)`, deletes the resolved questions, updates the affected contract-dimension rows and confidence counts, re-runs the backtest on the changed areas, and regenerates the YAML sidecar. There is no separate command — re-invoking the skill with the answers continues the same modeling exercise. You can also answer in waves; each pass shrinks §1.18 until the model reaches `accepted` (zero inferred/assumption claims left).

### When to re-run

Re-run a threat-model update when something changes what the model describes. Section `§1.16 Conditions that would change this model` lists the triggers — a new public API or input format, a new network surface or deployment context, a changed configuration default, a new or updated dependency, a shipped-but-unsupported component promoted to core, or any inbound report that cannot be cleanly routed to a disposition. Also re-bind the model to each release, since it is versioned alongside the project (a report against version *N* is triaged against the model as it stood at *N*).


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
skills/
├── threat-model/                     # orchestrator: drives the 3.1–3.7 procedure; owns the shared references
│   ├── SKILL.md
│   └── references/
│       ├── principles.md             # what a threat model is/is not; the four-question framework
│       ├── output-structure.md       # the §1.1–§1.19 document spec, provenance tags, disposition set
│       ├── question-bank.md          # maintainer questions, grouped by wave
│       ├── sidecar-schema.md         # the threat-model.yaml schema
│       ├── self-check.md             # the finalize gates
│       └── worked-example.md         # a zlib flavor sketch
├── threat-model-recon/               # orient + mine existing docs (phases 3.1–3.2)
├── threat-model-surface/             # deep in-scope code pass (phase 3.3)
├── threat-model-interview/           # maintainer question waves (phase 3.4)
├── threat-model-authoring/           # draft the prose document (phase 3.5)
├── threat-model-backtest/            # validate against historical findings (phase 3.6)
├── threat-model-sidecar/             # emit + validate threat-model.yaml (§1.19)
└── threat-model-triage/              # downstream: route one finding to a disposition
```

The orchestrator and its specialists share the §1.1–§1.19 section numbering, so cross-references (`see §1.8`) resolve regardless of which file you are reading. See [`skills/README.md`](./skills/README.md) for the call graph and per-skill roles.

## Related

Part of the [Alpha-Omega](https://alpha-omega.dev/) tooling family alongside [scrutineer](https://github.com/alpha-omega-security/scrutineer).

## License

MIT
