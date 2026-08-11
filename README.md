# Threat Model Generator

A set of [agent skills](https://agentskills.io/) for producing threat models for open-source projects, including an orchestrator and independently invocable specialists.

The output is a document describing the implicit security contract between a project and its downstream users: what the project assumes about its environment and inputs, which security properties it claims, which it explicitly disclaims, and which threats are left to the integrator. It is written to serve two readers at once: the downstream integrator deciding what they are now responsible for, and the maintainer or triager deciding whether an inbound vulnerability report is valid, out of model, or by design.

This is not a vulnerability scanner or audit tool. It produces a contract, not findings.

New to security threat modeling? The [glossary](./skills/threat-model/references/glossary.md) defines the jargon — dispositions, sinks, disclaimed properties, provenance tags — in plain language for maintainers coming at this fresh.

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

The skill runs draft-first by default: it orients on the codebase and existing docs, writes a provisional model with every claim tagged documented / maintainer / inferred, and collects open questions for the maintainers into waves. Answering a wave promotes the matching claims and retires the questions.

### Answering the open questions

The open questions live **inside the model itself**, in the `§1.18 Open questions for the maintainers` section — that section *is* the working scratchpad, so you do not need a separate document. Each question states a proposed answer and names the section its answer lands in, so you (or a maintainer) can react to a draft rather than fill in a blank questionnaire.

To resolve them, hand the answers back to the agent and ask it to continue — for example:

```
Here are answers to the §1.18 open questions: Q3 yes, Q4 no (we never spawn processes), Q7 confirmed. Update the threat model.
```

The agent re-runs the interview/authoring loop: it promotes each answered claim from inferred / assumption to `(maintainer, YYYY-MM)`, deletes the resolved questions, updates the affected contract-dimension rows and confidence counts, re-runs the backtest on the changed areas, and regenerates the YAML sidecar. There is no separate command — re-invoking the skill with the answers continues the same modeling exercise. You can also answer in waves; each pass shrinks §1.18 until the model reaches `accepted` (zero inferred/assumption claims left).

### When to re-run

Re-run a threat-model update when something changes what the model describes. Section `§1.16 Conditions that would change this model` lists the triggers — a new public API or input format, a new network surface or deployment context, a changed configuration default, a new or updated dependency, a shipped-but-unsupported component promoted to core, or any inbound report that cannot be cleanly routed to a disposition. Also re-bind the model to each release, since it is versioned alongside the project (a report against version *N* is triaged against the model as it stood at *N*).

### Generate non-interactively (`new_threat_model.py`)

For CI or batch runs, [`new_threat_model.py`](./new_threat_model.py) drives the whole flow from the command line: it clones a target repo, installs these skills into the checkout, runs a coding-agent CLI (GitHub Copilot or Claude) to produce the model, validates it, and feeds any errors back for up to a few self-repair passes before collecting the colocated `threat-model.md` + `threat-model.yaml` + `threat-model.json` artifacts into the output directory.

```pwsh
# needs `git` plus an authenticated `copilot` (or `claude`) CLI on PATH
python new_threat_model.py --repo https://github.com/madler/zlib --out ./out/zlib

# choose the agent, scope to a monorepo subdirectory, and triage a finding corpus
python new_threat_model.py --agent claude --repo https://github.com/owner/repo `
    --subdir src --corpus findings.jsonl --out ./out/repo
```

It is pure-stdlib Python 3.9+ (no dependencies). Run `python new_threat_model.py --help` for all options. This is the same adapter the evaluation harness drives; see [`tests/README.md`](./tests/README.md) for the full generate → validate → score pipeline.

The headless agent runs use broad internal permission flags so they can inspect a checkout and write the model without stopping for approval. To keep those permissions inside an OS-enforced filesystem boundary, follow the tested [`nono` sandbox guide](./docs/nono.md). The guide covers Claude, Copilot, batch runs, network limitations, and commands for checking the effective policy before starting an agent.

### Vendor external security history (`fetch_security_context.py`)

By default a generation run works only from what is in the clone; whether the agent also consults advisories or the issue tracker depends on its web tools. [`fetch_security_context.py`](./fetch_security_context.py) makes that input deterministic: it gathers the repository's published GitHub security advisories, the matching OSV.dev records (with fixing commits), security-related issues (labeled **or** mentioning security-type terms — repos like zlib use no labels at all), issues maintainers closed as not-planned/wontfix/invalid, and security/audit links discovered on the project homepage (how an external audit report linked from zlib.net gets found) into a single `security-context.md`. `--extra-url` additionally vendors the text of named pages, e.g. a commissioned audit report. The recon phase mines that file as maintainer-authored or maintainer-acknowledged public record — citing the original advisory/issue URLs as `(documented, <url>)` — and the backtest phase seeds its corpus from the vulnerability history. Per the leave-out list, none of the CVE history itself enters the published document.

```pwsh
# standalone (GITHUB_TOKEN recommended; --package adds an OSV ecosystem query)
$env:GITHUB_TOKEN = "<token>"
python fetch_security_context.py --repo https://github.com/libexpat/libexpat `
    --package Debian:expat --out ./security-context.md

# vendor a specific external document (audit report, security page) as well
python fetch_security_context.py --repo https://github.com/madler/zlib `
    --extra-url https://7asecurity.com/blog/2026/02/zlib-7asecurity-audit/ `
    --out ./security-context.md

# or let the runner fetch it into the clone before generation
python new_threat_model.py --repo https://github.com/libexpat/libexpat `
    --fetch-security-context --out ./out/libexpat

# or reuse a pre-built file
python new_threat_model.py --repo https://github.com/libexpat/libexpat `
    --security-context ./security-context.md --out ./out/libexpat
```

Page fetches are SSRF-guarded: the homepage scan, every `--extra-url`, and every redirect hop must be plain http(s) to a host resolving only to public addresses — `file://` URLs, loopback/private/link-local ranges, and cloud metadata endpoints are refused and recorded as notes in the output. A redirect that crosses hosts drops the `Authorization` header so a GitHub token cannot follow it off `api.github.com`. A fetch failure never aborts generation — the run degrades to repo-only and the prompt drops the reference to the file.

Because the vendored issue bodies and page text are written by arbitrary third parties — anyone can file an issue — both the file header and the generation prompt mark the content as untrusted data rather than instructions, and tell the agent to report anything asking it to run commands, fetch unlisted URLs, or reveal credentials as a prompt-injection attempt. That framing is mitigation, not a guarantee; it is a further reason to run generation in a container or under the tested [`nono` sandbox guide](./docs/nono.md) when the target is untrusted. The vendored file is copied next to the output artifacts so a reviewer can see exactly which external history informed the run.

## What you get

A `threat-model.md` (or similar) with:

- scope, intended use, and out-of-scope components
- per-parameter input trust table (or default + exceptions for large APIs)
- outputs and their expected sinks
- dependencies reachable from attacker input, and whether findings there are owned or redirected upstream
- adversary model, including plugin authors, co-tenants, and Byzantine peers where relevant
- security properties claimed (with violation symptom and severity tier) and disclaimed (with false-friend callouts)
- downstream responsibilities and known misuse patterns
- recurring false positives that scanners report against the project
- a closed set of triage dispositions, each citing the section that licenses it

A machine-readable YAML sidecar (`threat-model.yaml`) for automated triage, plus a flat JSON export (`threat-model.json`) conforming to [`schema.json`](./schema.json) for external consumers — authority order prose > yaml > json

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
│       ├── json-report-schema.md     # the threat-model.json export mapping
│       ├── self-check.md             # the finalize gates
│       ├── glossary.md               # plain-language definitions of the jargon
│       └── worked-example.md         # a zlib flavor sketch
├── threat-model-recon/               # orient + mine existing docs (phases 3.1–3.2)
├── threat-model-surface/             # deep in-scope code pass (phase 3.3)
├── threat-model-interview/           # maintainer question waves (phase 3.4)
├── threat-model-authoring/           # draft the prose document (phase 3.5)
├── threat-model-backtest/            # validate against historical findings (phase 3.6)
├── threat-model-sidecar/             # emit + validate threat-model.yaml + .json (§1.19)
└── threat-model-triage/              # downstream: route one finding to a disposition
```

The orchestrator and its specialists share the §1.1–§1.19 section numbering, so cross-references (`see §1.8`) resolve regardless of which file you are reading. See [`skills/README.md`](./skills/README.md) for the call graph and per-skill roles.

## Related

Part of the [Alpha-Omega](https://alpha-omega.dev/) tooling family alongside [scrutineer](https://github.com/alpha-omega-security/scrutineer).

## License

MIT
