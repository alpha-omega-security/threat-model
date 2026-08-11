---
title: Quickstart
description: Install the threat-model skills and generate a first evidence-backed draft.
---

<header class="page-hero">
  <div class="wrap">
    <span class="eyebrow">Quickstart</span>
    <h1>From checkout to reviewable draft.</h1>
    <p class="lede">Use the skills interactively, or run the same generation and validation loop non-interactively.</p>
  </div>
</header>

<section class="section">
<div class="wrap content-grid">
<aside class="side-note">
  <strong>Before you begin</strong>
  Generation runs a coding-agent CLI with broad tool access inside the target checkout. Use a container, throwaway user, or sandbox for repositories you do not trust.
</aside>
<div class="prose" markdown="1">

## 1. Install the skills

### Claude Code

```text
/plugin marketplace add alpha-omega-security/threat-model
/plugin install threat-model@threat-model
```

Then open the target checkout and invoke:

```text
/threat-model:threat-model
```

### GitHub Copilot

In an interactive Copilot CLI session:

```text
/plugin marketplace add https://github.com/alpha-omega-security/threat-model
/plugin install threat-model@threat-model
```

### Other compatible agents

Other [Agent Skills](https://agentskills.io/clients) clients may use a different skill path. If you load the skills directly from a checkout, keep the skill directories as siblings under `skills/` so the specialists can resolve shared references via relative paths.

## 2. Ask for the model

From the target repository:

```text
Produce a threat model for this project.
```

The first pass is intentionally a draft. Claims are tagged as documented,
maintainer-confirmed, inferred, or assumed, and unresolved decisions become
proposed questions in §1.18.

<div class="callout">
  <strong>You review claims, not a blank questionnaire.</strong>
  The draft proposes the likely contract first. Maintainers can answer in waves:
  “Q3 yes, Q4 no—we never spawn processes, Q7 confirmed.”
</div>

## 3. Review the three artifacts

| Artifact | Role |
| --- | --- |
| `threat-model.md` | Canonical, human-readable model |
| `threat-model.yaml` | Near-lossless structured sidecar used by triage |
| `threat-model.json` | Conservative schema-backed export for external consumers |

Always review the prose first. Authority flows **prose → YAML → JSON**.

## 4. Generate non-interactively

The standard-library runner clones the target, installs the skills, invokes
Copilot or Claude, validates the result, and feeds validation failures back for
repair:

```bash
python new_threat_model.py \
  --repo https://github.com/madler/zlib \
  --out ./out/zlib
```

Choose the agent or scope a monorepo:

```bash
python new_threat_model.py \
  --agent claude \
  --repo https://github.com/owner/repo \
  --subdir packages/parser \
  --out ./out/parser
```

Run `python new_threat_model.py --help` for corpus, security-context, build,
and triage-policy options.

## 5. Keep it version-bound

Re-run when public APIs, input formats, deployment assumptions, defaults,
dependencies, or supported components change. Re-bind the model to each
release; a finding against version *N* should be evaluated against the model as
it stood at *N*.

<div class="button-row">
  <a class="button button-light" href="{{ '/methodology/' | relative_url }}">Understand the method</a>
  <a class="button button-light" href="{{ '/models/zlib/' | relative_url }}">Inspect the zlib example</a>
</div>

</div>
</div>
</section>
