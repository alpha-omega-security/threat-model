# Security Policy

Thanks for helping keep this project and its users safe.

This repository ships **agent skills** (Markdown instructions and references under
[`skills/`](./skills/)) plus a small, dependency-free helper script
([`new_threat_model.py`](./new_threat_model.py)) and an evaluation harness under
[`tests/`](./tests/). It is not a hosted service and processes no user data of its
own. Please keep that scope in mind when reporting.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's coordinated disclosure:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** to open a private advisory
   (GitHub Private Vulnerability Reporting).

Please include, as far as you can:

- a description of the issue and its impact,
- the affected file(s) or skill(s) and the commit or version,
- steps to reproduce (a minimal example, command, or repo/input that triggers it),
- and any suggested remediation.

### What to expect

- We aim to acknowledge a report within **5 business days**.
- We will work with you to confirm the issue, agree on a fix and disclosure
  timeline, and credit you in the advisory unless you prefer to remain anonymous.
- Please give us a reasonable window to release a fix before any public
  disclosure.

## What is in scope

- The generation/triage scripts and evaluation harness (for example, path
  traversal, command injection, or unsafe handling of untrusted repository
  content in [`new_threat_model.py`](./new_threat_model.py) or `tests/`).
- Skill or reference content that could cause an agent to take an unsafe action
  (for example, instructions that would lead an agent to exfiltrate secrets or
  run destructive commands).

## What is out of scope

- **Findings inside a threat model that the tool generates.** Those are the
  responsibility of the target project, not of this repository. To dispute
  whether a finding is in scope for a *generated* model, use the model's own
  `§1.17` disposition set and `§1.18` open-question process.
- The behavior of the third-party coding-agent CLIs
  (GitHub Copilot CLI, Claude CLI) or the LLMs behind them.

## Operational note

[`new_threat_model.py`](./new_threat_model.py) clones a target repository and runs
a coding-agent CLI with broad tool access (`--allow-all-tools` /
`--dangerously-skip-permissions`) in that checkout. Run it **only against
repositories you trust**, and prefer an isolated or ephemeral environment for
untrusted input. Reports about running the tool against untrusted repositories
are welcome as hardening suggestions, but the documented guidance is to treat the
cloned repository as trusted input.
