# Sandbox headless generation with `nono`

`new_threat_model.py` runs Claude with `--dangerously-skip-permissions` or Copilot with `--allow-all-tools` so a non-interactive job does not stop for approval prompts. Those flags still appear inside the commands below, but [`nono`](https://nono.sh/) applies an outer, OS-enforced capability boundary that the Python process, agent CLI, and their child processes inherit.

The examples give the generator source checkout read-only access and grant read/write access only to a dedicated `.nono-runs/<name>` directory. They also set `--work-root` explicitly because the generator otherwise clones into the system temporary directory, which is outside that dedicated boundary.

## Install and authenticate

Install `nono` using its [CLI guide](https://nono.sh/cli) or Homebrew, then install the signed agent profiles from the current `nolabs-ai` registry namespace:

```bash
brew install nono
nono pull nolabs-ai/claude
nono pull nolabs-ai/copilot-cli
```

Authenticate the selected agent before entering the sandbox. Run `claude` once interactively for Claude Code, or run `gh auth login` for the `copilot-cli` profile. The profiles intentionally expose the selected agent's configuration, cache, and authentication paths; they do not make those paths invisible to the agent.

The Claude profile supports macOS and Linux. The current `nolabs-ai/copilot-cli` package declares macOS support; check `nono profile list` and the installed package documentation before using it on another platform.

## Generate one model with Claude

Run this from the root of the `threat-model` checkout:

```bash
REPO_ROOT="$(pwd)"
RUN_ROOT="$REPO_ROOT/.nono-runs/zlib-claude"
mkdir -p "$RUN_ROOT"

nono run \
  --profile claude-code \
  --network-profile claude-code \
  --workdir "$RUN_ROOT" \
  --read "$REPO_ROOT" \
  --allow "$RUN_ROOT" \
  -- python3 "$REPO_ROOT/new_threat_model.py" \
    --agent claude \
    --repo https://github.com/madler/zlib \
    --work-root "$RUN_ROOT/work" \
    --out "$RUN_ROOT/out"
```

The `claude-code` network profile routes allowed traffic through `nono`'s filtering proxy. If the target or a future Claude release needs another host, keep the default deny behavior and add the narrowest required `--allow-domain` entry after reviewing the denial.

## Generate one model with Copilot

Use a separate run directory and the Copilot profile:

```bash
REPO_ROOT="$(pwd)"
RUN_ROOT="$REPO_ROOT/.nono-runs/zlib-copilot"
mkdir -p "$RUN_ROOT"

nono run \
  --profile copilot-cli \
  --workdir "$RUN_ROOT" \
  --read "$REPO_ROOT" \
  --allow "$RUN_ROOT" \
  -- python3 "$REPO_ROOT/new_threat_model.py" \
    --agent copilot \
    --repo https://github.com/madler/zlib \
    --work-root "$RUN_ROOT/work" \
    --out "$RUN_ROOT/out"
```

The current `copilot-cli` package confines filesystem access but does not install a named Copilot network profile, so outbound networking remains allowed in this example. Do not describe this as network or exfiltration containment. Operators who require egress filtering should add and test explicit `--allow-domain` entries for their Copilot CLI version and authentication flow.

## Run a mixed-agent batch

When a batch configuration uses both Claude and Copilot, compose the two filesystem profiles with `--extends` so both CLIs can reach their own state. This example intentionally leaves networking unrestricted because the Claude network profile does not include every Copilot endpoint:

```bash
REPO_ROOT="$(pwd)"
RUN_ROOT="$REPO_ROOT/.nono-runs/batch"
mkdir -p "$RUN_ROOT"

nono run \
  --profile claude-code \
  --extends copilot-cli \
  --workdir "$RUN_ROOT" \
  --read "$REPO_ROOT" \
  --allow "$RUN_ROOT" \
  -- python3 "$REPO_ROOT/batch_threat_models.py" \
    --targets "$REPO_ROOT/batch/targets.example.txt" \
    --configs "$REPO_ROOT/batch/configs.example.json" \
    --out "$RUN_ROOT/out"
```

For a batch that uses only one agent, use only that agent's profile. Add `--network-profile claude-code` for a Claude-only batch when its required hosts fit that policy.

## Verify the boundary before running

Use `nono why` to confirm that unrelated credentials are denied, the generator checkout is read-only, and the run directory is writable:

```bash
nono why --profile claude-code --workdir "$RUN_ROOT" --read "$REPO_ROOT" --allow "$RUN_ROOT" --path "$HOME/.ssh" --op read
nono why --profile claude-code --workdir "$RUN_ROOT" --read "$REPO_ROOT" --allow "$RUN_ROOT" --path "$REPO_ROOT/README.md" --op write
nono why --profile claude-code --workdir "$RUN_ROOT" --read "$REPO_ROOT" --allow "$RUN_ROOT" --path "$RUN_ROOT/out" --op write
```

The expected results are `DENIED`, `DENIED`, and `ALLOWED`. You can also add `--dry-run` immediately before `--` in a `nono run` command to print the complete capability set without launching Python.

## Security boundaries and limitations

- Treat the target repository as untrusted agent input even when its Git history is trusted. A repository can contain instructions designed to influence a coding agent.
- Use a fresh run directory for each target. The agent can read and modify everything under that run directory, including previous output and logs if they are reused.
- The generator source checkout is readable because the script, skills, and validator live there, but `--read` prevents the sandboxed process from modifying it.
- The selected profile exposes the agent's required state and authentication paths. Review the installed profile with `nono profile show claude-code` or `nono profile show copilot-cli` before relying on it.
- Filesystem isolation does not imply network isolation. Only the Claude example above enables a verified network profile; the Copilot and mixed-agent examples explicitly do not.
- Keep `nono` and its signed profiles updated. Profile names, supported platforms, and required service endpoints can change before `nono` reaches a stable release.
