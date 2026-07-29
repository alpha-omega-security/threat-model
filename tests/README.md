# Threat-model quality harness

This directory proves the threat-model skill set in
[../.github/skills/](../.github/skills/) produces **high-quality** threat
models — not just that it runs. Quality is defined by the skill's own gates in
[self-check.md](../.github/skills/threat-model/references/self-check.md), so the
harness turns those gates into executable checks and measures the two outcomes
that matter: is the model *well-formed and internally consistent*, and does it
let a triager *route real findings correctly and fail safe*.

## The five tiers

| Tier | Question | Mechanism | Runs offline? |
| --- | --- | --- | --- |
| **0 — Structure** | Is the document well-formed (all sections, provenance legend, sidecar schema)? | `threatmodel_eval` deterministic checks | yes |
| **1 — Consistency (mutation)** | Do the checks actually bite? | `mutate.py` injects one defect per case; each must be caught by exactly its owning check | yes |
| **2 — Triage backtest** | Does the model route real findings correctly, and **never wrongly close a valid vuln**? | labeled corpora + `backtest.py` fail-safe scorer | yes |
| **3 — Judgement** | Is the content good (crisp scope, real adversary, model-not-audit)? | blind LLM judge, [rubric/quality-rubric.md](rubric/quality-rubric.md) | needs a judge model |
| **4 — Robustness** | Determinism, sidecar round-trip, graceful failure on thin input | pytest | yes |
| **5 — Historical replay** | Would the pipeline have **caught** a now-known vuln without **crying wolf** on same-month noise? | vendored real disclosures + `replay.py` catch / cry-wolf scorer | yes (after a networked build step) |

Tiers 0, 1, 2, and 4 are fully deterministic and run with no agent and no
network. Tier 3 needs a judge model. Tier 5 scores offline against vendored
fixtures, but building those fixtures (`fetch_replay.py`) hits the network once.
Live end-to-end generation (invoking the actual skill against real repos) is
driven by `run_eval.py` with a pluggable runner; live triage replay is driven by
`replay_eval.py`.

## Layout

```
tests/
  harness/
    threatmodel_eval/      the validator + scorer package
      parse.py             prose + sidecar parsing
      checks.py            Gate 1–4 deterministic checks (prose)
      sidecar.py           sidecar schema + cross-consistency checks
      report.py            Finding / Report types
      backtest.py          Tier-2 fail-safe triage scorer
      replay.py            Tier-5 catch / cry-wolf scorer
      gaps.py              gap analyzer: open questions, inferred claims, coverage
      runners.py           pluggable generation (Stub / Subprocess)
    validate_model.py      CLI: validate one model (+ sidecar)
    score_triage.py        CLI: score triage predictions vs corpus
    run_eval.py            orchestrator: generate -> validate -> score -> scorecard
    run_job.py             arbitrary-repo job: generate -> validate -> gaps -> (history)
    replay_eval.py         Tier-5 orchestrator: triage vendored disclosures -> catch/cry-wolf
    fetch_replay.py        Tier-5 build step: fetch + vendor real disclosures
    mutate.py              Tier-1 mutation generator
    projects.json          project registry (repo, ref, corpus, golden, replay)
    requirements.txt
    conftest.py            makes the package importable under pytest
    tests/                 pytest: test_validator / test_backtest / test_robustness / test_replay / test_gaps
  fixtures/golden/zlib/    the golden reference model + sidecar (passes every check)
  fixtures/mutations/      generated negative fixtures (gitignored)
  corpora/{zlib,libexpat,sqlite}/corpus.jsonl   labeled historical findings
  replay/{zlib,libexpat,sqlite}/   Tier-5 datasets: sources.json + episodes.jsonl + reports/
  rubric/quality-rubric.md Tier-3 LLM-judge rubric
  runs/                    orchestrator output (gitignored)
```

## The golden fixture

[fixtures/golden/zlib/](fixtures/golden/zlib/) is a compact, structurally
complete zlib threat model that passes every error-level check with zero
warnings. It does triple duty: the positive validator fixture, the base the
mutation generator corrupts, and a worked example of the target output. Its
provenance counts in the §1.1 header exactly match the body tags, and its
sidecar matches the prose — the invariants the checks enforce.

## The corpora and the fail-safe metric

Each `corpus.jsonl` is a set of real historical findings (cited by CVE where
one exists) with a defensible ground-truth disposition from the closed §1.17
set. Labels that are genuinely arguable are marked `"contested": true` with a
note — mirroring the skill's own anti-fabrication stance, these are flagged for
human ratification rather than asserted as fact.

The headline Tier-2 metric is the **fail-safe rate**: how often a finding whose
truth is `VALID` was wrongly *closed* (routed to any OUT-OF-MODEL / BY-DESIGN /
KNOWN-NON-FINDING disposition). This error is asymmetric and disqualifying —
wrongly closing a real vulnerability is far worse than wrongly escalating a
non-finding, which is recorded as a cheap "over-escalation". A run with any
fail-safe violation is **not acceptable** regardless of overall agreement.

> ⚠️ The corpus ground-truth labels are a starting point authored from public
> CVE data and documented maintainer stances. Before using them to gate a real
> agent, have a security reviewer ratify each label — especially the
> `contested` ones.

## Historical replay (Tier 5)

Tier 2 scores distilled findings; Tier 5 replays **real historical
disclosures** against a *fixed* threat model to answer the two questions a
maintainer actually cares about:

- **Catch** — given the real report text for a now-known vulnerability, does the
  triager keep it *open*? Routing a real vuln to any closing disposition is a
  **miss**: the asymmetric, disqualifying error (the Tier-2 fail-safe rule, one
  layer up).
- **Cry-wolf** — each episode pairs its real vuln with same-month reports the
  maintainers closed as `invalid` / `wontfix`. Escalating one of those controls
  to `VALID` / `VALID-HARDENING` is a false alarm.

An *episode* is one real vulnerability plus its same-month controls. The model
is held **fixed** — this tier measures the *triage* skill, not blind generation,
so generation leakage (the model may already "know" a famous CVE) is accepted by
design. Controls are scored as a binary **must-not-escalate**, since a
maintainer's `invalid`/`wontfix` label doesn't map onto the closed §1.17 set;
`contested` items are excluded from the strict metrics.

Datasets live under `replay/<project>/` and are built once from the network,
then vendored for offline, reproducible scoring:

```
replay/<project>/
  sources.json      fetcher input: repo + real vuln ids (CVE/GHSA) + ground truth
  episodes.jsonl    one episode per vuln (+ discovered same-month controls)
  reports/<id>.md   vendored raw report text
  manifest.json     provenance: source URLs, fetch timestamp, sha256
```

Build/refresh a dataset (needs `GITHUB_TOKEN` for the commit/issue/search APIs;
OSV.dev resolves each CVE to its fixing commit and pre-fix parent):

```pwsh
$env:GITHUB_TOKEN = "<token>"
python tests/harness/fetch_replay.py --project zlib
```

Score it. The stub runner replays a correct routing (a wiring proof, not a
quality signal); a live triage agent is wired via `--runner subprocess` with a
per-report command. Because a live agent is nondeterministic, `--repeats N` runs
the whole pass N times and the run passes only when *every* repeat catches every
vuln and stays at or below `--cry-wolf-threshold`:

```pwsh
python tests/harness/replay_eval.py --runner stub --repeats 3
python tests/harness/replay_eval.py --runner subprocess --repeats 3 `
    --command "pwsh ./scripts/triage.ps1 -Model {model} -Sidecar {sidecar} -Report {report}"
```

Placeholders: `{name} {model} {sidecar} {report} {id} {outdir} {skill_dir}`. The
command triages one report and prints exactly one disposition on stdout. The
orchestrator writes `replay-scorecard.json` + `replay-summary.md` to
`tests/runs/replay-<timestamp>/`.

## Arbitrary-repo job (`run_job.py`)

`run_eval.py` and `replay_eval.py` iterate the curated `projects.json` registry.
`run_job.py` instead takes **any** GitHub repo — no pre-registration, no
hand-authored corpus or golden — and runs the whole pipeline end to end:

1. **generate** the model via a pluggable command (default:
   `new_threat_model.py`, which itself runs the validator after
   generation and feeds any errors back to the agent for up to
   `--max-repair-attempts` self-repair passes — disable with `--no-repair`);
2. **validate** it with the deterministic Tier-0/1 checks;
3. **gap-analyze** it (`gaps.py`): stated status + provenance mix
   (documented / maintainer / inferred), §1.18 open questions, dangling
   inferred tags, and missing / thin required sections; and
4. optionally **score against history** (`--with-history`): discover the repo's
   published GitHub security advisories, vendor them as a replay dataset, triage
   each against the fresh model, and report **catch** / **cry-wolf** — quality
   scoring bootstrapped from the repo's own real CVEs.

```pwsh
# generate + validate + gaps (needs the generating agent CLI available)
python tests/harness/run_job.py --repo https://github.com/madler/zlib

# also score against the repo's own advisory history
$env:GITHUB_TOKEN = "<token>"
python tests/harness/run_job.py --repo https://github.com/madler/zlib `
    --with-history --token $env:GITHUB_TOKEN `
    --triage-command "pwsh ./scripts/triage.ps1 -Model {model} -Report {report}"
```

The generation command uses the same placeholders as `run_eval.py`
(`{name} {repo} {ref} {corpus} {outdir} {skill_dir}`). Output — `scorecard.json`
(validation + gaps + history) and a human-readable `report.md` — lands in
`tests/runs/job-<name>-<timestamp>/`. The job exits nonzero if validation fails
or history scoring records a missed vuln. Tier-2 labeled-corpus scoring is *not*
available for arbitrary repos (no ground truth), which is exactly why history
replay is the quality signal here.

## Running it

Install deps (PyYAML + pytest):

```pwsh
python -m pip install -r tests/harness/requirements.txt
```

Run the deterministic test suite (Tiers 0, 1, 2, 4):

```pwsh
python -m pytest tests/harness/tests -q
```

Validate a single model (and sidecar):

```pwsh
python tests/harness/validate_model.py tests/fixtures/golden/zlib/docs/threat-model.md tests/fixtures/golden/zlib/threat-model.yaml
```

Materialize the mutation fixtures for inspection:

```pwsh
python tests/harness/mutate.py
```

Score triage predictions against the corpus (or self-check with `--reference`):

```pwsh
python tests/harness/score_triage.py --reference
python tests/harness/score_triage.py path/to/predictions.jsonl
```

Run the full pipeline offline (stub runner — smoke test, not a quality signal):

```pwsh
python tests/harness/run_eval.py --runner stub
```

## Wiring in a live agent (Tiers 2–3 for real)

The exact CLI of the generating agent is environment-specific, so `run_eval.py`
delegates generation to a pluggable runner. The `subprocess` runner invokes a
command you supply; it must clone/prepare the project, drive the threat-model
skill, triage the corpus, and write `threat-model.md`, `threat-model.yaml`, and
`predictions.jsonl` into `{outdir}`:

```pwsh
python tests/harness/run_eval.py --runner subprocess `
    --command "pwsh ./scripts/generate.ps1 -Project {name} -Repo {repo} -Ref {ref} -Corpus {corpus} -Out {outdir} -SkillDir {skill_dir}"
```

Placeholders: `{name} {repo} {ref} {corpus} {outdir} {skill_dir}`. The
orchestrator then runs Tier 0/1 validation and the Tier-2 backtest over whatever
the agent produced, and writes an aggregate `scorecard.json` + `summary.md` to
`tests/runs/<timestamp>/`. Feed the generated model to the Tier-3 judge with the
[rubric](rubric/quality-rubric.md) for the qualitative gate.

## Predictions format

`predictions.jsonl` — one JSON object per line mapping a corpus finding id to
the disposition the model/triager assigned:

```json
{"id": "zlib-cve-2022-37434", "predicted_disposition": "VALID"}
```
