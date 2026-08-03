"""Tests for the Tier-5 historical-replay scorer, stub runner, and fetcher.

Fully offline: episodes are synthesized in a tmp dir, the stub triage runner
replays a correct routing, and the fetcher's pure resolution helpers are checked
against inline API payloads (no network).
"""
from __future__ import annotations

import json
from pathlib import Path

import fetch_replay
from threatmodel_eval import load_episodes, score_replay
from threatmodel_eval.runners import ReplaySpec, StubTriageRunner


def _write_episodes(dir_: Path) -> Path:
    (dir_ / "reports").mkdir(parents=True, exist_ok=True)
    eps = [
        {
            "episode_id": "demo-cve-1", "project": "demo", "month": "2022-07",
            "vuln": {"id": "demo-cve-1", "source": "CVE-2022-1",
                     "ground_truth": "VALID", "report_file": "reports/v1.md"},
            "controls": [
                {"id": "demo-issue-10", "close_reason": "not_planned",
                 "report_file": "reports/c10.md"},
                {"id": "demo-issue-11", "close_reason": "invalid",
                 "report_file": "reports/c11.md"},
            ],
        },
        {
            "episode_id": "demo-cve-2", "project": "demo", "month": "2022-08",
            "vuln": {"id": "demo-cve-2", "source": "CVE-2022-2",
                     "ground_truth": "VALID", "report_file": "reports/v2.md"},
            "controls": [
                {"id": "demo-issue-20", "close_reason": "wontfix",
                 "report_file": "reports/c20.md"},
            ],
        },
    ]
    p = dir_ / "episodes.jsonl"
    with p.open("w", encoding="utf-8") as fh:
        for e in eps:
            fh.write(json.dumps(e) + "\n")
    for name in ("v1", "c10", "c11", "v2", "c20"):
        (dir_ / "reports" / f"{name}.md").write_text("report body", encoding="utf-8")
    return p


def _perfect(episodes) -> dict:
    preds = {}
    for ep in episodes:
        preds[ep.vuln.id] = "VALID"
        for c in ep.controls:
            preds[c.id] = "KNOWN-NON-FINDING"
    return preds


def test_perfect_predictions_score_clean(tmp_path):
    load = load_episodes([_write_episodes(tmp_path)])
    card = score_replay(load, _perfect(load))
    assert card.ok
    assert card.catch_rate == 1.0
    assert card.cry_wolf_rate == 0.0
    assert not card.misses
    assert not card.cry_wolves


def test_wrongly_closing_vuln_is_a_miss(tmp_path):
    load = load_episodes([_write_episodes(tmp_path)])
    preds = _perfect(load)
    preds["demo-cve-1"] = "OUT-OF-MODEL: trusted-input"
    card = score_replay(load, preds)
    assert not card.ok
    assert any(m["id"] == "demo-cve-1" for m in card.misses)
    assert card.catch_rate < 1.0


def test_escalating_a_control_is_cry_wolf(tmp_path):
    load = load_episodes([_write_episodes(tmp_path)])
    preds = _perfect(load)
    preds["demo-issue-10"] = "VALID"
    card = score_replay(load, preds)
    assert not card.ok  # default threshold 0.0
    assert any(c["id"] == "demo-issue-10" for c in card.cry_wolves)
    assert card.cry_wolf_rate > 0.0


def test_cry_wolf_threshold_tolerates_some_noise(tmp_path):
    load = load_episodes([_write_episodes(tmp_path)])
    preds = _perfect(load)
    preds["demo-issue-10"] = "VALID"  # 1 of 3 controls
    card = score_replay(load, preds, cry_wolf_threshold=0.5)
    assert card.ok  # 33% <= 50%, and no vuln missed


def test_contested_vuln_is_excluded(tmp_path):
    p = tmp_path / "episodes.jsonl"
    (tmp_path / "reports").mkdir(exist_ok=True)
    p.write_text(json.dumps({
        "episode_id": "c", "project": "demo", "month": "2022-07",
        "vuln": {"id": "cv", "ground_truth": "VALID", "contested": True},
        "controls": [],
    }) + "\n", encoding="utf-8")
    load = load_episodes([p])
    # Even a wrong close is not a miss for a contested vuln.
    card = score_replay(load, {"cv": "OUT-OF-MODEL: trusted-input"})
    assert card.n_vulns_scored == 0
    assert not card.misses
    assert card.ok


def test_missing_and_unknown_predictions_fail(tmp_path):
    load = load_episodes([_write_episodes(tmp_path)])
    # Missing prediction for a vuln.
    card = score_replay(load, {})
    assert not card.ok
    assert "demo-cve-1" in card.missing_predictions

    preds = _perfect(load)
    preds["demo-cve-2"] = "NONSENSE"
    card2 = score_replay(load, preds)
    assert not card2.ok
    assert any(u["id"] == "demo-cve-2" for u in card2.unknown_predictions)


def test_stub_triage_runner_end_to_end(tmp_path):
    episodes_path = _write_episodes(tmp_path)
    spec = ReplaySpec(name="demo", episodes=episodes_path,
                      dataset_dir=tmp_path, model=None, sidecar=None)
    preds_path = StubTriageRunner().predict(spec, tmp_path / "out")
    preds = {}
    for line in preds_path.read_text(encoding="utf-8").splitlines():
        d = json.loads(line)
        preds[d["id"]] = d["predicted_disposition"]
    card = score_replay(load_episodes([episodes_path]), preds)
    assert card.ok
    assert card.catch_rate == 1.0
    assert card.cry_wolf_rate == 0.0


# --- fetcher pure helpers (no network) ------------------------------------
def test_osv_fix_commits_extracts_git_fixed():
    osv = {"affected": [{"ranges": [
        {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]},
        {"type": "SEMVER", "events": [{"fixed": "1.2.12"}]},
    ]}]}
    assert fetch_replay.osv_fix_commits(osv) == ["abc123"]


def test_classify_control_recognizes_noise():
    assert fetch_replay.classify_control(
        {"state": "closed", "state_reason": "not_planned"})
    assert fetch_replay.classify_control(
        {"state": "closed", "labels": [{"name": "invalid"}]})
    assert not fetch_replay.classify_control(
        {"state": "closed", "state_reason": "completed"})
    assert not fetch_replay.classify_control(
        {"state": "open", "state_reason": "not_planned"})
    assert not fetch_replay.classify_control(
        {"state": "closed", "state_reason": "not_planned",
         "pull_request": {"url": "x"}})


def test_same_month():
    assert fetch_replay.same_month("2022-07-15T00:00:00Z", "2022-07")
    assert not fetch_replay.same_month("2022-08-01T00:00:00Z", "2022-07")
    assert not fetch_replay.same_month("", "2022-07")
