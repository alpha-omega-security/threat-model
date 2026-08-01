"""Tests for the per-agent wiring in ``new_threat_model.py``.

Both regressions covered here made ``--agent claude`` look like it did nothing:
the skills were installed where only Copilot looks for them, and Claude's
default text output buffers until the run ends, so the console and the log
stayed empty for the whole generation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO))

from new_threat_model import (  # noqa: E402
    CLAUDE_STREAM_ARGS,
    build_prompt,
    format_claude_event,
    skill_install_relpath,
)


# --- skill discovery path ---------------------------------------------------
def test_claude_skills_go_to_dot_claude():
    # Claude Code reads .claude/skills and ignores .github/skills entirely.
    assert skill_install_relpath("claude") == Path(".claude") / "skills"


def test_copilot_skills_go_to_dot_github():
    assert skill_install_relpath("copilot") == Path(".github") / "skills"


def test_prompt_points_at_the_agents_own_skill_path():
    claude = build_prompt("zlib", "", "strict", None, "high", "claude")
    copilot = build_prompt("zlib", "", "strict", None, "high", "copilot")
    assert ".claude/skills" in claude and ".github/skills" not in claude
    assert ".github/skills" in copilot and ".claude/skills" not in copilot


# --- streaming --------------------------------------------------------------
def test_stream_args_request_incremental_events():
    # Without stream-json the CLI prints nothing until the run finishes;
    # without --verbose the stream carries only the final result.
    assert "--output-format" in CLAUDE_STREAM_ARGS
    assert "stream-json" in CLAUDE_STREAM_ARGS
    assert "--verbose" in CLAUDE_STREAM_ARGS


def _event(payload: dict) -> str:
    return json.dumps(payload) + "\n"


def test_init_event_names_the_model():
    out = format_claude_event(_event(
        {"type": "system", "subtype": "init", "model": "claude-opus-5"}
    ))
    assert out is not None and "claude-opus-5" in out


def test_assistant_text_and_tool_calls_are_rendered():
    out = format_claude_event(_event({
        "type": "assistant",
        "message": {"content": [
            {"type": "text", "text": "Reading the headers."},
            {"type": "tool_use", "name": "Skill", "input": {"skill": "threat-model-recon"}},
        ]},
    }))
    assert out is not None
    assert "Reading the headers." in out
    assert "Skill(threat-model-recon)" in out


def test_long_tool_arguments_are_truncated():
    out = format_claude_event(_event({
        "type": "assistant",
        "message": {"content": [
            {"type": "tool_use", "name": "Bash", "input": {"command": "x" * 400}},
        ]},
    }))
    assert out is not None and len(out) < 200 and out.rstrip().endswith("...)")


def test_noise_events_are_dropped():
    for payload in (
        {"type": "rate_limit_event", "rate_limit_info": {"status": "allowed"}},
        {"type": "system", "subtype": "thinking_tokens", "estimated_tokens": 50},
        {"type": "user", "message": {"content": [{"tool_use_id": "t1", "content": "ok"}]}},
    ):
        assert format_claude_event(_event(payload)) is None


def test_tool_errors_are_surfaced():
    out = format_claude_event(_event({
        "type": "user",
        "message": {"content": [{"tool_use_id": "t1", "is_error": True, "content": "denied"}]},
    }))
    assert out is not None and "error" in out


def test_successful_result_does_not_repeat_the_streamed_text():
    out = format_claude_event(_event({
        "type": "result", "subtype": "success", "is_error": False,
        "num_turns": 5, "duration_ms": 8000, "result": "already streamed",
    }))
    assert out is not None
    assert "success" in out and "5 turns" in out
    assert "already streamed" not in out


def test_failed_result_keeps_the_reason():
    out = format_claude_event(_event({
        "type": "result", "subtype": "error_max_turns", "is_error": True,
        "num_turns": 40, "duration_ms": 1000, "result": "turn limit reached",
    }))
    assert out is not None and "error" in out and "turn limit reached" in out


def test_non_json_lines_pass_through_untouched():
    # CLI-level failures arrive on stderr as plain text and must still be seen.
    line = "Error: not authenticated. Run `claude` once interactively.\n"
    assert format_claude_event(line) == line


def test_blank_lines_are_dropped():
    assert format_claude_event("\n") is None
