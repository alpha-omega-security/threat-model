"""Tests for the cross-model compatibility analyzer (``compat.py``).

Each test wires two tiny synthetic sidecars along one edge and asserts that the
owning rule fires (or stays silent for a compatible pair).
"""
from __future__ import annotations

from threatmodel_eval import Closure, Edge, analyze_compat


def _closure(consumer: dict, dependency: dict, via: str = "") -> Closure:
    return Closure(
        sidecars={"C": consumer, "D": dependency},
        edges=[Edge("C", "D", via)],
    )


def _ids(report) -> set[str]:
    return {f.check_id for f in report.findings if not f.passed}


def test_relied_property_disclaimed_is_error():
    consumer = {
        "project": "C",
        "dependencies": [
            {"name": "D", "relied_on_for": "decompression bomb resistance",
             "covered_here": False},
        ],
    }
    dependency = {
        "project": "D",
        "properties_disclaimed": [
            {"id": "decompression-bomb-resistance", "false_friend": False},
        ],
    }
    report = analyze_compat(_closure(consumer, dependency, via="D"))
    assert not report.ok
    assert "COMPAT.relied-disclaimed" in _ids(report)


def test_structured_relied_property_id_disclaimed_is_error():
    consumer = {
        "project": "C",
        "dependencies": [{
            "name": "D", "relied_on_for": "safe expansion",
            "relied_on_properties": ["decompression-bomb-resistance"],
            "covered_here": False,
        }],
    }
    dependency = {
        "project": "D",
        "properties_disclaimed": [
            {"id": "decompression-bomb-resistance", "false_friend": False},
        ],
    }
    report = analyze_compat(_closure(consumer, dependency, via="D"))
    assert "COMPAT.relied-disclaimed" in _ids(report)


def test_false_friend_reliance_is_called_out():
    consumer = {
        "project": "C",
        "dependencies": [
            {"name": "D", "relied_on_for": "crc as mac integrity",
             "covered_here": False},
        ],
    }
    dependency = {
        "project": "D",
        "properties_disclaimed": [{"id": "crc-as-mac", "false_friend": True}],
    }
    report = analyze_compat(_closure(consumer, dependency, via="D"))
    msg = " ".join(f.message for f in report.findings if not f.passed)
    assert "false friend" in msg.lower()


def test_unbacked_reliance_is_warning():
    consumer = {
        "project": "C",
        "dependencies": [
            {"name": "D", "relied_on_for": "constant time comparison",
             "covered_here": False},
        ],
    }
    dependency = {"project": "D", "properties_claimed": [
        {"id": "memory-safety", "tier": "security-critical",
         "violation_symptoms": ["crash"]}]}
    report = analyze_compat(_closure(consumer, dependency, via="D"))
    ids = _ids(report)
    assert "COMPAT.relied-unbacked" in ids
    # Unbacked reliance is a soft signal, not a hard gate.
    assert report.ok


def test_adversary_scope_gap_is_error():
    consumer = {
        "project": "C",
        "dependencies": [{
            "name": "D", "relied_on_for": "network parsing",
            "adversary_capabilities_forwarded": ["supply-network-bytes"],
        }],
        "adversaries": [
            {"name": "net-peer", "scope": "in",
             "capabilities": ["supply-network-bytes"]},
        ],
    }
    dependency = {
        "project": "D",
        "adversaries": [
            {"name": "trusted-caller", "scope": "in", "capabilities": [],
             "excluded_capabilities": ["supply-network-bytes"]},
        ],
    }
    report = analyze_compat(_closure(consumer, dependency, via="D"))
    assert not report.ok
    assert "COMPAT.adversary-scope-gap" in _ids(report)


def test_adversary_scope_gap_requires_declared_forwarding():
    consumer = {
        "project": "C",
        "dependencies": [{"name": "D", "relied_on_for": "local formatting"}],
        "adversaries": [{
            "name": "net-peer", "scope": "in",
            "capabilities": ["supply-network-bytes"],
        }],
    }
    dependency = {
        "project": "D",
        "adversaries": [{
            "name": "trusted-caller", "scope": "in", "capabilities": [],
            "excluded_capabilities": ["supply-network-bytes"],
        }],
    }
    report = analyze_compat(_closure(consumer, dependency, via="D"))
    assert "COMPAT.adversary-scope-gap" not in _ids(report)


def test_tainted_output_consumed_is_warning():
    consumer = {
        "project": "C",
        "dependencies": [{
            "name": "D", "relied_on_for": "parsing",
            "outputs_consumed": [{
                "channel": "parsed-tree", "taint_handling": "passthrough",
                "supports_property_id": "output-safe",
            }],
        }],
        "properties_claimed": [
            {"id": "output-safe", "kind": "output-sanitization",
             "tier": "security-critical",
             "violation_symptoms": ["xss"]}],
    }
    dependency = {
        "project": "D",
        "outputs": [{"channel": "parsed-tree", "taint": "same-as-input"}],
    }
    report = analyze_compat(_closure(consumer, dependency, via="D"))
    assert "COMPAT.tainted-output-consumed" in _ids(report)


def test_tainted_output_does_not_warn_for_unrelated_memory_safety_claim():
    consumer = {
        "project": "C",
        "properties_claimed": [{
            "id": "memory-safety", "kind": "memory-safety",
            "tier": "security-critical", "violation_symptoms": ["crash"],
        }],
    }
    dependency = {
        "project": "D",
        "outputs": [{"channel": "parsed-tree", "taint": "same-as-input"}],
    }
    report = analyze_compat(_closure(consumer, dependency))
    assert "COMPAT.tainted-output-consumed" not in _ids(report)


def test_tainted_output_does_not_warn_without_declared_edge_flow():
    consumer = {
        "project": "C",
        "dependencies": [{"name": "D", "relied_on_for": "unrelated metadata"}],
        "properties_claimed": [{
            "id": "output-safe", "kind": "output-sanitization",
            "tier": "security-critical", "violation_symptoms": ["xss"],
        }],
    }
    dependency = {
        "project": "D",
        "outputs": [{"channel": "parsed-tree", "taint": "same-as-input"}],
    }
    report = analyze_compat(_closure(consumer, dependency, via="D"))
    assert "COMPAT.tainted-output-consumed" not in _ids(report)


def test_unenforced_caller_obligation_is_warning():
    consumer = {"project": "C"}  # no dependencies[] acknowledging obligations
    dependency = {
        "project": "D",
        "entry_points": [
            {"id": "parse", "parameters": [
                {"name": "buf", "attacker_controllable": True,
                 "obligation_id": "enforce-length-bound",
                 "caller_must_enforce": "length bound"}]},
        ],
    }
    report = analyze_compat(_closure(consumer, dependency))
    assert "COMPAT.unenforced-caller-obligation" in _ids(report)


def test_unrelated_reliance_does_not_acknowledge_obligation():
    consumer = {
        "project": "C",
        "dependencies": [{
            "name": "D", "relied_on_for": "logging availability",
            "caller_obligations_acknowledged": [],
        }],
    }
    dependency = {
        "project": "D",
        "entry_points": [{"id": "parse", "parameters": [{
            "name": "buf", "attacker_controllable": True,
            "obligation_id": "enforce-length-bound",
            "caller_must_enforce": "length bound",
        }]}],
    }
    report = analyze_compat(_closure(consumer, dependency, via="D"))
    assert "COMPAT.unenforced-caller-obligation" in _ids(report)


def test_exact_obligation_acknowledgement_is_accepted():
    consumer = {
        "project": "C",
        "dependencies": [{
            "name": "D", "relied_on_for": "bounded parse",
            "caller_obligations_acknowledged": ["enforce-length-bound"],
        }],
    }
    dependency = {
        "project": "D",
        "entry_points": [{"id": "parse", "parameters": [{
            "name": "buf", "attacker_controllable": True,
            "obligation_id": "enforce-length-bound",
            "caller_must_enforce": "length bound",
        }]}],
    }
    report = analyze_compat(_closure(consumer, dependency, via="D"))
    assert "COMPAT.unenforced-caller-obligation" not in _ids(report)


def test_compatible_pair_is_clean():
    consumer = {
        "project": "C",
        "dependencies": [
            {"name": "D", "relied_on_for": "memory safety on untrusted input",
             "covered_here": False}],
    }
    dependency = {
        "project": "D",
        "properties_claimed": [
            {"id": "memory-safety-untrusted-input", "tier": "security-critical",
             "violation_symptoms": ["crash"]}],
    }
    report = analyze_compat(_closure(consumer, dependency, via="D"))
    assert report.ok
    assert "COMPAT.clean" in {f.check_id for f in report.findings if f.passed}


def test_missing_dependency_node_is_flagged():
    closure = Closure(sidecars={"C": {"project": "C"}},
                      edges=[Edge("C", "D")])
    report = analyze_compat(closure)
    assert not report.ok
    assert "COMPAT.missing-node" in _ids(report)
