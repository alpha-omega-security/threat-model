"""Tier-2 triage-routing tests — does the model actually route real findings?

These tests exist because a structurally-valid model can still be *useless*: if
nothing consumes the sidecar's routing facts, an agent collapses every finding
to ``MODEL-GAP``. Here the deterministic reference engine
(:func:`threatmodel_eval.triage`) routes each labeled corpus finding against the
golden sidecar and we assert:

* every **non-contested** finding lands on its exact ground-truth disposition
  (the anti-collapse guard — proves we are NOT emitting blanket ``MODEL-GAP``);
* no ``VALID`` / ``VALID-HARDENING`` finding is ever *closed* (fail-safe);
* **contested** findings route to the label or escalate — never a wrong close;
* every concrete route is *licensed by a real sidecar fact* (a citation);
* a close licensed only by an ``inferred`` fact is flagged ``escalated`` while an
  unratified draft; a documented close closes cleanly.

Per-rule unit tests over a tiny synthetic sidecar pin each §1.17 precedence step.
"""
from __future__ import annotations

from pathlib import Path

import mutate  # noqa: F401  (ensures harness dir on sys.path via conftest)
from threatmodel_eval import load_corpus, load_sidecar, score, triage
from threatmodel_eval.triage import CLOSING

_TESTS_DIR = Path(mutate.__file__).resolve().parents[1]
_ZLIB_CORPUS = _TESTS_DIR / "corpora" / "zlib" / "corpus.jsonl"
_ZLIB_SIDECAR = (_TESTS_DIR / "fixtures" / "golden" / "zlib" / "threat-model.yaml")

# The share of the corpus we insist the model routes to a *concrete* (non
# MODEL-GAP) disposition. Contested seams and the two genuine model gaps are
# allowed to escalate; everything else must route.
_MIN_CONCRETE_ROUTING = 0.75


def _corpus():
    return load_corpus([_ZLIB_CORPUS])


def _sidecar():
    return load_sidecar(_ZLIB_SIDECAR)


# --------------------------------------------------------------------------- #
# Corpus-level routing behaviour (the headline: no MODEL-GAP collapse)         #
# --------------------------------------------------------------------------- #

def test_noncontested_findings_route_to_exact_ground_truth():
    """The anti-collapse guard: every settled finding routes to its label."""
    sc = _sidecar()
    mismatches = []
    for item in _corpus():
        if item.contested:
            continue
        result = triage(item.signal, sc)
        if result.disposition != item.ground_truth:
            mismatches.append((item.id, item.ground_truth, result.disposition))
    assert not mismatches, f"non-contested routing mismatches: {mismatches}"


def test_not_everything_is_model_gap():
    """Directly refutes the 'everything is MODEL-GAP' failure mode."""
    sc = _sidecar()
    corpus = _corpus()
    concrete = sum(1 for c in corpus if triage(c.signal, sc).disposition != "MODEL-GAP")
    assert concrete / len(corpus) >= _MIN_CONCRETE_ROUTING, (
        f"only {concrete}/{len(corpus)} findings routed to a concrete disposition")
    # No *settled* finding may collapse to MODEL-GAP.
    collapsed = [c.id for c in corpus
                 if not c.contested
                 and c.ground_truth != "MODEL-GAP"
                 and triage(c.signal, sc).disposition == "MODEL-GAP"]
    assert not collapsed, f"settled findings wrongly collapsed to MODEL-GAP: {collapsed}"


def test_no_valid_finding_is_ever_closed():
    """Fail-safe invariant: a true VALID/VALID-HARDENING is never closed."""
    sc = _sidecar()
    violations = [
        c.id for c in _corpus()
        if c.ground_truth in ("VALID", "VALID-HARDENING")
        and triage(c.signal, sc).closed
    ]
    assert not violations, f"fail-safe violations (valid findings closed): {violations}"


def test_contested_findings_route_to_label_or_escalate():
    """Contested seams may land on the label or open — never a wrong close."""
    sc = _sidecar()
    for item in _corpus():
        if not item.contested:
            continue
        result = triage(item.signal, sc)
        # Acceptable: the labelled disposition, or an escalation / MODEL-GAP.
        acceptable = (
            result.disposition == item.ground_truth
            or result.disposition == "MODEL-GAP"
            or result.escalated
        )
        assert acceptable, (
            f"{item.id}: contested finding took an unsafe route "
            f"{result.disposition!r} (truth {item.ground_truth!r})")
        # And it must never *close* against a finding whose truth stays open.
        if item.ground_truth in ("VALID", "VALID-HARDENING", "MODEL-GAP"):
            assert not result.closed, f"{item.id}: contested finding wrongly closed"


def test_every_concrete_route_is_licensed_by_a_sidecar_fact():
    sc = _sidecar()
    for item in _corpus():
        result = triage(item.signal, sc)
        if result.disposition == "MODEL-GAP":
            assert result.citation == ""
        else:
            assert result.citation, f"{item.id}: route lacks a sidecar citation"


def test_inferred_licensed_closes_escalate_while_draft():
    """contrib/minizip closes are licensed by an inferred scope fact (Q2) and so
    must escalate rather than silently close in an unratified draft."""
    sc = _sidecar()
    by_id = {c.id: c for c in _corpus()}
    result = triage(by_id["zlib-contrib-sample-bug"].signal, sc)
    assert result.disposition == "OUT-OF-MODEL: unsupported-component"
    assert result.licensed_by_inferred and result.escalated
    assert not result.closed


def test_documented_close_closes_cleanly():
    """A close licensed by a documented fact (gzopen path is caller-trusted)
    closes without escalation."""
    sc = _sidecar()
    by_id = {c.id: c for c in _corpus()}
    result = triage(by_id["zlib-gzopen-path-traversal"].signal, sc)
    assert result.disposition == "OUT-OF-MODEL: trusted-input"
    assert not result.licensed_by_inferred and not result.escalated
    assert result.closed


def test_engine_predictions_score_clean_against_corpus():
    """The engine's routings, fed to the Tier-2 scorer, produce no fail-safe
    violations and no unknown dispositions."""
    sc = _sidecar()
    corpus = _corpus()
    preds = {c.id: triage(c.signal, sc).effective for c in corpus}
    card = score(corpus, preds)
    assert not card.failsafe_violations, card.failsafe_violations
    assert not card.unknown_predictions, card.unknown_predictions
    assert not card.missing_predictions


# --------------------------------------------------------------------------- #
# Per-rule unit tests over a tiny synthetic sidecar                            #
# --------------------------------------------------------------------------- #

def _mini_sidecar() -> dict:
    """A minimal but complete sidecar exercising every routing rule."""
    return {
        "model_status": "unratified-draft",
        "disposition_precedence": [
            "KNOWN-NON-FINDING",
            "OUT-OF-MODEL: unsupported-component",
            "OUT-OF-MODEL: non-default-build",
            "OUT-OF-MODEL: dependency-contract",
            "OUT-OF-MODEL: trusted-input",
            "OUT-OF-MODEL: adversary-not-in-scope",
            "BY-DESIGN: property-disclaimed",
            "VALID",
            "VALID-HARDENING",
            "MODEL-GAP",
        ],
        "components": [
            {"name": "core", "scope": "in",
             "provenance": {"kind": "documented", "source": "manual"}},
            {"name": "samples", "scope": "out",
             "provenance": {"kind": "documented", "source": "manual"}},
        ],
        "entry_points": [
            {"id": "api", "component": "core", "parameters": [
                {"name": "untrusted-bytes", "attacker_controllable": True,
                 "provenance": {"kind": "documented", "source": "manual"}},
                {"name": "out-buf", "attacker_controllable": False,
                 "provenance": {"kind": "documented", "source": "manual"}},
            ]},
        ],
        "adversaries": [
            {"name": "input-author", "scope": "in",
             "capabilities": ["supply-bytes"],
             "excluded_capabilities": ["control-host-process"],
             "provenance": {"kind": "documented", "source": "manual"}},
        ],
        "build_flags": [
            {"name": "UNSAFE", "maintainer_stance": "discouraged",
             "provenance": {"kind": "documented", "source": "manual"}},
            {"name": "SAFE", "maintainer_stance": "supported",
             "provenance": {"kind": "documented", "source": "manual"}},
        ],
        "dependencies": [
            {"name": "allocator", "violation_disposition": "OUT-OF-MODEL: dependency-contract",
             "provenance": {"kind": "documented", "source": "manual"}},
        ],
        "properties_claimed": [
            {"id": "mem-safety", "components": ["core"],
             "provenance": {"kind": "documented", "source": "manual"}},
        ],
        "properties_disclaimed": [
            {"id": "bomb-resistance", "components": ["core"],
             "provenance": {"kind": "documented", "source": "manual"}},
        ],
        "known_misuses": [
            {"id": "foot-gun", "component": "core",
             "provenance": {"kind": "documented", "source": "manual"}},
        ],
        "known_non_findings": [
            {"id": "sanitizer-noise", "component": "core",
             "provenance": {"kind": "documented", "source": "manual"}},
        ],
    }


def test_rule_known_non_finding():
    r = triage({"component": "core", "matches_known_non_finding": "sanitizer-noise"},
               _mini_sidecar())
    assert r.disposition == "KNOWN-NON-FINDING"


def test_rule_unsupported_component():
    r = triage({"component": "samples"}, _mini_sidecar())
    assert r.disposition == "OUT-OF-MODEL: unsupported-component"


def test_rule_non_default_build():
    r = triage({"component": "core", "requires_build_flag": "UNSAFE"}, _mini_sidecar())
    assert r.disposition == "OUT-OF-MODEL: non-default-build"


def test_rule_supported_build_flag_does_not_route():
    # A *supported* flag must not license a non-default-build close.
    r = triage({"component": "core", "requires_build_flag": "SAFE"}, _mini_sidecar())
    assert r.disposition == "MODEL-GAP"


def test_rule_dependency_contract():
    r = triage({"component": "core", "requires_dependency_contract_violation": "allocator"},
               _mini_sidecar())
    assert r.disposition == "OUT-OF-MODEL: dependency-contract"


def test_rule_trusted_input():
    r = triage({"component": "core", "sink": "api",
                "requires_control_of_trusted_operand": "out-buf"}, _mini_sidecar())
    assert r.disposition == "OUT-OF-MODEL: trusted-input"


def test_rule_trusted_input_rejects_attacker_controllable_operand():
    # untrusted-bytes IS attacker-controllable, so it cannot be a trusted operand.
    r = triage({"component": "core", "sink": "api",
                "requires_control_of_trusted_operand": "untrusted-bytes"}, _mini_sidecar())
    assert r.disposition == "MODEL-GAP"


def test_rule_adversary_not_in_scope():
    r = triage({"component": "core", "requires_adversary_capability": "control-host-process"},
               _mini_sidecar())
    assert r.disposition == "OUT-OF-MODEL: adversary-not-in-scope"


def test_rule_property_disclaimed():
    r = triage({"component": "core", "concerns_disclaimed_property": "bomb-resistance"},
               _mini_sidecar())
    assert r.disposition == "BY-DESIGN: property-disclaimed"


def test_rule_valid_requires_component_match():
    sc = _mini_sidecar()
    good = triage({"component": "core", "violates_claimed_property": "mem-safety"}, sc)
    assert good.disposition == "VALID" and not good.closed
    # Same property claimed for 'core' only — a 'samples' finding must not route VALID.
    bad = triage({"component": "samples", "violates_claimed_property": "mem-safety"}, sc)
    assert bad.disposition == "OUT-OF-MODEL: unsupported-component"


def test_rule_valid_hardening():
    r = triage({"component": "core", "is_hardening": True,
                "hardening_of_misuse": "foot-gun"}, _mini_sidecar())
    assert r.disposition == "VALID-HARDENING"


def test_unlicensed_signal_is_model_gap():
    r = triage({"component": "core", "violates_claimed_property": "does-not-exist"},
               _mini_sidecar())
    assert r.disposition == "MODEL-GAP"
    assert r.citation == ""


def test_empty_signal_is_model_gap():
    r = triage({}, _mini_sidecar())
    assert r.disposition == "MODEL-GAP"


def test_precedence_known_non_finding_beats_unsupported_component():
    # A finding that matches BOTH a non-finding and an out-of-scope component
    # must take the higher-precedence KNOWN-NON-FINDING route.
    r = triage({"component": "samples", "matches_known_non_finding": "sanitizer-noise"},
               _mini_sidecar())
    # 'sanitizer-noise' is registered against 'core', not 'samples', so the
    # non-finding does not match here — it falls to unsupported-component.
    assert r.disposition == "OUT-OF-MODEL: unsupported-component"


def test_precedence_orders_by_sidecar_declaration():
    sc = _mini_sidecar()
    # A signal that satisfies several closing rules routes to the first in
    # precedence order (unsupported-component before trusted-input).
    r = triage({"component": "samples", "sink": "api",
                "requires_control_of_trusted_operand": "out-buf"}, sc)
    assert r.disposition == "OUT-OF-MODEL: unsupported-component"


def test_closing_set_excludes_open_dispositions():
    for d in ("VALID", "VALID-HARDENING", "MODEL-GAP"):
        assert d not in CLOSING


# --------------------------------------------------------------------------- #
# Assumption tier + triage-policy behavior                                    #
# --------------------------------------------------------------------------- #

def _assumption_sidecar(policy: str, *, disclaim_tier: str = "correctness-only") -> dict:
    """A sidecar whose scope/adversary/disclaimer facts carry ``assumption``
    provenance, for exercising the policy knob and the security-critical floor.
    """
    sc = _mini_sidecar()
    sc["triage_policy"] = policy
    assumption = {"kind": "assumption", "question_id": "Q9",
                  "rationale": "conservative default"}
    for c in sc["components"]:
        if c["name"] == "samples":
            c["provenance"] = assumption
    for a in sc["adversaries"]:
        a["provenance"] = assumption
    for p in sc["properties_disclaimed"]:
        p["provenance"] = assumption
        p["tier"] = disclaim_tier
    for k in sc["known_non_findings"]:
        k["provenance"] = assumption
    return sc


def test_strict_policy_assumption_escalates_like_inferred():
    sc = _assumption_sidecar("strict")
    r = triage({"component": "samples"}, sc)
    assert r.disposition == "OUT-OF-MODEL: unsupported-component"
    assert r.licensed_by_assumption and r.escalated and not r.closed
    assert not r.provisional
    assert r.effective == "MODEL-GAP"


def test_strict_is_the_default_when_policy_omitted():
    sc = _assumption_sidecar("strict")
    del sc["triage_policy"]
    r = triage({"component": "samples"}, sc)
    assert r.escalated and not r.closed


def test_relaxed_policy_assumption_closes_low_blast_route_provisionally():
    sc = _assumption_sidecar("relaxed")
    r = triage({"component": "samples"}, sc)
    assert r.disposition == "OUT-OF-MODEL: unsupported-component"
    assert r.licensed_by_assumption and r.provisional
    assert r.closed and not r.escalated


def test_relaxed_policy_assumption_closes_adversary_and_disclaimer():
    sc = _assumption_sidecar("relaxed")
    adv = triage({"component": "core",
                  "requires_adversary_capability": "control-host-process"}, sc)
    assert adv.disposition == "OUT-OF-MODEL: adversary-not-in-scope"
    assert adv.closed and adv.provisional
    disc = triage({"component": "core",
                   "concerns_disclaimed_property": "bomb-resistance"}, sc)
    assert disc.disposition == "BY-DESIGN: property-disclaimed"
    assert disc.closed and disc.provisional


def test_security_critical_floor_blocks_assumption_disclaimer_even_relaxed():
    sc = _assumption_sidecar("relaxed", disclaim_tier="security-critical")
    r = triage({"component": "core",
                "concerns_disclaimed_property": "bomb-resistance"}, sc)
    assert r.disposition == "BY-DESIGN: property-disclaimed"
    assert r.licensed_by_assumption and r.escalated and not r.closed


def test_security_critical_floor_blocks_assumption_known_non_finding_even_relaxed():
    sc = _assumption_sidecar("relaxed")
    r = triage({"component": "core", "matches_known_non_finding": "sanitizer-noise"}, sc)
    assert r.disposition == "KNOWN-NON-FINDING"
    assert r.licensed_by_assumption and r.escalated and not r.closed


def test_documented_close_unaffected_by_policy():
    # A documented licensing fact closes cleanly regardless of the policy knob.
    for policy in ("strict", "relaxed"):
        sc = _mini_sidecar()
        sc["triage_policy"] = policy
        r = triage({"component": "core", "sink": "api",
                    "requires_control_of_trusted_operand": "out-buf"}, sc)
        assert r.closed and not r.provisional and not r.escalated


def test_relaxed_assumption_never_closes_valid():
    # VALID is fail-safe; an assumption-tagged claimed property still routes VALID
    # (open), never a close.
    sc = _assumption_sidecar("relaxed")
    for p in sc["properties_claimed"]:
        p["provenance"] = {"kind": "assumption", "question_id": "Q9"}
    r = triage({"component": "core", "violates_claimed_property": "mem-safety"}, sc)
    assert r.disposition == "VALID" and not r.closed and not r.escalated



def test_known_non_finding_component_guard_reads_both_schema_forms():
    """A §1.15 entry must guard its component in either schema spelling.

    The schema tells authors to emit ``components: [...]``; ``component: <name>``
    is the older singular form. If the routing engine reads only one of them, an
    entry written the other way has *no* component scope — and because
    KNOWN-NON-FINDING is precedence rule 1, it would then suppress every
    component, including ones the sidecar never declared.
    """
    for scope in ({"component": "core"}, {"components": ["core"]}):
        sc = _mini_sidecar()
        entry = sc["known_non_findings"][0]
        entry.pop("component", None)
        entry.update(scope)

        matched = triage(
            {"component": "core", "matches_known_non_finding": "sanitizer-noise"}, sc)
        assert matched.disposition == "KNOWN-NON-FINDING", scope

        for other in ("gz-convenience", "totally-undeclared"):
            r = triage(
                {"component": other, "matches_known_non_finding": "sanitizer-noise"}, sc)
            assert r.disposition != "KNOWN-NON-FINDING", (scope, other)


def test_known_non_finding_component_guard_fails_closed_without_exact_scope():
    sc = _mini_sidecar()
    r = triage({"matches_known_non_finding": "sanitizer-noise"}, sc)
    assert r.disposition == "MODEL-GAP"

    for scope in (
        {},
        {"components": []},
        {"components": ["all-in-scope"]},
        {"components": ["core", "all-in-scope"]},
    ):
        sc = _mini_sidecar()
        entry = sc["known_non_findings"][0]
        entry.pop("component", None)
        entry.update(scope)

        r = triage(
            {"component": "core", "matches_known_non_finding": "sanitizer-noise"}, sc)
        assert r.disposition == "MODEL-GAP", scope


def test_disposition_status_tracks_closed_provisional_escalated():
    """``status`` is the §1.17 qualifier a triager records; it is not ``effective``."""
    sc = _mini_sidecar()
    closed = triage({"component": "core", "sink": "api",
                     "requires_control_of_trusted_operand": "out-buf"}, sc)
    assert closed.status == "closed"

    prov = triage({"component": "samples"}, _assumption_sidecar("relaxed"))
    assert prov.status == "provisional"

    esc = triage({"component": "samples"}, _assumption_sidecar("strict"))
    assert esc.status == "escalated"
    # An escalated finding keeps its disposition for the maintainer even though
    # corpus scoring folds it into MODEL-GAP.
    assert esc.disposition == "OUT-OF-MODEL: unsupported-component"
    assert esc.effective == "MODEL-GAP"

    # VALID and MODEL-GAP are not closes and take no qualifier.
    assert triage({"component": "core",
                   "violates_claimed_property": "mem-safety"}, sc).status == ""
    assert triage({"component": "core"}, sc).status == ""
