"""Deterministic, sidecar-driven reference triage engine (Tier-2 routing).

This is the piece the harness was missing. The backtest *scorer* compared
predictions to labels, but nothing ever *produced* a routing from the model —
predictions came from the stub (which replays the labels) or an external agent.
With no worked routing to lean on, an unaided agent defaults every finding to
``MODEL-GAP``. That collapse is exactly the symptom this engine exists to rule
out.

The engine takes a **structured finding signal** (the routing-relevant facts a
triager extracts from a report — never the answer) plus a **sidecar** and
applies the §1.17 first-match disposition precedence. Every route must be
*licensed by a concrete sidecar fact*: if the fact the signal points at is not
present in the sidecar, that rule does not fire and the finding falls through —
ultimately to ``MODEL-GAP``. That makes an under-specified model *visibly* fail
to route rather than silently guessing.

The inferred-claim / unratified-draft constraint is honored: a *closing*
disposition licensed only by an ``inferred`` sidecar fact cannot close — it is
flagged ``escalated`` (open) even though the identified route is recorded. VALID
/ VALID-HARDENING / MODEL-GAP never close, so they never escalate.

The ``assumption`` provenance tier is governed by the sidecar's ``triage_policy``
(``strict`` by default, or ``relaxed``). Under ``strict`` an assumption behaves
exactly like ``inferred`` — escalate-only. Under ``relaxed`` an assumption may
*provisionally* close the low-blast-radius routes, but the **security-critical
floor** still holds under both policies: an assumption never closes
``KNOWN-NON-FINDING``, a ``security-critical`` ``property-disclaimed``, or
``dependency-contract``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .checks import DISPOSITIONS, ALL_IN_SCOPE, entry_components

# Dispositions that close a report against the reporter.
CLOSING = {
    d for d in DISPOSITIONS
    if d.startswith("OUT-OF-MODEL") or d.startswith("BY-DESIGN")
    or d == "KNOWN-NON-FINDING"
}

# Canonical §1.17 precedence, used when the sidecar omits disposition_precedence.
_DEFAULT_PRECEDENCE = [
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
]

# Build-flag stances that mean "not the supported default build".
_UNSUPPORTED_STANCES = {"dev-only", "discouraged", "unsupported", "deprecated"}

# Under the `relaxed` policy, an `assumption` may provisionally close only these
# low-blast-radius routes. `KNOWN-NON-FINDING` and `dependency-contract` are
# excluded by design (the security-critical floor), as is a security-critical
# `property-disclaimed` (handled per-route in `triage`).
_ASSUMPTION_CLOSEABLE = {
    "OUT-OF-MODEL: trusted-input",
    "OUT-OF-MODEL: adversary-not-in-scope",
    "OUT-OF-MODEL: unsupported-component",
    "OUT-OF-MODEL: non-default-build",
    "BY-DESIGN: property-disclaimed",
}


@dataclass
class TriageResult:
    """Outcome of routing one finding signal against a sidecar."""

    disposition: str
    """The §1.17 route the facts point at (what the corpus labels)."""

    citation: str = ""
    """The sidecar fact that licensed the route (empty for MODEL-GAP)."""

    licensed_by_inferred: bool = False
    """True when the licensing fact carries ``inferred`` provenance."""

    licensed_by_assumption: bool = False
    """True when the licensing fact carries ``assumption`` provenance."""

    provisional: bool = False
    """True when an ``assumption`` licensed a close under the ``relaxed`` policy.
    The close holds, but a reporter may re-open it on challenge."""

    escalated: bool = False
    """True when a *closing* route was demoted to open because its license was
    inferred (or the model is an unratified draft closing on an unratified
    fact). The identified route is still recorded in ``disposition``."""

    reason: str = ""
    """Human-readable explanation of the routing decision."""

    @property
    def closed(self) -> bool:
        """Did this actually close the report against the reporter?"""
        return self.disposition in CLOSING and not self.escalated

    @property
    def status(self) -> str:
        """The §1.17 status qualifier: what a triager may *do* with this route.

        ``closed`` (licensed outright), ``provisional`` (a ``relaxed``-policy
        assumption close, re-openable on challenge), or ``escalated`` (the route
        is right but its license cannot close it yet). Empty for ``VALID`` and
        ``MODEL-GAP``, which are not closes and take no qualifier.

        Note this is deliberately *not* ``effective``: an escalated finding keeps
        its disposition and goes to the maintainer, whereas ``effective`` folds
        it into ``MODEL-GAP`` for corpus scoring.
        """
        if self.disposition not in CLOSING:
            return ""
        if self.escalated:
            return "escalated"
        return "provisional" if self.provisional else "closed"

    @property
    def effective(self) -> str:
        """Disposition after escalation, for corpus scoring only.

        An escalated close is unfinished work, so scoring treats it as a gap.
        This is a *scoring* convention: per §1.17 an escalated finding keeps its
        disposition and routes to the maintainer, and must not be fed into the
        §1.16 model-revision loop. Use ``status`` for what the triager records.
        """
        return "MODEL-GAP" if self.escalated else self.disposition


def _prov_is_inferred(prov: Any) -> bool:
    return isinstance(prov, dict) and prov.get("kind") == "inferred"


def _prov_is_assumption(prov: Any) -> bool:
    return isinstance(prov, dict) and prov.get("kind") == "assumption"


def _index(seq: Any, key: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if isinstance(seq, list):
        for item in seq:
            if isinstance(item, dict) and item.get(key) is not None:
                out[str(item[key])] = item
    return out


class _Router:
    """Applies each disposition's licensing rule against a sidecar."""

    def __init__(self, sidecar: dict):
        self.s = sidecar
        self.components = _index(sidecar.get("components"), "name")
        self.build_flags = _index(sidecar.get("build_flags"), "name")
        self.dependencies = _index(sidecar.get("dependencies"), "name")
        self.knf = _index(sidecar.get("known_non_findings"), "id")
        self.claimed = _index(sidecar.get("properties_claimed"), "id")
        self.disclaimed = _index(sidecar.get("properties_disclaimed"), "id")
        self.misuses = _index(sidecar.get("known_misuses"), "id")
        self.entry_points = sidecar.get("entry_points") or []
        self.adversaries = sidecar.get("adversaries") or []

    # Each rule returns (citation, provenance) when it fires, else None.

    def known_non_finding(self, sig):
        ref = sig.get("matches_known_non_finding")
        if ref and ref in self.knf:
            k = self.knf[ref]
            comp = sig.get("component")
            # §1.15 suppression is an *exact* match — a non-finding registered
            # for one component must not silently discharge another. Read the
            # scope through the shared helper: a `components: [...]` entry read
            # as if it were singular yields no scope at all, which would turn
            # every entry into a universal suppressor at precedence rule 1.
            entry_comps = entry_components(k)
            if (not comp or not entry_comps or ALL_IN_SCOPE in entry_comps
                    or comp not in entry_comps):
                return None
            return f"known_non_findings[{ref}]", k.get("provenance")
        return None

    def unsupported_component(self, sig):
        name = sig.get("component")
        comp = self.components.get(name)
        if comp is not None and comp.get("scope") == "out":
            return f"components[{name}].scope=out", comp.get("provenance")
        return None

    def non_default_build(self, sig):
        ref = sig.get("requires_build_flag")
        flag = self.build_flags.get(ref)
        if flag is not None and flag.get("maintainer_stance") in _UNSUPPORTED_STANCES:
            return f"build_flags[{ref}]", flag.get("provenance")
        return None

    def dependency_contract(self, sig):
        ref = sig.get("requires_dependency_contract_violation")
        dep = self.dependencies.get(ref)
        if dep is not None:
            return f"dependencies[{ref}]", dep.get("provenance")
        return None

    def trusted_input(self, sig):
        operand = sig.get("requires_control_of_trusted_operand")
        if not operand:
            return None
        sink = sig.get("sink")
        for ep in self.entry_points:
            if not isinstance(ep, dict):
                continue
            if sink and ep.get("id") != sink:
                continue
            for param in ep.get("parameters") or []:
                if not isinstance(param, dict):
                    continue
                if param.get("name") == operand and param.get("attacker_controllable") is False:
                    return (f"entry_points[{ep.get('id')}].{operand}"
                            f"(attacker_controllable=false)", param.get("provenance"))
        return None

    def adversary_not_in_scope(self, sig):
        cap = sig.get("requires_adversary_capability")
        if not cap:
            return None
        in_scope = [a for a in self.adversaries
                    if isinstance(a, dict) and a.get("scope") == "in"]
        # Preferred: an in-scope adversary explicitly excludes the capability.
        for a in in_scope:
            if cap in (a.get("excluded_capabilities") or []):
                return (f"adversaries[{a.get('name')}].excluded_capabilities",
                        a.get("provenance"))
        # Otherwise: no in-scope adversary holds it, but an out-of-scope one does.
        held_in_scope = any(cap in (a.get("capabilities") or []) for a in in_scope)
        if not held_in_scope:
            for a in self.adversaries:
                if (isinstance(a, dict) and a.get("scope") == "out"
                        and cap in (a.get("capabilities") or [])):
                    return (f"adversaries[{a.get('name')}](out-of-scope)",
                            a.get("provenance"))
        return None

    def property_disclaimed(self, sig):
        ref = sig.get("concerns_disclaimed_property")
        prop = self.disclaimed.get(ref)
        if prop is None:
            return None
        comp = sig.get("component")
        if comp and comp not in (prop.get("components") or []):
            return None
        return f"properties_disclaimed[{ref}]", prop.get("provenance")

    def valid(self, sig):
        ref = sig.get("violates_claimed_property")
        prop = self.claimed.get(ref)
        if prop is None:
            return None
        comp = sig.get("component")
        if comp and comp not in (prop.get("components") or []):
            return None
        return f"properties_claimed[{ref}]", prop.get("provenance")

    def valid_hardening(self, sig):
        if not sig.get("is_hardening"):
            return None
        ref = sig.get("hardening_of_misuse")
        if ref and ref in self.misuses:
            return f"known_misuses[{ref}]", self.misuses[ref].get("provenance")
        return "§1.14 maintainer-discretion hardening", None

    def rule_for(self, disposition: str):
        return {
            "KNOWN-NON-FINDING": self.known_non_finding,
            "OUT-OF-MODEL: unsupported-component": self.unsupported_component,
            "OUT-OF-MODEL: non-default-build": self.non_default_build,
            "OUT-OF-MODEL: dependency-contract": self.dependency_contract,
            "OUT-OF-MODEL: trusted-input": self.trusted_input,
            "OUT-OF-MODEL: adversary-not-in-scope": self.adversary_not_in_scope,
            "BY-DESIGN: property-disclaimed": self.property_disclaimed,
            "VALID": self.valid,
            "VALID-HARDENING": self.valid_hardening,
        }.get(disposition)


def triage(signal: dict, sidecar: dict, *, model_status: str | None = None) -> TriageResult:
    """Route one structured finding signal against a sidecar via §1.17 precedence.

    ``signal`` carries the routing-relevant facts a triager extracts (component,
    sink/operand, matched non-finding, required build flag / adversary
    capability, violated or disclaimed property, hardening flag). Each field is
    optional; the engine tries dispositions in precedence order and takes the
    first whose licensing fact is present in the sidecar.
    """
    signal = signal or {}
    status = model_status or sidecar.get("model_status")
    policy = (sidecar.get("triage_policy") or "strict").lower()
    precedence = sidecar.get("disposition_precedence") or _DEFAULT_PRECEDENCE
    router = _Router(sidecar)

    for disposition in precedence:
        if disposition == "MODEL-GAP":
            break
        rule = router.rule_for(disposition)
        if rule is None:
            continue
        hit = rule(signal)
        if hit is None:
            continue
        citation, prov = hit
        inferred = _prov_is_inferred(prov)
        assumption = _prov_is_assumption(prov)
        is_closing = disposition in CLOSING
        # An unratified draft cannot confidently *close* on an unratified fact.
        draft = status not in ("ratified", "accepted", None)

        # Decide whether an assumption is permitted to close this route. The
        # security-critical floor holds under every policy: an assumption never
        # closes KNOWN-NON-FINDING, dependency-contract, or a security-critical
        # disclaimed property.
        assumption_may_close = False
        if assumption and is_closing and policy == "relaxed":
            if disposition in _ASSUMPTION_CLOSEABLE:
                if disposition == "BY-DESIGN: property-disclaimed":
                    prop = router.disclaimed.get(
                        signal.get("concerns_disclaimed_property"), {})
                    # Fail closed on a missing or unrecognized tier. `tier` is
                    # required on every disclaimed property, but an older or
                    # hand-edited sidecar may omit it -- and reading "absent" as
                    # "not security-critical" would let an assumption close
                    # exactly the reports the security-critical floor exists to
                    # protect. Only an explicit `correctness-only` opens the gate.
                    assumption_may_close = prop.get("tier") == "correctness-only"
                else:
                    assumption_may_close = True

        escalate = is_closing and (
            inferred
            or (assumption and not assumption_may_close)
            or (draft and prov is None)
        )
        provisional = bool(assumption and assumption_may_close and not escalate)

        reason = f"routed to {disposition} via {citation}"
        if escalate:
            reason += " — escalated (closing license is not ratified)"
        elif provisional:
            reason += " — provisional close (assumption, relaxed policy; re-opens on challenge)"
        return TriageResult(
            disposition=disposition,
            citation=citation,
            licensed_by_inferred=inferred,
            licensed_by_assumption=assumption,
            provisional=provisional,
            escalated=escalate,
            reason=reason,
        )

    return TriageResult(
        disposition="MODEL-GAP",
        citation="",
        reason="no §1.17 disposition is licensed by the sidecar for this signal",
    )
