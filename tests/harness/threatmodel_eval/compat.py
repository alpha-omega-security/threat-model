"""Cross-model compatibility analysis over a dependency closure.

A single ``threat-model.yaml`` states the security *contract* a project offers
downstream and what it *relies on* from its own dependencies. When you have the
sidecars for a whole dependency tree, you can check the edges between them: an
**incompatibility** is a place where a consumer ``C`` assumes something that its
dependency ``D`` refuses to guarantee.

This module is deterministic and reads only the sidecars — no source, no agent.
It complements the per-model validator (``sidecar.py``): the validator asks "is
this one model well-formed?"; the compat analyzer asks "do these models, wired
along their dependency edges, agree with each other?".

Detected mismatch classes (all keyed on an edge ``C -> D``):

* ``COMPAT.relied-disclaimed`` (error) — C relies on a property that D lists in
    ``properties_disclaimed`` (matched by stable v2 property ID). If D flags it
    ``false_friend: true`` the message
  says so: C is trusting something that only *looks* like a guarantee.
* ``COMPAT.relied-unbacked`` (warn) — C names a reliance that D neither claims
  nor disclaims. The assumption is unverified against D's own contract.
* ``COMPAT.adversary-scope-gap`` (error) — C treats an adversary capability as
    in-scope and explicitly forwards it across this edge, but D excludes that
    capability from every in-scope adversary. The threat C must defend against is
    out-of-model for D.
* ``COMPAT.tainted-output-consumed`` (warn) — D emits ``taint: same-as-input``
    on a channel C explicitly consumes as passthrough to support a security-
    critical output-sanitization property.
* ``COMPAT.unenforced-caller-obligation`` (warn) — D has entry-point parameters
    with a stable ``obligation_id`` and C records no matching
    ``caller_obligations_acknowledged`` entry.

Missing sidecars in the closure are surfaced as ``COMPAT.missing-node`` so a
partially generated tree degrades loudly rather than silently skipping edges.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .parse import load_sidecar
from .report import Finding, Report

# Tokens too generic to carry meaning when fuzzy-matching property ids / text.
_STOPWORDS = frozenset({
    "the", "and", "for", "with", "from", "that", "this", "input", "output",
    "data", "value", "based", "over", "into", "must", "not", "any", "all",
    "supported", "standard", "contract", "api", "property", "properties",
})
_TOKEN = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class Edge:
    """A dependency edge: ``consumer`` depends on ``dependency`` (both project
    names as they appear in the sidecar ``project`` field). ``via`` optionally
    records the ``dependencies[].name`` in the consumer sidecar that this edge
    resolves, which sharpens reliance matching."""

    consumer: str
    dependency: str
    via: str = ""


@dataclass
class Closure:
    """A dependency tree of threat-model sidecars keyed by project name."""

    sidecars: dict[str, dict] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    root: str = ""

    @classmethod
    def from_manifest(cls, path: str | Path) -> "Closure":
        """Load a closure from a JSON manifest of the form::

            {
              "root": "app",
              "nodes": {"app": {"sidecar": "out/app/threat-model.yaml"}, ...},
              "edges": [{"consumer": "app", "dependency": "libfoo"}, ...]
            }

        Node sidecar paths are resolved relative to the manifest file.
        """
        import json

        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        base = p.parent
        sidecars: dict[str, dict] = {}
        for name, node in (data.get("nodes") or {}).items():
            sc_path = (node or {}).get("sidecar")
            if not sc_path:
                continue
            resolved = Path(sc_path)
            if not resolved.is_absolute():
                resolved = base / resolved
            if resolved.exists():
                sc = load_sidecar(resolved)
                # Key by the manifest node name — it is the identity the edges
                # reference. (The sidecar's own `project` field may differ, e.g.
                # a scoped npm name sanitized for the filesystem.)
                sidecars[name] = sc
        edges = [
            Edge(e["consumer"], e["dependency"], e.get("via", ""))
            for e in (data.get("edges") or [])
        ]
        return cls(sidecars=sidecars, edges=edges, root=data.get("root", ""))

    @classmethod
    def from_dir(cls, root_dir: str | Path, edges: Iterable[Edge]) -> "Closure":
        """Load every ``threat-model.yaml`` under ``root_dir`` (one per node),
        keyed by the sidecar's ``project`` field, and pair with an edge list."""
        base = Path(root_dir)
        sidecars: dict[str, dict] = {}
        for sc_path in sorted(base.rglob("threat-model.yaml")):
            try:
                sc = load_sidecar(sc_path)
            except ValueError:
                continue
            name = sc.get("project") or sc_path.parent.name
            sidecars[name] = sc
        return cls(sidecars=sidecars, edges=list(edges))


# --------------------------------------------------------------------------
# Text / id matching helpers
# --------------------------------------------------------------------------
def _tokens(text: str) -> set[str]:
    return {
        t for t in _TOKEN.findall((text or "").lower())
        if t not in _STOPWORDS and len(t) > 2
    }


def _text_refers_to(text: str, prop_id: str) -> bool:
    """Does free-text reliance ``text`` reference the property ``prop_id``?"""
    pt = _tokens(prop_id)
    return bool(pt) and pt <= _tokens(text)


# --------------------------------------------------------------------------
# Sidecar field accessors (tolerant of v1/v2 and missing keys)
# --------------------------------------------------------------------------
def _list(sidecar: dict, key: str) -> list[dict]:
    v = sidecar.get(key)
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def _disclaimed(sidecar: dict) -> list[dict]:
    return _list(sidecar, "properties_disclaimed")


def _claimed(sidecar: dict) -> list[dict]:
    return _list(sidecar, "properties_claimed")


def _reliances(sidecar: dict) -> list[dict]:
    return _list(sidecar, "dependencies")


def _adversary_caps(sidecar: dict, scope: str) -> set[str]:
    caps: set[str] = set()
    for adv in _list(sidecar, "adversaries"):
        if adv.get("scope") == scope:
            caps.update(adv.get("capabilities") or [])
    return caps


def _excluded_caps(sidecar: dict) -> set[str]:
    caps: set[str] = set()
    for adv in _list(sidecar, "adversaries"):
        caps.update(adv.get("excluded_capabilities") or [])
    return caps


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
def _reliances_for_edge(consumer_sc: dict, edge: Edge) -> list[dict]:
    """The consumer's ``dependencies[]`` entries that this edge resolves.

    Prefer an explicit ``via`` name; otherwise fall back to name-token overlap
    with the dependency project. Never reuse unrelated reliances for an
    unmatched edge."""
    rels = _reliances(consumer_sc)
    if edge.via:
        matched = [r for r in rels if r.get("name") == edge.via]
        if matched:
            return matched
    dep_tokens = _tokens(edge.dependency)
    matched = [r for r in rels if _tokens(r.get("name", "")) & dep_tokens]
    return matched


def _check_edge(closure: Closure, edge: Edge) -> Iterable[Finding]:
    c_name, d_name = edge.consumer, edge.dependency
    loc = f"{c_name} -> {d_name}"
    c = closure.sidecars.get(c_name)
    d = closure.sidecars.get(d_name)

    if c is None:
        yield Finding("COMPAT.missing-node", "compat", "error", False,
                      f"consumer sidecar '{c_name}' not found in closure", loc)
        return
    if d is None:
        yield Finding("COMPAT.missing-node", "compat", "error", False,
                      f"dependency sidecar '{d_name}' not found in closure", loc)
        return

    reliances = _reliances_for_edge(c, edge)
    reliance_texts = [
        " ".join(str(r.get(k, "")) for k in ("name", "relied_on_for"))
        for r in reliances
    ]
    c_claimed = _claimed(c)

    # Rule 1 + 2: reliance vs. the dependency's own claimed/disclaimed contract.
    d_disclaimed = _disclaimed(d)
    d_claimed_ids = [p.get("id", "") for p in _claimed(d)]
    d_disclaimed_ids = [p.get("id", "") for p in d_disclaimed]

    for rel, rtext in zip(reliances, reliance_texts):
        relied_ids = set(rel.get("relied_on_properties") or [])
        # 1. relied-on property the dependency explicitly disclaims.
        hit = None
        for dp in d_disclaimed:
            did = dp.get("id", "")
            if did in relied_ids or (not relied_ids and _text_refers_to(rtext, did)):
                hit = dp
                break
        if hit is not None:
            ff = " (false friend — looks like a guarantee but is not)" \
                if hit.get("false_friend") else ""
            yield Finding(
                "COMPAT.relied-disclaimed", "compat", "error", False,
                f"{c_name} relies on '{rel.get('relied_on_for') or rel.get('name')}'"
                f" which {d_name} DISCLAIMS ('{hit.get('id')}'){ff}", loc)
            continue

        # 2. reliance not backed by any claim/disclaimer in the dependency.
        backed = (bool(relied_ids) and relied_ids <= set(d_claimed_ids + d_disclaimed_ids)) \
            or (not relied_ids and any(_text_refers_to(rtext, cid) for cid in d_claimed_ids)) \
            or (not relied_ids and any(_text_refers_to(rtext, did) for did in d_disclaimed_ids))
        # Only flag reliances that the consumer says it does NOT cover itself.
        if not backed and rel.get("covered_here") is False:
            yield Finding(
                "COMPAT.relied-unbacked", "compat", "warn", False,
                f"{c_name} relies on '{rel.get('relied_on_for') or rel.get('name')}'"
                f" but {d_name} neither claims nor disclaims a matching property", loc)

    # Rule 3: adversary-scope gap — C treats a capability as in-scope that D
    # excludes from every in-scope adversary.
    c_in = _adversary_caps(c, "in")
    d_in = _adversary_caps(d, "in")
    d_excluded = _excluded_caps(d)
    forwarded_caps = {
        cap for rel in reliances
        for cap in (rel.get("adversary_capabilities_forwarded") or [])
    }
    for cap in sorted(c_in & forwarded_caps & d_excluded - d_in):
        yield Finding(
            "COMPAT.adversary-scope-gap", "compat", "error", False,
            f"{c_name} treats adversary capability '{cap}' as in-scope, but "
            f"{d_name} excludes it from its threat model", loc)

    # Rule 4: tainted output consumed — D passes taint through and C makes a
    # security-critical claim that a downstream integrator might read as
    # "output is safe".
    d_passthrough = {
        o.get("channel") for o in _list(d, "outputs")
        if o.get("taint") == "same-as-input" and o.get("channel")
    }
    c_claimed_by_id = {p.get("id"): p for p in c_claimed}
    risky_channels: set[str] = set()
    for rel in reliances:
        for use in rel.get("outputs_consumed", []) or []:
            if not isinstance(use, dict):
                continue
            prop = c_claimed_by_id.get(use.get("supports_property_id"))
            if (use.get("channel") in d_passthrough
                    and use.get("taint_handling") == "passthrough"
                    and prop is not None
                    and prop.get("kind") == "output-sanitization"
                    and prop.get("tier") == "security-critical"):
                risky_channels.add(use["channel"])
    if risky_channels:
        chans = ", ".join(sorted(risky_channels))
        yield Finding(
            "COMPAT.tainted-output-consumed", "compat", "warn", False,
            f"{d_name} output ({chans}) is taint 'same-as-input'; {c_name} "
            f"declares passthrough handling while using it to support a security-"
            f"critical output-sanitization property", loc)

    # Rule 5: unenforced caller obligation — D requires the caller to enforce
    # something and C (the caller) records no reliance acknowledging it.
    d_obligations: list[tuple[str, str]] = []
    for ep in _list(d, "entry_points"):
        for prm in (ep.get("parameters") or []):
            if isinstance(prm, dict) and prm.get("obligation_id"):
                oid = prm["obligation_id"]
                text = (f"{ep.get('id', '?')}.{prm.get('name', '?')}: "
                        f"{prm.get('caller_must_enforce')}")
                d_obligations.append((oid, text))
    acknowledged = {
        oid for rel in reliances
        for oid in (rel.get("caller_obligations_acknowledged") or [])
    }
    missing_obligations = [
        text for oid, text in d_obligations
        if oid not in acknowledged
    ]
    if missing_obligations:
        yield Finding(
            "COMPAT.unenforced-caller-obligation", "compat", "warn", False,
            f"{d_name} imposes caller obligations "
            f"({'; '.join(missing_obligations[:3])}"
            f"{' …' if len(missing_obligations) > 3 else ''}) but {c_name} "
            f"does not acknowledge their obligation IDs", loc)


def analyze_compat(closure: Closure) -> Report:
    """Run every cross-model rule over each edge and return a merged Report."""
    report = Report()
    seen: set[tuple[str, str]] = set()
    for edge in closure.edges:
        key = (edge.consumer, edge.dependency)
        if key in seen:
            continue
        seen.add(key)
        report.extend(_check_edge(closure, edge))
    # A closure with edges but zero findings still gets a single PASS marker so
    # the report is never empty.
    if closure.edges and not report.findings:
        report.add(Finding("COMPAT.clean", "compat", "error", True,
                           "no cross-model incompatibilities detected"))
    return report
