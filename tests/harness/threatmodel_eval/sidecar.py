"""Checks over the machine-readable sidecar (`threat-model.yaml`).

Validates the ``threat-model-sidecar/v2`` shape from ``sidecar-schema.md`` and
its cross-consistency with the prose document (confidence count, disposition
set). Hand-rolled rather than JSON-Schema-based so error messages point at the
exact offending key.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable

from .checks import DISPOSITIONS, ALL_IN_SCOPE, entry_components
from .parse import Model
from .report import Finding, Report

_STATUS = {"draft", "unratified-draft", "under-review", "accepted"}
_TAINT = {"same-as-input", "sanitized", "constrained"}
_STANCE = {"supported", "dev-only", "discouraged", "unsupported"}
_TIER = {"security-critical", "correctness-only"}
_PROPERTY_KIND = {
    "memory-safety", "output-sanitization", "resource-bound", "availability",
    "confidentiality", "integrity", "authentication", "authorization",
    "correctness",
}
_CONTROL_KIND = {
    "data", "size", "rate", "type-class", "callback-code", "object-topology",
    "collaborator-implementation", "resource-name", "serialized-state",
    "credential", "principal",
}
_DIMENSIONS = {
    "numeric-domain", "failure-atomicity", "recursive-cyclic-topology",
    "callback-execution", "serialization-reconstruction", "reference-lifecycle",
    "concurrency-reentrancy", "resource-complexity", "authorization-scope",
}
_DIM_STATUS = {"claimed", "disclaimed", "not-applicable", "unresolved"}
_EFFECT = {"preserves", "narrows", "voids"}
_TAINT_HANDLING = {"passthrough", "sanitized", "constrained"}
_SIDE_EFFECT_STANCE = {"absent", "present", "conditional"}
_DISPOSITION_PRECEDENCE = [
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
_PROSE_VERSION = re.compile(r"^([^@]+)@sha256:([0-9a-f]{64})$")
_REQUIRED_KEYS = {
    "schema", "project", "prose_version", "model_status", "confidence",
    "components", "host_side_effects", "entry_points", "contract_dimensions", "outputs",
    "adversaries", "dependency_policy", "dependencies", "build_policy",
    "build_flags", "properties_claimed", "properties_disclaimed",
    "downstream_responsibilities", "known_misuses", "known_non_findings",
    "dispositions", "disposition_precedence",
}
_LIST_KEYS = {
    "components", "host_side_effects", "entry_points", "contract_dimensions", "outputs",
    "adversaries", "dependencies", "build_flags", "properties_claimed",
    "properties_disclaimed", "downstream_responsibilities", "known_misuses",
    "known_non_findings", "dispositions", "disposition_precedence",
}
_MAPPING_KEYS = {"confidence", "dependency_policy", "build_policy"}
_RECORD_LIST_KEYS = _LIST_KEYS - {"dispositions", "disposition_precedence"}


def _list(sidecar: dict, key: str) -> list[dict]:
    value = sidecar.get(key)
    return [item for item in value if isinstance(item, dict)] \
        if isinstance(value, list) else []


def _valid_provenance(value) -> bool:
    if not isinstance(value, dict):
        return False
    kind = value.get("kind")
    if kind == "documented":
        return bool(value.get("source"))
    if kind == "maintainer":
        return bool(re.fullmatch(r"\d{4}-\d{2}", str(value.get("date", ""))))
    if kind in ("inferred", "assumption"):
        # sidecar-schema.md: inferred carries question_id; assumption carries
        # question_id plus an optional rationale.
        return bool(value.get("question_id"))
    return False


def _unique_ids(items: list[dict]) -> bool:
    ids = [item.get("id") for item in items]
    return all(ids) and len(ids) == len(set(ids))


def _string_list(value, *, nonempty: bool = False) -> bool:
    return (isinstance(value, list)
            and (not nonempty or bool(value))
            and all(isinstance(item, str) and bool(item.strip()) for item in value))


def _explicit_no_obligation(value) -> bool:
    return isinstance(value, str) and bool(
        re.match(r"^\s*(?:none|no caller obligation)\b", value, re.IGNORECASE))


def _contains_inferred_provenance(value) -> bool:
    if isinstance(value, dict):
        return (value.get("kind") == "inferred"
                or any(_contains_inferred_provenance(item) for item in value.values()))
    if isinstance(value, list):
        return any(_contains_inferred_provenance(item) for item in value)
    return False


def _f(cid, passed, msg, loc="") -> Finding:
    return Finding(cid, "sidecar", "error", passed, msg, loc)


def _entry_scope_ok(item: dict, declared: set[str], *, allow_all: bool) -> bool:
    """Is this §1.15/§1.14 entry scoped to declared components?

    ``allow_all`` permits the ``all-in-scope`` sentinel. It is allowed for
    §1.14 misuses, which close nothing, and refused for §1.15 non-findings:
    those fire first in the precedence order, so an entry that matches
    everywhere is a universal suppressor — which is exactly what §1.15's
    "no `any in-scope family` component" rule forbids.
    """
    raw = item.get("components")
    if isinstance(raw, list) and not _string_list(raw, nonempty=True):
        return False              # a malformed list must not read as narrower
    comps = entry_components(item)
    if not comps:
        return False
    return all((allow_all and c == ALL_IN_SCOPE) or c in declared
               for c in comps)


def check_sidecar(sidecar: dict, model: Model | None = None,
                  sidecar_path: str | Path | None = None) -> Iterable[Finding]:
    schema = sidecar.get("schema")
    yield _f("SC.schema", schema == "threat-model-sidecar/v2",
             f"schema is {schema!r}, expected 'threat-model-sidecar/v2'"
             if schema != "threat-model-sidecar/v2" else "schema tag ok")

    missing_keys = sorted(_REQUIRED_KEYS - set(sidecar))
    yield _f("SC.required-keys", not missing_keys,
             "all v2 top-level keys are present" if not missing_keys
             else f"missing required top-level keys: {missing_keys}")

    bad_shapes = sorted(
        [key for key in _LIST_KEYS if key in sidecar and not isinstance(sidecar[key], list)]
        + [key for key in _MAPPING_KEYS
           if key in sidecar and not isinstance(sidecar[key], dict)]
          + [key for key in _RECORD_LIST_KEYS
              if isinstance(sidecar.get(key), list)
              and any(not isinstance(item, dict) for item in sidecar[key])]
    )
    project_ok = isinstance(sidecar.get("project"), str) and bool(sidecar["project"].strip())
    if not project_ok:
        bad_shapes.append("project")
    yield _f("SC.top-level-shapes", not bad_shapes,
             "all top-level values have the required shapes" if not bad_shapes
             else f"top-level values with invalid shapes: {bad_shapes}")

    status = sidecar.get("model_status")
    prose_status = model.stated_status() if model is not None else None
    status_ok = status in _STATUS and (prose_status is None or status == prose_status)
    yield _f("SC.status", status_ok,
             (f"model_status {status!r} not in {sorted(_STATUS)}"
              if status not in _STATUS else
              f"sidecar status {status!r} != prose status {prose_status!r}")
             if not status_ok else "model_status matches the normalized prose status")

    pv = sidecar.get("prose_version")
    pv_match = _PROSE_VERSION.fullmatch(str(pv or ""))
    pv_path = pv_match.group(1) if pv_match else ""
    pv_digest = pv_match.group(2) if pv_match else ""
    pv_ok = bool(pv_match) and pv_path == "threat-model.md"
    pv_msg = "prose_version binds root-level threat-model.md by SHA-256" if pv_ok else (
        "prose_version must be 'threat-model.md@sha256:<64 lowercase hex>'")
    if pv_ok and model is not None and model.path.exists():
        actual = hashlib.sha256(model.path.read_bytes()).hexdigest()
        actual_path = model.path.as_posix()
        path_matches = model.path.name == pv_path
        if sidecar_path is not None:
            path_matches = (
                path_matches
                and model.path.resolve().parent == Path(sidecar_path).resolve().parent
            )
        pv_ok = actual == pv_digest and path_matches
        pv_msg = ("prose_version digest matches the prose" if pv_ok else
                  f"prose_version path/digest does not match {actual_path}@sha256:{actual}")
    yield _f("SC.prose-version", pv_ok, pv_msg)

    conf = sidecar.get("confidence")
    confidence_keys = {"documented", "maintainer", "inferred"}
    # "assumption" is an optional fourth tier (see sidecar-schema.md); when the
    # relaxed/strict policy work is in use the header may read ".../ N assumption".
    conf_ok = (isinstance(conf, dict)
               and confidence_keys <= set(conf) <= (confidence_keys | {"assumption"})
               and all(type(conf.get(k)) is int and conf[k] >= 0 for k in conf))
    yield _f("SC.confidence-shape", conf_ok,
             "confidence has documented/maintainer/inferred integers (optional assumption)"
             if conf_ok
             else "confidence must be {documented:int, maintainer:int, inferred:int} "
                  "(optional assumption:int)")
    if conf_ok and model is not None and model.stated_confidence():
        d, m, i, a = model.stated_confidence()
        match = ((conf["documented"], conf["maintainer"], conf["inferred"],
                  conf.get("assumption", 0)) == (d, m, i, a))
        yield _f("SC.confidence-matches-header", match,
                 "sidecar confidence matches the prose header" if match
                 else f"sidecar confidence {conf} != header ({d}/{m}/{i}/{a})")
    accepted_safe = not (status == "accepted" and (
        not conf_ok or conf["inferred"] > 0 or _contains_inferred_provenance(sidecar)
    ))
    yield _f("SC.accepted-no-inferred", accepted_safe,
             "accepted model has no inferred claims" if accepted_safe else
             "accepted model must have confidence.inferred == 0")

    if model is not None:
        projection_sections = {
            "components": "2",
            "host_side_effects": "5",
            "entry_points": "7",
            "contract_dimensions": "7",
            "outputs": "8",
            "adversaries": "10",
            "properties_claimed": "11",
            "properties_disclaimed": "12",
            "downstream_responsibilities": "13",
            "known_misuses": "14",
            "known_non_findings": "15",
        }
        missing_projection = [
            key for key, section_number in projection_sections.items()
            if (section := model.section(section_number)) is not None
            and not section.is_na and not _list(sidecar, key)
        ]
        yield _f("SC.prose-projection-coverage", not missing_projection,
                 "every substantive prose block has a sidecar projection"
                 if not missing_projection else
                 f"substantive prose blocks missing sidecar records: {missing_projection}")

    disp = sidecar.get("dispositions")
    disp_ok = isinstance(disp, list) and set(disp) == set(DISPOSITIONS)
    if disp_ok:
        yield _f("SC.dispositions", True, "dispositions equal the closed set")
    else:
        extra = sorted(set(disp) - set(DISPOSITIONS)) if isinstance(disp, list) else []
        missing = sorted(set(DISPOSITIONS) - set(disp)) if isinstance(disp, list) else DISPOSITIONS
        msg = "dispositions must equal the closed set"
        if extra:
            msg += f"; invented: {extra}"
        if missing:
            msg += f"; missing: {missing}"
        yield _f("SC.dispositions", False, msg)

    precedence = sidecar.get("disposition_precedence")
    precedence_ok = precedence == _DISPOSITION_PRECEDENCE
    yield _f("SC.disposition-precedence", precedence_ok,
             "disposition precedence equals the canonical first-match order"
             if precedence_ok else
             "disposition_precedence must equal the canonical first-match order")

    components = _list(sidecar, "components")
    in_components = {c.get("name") for c in components if c.get("scope") == "in"}
    # Every declared component, in- or out-of-scope. sidecar-schema.md mandates
    # an in-scope component only for outputs and contract-dimension rows; §1.13
    # responsibilities and §1.14 misuses may legitimately concern an
    # out-of-scope surface (e.g. "escalate reliance on an undocumented,
    # out-of-scope export"), so those records only require a *declared*
    # component. §1.15 non-findings are declared-component too, but rule 3 plus
    # SC.non-finding-discharge-scope effectively confine them to in-scope
    # surface: an entry that reduces to "the code is out of scope" is an
    # OUT-OF-MODEL route and keeps that label.
    declared_components = {c.get("name") for c in components}

    side_effect_bad = [
        effect.get("effect", "?") for effect in _list(sidecar, "host_side_effects")
        if not effect.get("effect")
        or effect.get("stance") not in _SIDE_EFFECT_STANCE
        or not effect.get("conditions")
        or not _string_list(effect.get("components"), nonempty=True)
        or not set(effect.get("components") or []) <= in_components
        or not _valid_provenance(effect.get("provenance"))
    ]
    yield _f("SC.host-side-effects", not side_effect_bad,
             "host side effects are explicit, scoped, and provenanced"
             if not side_effect_bad else f"bad host-side-effect records: {side_effect_bad}")

    # entry_points → parameters
    ep_bad: list[str] = []
    control_bad: list[str] = []
    obligation_id_values: list[str] = []
    # obligation_id -> the set of distinct requirement texts it is bound to.
    obligation_texts: dict[str, set[str]] = {}
    entry_points = _list(sidecar, "entry_points")
    for ep in entry_points:
        eid = ep.get("id", "?")
        if (not eid or ep.get("component") not in in_components
                or not isinstance(ep.get("parameters"), list)):
            ep_bad.append(f"{eid} (bad entry point shape/component)")
        for p in ep.get("parameters", []) if isinstance(ep.get("parameters"), list) else []:
            if not isinstance(p, dict):
                ep_bad.append(f"{eid}.? (parameter is not a mapping)")
                continue
            pname = p.get("name", "?")
            enforce = p.get("caller_must_enforce")
            if not pname or not isinstance(p.get("attacker_controllable"), bool):
                ep_bad.append(f"{eid}.{pname} (bad name/attacker_controllable)")
            if p.get("attacker_controllable") and not enforce:
                ep_bad.append(f"{eid}.{p.get('name', '?')}")
            if enforce and not _explicit_no_obligation(enforce) and not p.get("obligation_id"):
                ep_bad.append(f"{eid}.{pname} (obligation has no ID)")
            kinds = p.get("control_kinds")
            if not isinstance(kinds, list) or not kinds or any(
                    k not in _CONTROL_KIND and not str(k).startswith("x-") for k in kinds):
                control_bad.append(f"{eid}.{p.get('name', '?')}")
            if enforce and not _explicit_no_obligation(enforce) and p.get("obligation_id"):
                obligation_id_values.append(p["obligation_id"])
                obligation_texts.setdefault(p["obligation_id"], set()).add(
                    " ".join(str(enforce).split()).casefold())
            if not _valid_provenance(p.get("provenance")):
                ep_bad.append(f"{eid}.{p.get('name', '?')} (bad provenance)")
    obligation_ids = set(obligation_id_values)
    ep_ids = [ep.get("id") for ep in entry_points]
    if not all(ep_ids) or len(ep_ids) != len(set(ep_ids)):
        ep_bad.append("entry point IDs must be unique and non-empty")
    yield _f("SC.param-enforce", not ep_bad,
             "every attacker-controllable parameter has caller_must_enforce"
             if not ep_bad else
             f"attacker-controllable params without caller_must_enforce: {ep_bad}")

    # One obligation ID names one obligation, globally. Several entry points may
    # legitimately *share* an ID when they impose the same requirement -- that is
    # the shape sidecar-schema.md mandates, precisely so the §1.13 responsibility
    # that `enforces[]` points at stays whole. What is forbidden is one ID
    # standing for two different obligations, which silently merges them.
    #
    # Reported separately from SC.param-enforce: folded in, this read as a
    # missing caller_must_enforce, and the repair cloned the obligation per entry
    # point -- fragmenting the responsibility, which SC.reference-integrity
    # cannot see because it detects dangling references, never under-coverage.
    collisions = sorted(oid for oid, texts in obligation_texts.items()
                        if len(texts) > 1)
    yield _f("SC.obligation-id-unique", not collisions,
             "each obligation ID names exactly one obligation" if not collisions
             else
             f"one obligation ID used for different obligations: {collisions}. "
             "IDs are global: give distinct requirements distinct IDs, and let "
             "entry points that share a requirement share its ID rather than "
             "cloning it.")
    yield _f("SC.param-control-kinds", not control_bad,
             "every parameter has valid control_kinds" if not control_bad else
             f"parameters with invalid control_kinds: {control_bad}")

    # outputs
    outputs = _list(sidecar, "outputs")
    out_bad = [o.get("channel", "?") for o in outputs
               if not o.get("channel") or o.get("component") not in in_components
               or o.get("taint") not in _TAINT
               or not _valid_provenance(o.get("taint_provenance"))
               or not isinstance(o.get("invariants"), list)
               or not isinstance(o.get("downstream_must_not_assume"), list)]
    yield _f("SC.output-taint", not out_bad,
             "every output has a valid taint value" if not out_bad
             else f"outputs with bad taint (need {sorted(_TAINT)}): {out_bad}")

    # policies and adversaries
    dependency_policy = sidecar.get("dependency_policy")
    build_policy = sidecar.get("build_policy")
    policy_bad: list[str] = []
    if (not isinstance(dependency_policy, dict)
            or not isinstance(dependency_policy.get("zero_runtime_dependencies"), bool)
            or not _valid_provenance(dependency_policy.get("provenance"))):
        policy_bad.append("dependency_policy")
    if (not isinstance(build_policy, dict)
            or not isinstance(build_policy.get("security_relevant_flags_present"), bool)
            or not _valid_provenance(build_policy.get("provenance"))):
        policy_bad.append("build_policy")
    yield _f("SC.policy-provenance", not policy_bad,
             "dependency and build policy are explicit and provenanced"
             if not policy_bad else f"bad policy records: {policy_bad}")

    adversaries = _list(sidecar, "adversaries")
    adversary_bad = [a.get("name", "?") for a in adversaries
                     if not a.get("name") or a.get("scope") not in {"in", "out"}
                     or not _string_list(a.get("capabilities"))
                     or not _string_list(a.get("excluded_capabilities"))
                     or not _string_list(a.get("goals"))
                     or not _valid_provenance(a.get("provenance"))]
    adversary_names = [a.get("name") for a in adversaries]
    if not all(adversary_names) or len(adversary_names) != len(set(adversary_names)):
        adversary_bad.append("adversary names must be unique and non-empty")
    yield _f("SC.adversaries", not adversary_bad,
             "every adversary is scoped, structured, and provenanced"
             if not adversary_bad else f"bad adversary records: {adversary_bad}")
    in_adversary_capabilities = {
        capability for adversary in adversaries if adversary.get("scope") == "in"
        for capability in (adversary.get("capabilities") or [])
    }

    # build_flags
    build_flags = _list(sidecar, "build_flags")
    bf_bad = [b.get("name", "?") for b in build_flags
              if not b.get("name") or b.get("default") in {None, ""}
              or not isinstance(b.get("security_relevant"), bool)
              or b.get("maintainer_stance") not in _STANCE
              or not isinstance(b.get("affects_properties"), list)
              or (b.get("security_relevant") and not b.get("affects_properties"))
              or not _valid_provenance(b.get("provenance"))]
    if isinstance(build_policy, dict) and isinstance(
            build_policy.get("security_relevant_flags_present"), bool):
        actual_security_flags = any(b.get("security_relevant") is True for b in build_flags)
        if build_policy["security_relevant_flags_present"] != actual_security_flags:
            bf_bad.append("build_policy contradicts build_flags")
    yield _f("SC.build-flag-stance", not bf_bad,
             "every build flag has a valid maintainer_stance" if not bf_bad
             else f"build flags with bad stance (need {sorted(_STANCE)}): {bf_bad}")

    # properties_claimed
    pc_bad: list[str] = []
    claimed = _list(sidecar, "properties_claimed")
    disclaimed = _list(sidecar, "properties_disclaimed")
    claimed_ids = {p.get("id") for p in claimed}
    disclaimed_ids = {p.get("id") for p in disclaimed}
    property_ids = claimed_ids | disclaimed_ids
    claimed_by_id = {p.get("id"): p for p in claimed}
    disclaimed_by_id = {p.get("id"): p for p in disclaimed}
    for p in claimed:
        sym = p.get("violation_symptoms")
        kind = p.get("kind")
        p_components = p.get("components")
        if (p.get("tier") not in _TIER or not (isinstance(sym, list) and sym)
            or not p.get("conditions") or not _string_list(p_components, nonempty=True)
            or not set(p_components or []) <= in_components
                or (kind not in _PROPERTY_KIND and not str(kind).startswith("x-"))
                or not _valid_provenance(p.get("provenance"))):
            pc_bad.append(p.get("id", "?"))
    yield _f("SC.claimed-tier-symptom", not pc_bad,
             "every claimed property has a tier and >=1 violation symptom"
             if not pc_bad else
             f"claimed properties missing tier/symptom: {pc_bad}")

    # An inferred guarantee at the CVE tier is a promise the project never made.
    # §1.11 requires it to stay an `unresolved` matrix row plus a §1.18 choice
    # question until a maintainer ratifies it -- integrators build on §1.11, so
    # an unratified security-critical claim is worse than a visible gap.
    pc_inferred_critical = [
        p.get("id", "?") for p in claimed
        if p.get("tier") == "security-critical"
        and isinstance(p.get("provenance"), dict)
        and p["provenance"].get("kind") in ("inferred", "assumption")
    ]
    yield _f("SC.claimed-inferred-tier", not pc_inferred_critical,
             "no claimed property is both unratified and security-critical"
             if not pc_inferred_critical else
             "unratified (inferred/assumption) claimed properties may not be "
             f"security-critical (move to §1.18): {pc_inferred_critical}")

    # properties_disclaimed
    pd_bad = [p.get("id", "?") for p in disclaimed
              if not isinstance(p.get("false_friend"), bool)
              or not p.get("conditions")
              or not _string_list(p.get("components"), nonempty=True)
              or not set(p.get("components") or []) <= in_components
              or not _valid_provenance(p.get("provenance"))]
    yield _f("SC.disclaimed-false-friend", not pd_bad,
             "every disclaimed property flags false_friend true/false"
             if not pd_bad else
             f"disclaimed properties missing false_friend bool: {pd_bad}")

    # `tier` gates whether an assumption may provisionally close a
    # property-disclaimed route, and triage fails closed on a missing value.
    # Without this check an untiered disclaimer silently escalates every
    # matching report instead of closing it -- or, before the fail-closed fix,
    # closed reports it had no authority to close.
    pd_untiered = [p.get("id", "?") for p in disclaimed
                   if p.get("tier") not in _TIER]
    yield _f("SC.disclaimed-tier", not pd_untiered,
             "every disclaimed property carries a security-critical/"
             "correctness-only tier"
             if not pd_untiered else
             f"disclaimed properties missing a valid tier: {pd_untiered}")

    # components
    comp_bad: list[str] = []
    for c in components:
        if not c.get("name") or c.get("scope") not in ("in", "out"):
            comp_bad.append(c.get("name", "?"))
        elif c.get("scope") == "out" and not c.get("reason"):
            comp_bad.append(c.get("name", "?") + " (out w/o reason)")
        elif c.get("scope") == "in" and not c.get("reachability_precondition"):
            comp_bad.append(c.get("name", "?") + " (in w/o reachability)")
        elif not _valid_provenance(c.get("provenance")):
            comp_bad.append(c.get("name", "?") + " (bad provenance)")
    yield _f("SC.components", not comp_bad,
             "every component has scope in/out (out with a reason)"
             if not comp_bad else f"bad components: {comp_bad}")

    # Contract-dimension closure and stable routing references.
    rows = _list(sidecar, "contract_dimensions")
    expected = {(component, dimension) for component in in_components
                for dimension in _DIMENSIONS}
    seen: set[tuple[str, str]] = set()
    dim_bad: list[str] = []
    for row in rows:
        key = (row.get("component"), row.get("dimension"))
        if key in seen:
            dim_bad.append(f"duplicate {key}")
        seen.add(key)
        status_value = row.get("status")
        dimension = row.get("dimension")
        if row.get("component") not in in_components \
                or (dimension not in _DIMENSIONS and not str(dimension).startswith("x-")) \
                or status_value not in _DIM_STATUS or not row.get("conditions") \
                or not _valid_provenance(row.get("provenance")):
            dim_bad.append(str(key))
        expected_properties = claimed_ids if status_value == "claimed" else disclaimed_ids
        if status_value in {"claimed", "disclaimed"} and row.get("property_id") not in expected_properties:
            dim_bad.append(f"{key} property_id does not match {status_value} properties")
        elif status_value in {"claimed", "disclaimed"}:
            owner = (claimed_by_id if status_value == "claimed" else disclaimed_by_id)[
                row["property_id"]
            ]
            if row.get("component") not in (owner.get("components") or []):
                dim_bad.append(f"{key} property_id does not cover component")
        if status_value == "unresolved" and (
                row.get("property_id") is not None
                or row.get("provenance", {}).get("kind") != "inferred"):
            dim_bad.append(f"{key} unresolved without inferred provenance")
        if status_value == "not-applicable" and row.get("property_id") is not None:
            dim_bad.append(f"{key} not-applicable with property_id")
    missing_dimensions = sorted(expected - seen)
    if missing_dimensions:
        dim_bad.extend(f"missing {key}" for key in missing_dimensions)
    yield _f("SC.contract-dimensions", not dim_bad,
             "contract dimensions cover every in-scope component" if not dim_bad
             else f"bad contract dimension rows: {dim_bad}")

    # Stable reference integrity and output contracts.
    reference_ids = set(property_ids) | obligation_ids
    output_bad: list[str] = []
    for output in outputs:
        for invariant in output.get("invariants", []) or []:
            if not isinstance(invariant, dict):
                output_bad.append(f"{output.get('channel', '?')} invariant is not a mapping")
                continue
            if invariant.get("id"):
                reference_ids.add(invariant["id"])
            if (not invariant.get("id") or not invariant.get("statement")
                    or invariant.get("property_id") not in claimed_ids
                    or output.get("component") not in (
                        claimed_by_id.get(invariant.get("property_id"), {}).get("components") or [])
                    or not _valid_provenance(invariant.get("provenance"))):
                output_bad.append(f"output invariant {invariant.get('id', '?')}")
        for item in output.get("downstream_must_not_assume", []) or []:
            if not isinstance(item, dict):
                output_bad.append(f"{output.get('channel', '?')} assumption is not a mapping")
                continue
            if item.get("id"):
                reference_ids.add(item["id"])
            if (not item.get("id") or not item.get("statement")
                    or not _valid_provenance(item.get("provenance"))):
                output_bad.append(f"output assumption {item.get('id', '?')}")
    yield _f("SC.output-contract", not output_bad,
             "output invariants and non-assumptions resolve and carry provenance"
             if not output_bad else f"bad output contract records: {output_bad}")

    ref_bad: list[str] = []
    for flag in build_flags:
        for effect in flag.get("affects_properties", []) or []:
            if effect.get("property_id") not in claimed_ids or effect.get("effect") not in _EFFECT:
                ref_bad.append(f"build flag {flag.get('name', '?')}")
    dependency_bad: list[str] = []
    dependencies = _list(sidecar, "dependencies")
    for dependency in dependencies:
        forwarded = dependency.get("adversary_capabilities_forwarded")
        outputs_consumed = dependency.get("outputs_consumed")
        if (not dependency.get("name") or not dependency.get("relied_on_for")
                or not _string_list(dependency.get("relied_on_properties"))
                or not _string_list(dependency.get("caller_obligations_acknowledged"))
                or not _string_list(forwarded)
                or not set(forwarded or []) <= in_adversary_capabilities
                or not isinstance(outputs_consumed, list)
                or not isinstance(dependency.get("covered_here"), bool)
                or dependency.get("violation_disposition") !=
                "OUT-OF-MODEL: dependency-contract"
                or not _valid_provenance(dependency.get("provenance"))):
            dependency_bad.append(dependency.get("name", "?"))
            continue
        for use in outputs_consumed:
            prop = next(
                (p for p in claimed if p.get("id") == use.get("supports_property_id")),
                None,
            ) if isinstance(use, dict) else None
            if not isinstance(use, dict):
                dependency_bad.append(
                    f"{dependency.get('name', '?')} output use {use!r} "
                    f"(each outputs_consumed entry must be a mapping)")
            elif not use.get("channel") or use.get("taint_handling") not in _TAINT_HANDLING:
                dependency_bad.append(
                    f"{dependency.get('name', '?')} output use {use!r} "
                    f"(needs a channel and taint_handling in {sorted(_TAINT_HANDLING)})")
            elif prop is None or prop.get("kind") != "output-sanitization":
                dependency_bad.append(
                    f"{dependency.get('name', '?')} output use {use!r} "
                    f"(supports_property_id must reference a kind:output-sanitization "
                    f"property; leave outputs_consumed empty when the project only "
                    f"passes the dependency output through and disclaims sanitization)")
    zero_deps_consistent = isinstance(dependency_policy, dict) and (
        dependency_policy.get("zero_runtime_dependencies") == (len(dependencies) == 0)
    )
    if not zero_deps_consistent:
        dependency_bad.append("dependency_policy contradicts dependencies")
    yield _f("SC.dependencies", not dependency_bad,
             "dependencies carry exact external IDs and agree with policy"
             if not dependency_bad else f"bad dependency records: {dependency_bad}")

    for responsibility in _list(sidecar, "downstream_responsibilities"):
        # `enforces` may be empty: a responsibility for a shipped-but-unsupported
        # component (e.g. "escalate any reliance on an undocumented export") has
        # no contract to enforce, so there is no stable obligation ID to cite.
        # sidecar-schema.md mandates non-emptiness for other fields but not here.
        # Referential integrity of any present ref is still enforced below.
        if (not responsibility.get("id") or not responsibility.get("statement")
                or responsibility.get("component") not in declared_components
                or not _string_list(responsibility.get("enforces"))
                or not _valid_provenance(responsibility.get("provenance"))):
            ref_bad.append(f"responsibility {responsibility.get('id', '?')} provenance")
        for ref in responsibility.get("enforces", []) or []:
            if ref not in reference_ids:
                ref_bad.append(f"responsibility {responsibility.get('id', '?')} -> {ref}")
    for item in _list(sidecar, "known_non_findings"):
        # `symptom` is required (§1.15 rule 3): an entry identified only by
        # location is a scope question, which belongs to an OUT-OF-MODEL route
        # rather than to the precedence-1 suppression list.
        if (not item.get("id") or not item.get("tool_pattern")
                or not _entry_scope_ok(item, declared_components, allow_all=False)
                or not item.get("conditions")
                or not _string_list(item.get("discharged_by"), nonempty=True)
                or not _valid_provenance(item.get("provenance"))):
            ref_bad.append(f"non-finding {item.get('id', '?')} provenance")
        for ref in item.get("discharged_by", []) or []:
            if ref not in reference_ids:
                ref_bad.append(f"non-finding {item.get('id', '?')} -> {ref}")
    for misuse in _list(sidecar, "known_misuses"):
        if (not misuse.get("id")
                or not _entry_scope_ok(misuse, declared_components, allow_all=True)
                or not misuse.get("pattern") or not misuse.get("safer_alternative")
                or not _valid_provenance(misuse.get("provenance"))):
            ref_bad.append(f"misuse {misuse.get('id', '?')} provenance")
    yield _f("SC.reference-integrity", not ref_bad,
             "all stable references and provenance resolve" if not ref_bad
             else f"bad stable references: {ref_bad}")

    # §1.15 rule 4: a discharging claim must actually cover the component the
    # entry matches. Without this, a disclaimer written for one component
    # silently discharges reports against another -- and because
    # KNOWN-NON-FINDING is first in the precedence order, that suppression wins
    # over every scope, configuration, and adversary check below it.
    scope_bad: list[str] = []
    for item in _list(sidecar, "known_non_findings"):
        entry_comps = set(entry_components(item))
        # At least one discharging reference must be a property, so that this
        # check has something component-bearing to compare against. §1.7
        # obligation and §1.3 scope IDs may accompany a property but never
        # stand alone -- otherwise citing one turns rule 4 off entirely.
        refs = item.get("discharged_by", []) or []
        owners = [claimed_by_id.get(r) or disclaimed_by_id.get(r) for r in refs]
        if not any(o is not None for o in owners):
            scope_bad.append(
                f"{item.get('id', '?')} is discharged by no §1.11/§1.12 "
                f"property (refs: {sorted(refs)})")
            continue
        for ref, owner in zip(refs, owners):
            if owner is None:
                continue          # accompanying obligation/scope ID
            owner_comps = set(owner.get("components") or [])
            uncovered = entry_comps - owner_comps
            if uncovered:
                scope_bad.append(
                    f"{item.get('id', '?')} -> {ref} does not cover "
                    f"{sorted(uncovered)}")
    yield _f("SC.non-finding-discharge-scope", not scope_bad,
             "every known non-finding is discharged by a claim covering its "
             "components" if not scope_bad else
             f"known non-findings discharged out of scope: {scope_bad}")

    # §1.15 rule 3: an entry identified only by location is a scope question,
    # and that is an OUT-OF-MODEL route rather than a precedence-1 suppression.
    # Kept as its own check so a repair agent is told the field that failed --
    # folded into SC.reference-integrity it reads as a provenance error.
    sym_bad = [item.get("id", "?") for item in _list(sidecar, "known_non_findings")
               if not (isinstance(item.get("symptom"), str)
                       and item["symptom"].strip())]
    yield _f("SC.non-finding-symptom", not sym_bad,
             "every known non-finding names a symptom or attack class"
             if not sym_bad else
             f"known non-findings missing a symptom/attack class: {sym_bad}")

    id_lists = [claimed, disclaimed, _list(sidecar, "known_non_findings"),
                _list(sidecar, "known_misuses"),
                _list(sidecar, "downstream_responsibilities")]
    component_ids = [c.get("name") for c in components]
    ids_ok = (all(_unique_ids(items) for items in id_lists)
              and len(component_ids) == len(set(component_ids)))
    yield _f("SC.unique-ids", ids_ok,
             "IDs are unique within each structured list" if ids_ok else
             "every structured record list must have unique non-empty IDs")

    # keys outside schema (only x- extensions allowed)
    known = {
        "schema", "project", "prose_version", "model_status", "confidence",
        "components", "host_side_effects", "entry_points", "contract_dimensions", "outputs",
        "adversaries", "dependency_policy", "dependencies", "build_policy",
        "build_flags", "properties_claimed", "properties_disclaimed",
        "downstream_responsibilities", "known_misuses", "known_non_findings",
        "dispositions", "disposition_precedence",
        # optional (defaults to "strict" when omitted); see sidecar-schema.md
        "triage_policy",
        # optional §1.17 status vocabulary; a closed enum fixed by the spec and
        # identical in every model, so it is recognized but never required
        "disposition_statuses",
        # optional §1.1 generation metadata; descriptive only, see sidecar-schema.md
        "generation",
    }
    unknown = [k for k in sidecar if k not in known and not str(k).startswith("x-")]
    yield _f("SC.no-unknown-keys", not unknown,
             "no keys outside the schema (x- extensions allowed)" if not unknown
             else f"unknown top-level keys (prefix with x- to extend): {unknown}")

    # triage_policy, when present, must be one of the two known policies
    policy = sidecar.get("triage_policy")
    policy_ok = policy is None or policy in ("strict", "relaxed")
    yield _f("SC.triage-policy", policy_ok,
             "triage_policy is 'strict', 'relaxed', or omitted (defaults to strict)"
             if policy_ok else
             f"triage_policy must be 'strict' or 'relaxed', got {policy!r}")


def run_sidecar_checks(sidecar: dict, model: Model | None = None,
                       sidecar_path: str | Path | None = None) -> Report:
    report = Report()
    report.extend(check_sidecar(sidecar, model, sidecar_path))
    return report
