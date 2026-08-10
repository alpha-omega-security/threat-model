"""Checks over the flat JSON export (`threat-model.json`).

`threat-model.json` is the third artifact: a lossy projection into the shape
`schema.json` defines, for external consumers that speak that schema. The
authority order is prose > yaml > json. The mapping is engineered so that
whatever the JSON loses pushes a consumer toward escalating, never toward
closing. These checks defend that property against the export itself.

The one that matters most is `JSON.provenance-fail-safe`. The JSON has a
two-value provenance axis, and in this system that axis decides whether a
claim may close a report. A sidecar claim held as `inferred` or `assumption`
carries no such authority, so it must never surface as `documented` — that
direction hands a JSON-only consumer a licence the model never granted.
The reverse (documented surfacing as inferred) is merely over-conservative
and is allowed.

`project_from_sidecar` derives everything the sidecar can mechanically
supply. It is a starting point for an author, not an output.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from .checks import entry_components
from .jsonschema_mini import validate_instance
from .parse import _TAG, Model
from .report import Finding, Report

_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schema.json"

# schema.json's nine disposition labels. §1.17 has ten: `OUT-OF-MODEL:
# dependency-contract` has no JSON value. A JSON-only consumer meeting such a
# finding matches nothing and falls through to model_gap, which escalates —
# the safe direction, so the schema is complied with as written.
JSON_DISPOSITIONS = [
    "valid",
    "valid_hardening",
    "out_of_model_trusted_input",
    "out_of_model_adversary",
    "out_of_model_unsupported_component",
    "out_of_model_non_default_build",
    "by_design_disclaimed",
    "known_non_finding",
    "model_gap",
]

# §1.5 effect names → the JSON `touches` enum. A present/conditional effect
# that maps to none of the six values has no JSON home; it stays in the YAML
# rather than being forced into a near-miss bucket.
_EFFECT_TO_TOUCH = {
    "filesystem": "filesystem",
    "network-sockets": "network",
    "network": "network",
    "environment-reads": "env",
    "env": "env",
    "child-processes": "child_processes",
    "subprocess": "child_processes",
    "signal-handlers": "signals",
    "signals": "signals",
    "global-state": "global_state",
    "process-state": "global_state",
}
_TOUCH_ORDER = ["filesystem", "network", "env", "child_processes", "signals",
                "global_state"]

_TIER_TO_JSON = {"security-critical": "security",
                 "correctness-only": "correctness"}

_COMMIT = re.compile(r"[0-9a-f]{7,40}")
# §3d containment: `cites` must point at the discharging claim inside this
# document, in the schema's pointer-ish style.
_CITES = re.compile(
    r"(properties_provided|properties_not_provided|out_of_scope)\[(\d+)\]")


def _records(sidecar: dict, key: str) -> list[dict]:
    value = sidecar.get(key)
    return [item for item in value if isinstance(item, dict)] \
        if isinstance(value, list) else []


def _obj_rows(value) -> list[dict]:
    """Array-of-objects JSON field, defensively (never raises on bad shape)."""
    return [item for item in value if isinstance(item, dict)] \
        if isinstance(value, list) else []


def _is_na(value) -> bool:
    return isinstance(value, dict) and value.get("not_applicable") is True


def _kind(record: dict):
    prov = record.get("provenance")
    return prov.get("kind") if isinstance(prov, dict) else None


def _collapses_to_inferred(kind) -> bool:
    # Only documented/maintainer carry authority to close a report under every
    # policy; anything else — including a missing or unknown kind — must read
    # as inferred.
    return kind not in ("documented", "maintainer")


def _weakest(kinds) -> str:
    """Collapse a set of sidecar provenance kinds to one JSON value (§1a).

    The object's provenance is the weakest of the collapsed set. An empty set
    means nothing grounds a documented claim, so it also reads as inferred.
    """
    if not kinds or any(_collapses_to_inferred(k) for k in kinds):
        return "inferred"
    return "documented"


def _environment_kinds(sidecar: dict) -> list:
    # The JSON environment block collapses the §1.5 inventory and the §1.10
    # security model, so both contribute to its weakest-of-set provenance.
    return ([_kind(r) for r in _records(sidecar, "host_side_effects")]
            + [_kind(r) for r in _records(sidecar, "adversaries")])


def _adversary_kinds(sidecar: dict) -> list:
    return [_kind(r) for r in _records(sidecar, "adversaries")]


def _collapse(prov) -> tuple[str, str | None]:
    """Sidecar provenance mapping → (JSON `provenance`, JSON `source`)."""
    if not isinstance(prov, dict):
        return "inferred", None
    kind = prov.get("kind")
    if kind == "documented":
        return "documented", prov.get("source") or None
    if kind == "maintainer":
        date = prov.get("date")
        return "documented", (f"maintainer ruling, {date}" if date
                              else "maintainer ruling")
    qid = prov.get("question_id")
    return "inferred", (f"open question {qid}" if qid else None)


def _names(needle: str, haystack_cf: str) -> bool:
    """Does the casefolded text mention this name as a whole word?

    Names here are kebab-case IDs, so a hyphen is part of the word: the
    boundary is any character that could extend the ID. Plain substring
    matching would let "score-inflated" satisfy a "core-inflate" scope
    requirement by collision.
    """
    return re.search(r"(?<![\w-])" + re.escape(needle.casefold()) + r"(?![\w-])",
                     haystack_cf) is not None


def _f(cid, passed, msg, loc="", severity="error") -> Finding:
    return Finding(cid, "sidecar", severity, passed, msg, loc)


def check_json_report(report: dict, sidecar: dict, model: Model | None = None,
                      schema_path: str | Path | None = None
                      ) -> Iterable[Finding]:
    # ---- JSON.schema-valid -------------------------------------------------
    path = Path(schema_path) if schema_path else _SCHEMA_PATH
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        schema = None
        yield _f("JSON.schema-valid", False, f"cannot load schema {path}: {exc}")
    if schema is not None:
        errors = validate_instance(report, schema)
        shown = "; ".join(errors[:5])
        if len(errors) > 5:
            shown += f"; +{len(errors) - 5} more"
        yield _f("JSON.schema-valid", not errors,
                 "document validates against schema.json" if not errors
                 else f"schema violations: {shown}")

    # ---- JSON.dispositions-complete ---------------------------------------
    disp = report.get("dispositions")
    disp_ok = (isinstance(disp, list) and len(disp) == 9
               and set(disp) == set(JSON_DISPOSITIONS))
    if disp_ok:
        yield _f("JSON.dispositions-complete", True,
                 "dispositions carry all nine schema values")
    else:
        msg = "dispositions must be exactly the nine schema values"
        if isinstance(disp, list):
            extra = sorted(set(disp) - set(JSON_DISPOSITIONS), key=str)
            missing = sorted(set(JSON_DISPOSITIONS) - set(disp))
            if extra:
                msg += f"; invented: {extra}"
            if missing:
                msg += f"; missing: {missing}"
        yield _f("JSON.dispositions-complete", False, msg)

    # ---- shared sidecar indexes -------------------------------------------
    components = _records(sidecar, "components")
    comp_by_name = {c.get("name"): c for c in components}
    in_names = {c.get("name") for c in components if c.get("scope") == "in"}
    out_names = {c.get("name") for c in components if c.get("scope") == "out"}
    claimed = _records(sidecar, "properties_claimed")
    disclaimed = _records(sidecar, "properties_disclaimed")
    claimed_by_id = {p.get("id"): p for p in claimed}
    disclaimed_by_id = {p.get("id"): p for p in disclaimed}
    flags_by_name = {b.get("name"): b for b in _records(sidecar, "build_flags")}
    params: dict[tuple, dict] = {}
    for ep in _records(sidecar, "entry_points"):
        plist = ep.get("parameters")
        for p in plist if isinstance(plist, list) else []:
            if isinstance(p, dict):
                params[(ep.get("id"), p.get("name"))] = p

    json_components = _obj_rows(report.get("components"))
    json_eps = _obj_rows(report.get("entry_points"))
    json_provided = _obj_rows(report.get("properties_provided"))
    json_disclaimed = _obj_rows(report.get("properties_not_provided"))

    # ---- JSON.provenance-fail-safe ----------------------------------------
    # Match every JSON record that carries provenance to its sidecar
    # counterpart by identifying key, and report every upgrade, not the first.
    upgraded: list[str] = []

    def _check_upgrade(loc: str, json_row: dict, counterpart,
                       matchable: bool = True) -> None:
        if counterpart is None:
            # Record types owned by a *-match check leave unmatched rows to
            # that check, which fails on them. trust_boundaries and
            # build_variants have no such check, so an unmatched row claiming
            # documented fails closed HERE: a claim no sidecar record can
            # vouch for is exactly the upgrade this check exists to stop, and
            # renaming the key must not buy an exemption.
            if not matchable and json_row.get("provenance") == "documented":
                upgraded.append(f"{loc} (documented, but no sidecar record "
                                "vouches for it)")
            return
        kind = _kind(counterpart)
        if _collapses_to_inferred(kind) and json_row.get("provenance") == "documented":
            upgraded.append(f"{loc} (sidecar {kind or 'missing'} surfaced as "
                            "documented)")

    for i, row in enumerate(json_components):
        _check_upgrade(f"components[{i}] {row.get('name')}", row,
                       comp_by_name.get(row.get("name")))
    for i, row in enumerate(_obj_rows(report.get("out_of_scope"))):
        _check_upgrade(f"out_of_scope[{i}] {row.get('item')}", row,
                       comp_by_name.get(row.get("item")))
    # A boundary claim has no sidecar record of its own: the component row it
    # rides on describes the component, and the golden model itself holds its
    # components documented while §1.4 grounds the boundaries as inferred.
    # §1.4's prose tags are the only record of the boundary's own authority,
    # so a documented boundary row is licensed only when §1.4 carries at least
    # one documented/maintainer tag. No prose, no tags, or all-inferred tags
    # → fail closed: an unverifiable documented claim is exactly the upgrade
    # this check exists to stop.
    s4 = model.section("4") if model is not None else None
    s4_kinds = {m.group(1).lower() for m in _TAG.finditer(s4.body)} if s4 else set()
    boundary_grounded = any(not _collapses_to_inferred(k) for k in s4_kinds)
    for i, row in enumerate(_obj_rows(report.get("trust_boundaries"))):
        loc = f"trust_boundaries[{i}] {row.get('component')}"
        if row.get("provenance") == "documented" and not boundary_grounded:
            upgraded.append(
                f"{loc} (" + ("no prose was supplied, so the boundary claim "
                              "cannot be verified against §1.4"
                              if s4 is None else
                              "no §1.4 provenance tag is documented/"
                              "maintainer; the boundary claim has no "
                              "documented grounding") + ")")
        else:
            _check_upgrade(loc, row, comp_by_name.get(row.get("component")),
                           matchable=False)
    for i, row in enumerate(json_eps):
        key = (row.get("entry_point"), row.get("parameter"))
        _check_upgrade(f"entry_points[{i}] {key[0]}.{key[1]}", row,
                       params.get(key))
    for i, row in enumerate(json_provided):
        _check_upgrade(f"properties_provided[{i}] {row.get('property')}", row,
                       claimed_by_id.get(row.get("property")))
    for i, row in enumerate(json_disclaimed):
        _check_upgrade(f"properties_not_provided[{i}] {row.get('property')}",
                       row, disclaimed_by_id.get(row.get("property")))
    for i, row in enumerate(_obj_rows(report.get("build_variants"))):
        _check_upgrade(f"build_variants[{i}] {row.get('name')}", row,
                       flags_by_name.get(row.get("name")), matchable=False)
    # environment and adversaries collapse many sidecar records into one JSON
    # object; the object's provenance must be the weakest of the set (§1a).
    env = report.get("environment")
    if (isinstance(env, dict) and env.get("provenance") == "documented"
            and _weakest(_environment_kinds(sidecar)) == "inferred"):
        upgraded.append("environment (weakest contributing §1.5/§1.10 record "
                        "is inferred/assumption)")
    adv = report.get("adversaries")
    if (isinstance(adv, dict) and adv.get("provenance") == "documented"
            and _weakest(_adversary_kinds(sidecar)) == "inferred"):
        upgraded.append("adversaries (weakest contributing record is "
                        "inferred/assumption)")
    yield _f("JSON.provenance-fail-safe", not upgraded,
             "no inferred/assumption claim surfaces as documented"
             if not upgraded else
             f"provenance upgraded past what the model granted: {upgraded}")

    # ---- JSON.confidence-matches ------------------------------------------
    conf = report.get("confidence")
    sc_conf = sidecar.get("confidence")
    if conf is None:
        yield _f("JSON.confidence-matches", False,
                 "JSON omits the optional confidence block; emit it so a "
                 "consumer can see how much of the model is unratified",
                 severity="warn")
    elif not isinstance(sc_conf, dict):
        yield _f("JSON.confidence-matches", False,
                 "sidecar confidence is missing or malformed; cannot compare")
    else:
        def _n(key) -> int:
            value = sc_conf.get(key)
            return value if type(value) is int and value >= 0 else 0
        expected = {"documented": _n("documented") + _n("maintainer"),
                    "inferred": _n("inferred") + _n("assumption")}
        yield _f("JSON.confidence-matches", conf == expected,
                 "JSON confidence equals the collapsed sidecar counts"
                 if conf == expected else
                 f"JSON confidence {conf} != collapsed sidecar {expected} "
                 "(documented+maintainer / inferred+assumption)")

    # ---- JSON.components-match --------------------------------------------
    comp_problems: list[str] = []
    json_in_names = {row.get("name") for row in json_components}
    missing_in = sorted(in_names - json_in_names, key=str)
    extra_in = sorted(json_in_names - in_names, key=str)
    if missing_in:
        comp_problems.append(f"sidecar scope-in missing from JSON: {missing_in}")
    if extra_in:
        comp_problems.append(f"JSON components not sidecar scope-in: {extra_in}")
    oos = report.get("out_of_scope")
    if _is_na(oos):
        if out_names:
            comp_problems.append("out_of_scope is not_applicable but the "
                                 f"sidecar carves out: {sorted(out_names, key=str)}")
    else:
        json_out_names = {row.get("item") for row in _obj_rows(oos)}
        missing_out = sorted(out_names - json_out_names, key=str)
        extra_out = sorted(json_out_names - out_names, key=str)
        if missing_out:
            comp_problems.append(
                f"sidecar scope-out missing from JSON: {missing_out}")
        if extra_out:
            comp_problems.append(
                f"JSON out_of_scope not sidecar scope-out: {extra_out}")
    yield _f("JSON.components-match", not comp_problems,
             "components and out_of_scope agree with the sidecar scopes"
             if not comp_problems else "; ".join(comp_problems))

    # ---- JSON.properties-match --------------------------------------------
    prop_problems: list[str] = []
    json_prov_ids = {row.get("property") for row in json_provided}
    json_disc_ids = {row.get("property") for row in json_disclaimed}
    for label, json_ids, sidecar_ids in (
            ("properties_provided", json_prov_ids, set(claimed_by_id)),
            ("properties_not_provided", json_disc_ids, set(disclaimed_by_id))):
        missing = sorted(sidecar_ids - json_ids, key=str)
        extra = sorted(json_ids - sidecar_ids, key=str)
        if missing:
            prop_problems.append(f"{label} missing: {missing}")
        if extra:
            prop_problems.append(f"{label} not in sidecar: {extra}")
    yield _f("JSON.properties-match", not prop_problems,
             "claimed and disclaimed property IDs agree with the sidecar"
             if not prop_problems else "; ".join(prop_problems))

    # ---- JSON.tier-maps ----------------------------------------------------
    tier_bad: list[str] = []
    for i, row in enumerate(json_provided):
        owner = claimed_by_id.get(row.get("property"))
        if owner is None:
            continue              # JSON.properties-match reports it
        expected_tier = _TIER_TO_JSON.get(owner.get("tier"))
        if expected_tier is None:
            continue              # a bad sidecar tier is the sidecar gate's job
        if row.get("severity_tier") != expected_tier:
            tier_bad.append(
                f"properties_provided[{i}] {row.get('property')}: "
                f"{row.get('severity_tier')!r} != {expected_tier!r} "
                f"(sidecar tier {owner.get('tier')})")
    yield _f("JSON.tier-maps", not tier_bad,
             "every severity_tier is the correct collapse of the sidecar tier"
             if not tier_bad else f"wrong severity_tier: {tier_bad}")

    # ---- JSON.entry-points-match ------------------------------------------
    ep_problems: list[str] = []
    json_pairs: dict[tuple, object] = {
        (row.get("entry_point"), row.get("parameter")):
            row.get("attacker_controllable")
        for row in json_eps
    }
    for key in sorted(set(params) - set(json_pairs), key=str):
        ep_problems.append(f"sidecar {key[0]}.{key[1]} has no JSON row")
    for key in sorted(set(json_pairs) - set(params), key=str):
        ep_problems.append(f"JSON {key[0]}.{key[1]} has no sidecar parameter")
    for key in sorted(set(params) & set(json_pairs), key=str):
        sc_value = params[key].get("attacker_controllable")
        if not isinstance(sc_value, bool):
            continue              # the sidecar gate owns bad booleans
        allowed = {"no"} if sc_value is False else {"yes", "conditional"}
        if json_pairs[key] not in allowed:
            ep_problems.append(
                f"{key[0]}.{key[1]}: attacker_controllable "
                f"{json_pairs[key]!r} contradicts sidecar {sc_value}")
    yield _f("JSON.entry-points-match", not ep_problems,
             "every (entry point, parameter) pair matches the sidecar"
             if not ep_problems else
             f"entry-point rows disagree with the sidecar: {ep_problems}")

    # ---- JSON.conditional-has-condition -----------------------------------
    # schema.json states this requirement in a description but has no if/then
    # to enforce it, so it is enforced here.
    cond_bad = [
        f"entry_points[{i}] {row.get('entry_point')}.{row.get('parameter')}"
        for i, row in enumerate(json_eps)
        if row.get("attacker_controllable") == "conditional"
        and not (isinstance(row.get("condition"), str)
                 and row["condition"].strip())
    ]
    yield _f("JSON.conditional-has-condition", not cond_bad,
             "every conditional entry-point row states its condition"
             if not cond_bad else
             f"conditional rows without a condition: {cond_bad}")

    # ---- JSON.non-finding-scoped ------------------------------------------
    # The JSON non-finding drops `components` and `symptom` — exactly the two
    # fields §1.15 requires so a non-finding cannot suppress everything. The
    # containment rule: `why_safe` must name the scope in text, and `cites`
    # must resolve to the discharging claim inside this document.
    knf_by_pattern = {
        item.get("tool_pattern"): item
        for item in _records(sidecar, "known_non_findings")
        if isinstance(item.get("tool_pattern"), str)
    }
    knf_bad: list[str] = []
    for i, row in enumerate(_obj_rows(report.get("known_non_findings"))):
        loc = f"known_non_findings[{i}]"
        why = row.get("why_safe")
        why_cf = why.casefold() if isinstance(why, str) else ""
        counterpart = knf_by_pattern.get(row.get("reported_as"))
        if counterpart is None:
            knf_bad.append(f"{loc}: reported_as matches no sidecar tool_pattern")
        else:
            # Whole-name matches only. Substring matching lets a collision
            # satisfy the scope requirement ("score-inflated" contains
            # "core-inflate") without the text ever naming the component.
            comps = [c for c in entry_components(counterpart) if c in in_names]
            if not any(_names(str(c), why_cf) for c in comps):
                knf_bad.append(f"{loc}: why_safe names none of its in-scope "
                               f"components {sorted(comps, key=str)}")
            symptom = counterpart.get("symptom")
            if not (isinstance(symptom, str) and symptom.strip()
                    and _names(symptom, why_cf)):
                knf_bad.append(f"{loc}: why_safe does not name the sidecar "
                               f"symptom {symptom!r}")
            # §3d: cites must point at the DISCHARGING claim, not merely at a
            # real index. The sidecar's discharged_by IDs say which claim that
            # is; find each one's row in this document's own lists. An
            # unrelated-but-resolvable cite hands a JSON-only consumer the
            # wrong licence for a precedence-1 suppression entry.
            expected_cites = set()
            for ref in counterpart.get("discharged_by") or []:
                for list_name, rows in (
                        ("properties_provided", json_provided),
                        ("properties_not_provided", json_disclaimed)):
                    for j, prop in enumerate(rows):
                        if prop.get("property") == ref:
                            expected_cites.add(f"{list_name}[{j}]")
        cite = row.get("cites")
        match = _CITES.fullmatch(cite) if isinstance(cite, str) else None
        target = report.get(match.group(1)) if match else None
        if (match is None or not isinstance(target, list)
                or int(match.group(2)) >= len(target)):
            knf_bad.append(f"{loc}: cites {cite!r} does not resolve to an "
                           "index in this document")
        elif counterpart is not None and cite not in expected_cites:
            knf_bad.append(
                f"{loc}: cites {cite!r} is not the discharging claim"
                + (f" (expected one of {sorted(expected_cites)})"
                   if expected_cites else
                   " (no discharged_by ID resolves in this document)"))
    yield _f("JSON.non-finding-scoped", not knf_bad,
             "every non-finding names its scope in why_safe and cites its "
             "discharging claim" if not knf_bad else
             f"unscoped known non-findings: {knf_bad}")

    # ---- JSON.touches-grounded --------------------------------------------
    absent: dict[str, set[str]] = {}
    live: dict[str, set[str]] = {}
    for effect in _records(sidecar, "host_side_effects"):
        touch = _EFFECT_TO_TOUCH.get(effect.get("effect"))
        stance = effect.get("stance")
        if touch is None or stance not in ("absent", "present", "conditional"):
            continue
        bucket = absent if stance == "absent" else live
        comps = effect.get("components")
        for comp in comps if isinstance(comps, list) else []:
            bucket.setdefault(comp, set()).add(touch)
    touch_bad: list[str] = []
    for i, row in enumerate(json_components):
        name = row.get("name")
        # A present/conditional record beats a contradictory absent one; the
        # sidecar gate owns the contradiction itself.
        recorded_absent = absent.get(name, set()) - live.get(name, set())
        touches = row.get("touches")
        for touch in touches if isinstance(touches, list) else []:
            if touch in recorded_absent:
                touch_bad.append(f"components[{i}] {name}: touches {touch!r} "
                                 "but §1.5 records it absent")
    yield _f("JSON.touches-grounded", not touch_bad,
             "no touches value contradicts a §1.5 absent stance"
             if not touch_bad else f"ungrounded touches: {touch_bad}")

    # ---- JSON.commit-present ----------------------------------------------
    commit = report.get("commit")
    commit_ok = (isinstance(commit, str)
                 and _COMMIT.fullmatch(commit) is not None
                 and set(commit) != {"0"})
    yield _f("JSON.commit-present", commit_ok,
             "commit is a real hex sha" if commit_ok else
             f"commit {commit!r} is not a real hex sha (placeholders like "
             "all-zeros, HEAD, or unknown do not bind the model to a tree)")


def run_json_checks(report: dict, sidecar: dict, model: Model | None = None,
                    schema_path: str | Path | None = None) -> Report:
    out = Report()
    out.extend(check_json_report(report, sidecar, model, schema_path))
    return out


# --------------------------------------------------------------------------
# Projection: sidecar → threat-model.json starting point
# --------------------------------------------------------------------------
def project_from_sidecar(sidecar: dict, *, repository: str, commit: str,
                         date: str, description: str,
                         scope_subpath: str | None = None) -> dict:
    """Mechanically derive everything the sidecar can supply.

    Author-only fields (trust boundary prose, environment assumes/does_not,
    known-non-finding why_safe text, open questions) come back as empty or
    minimal and MUST be completed by the author. This is a starting point, not
    an output.
    """
    components = _records(sidecar, "components")
    in_comps = [c for c in components if c.get("scope") == "in"]
    out_comps = [c for c in components if c.get("scope") == "out"]
    entry_points = _records(sidecar, "entry_points")
    claimed = _records(sidecar, "properties_claimed")
    disclaimed = _records(sidecar, "properties_disclaimed")
    adversaries = _records(sidecar, "adversaries")

    def prov_fields(record: dict) -> dict:
        provenance, source = _collapse(record.get("provenance"))
        fields = {"provenance": provenance}
        if source:
            fields["source"] = source
        return fields

    # touches: present/conditional effects only. An absent stance produces
    # nothing — that is the whole point of the §1.5 inventory.
    touches: dict[str, set[str]] = {}
    for effect in _records(sidecar, "host_side_effects"):
        touch = _EFFECT_TO_TOUCH.get(effect.get("effect"))
        if touch and effect.get("stance") in ("present", "conditional"):
            comps = effect.get("components")
            for comp in comps if isinstance(comps, list) else []:
                touches.setdefault(comp, set()).add(touch)

    json_components = []
    trust_boundaries = []
    for c in in_comps:
        name = c.get("name")
        row = {
            "name": name,
            "entry_points": [ep.get("id") for ep in entry_points
                             if ep.get("component") == name and ep.get("id")],
            "touches": [t for t in _TOUCH_ORDER
                        if t in touches.get(name, set())],
            "in_scope": True,
        }
        row.update(prov_fields(c))
        json_components.append(row)
        # `boundary` is §1.4 prose; the author must write it. Its provenance
        # is likewise §1.4's, which this projection cannot see — the
        # component's record describes the component, not the boundary — so
        # the only honest claim here is inferred. The author upgrades it only
        # when §1.4 grounds the boundary in a documented/maintainer tag.
        boundary_row = {"component": name, "boundary": "",
                        "provenance": "inferred"}
        if c.get("reachability_precondition"):
            boundary_row["reachability_precondition"] = \
                c["reachability_precondition"]
        trust_boundaries.append(boundary_row)

    if out_comps:
        out_of_scope = []
        for c in out_comps:
            row = {"item": c.get("name"), "reason": c.get("reason") or ""}
            row.update(prov_fields(c))
            out_of_scope.append(row)
    else:
        out_of_scope = {"not_applicable": True,
                        "reason": "the model carves nothing out of scope"}

    # One JSON row per (entry point × parameter). The sidecar holds
    # controllability as a bool, so the projection emits yes/no only; a
    # `conditional` row is an authoring decision, not a mechanical one.
    json_entry_points = []
    for ep in entry_points:
        plist = ep.get("parameters")
        for p in plist if isinstance(plist, list) else []:
            if not isinstance(p, dict):
                continue
            row = {
                "entry_point": ep.get("id"),
                "parameter": p.get("name"),
                "attacker_controllable":
                    "yes" if p.get("attacker_controllable") else "no",
            }
            # `component` is optional in the schema but must be a string when
            # present; an entry point without one gets no key, not null.
            if ep.get("component"):
                row["component"] = ep["component"]
            if p.get("caller_must_enforce"):
                row["caller_must_enforce"] = p["caller_must_enforce"]
            row.update(prov_fields(p))
            json_entry_points.append(row)

    environment = {
        "assumes": [],            # §1.5/§1.10 prose; the author must write it
        "does_not": [],
        "provenance": _weakest(_environment_kinds(sidecar)),
    }

    json_adversaries = {
        "in_scope": [a.get("name") for a in adversaries
                     if a.get("scope") == "in" and a.get("name")],
        "out_of_scope": [a.get("name") for a in adversaries
                         if a.get("scope") == "out" and a.get("name")],
        "provenance": _weakest(_adversary_kinds(sidecar)),
    }

    properties_provided = []
    for p in claimed:
        symptoms = p.get("violation_symptoms")
        row = {
            "property": p.get("id"),
            "violation_symptom": ", ".join(
                str(s) for s in symptoms) if isinstance(symptoms, list) else "",
            # An unrecognized tier reads as security: the conservative side.
            "severity_tier": _TIER_TO_JSON.get(p.get("tier"), "security"),
        }
        if p.get("conditions"):
            row["conditions"] = p["conditions"]
        row.update(prov_fields(p))
        properties_provided.append(row)

    properties_not_provided = []
    for p in disclaimed:
        row = {
            "property": p.get("id"),
            "reason": p.get("conditions") or "",
            "false_friend": bool(p.get("false_friend")),
        }
        row.update(prov_fields(p))
        properties_not_provided.append(row)

    # goals of in-scope adversaries, first-seen order
    attack_classes: list[str] = []
    for a in adversaries:
        if a.get("scope") != "in":
            continue
        goals = a.get("goals")
        for goal in goals if isinstance(goals, list) else []:
            if isinstance(goal, str) and goal not in attack_classes:
                attack_classes.append(goal)

    responsibilities = [
        r["statement"] for r in _records(sidecar, "downstream_responsibilities")
        if isinstance(r.get("statement"), str) and r["statement"].strip()
    ]

    misuses = _records(sidecar, "known_misuses")
    if misuses:
        known_misuse = []
        for m in misuses:
            row = {"pattern": m.get("pattern") or "",
                   "why_unsafe": ""}      # author-only; the sidecar has no text
            if m.get("safer_alternative"):
                row["instead"] = m["safer_alternative"]
            known_misuse.append(row)
    else:
        known_misuse = {"not_applicable": True,
                        "reason": "the model records no known misuses"}

    # why_safe must name the components and symptom the JSON shape drops
    # (§3d); this scaffold carries the scope, the author supplies the reasoning.
    claimed_index = {p.get("id"): i for i, p in enumerate(claimed)}
    disclaimed_index = {p.get("id"): i for i, p in enumerate(disclaimed)}
    known_non_findings = []
    for item in _records(sidecar, "known_non_findings"):
        comps = entry_components(item)
        symptom = item.get("symptom") or ""
        row = {
            "reported_as": item.get("tool_pattern") or "",
            "why_safe": (f"Covers {', '.join(comps)}; discharges symptom "
                         f"'{symptom}'. The author must replace this with "
                         "the §1.15 reasoning."),
        }
        for ref in item.get("discharged_by") or []:
            if ref in claimed_index:
                row["cites"] = f"properties_provided[{claimed_index[ref]}]"
                break
            if ref in disclaimed_index:
                row["cites"] = \
                    f"properties_not_provided[{disclaimed_index[ref]}]"
                break
        if item.get("conditions"):
            row["suppression"] = item["conditions"]
        known_non_findings.append(row)

    flags = _records(sidecar, "build_flags")
    if flags:
        build_variants = []
        for b in flags:
            effects = [
                f"{e['effect']} {e['property_id']}"
                for e in (b.get("affects_properties")
                          if isinstance(b.get("affects_properties"), list)
                          else [])
                if isinstance(e, dict) and e.get("effect")
                and e.get("property_id")
            ]
            row = {
                "name": b.get("name") or "",
                "default": str(b.get("default", "")),
                "effect": "; ".join(effects)
                          or "no effect on claimed properties",
                "discouraged": b.get("maintainer_stance")
                               in ("discouraged", "unsupported"),
            }
            row.update(prov_fields(b))
            build_variants.append(row)
    else:
        build_variants = {"not_applicable": True,
                          "reason": "the model records no build variants"}

    conf = sidecar.get("confidence")
    confidence = None
    if isinstance(conf, dict):
        def _n(key) -> int:
            value = conf.get(key)
            return value if type(value) is int and value >= 0 else 0
        confidence = {"documented": _n("documented") + _n("maintainer"),
                      "inferred": _n("inferred") + _n("assumption")}

    report = {
        "spec_version": 1,
        "repository": repository,
        "commit": commit,
        "date": date,
        "scope_subpath": scope_subpath,
        "description": description,
    }
    if confidence is not None:
        report["confidence"] = confidence
    report.update({
        "components": json_components,
        "out_of_scope": out_of_scope,
        "trust_boundaries": trust_boundaries,
        "entry_points": json_entry_points,
        "environment": environment,
        "build_variants": build_variants,
        "adversaries": json_adversaries,
        "properties_provided": properties_provided,
        "properties_not_provided": properties_not_provided,
    })
    if attack_classes:
        report["attack_classes"] = attack_classes
    report.update({
        "downstream_responsibilities": responsibilities,
        "known_misuse": known_misuse,
        "known_non_findings": known_non_findings,
        "dispositions": list(JSON_DISPOSITIONS),
        "open_questions": [],     # §1.18 prose; the author must write them
    })
    return report
