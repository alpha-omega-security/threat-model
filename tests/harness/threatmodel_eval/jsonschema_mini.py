"""Validate `threat-model.json` against `schema.json` without a dependency.

The harness runs on stdlib + PyYAML only (``tests/harness/requirements.txt``)
and ``jsonschema`` is not on that list. Pulling in a full draft-2020-12
implementation to check one document is a heavier change than covering the
keyword subset ``schema.json`` actually uses, which is small and stable: local
``#/$defs/`` refs, type/required/properties, closed objects, enum/const/oneOf,
array bounds, one pattern, and two formats.

Anything outside that subset is treated as an error, not silently skipped —
a keyword this file does not implement would otherwise pass everything, which
is the worst possible failure mode for a validator. If the schema grows a
keyword, grow this file with it.

Errors are collected rather than raised: an author fixing a wrong-shaped
document needs the whole list, pathed and sorted, not the first complaint.
"""
from __future__ import annotations

import re
from datetime import date

# Past a screenful the list stops being read; a document with the wrong
# overall shape can fail hundreds of leaf checks.
_MAX_ERRORS = 40

# Strict calendar date. `format` is annotation-only in draft 2020-12, but a
# threat model dated 2026-13-01 is a real authoring mistake worth catching.
_DATE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")

# Lenient URI: a scheme, a colon, and at least one non-space character.
# Enough to catch "github.com/madler/zlib" (no scheme) without rejecting
# unusual-but-real forms like urn: or git+ssh: URLs.
_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:\S+$")

# Keywords this validator implements, plus the ones that carry no validation
# semantics for an instance. Anything else in the schema is reported.
_HANDLED = {
    "$ref", "$defs", "type", "required", "properties", "additionalProperties",
    "items", "enum", "const", "oneOf", "minItems", "maxItems", "minimum",
    "uniqueItems", "pattern", "format",
    # annotation-only: nothing to check
    "contentMediaType", "title", "description", "$schema",
}


def _show(value) -> str:
    """A repr short enough to keep one error on one line."""
    text = repr(value)
    return text if len(text) <= 60 else text[:57] + "..."


def _show_enum(values: list) -> str:
    inner = ", ".join(repr(v) for v in values[:6])
    return "[" + inner + (", ...]" if len(values) > 6 else "]")


def _canon(value):
    """A hashable key under JSON equality, where true != 1 but 1 == 1.0.

    Python's ``==`` says ``True == 1``, which would let a boolean sneak past
    an integer enum or make [true, 1] look like a uniqueItems violation.
    """
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, (int, float)):
        return ("num", float(value))
    if isinstance(value, str):
        return ("str", value)
    if value is None:
        return ("null",)
    if isinstance(value, list):
        return ("arr", tuple(_canon(v) for v in value))
    if isinstance(value, dict):
        return ("obj", tuple(sorted((k, _canon(v)) for k, v in value.items())))
    return ("other", repr(value))                     # pragma: no cover


def _type_ok(value, name: str) -> bool:
    # bool is a subclass of int in Python; JSON keeps them distinct, so an
    # `integer` or `number` must reject True/False explicitly.
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    return False


def _deref(ref: str, root: dict):
    """Follow a local ``#/...`` pointer; None if it does not resolve."""
    if not ref.startswith("#/"):
        return None
    node = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _valid_date(text: str) -> bool:
    m = _DATE.match(text)
    if not m:
        return False
    try:
        date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return False
    return True


def _scan_unknown(node, pointer: str, out: list[str]) -> None:
    """Find schema keywords this validator does not implement.

    Keys under ``properties`` and ``$defs`` are names, not keywords, so the
    walk has to know where it is; a flat key sweep would flag every property.
    """
    if not isinstance(node, dict):
        return
    for key, sub in node.items():
        here = f"{pointer}/{key}"
        if key in ("properties", "$defs"):
            if isinstance(sub, dict):
                for name, subschema in sub.items():
                    _scan_unknown(subschema, f"{here}/{name}", out)
        elif key in ("items", "additionalProperties"):
            _scan_unknown(sub, here, out)
        elif key == "oneOf":
            if isinstance(sub, list):
                for i, branch in enumerate(sub):
                    _scan_unknown(branch, f"{here}/{i}", out)
        elif key not in _HANDLED:
            out.append(f"$: schema uses unimplemented keyword {key!r} at {here}")


def _validate(value, schema, path: str, root: dict, errors: list[str],
              active_refs: tuple = ()) -> None:
    if not isinstance(schema, dict):
        return  # bare true/false schemas do not occur in schema.json

    ref = schema.get("$ref")
    if ref is not None:
        if ref in active_refs:
            # Only a broken schema can do this, and the alternative is an
            # infinite loop, so say so and stop following.
            errors.append(f"{path}: circular $ref {ref!r}")
        else:
            target = _deref(ref, root)
            if target is None:
                errors.append(f"{path}: unresolvable $ref {ref!r}")
            else:
                _validate(value, target, path, root, errors,
                          active_refs + (ref,))
        # 2020-12 lets other keywords sit beside $ref, so fall through.

    if "type" in schema:
        names = schema["type"]
        names = [names] if isinstance(names, str) else names
        if not any(_type_ok(value, n) for n in names):
            wanted = " or ".join(f"'{n}'" for n in names)
            errors.append(f"{path}: {_show(value)} is not of type {wanted}")

    if "enum" in schema:
        if _canon(value) not in {_canon(v) for v in schema["enum"]}:
            errors.append(
                f"{path}: {_show(value)} is not one of "
                f"{_show_enum(schema['enum'])}")

    if "const" in schema:
        if _canon(value) != _canon(schema["const"]):
            errors.append(
                f"{path}: {_show(value)} is not the constant "
                f"{schema['const']!r}")

    if "oneOf" in schema:
        branches = schema["oneOf"]
        matched: list[int] = []
        failures: list[tuple[int, list[str]]] = []
        for i, branch in enumerate(branches):
            sub: list[str] = []
            _validate(value, branch, path, root, sub, active_refs)
            if sub:
                failures.append((i, sub))
            else:
                matched.append(i)
        if not matched:
            # "no branch matched" alone is useless to an author; say why
            # each form was rejected, trimmed so one bad row stays one line.
            parts = []
            for i, sub in failures:
                shown = "; ".join(sub[:3])
                if len(sub) > 3:
                    shown += f"; +{len(sub) - 3} more"
                parts.append(f"[form {i + 1}] {shown}")
            errors.append(
                f"{path}: matches none of the {len(branches)} allowed forms "
                f"— {' | '.join(parts)}")
        elif len(matched) > 1:
            errors.append(
                f"{path}: matches {len(matched)} oneOf forms, "
                f"expected exactly one")

    if isinstance(value, dict):
        for name in schema.get("required", ()):
            if name not in value:
                errors.append(f"{path}: required property {name!r} is missing")
        props = schema.get("properties", {})
        for name, subschema in props.items():
            if name in value:
                _validate(value[name], subschema, f"{path}.{name}",
                          root, errors)
        extra = schema.get("additionalProperties")
        if extra is False:
            for name in value:
                if name not in props:
                    errors.append(f"{path}.{name}: unexpected property")
        elif isinstance(extra, dict):                 # unused today; cheap
            for name in value:
                if name not in props:
                    _validate(value[name], extra, f"{path}.{name}",
                              root, errors)

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(
                f"{path}: has {len(value)} items, "
                f"needs at least {schema['minItems']}")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(
                f"{path}: has {len(value)} items, "
                f"allows at most {schema['maxItems']}")
        if schema.get("uniqueItems"):
            seen: dict = {}
            dups = []
            for i, item in enumerate(value):
                key = _canon(item)
                if key in seen:
                    dups.append(f"{seen[key]} and {i}")
                else:
                    seen[key] = i
            if dups:
                errors.append(
                    f"{path}: duplicate items at positions "
                    + ", ".join(dups))
        if "items" in schema:
            for i, item in enumerate(value):
                _validate(item, schema["items"], f"{path}[{i}]", root, errors)

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(
                f"{path}: {value!r} is less than the minimum of "
                f"{schema['minimum']}")

    if isinstance(value, str):
        if "pattern" in schema:
            # JSON Schema patterns are unanchored; schema.json anchors its
            # own with ^...$ where it matters.
            if not re.search(schema["pattern"], value):
                errors.append(
                    f"{path}: {value!r} does not match "
                    f"{schema['pattern']!r}")
        fmt = schema.get("format")
        if fmt == "date":
            if not _valid_date(value):
                errors.append(
                    f"{path}: {value!r} is not a real YYYY-MM-DD date")
        elif fmt == "uri":
            if not _URI.match(value):
                errors.append(
                    f"{path}: {value!r} is not a URI (expected scheme:...)")
        elif fmt is not None:
            errors.append(
                f"{path}: format {fmt!r} is not implemented by this "
                f"validator")


# Splits "$.components[3].touches" into its property and index segments so
# errors sort in document order — a plain string sort puts [10] before [2].
_SEGMENT = re.compile(r"\.([^.\[\]]+)|\[(\d+)\]")


def _path_key(error: str):
    path = error.split(": ", 1)[0]
    key = []
    for name, idx in _SEGMENT.findall(path):
        key.append((1, "", int(idx)) if idx else (0, name, 0))
    return key


def validate_instance(instance, schema: dict) -> list[str]:
    """Return human-readable error strings; empty list means valid.

    Each error is "<json-path>: <problem>", e.g.
      $.components[0].touches[1]: 'sockets' is not one of ['filesystem', ...]
      $.commit: 'HEAD' does not match '^[0-9a-f]{7,40}$'
      $: required property 'entry_points' is missing
    """
    errors: list[str] = []
    _scan_unknown(schema, "#", errors)
    _validate(instance, schema, "$", schema, errors)
    errors.sort(key=_path_key)
    if len(errors) > _MAX_ERRORS:
        hidden = len(errors) - _MAX_ERRORS
        errors = errors[:_MAX_ERRORS] + [f"+{hidden} more error(s) not shown"]
    return errors
