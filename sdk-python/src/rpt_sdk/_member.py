"""Changing one member of a record without re-encoding the rest."""

from __future__ import annotations

import json
from typing import Any, TypeVar

from ._stream import _DECODER, Error, strict_loads

_WS = " \t\n\r"

T = TypeVar("T", bytes, str)


def dumps(value: Any) -> str:
    """``value`` as compact JSON, object members sorted, as rpt writes a value."""
    from ._records import Wire

    def default(o: Any) -> Any:
        if isinstance(o, Wire):
            return o.to_dict()
        raise TypeError(f"{type(o).__name__} is not JSON")

    return json.dumps(
        value, separators=(",", ":"), ensure_ascii=False, sort_keys=True, allow_nan=False, default=default
    )


def set_member(raw: T, name: str, value: Any) -> T:
    """Returns the JSON object ``raw`` with its member ``name`` set to ``value``.

    Every other member keeps its original text and position; an existing member is replaced
    where it stands, a new one is appended. Filters use it to change one field of a record
    without re-encoding the rest. It returns ``bytes`` for ``bytes`` and ``str`` for ``str``,
    and raises :class:`Error` when ``raw`` is not one JSON object.

    >>> set_member(b'{"kind":"finding", "id":"F-001"}', "x-tag-label", "triaged")
    b'{"kind":"finding","id":"F-001","x-tag-label":"triaged"}'
    """
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    try:
        if not isinstance(strict_loads(text), dict):
            raise ValueError("not a JSON object")
    except ValueError as e:
        raise Error(f"set {name!r}: {e}") from None
    member = f"{json.dumps(name, ensure_ascii=False)}:{dumps(value)}"

    pos = _skip(text, 0) + 1  # past the {
    members: list[str] = []
    found = False
    while True:
        pos = _skip(text, pos)
        if text[pos] == "}":
            break
        key, end = _DECODER.raw_decode(text, pos)
        raw_key = text[pos:end]
        pos = _skip(text, _skip(text, end) + 1)  # past the :
        _, end = _DECODER.raw_decode(text, pos)
        raw_value = text[pos:end]
        if key == name and not found:
            found = True
            members.append(member)
        else:
            members.append(f"{raw_key}:{raw_value}")
        pos = _skip(text, end)
        if text[pos] == ",":
            pos += 1
    if not found:
        members.append(member)
    out = "{" + ",".join(members) + "}"
    return out.encode("utf-8") if isinstance(raw, bytes) else out


def _skip(text: str, pos: int) -> int:
    while pos < len(text) and text[pos] in _WS:
        pos += 1
    return pos
