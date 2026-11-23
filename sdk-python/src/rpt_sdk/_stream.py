"""Reading a JSON Lines stream of records."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import IO, Any

#: The longest JSON Lines record rpt reads, in bytes.
MAX_LINE = 16 << 20


class Error(Exception):
    """Base class of this package's errors."""


@dataclass(frozen=True)
class Rec:
    """One record read from a JSON Lines stream."""

    #: The record's ``kind``, or ``""`` when it has none.
    kind: str
    #: The line exactly as received, without its line ending.
    raw: bytes
    #: 1-based line number in the stream.
    line: int

    def json(self) -> dict[str, Any]:
        """The record, decoded."""
        data: dict[str, Any] = json.loads(self.raw)
        return data


class LineError(Error):
    """A line that is not a record: invalid JSON, JSON that is not an object, or a line
    longer than :data:`MAX_LINE`. :func:`records` yields it and keeps reading."""

    def __init__(self, line: int, reason: str) -> None:
        super().__init__(f"line {line}: {reason}")
        self.line = line
        #: What is wrong, e.g. ``not a record: null``.
        self.reason = reason

    def __eq__(self, other: object) -> bool:
        return isinstance(other, LineError) and (self.line, self.reason) == (other.line, other.reason)

    def __hash__(self) -> int:
        return hash((self.line, self.reason))


class Stopped(Error):
    """Raised by :func:`records` with ``stop_at_error=True`` at the first error-level problem
    record, :attr:`rec`. Nothing comes after it: pass it on, write nothing of your own, and
    exit 1."""

    def __init__(self, rec: Rec) -> None:
        super().__init__(f"line {rec.line}: stopped at an error-level problem")
        self.rec = rec


def records(stream: IO[bytes], *, stop_at_error: bool = False) -> Iterator[Rec | LineError]:
    """Reads a JSON Lines stream, such as ``sys.stdin.buffer``.

    It yields each record as a :class:`Rec` with its original bytes, so filters can pass
    through records they don't own byte for byte. Blank lines are skipped; lines may end in
    ``\\n`` or ``\\r\\n``, and the last line needs no newline. A line that isn't a record
    yields a :class:`LineError` and reading continues.

    With ``stop_at_error``, it raises :class:`Stopped` at the first error-level problem
    record. A writer or renderer reads this way, since it must not act on a stream an earlier
    stage found broken. Filters and checkers read on and pass problems through.
    """
    n = 0
    while True:
        n += 1
        line = stream.readline(MAX_LINE + 3)  # +2 for a \r\n ending, +1 to see past it
        if not line:
            return
        if isinstance(line, str):  # a text stream, given anyway
            line = line.encode()
        last = not line.endswith(b"\n")
        if last and len(line) == MAX_LINE + 3:
            while True:  # discard the rest of the line
                more = stream.readline(64 << 10)
                if not more or more.endswith(b"\n" if isinstance(more, bytes) else "\n"):
                    break
            yield LineError(n, f"line longer than {MAX_LINE} bytes")
            continue
        line = line.removesuffix(b"\n").removesuffix(b"\r")
        if len(line) > MAX_LINE:
            yield LineError(n, f"line longer than {MAX_LINE} bytes")
            continue
        if not line.strip():
            continue
        try:
            data = strict_loads(line)
        except ValueError as e:
            yield LineError(n, f"not a record: {e}")
            continue
        if data is None:
            yield LineError(n, "not a record: null")
            continue
        if not isinstance(data, dict):
            yield LineError(n, "not a record: not a JSON object")
            continue
        kind = data.get("kind")
        rec = Rec(kind if isinstance(kind, str) else "", line, n)
        if stop_at_error and rec.kind == "problem" and data.get("level") == "error":
            raise Stopped(rec)
        yield rec


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in pairs:
        if name in out:
            raise ValueError(f"duplicate object member name {name!r}")
        out[name] = value
    return out


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


#: Decodes JSON as rpt does: UTF-8, no NaN or Infinity, no member name twice in one object.
_DECODER = json.JSONDecoder(object_pairs_hook=_no_duplicates, parse_constant=_no_constant)


def strict_loads(text: bytes | str) -> Any:
    """Decodes one JSON value as rpt does; a ValueError says what is wrong."""
    if isinstance(text, bytes):
        text = text.decode("utf-8")  # UnicodeDecodeError is a ValueError
    return _DECODER.decode(text)
