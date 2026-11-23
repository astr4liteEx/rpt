"""Calling back into rpt, reading settings, and writing records."""

from __future__ import annotations

import copy
import io
import json
import subprocess
from dataclasses import dataclass, field
from typing import IO, Any

from ._plugin import rpt_bin
from ._records import Problem, Wire
from ._stream import Error, LineError, Rec, records


class BadOutput(Error):
    """rpt printed something that isn't records."""


class SettingsError(Error):
    """The plugin's settings couldn't be read."""


def emit(stream: IO[bytes] | IO[str], record: Wire | dict[str, Any]) -> None:
    """Writes ``record`` as one record: one JSON line. This package's record types write their
    kind when ``kind`` is empty. ``stream`` may be binary or text."""
    data = record.to_dict() if isinstance(record, Wire) else record
    line = json.dumps(data, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
    if isinstance(stream, io.TextIOBase):
        stream.write(line)
    else:
        stream.write(line.encode())  # type: ignore[arg-type]


@dataclass
class Result:
    """What one rpt command printed and how it exited."""

    #: stdout, record by record.
    records: list[Rec] = field(default_factory=list)
    #: The exit code: 0 ok, 1 problems, 2 usage, 3 couldn't do its work; -1 for a signal.
    code: int = 0
    #: The text rpt wrote for people.
    stderr: str = ""

    def problems(self) -> list[Problem]:
        """The problem records among the records."""
        return [Problem.from_json(r.raw) for r in self.records if r.kind == "problem"]

    def stale(self) -> bool:
        """Whether a write was refused because something changed since it was read (rule
        ``rev``): read again and decide again. rpt never retries on its own."""
        return any(p.rule == "rev" for p in self.problems())


def call(*args: str, stdin: bytes | str | None = None, timeout: float | None = None) -> Result:
    """Runs :func:`rpt_bin` with ``args``, feeding it ``stdin`` (none when None), and returns
    what it printed::

        res = rpt_sdk.call("finding", "get", "F-001")

    A command that runs and exits non-zero is a :class:`Result` with that code, not an error.
    An rpt that can't be started raises OSError; one that runs past ``timeout`` seconds is
    killed and raises ``subprocess.TimeoutExpired``; output that isn't records raises
    :class:`BadOutput`.
    """
    data = stdin.encode() if isinstance(stdin, str) else stdin
    proc = subprocess.run(
        [rpt_bin(), *args],
        input=data,
        stdin=subprocess.DEVNULL if data is None else None,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    res = Result(code=proc.returncode if proc.returncode >= 0 else -1, stderr=proc.stderr.decode(errors="replace"))
    for item in records(io.BytesIO(proc.stdout)):
        if isinstance(item, LineError):
            raise BadOutput(f"rpt {' '.join(args)}: {item}")
        res.records.append(item)
    return res


def settings(plugin: str, defaults: dict[str, Any] | None = None) -> dict[str, Any]:
    """The plugin's settings over ``defaults``: the user's
    ``~/.config/rpt/plugins/<plugin>/config.yaml`` with the report's ``x-<plugin>`` section of
    rpt.yaml laid over it, as ``rpt config get --merged`` gives them, laid over ``defaults``
    the same way (objects merge member by member; lists and plain values are replaced).
    Members neither sets keep their defaults; parse flags after, so they win. ``plugin`` is
    the command name, as in ``rpt <plugin>``. Raises :class:`SettingsError`."""
    member = f"x-{plugin}"
    merged = copy.deepcopy(defaults) if defaults is not None else {}
    res = call("config", "get", "--merged", "--json", member)
    if res.code != 0:
        problems = res.problems()
        why = problems[0].message if problems else f"rpt config get exited {res.code}: {res.stderr.strip()}"
        raise SettingsError(f"settings: {why}")
    for rec in res.records:
        if rec.kind != "config":
            continue
        value = rec.json().get(member)
        if value is None:
            return merged  # nothing set: the defaults stand
        if not isinstance(value, dict):
            raise SettingsError(f"settings: {member}: got {type(value).__name__}, want an object")
        _merge(merged, value)
        return merged
    return merged


def _merge(base: dict[str, Any], over: dict[str, Any]) -> None:
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
