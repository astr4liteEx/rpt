"""Calling back into rpt, reading settings, and writing records."""

from __future__ import annotations

import copy
import io
import json
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
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
    #: The exit code: 0 ok, 1 problems, 2 usage, 3 couldn't do its work; -1 for a signal. From
    #: one of rpt's own write commands, 3 means a file changed while it wrote and nothing was
    #: written, so running it again is safe; from a plugin, 3 means its work failed, perhaps
    #: partway, so it isn't. call never retries: only the caller knows which it ran.
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


#: How long call keeps reading rpt's output after rpt has exited, while something rpt started
#: holds the pipes open.
WAIT_DELAY = 1.0


def call(
    *args: str,
    stdin: bytes | str | None = None,
    timeout: float | None = None,
    bin: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    process_group: bool = False,
) -> Result:
    """Runs :func:`rpt_bin` with ``args``, feeding it ``stdin`` (none when None), and returns
    what it printed::

        res = rpt_sdk.call("finding", "get", "F-001")

    A command that runs and exits non-zero is a :class:`Result` with that code, not an error.
    An rpt that can't be started raises OSError; one that runs past ``timeout`` seconds is
    killed and raises ``subprocess.TimeoutExpired``; output that isn't records raises
    :class:`BadOutput`.

    A program that runs rpt itself rather than being started by it (an editor, a TUI, CI
    tooling) says how: ``bin`` is the rpt to run, ``cwd`` the folder, and ``env`` its whole
    environment (None: this process's). ``process_group`` starts rpt in a process group of its
    own and at the timeout kills the whole group: rpt, the plugin it became, and what that
    started, which would otherwise outlive the call. The group is out of the terminal's reach,
    so Ctrl-C no longer stops it: use it in a program that handles keys itself, not in a plugin,
    whose rpt must stop when the user stops the pipeline. POSIX only; elsewhere it is ignored.
    """
    data = stdin.encode() if isinstance(stdin, str) else stdin
    group = process_group and os.name == "posix"
    proc = subprocess.Popen(
        [os.fspath(bin) if bin is not None else rpt_bin(), *args],
        stdin=subprocess.DEVNULL if data is None else subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=None if env is None else dict(env),
        start_new_session=group,
    )

    def kill() -> None:
        if group:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            proc.kill()
        proc.wait()

    out, err = _communicate(proc, data, timeout, kill)
    res = Result(code=proc.returncode if proc.returncode >= 0 else -1, stderr=err.decode(errors="replace"))
    for item in records(io.BytesIO(out)):
        if isinstance(item, LineError):
            raise BadOutput(f"rpt {' '.join(args)}: {item}")
        res.records.append(item)
    return res


def _communicate(
    proc: subprocess.Popen[bytes], data: bytes | None, timeout: float | None, kill: Callable[[], None]
) -> tuple[bytes, bytes]:
    """rpt's output: read until the pipes close, for WAIT_DELAY at most after rpt exits, or
    until the timeout when that comes first. Past the timeout, kill and raise TimeoutExpired."""
    chunks: dict[str, list[bytes]] = {"out": [], "err": []}

    def read(name: str, pipe: IO[bytes]) -> None:
        for chunk in iter(lambda: pipe.read1(64 << 10), b""):  # type: ignore[attr-defined]
            chunks[name].append(chunk)

    readers = [
        threading.Thread(target=read, args=("out", proc.stdout), daemon=True),
        threading.Thread(target=read, args=("err", proc.stderr), daemon=True),
    ]
    for r in readers:
        r.start()
    if data is not None and proc.stdin is not None:

        def feed(pipe: IO[bytes]) -> None:
            try:
                pipe.write(data)
                pipe.close()
            except OSError:
                pass  # rpt stopped reading; its exit code says why

        threading.Thread(target=feed, args=(proc.stdin,), daemon=True).start()
    deadline = None if timeout is None else time.monotonic() + timeout
    try:
        proc.wait(timeout)
    except subprocess.TimeoutExpired:
        kill()
        raise
    limit = time.monotonic() + WAIT_DELAY
    if deadline is not None:
        limit = min(limit, deadline)
    for r in readers:
        r.join(max(0.0, limit - time.monotonic()))
    if any(r.is_alive() for r in readers) and deadline is not None and deadline <= limit:
        kill()
        raise subprocess.TimeoutExpired(proc.args, timeout or 0)
    return b"".join(chunks["out"]), b"".join(chunks["err"])


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
