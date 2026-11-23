"""The plugin entry points."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import IO, NoReturn

from ._records import Description

#: A plugin's work: ``run(args, stdin, stdout, stderr)`` returns the exit code.
RunFunc = Callable[[list[str], IO[bytes], IO[bytes], IO[str]], int]
#: ``complete(args, word)``: the candidates for ``word``, each "value" or "value\tdescription".
CompleteFunc = Callable[[list[str], str], Sequence[str]]

# Shell completion directives, as cobra's __complete protocol ends its answer with
# ":<directive>".
_COMPLETE_DEFAULT = 0  # the shell may fall back to file names
_COMPLETE_NO_FILES = 4  # only the candidates given


@dataclass
class Plugin:
    """A plugin program: its description and the function that does its work.

    ``run`` gets the arguments after the command, its stdin and stdout as binary streams (so
    records pass through byte for byte) and stderr as text, and returns the exit code: 0
    success, 1 problems in the input, 2 usage, 3 the plugin couldn't do its work.

    ``complete``, if set, gives shell completion its candidates for the word being typed;
    unset, the shell completes file names.
    """

    description: Description
    run: RunFunc
    complete: CompleteFunc | None = None


def run(plugin: Plugin, args: Sequence[str], stdin: IO[bytes], stdout: IO[bytes], stderr: IO[str]) -> int:
    """Runs a plugin. It answers these itself, doing no work:

    - a lone ``--describe``: the description, one JSON line;
    - a lone ``--help`` or ``-h``: the usage and summary;
    - ``__complete <args...> <word>``: shell completion, from ``plugin.complete``.

    Anything else goes to ``plugin.run``. It never exits and never touches the process's
    streams, so plugin tests call it directly.
    """
    args = list(args)
    d = plugin.description
    if args in (["--help"], ["-h"]):
        text = f"Usage: {d.usage}\n\n{d.summary}\n" if d.usage else f"{d.summary}\n"
        stdout.write(text.encode())
        stdout.flush()
        return 0
    if args and args[0] in ("__complete", "__completeNoDesc"):
        rest, word = (args[1:-1], args[-1]) if len(args) > 1 else ([], "")
        out = ""
        directive = _COMPLETE_DEFAULT
        if plugin.complete is not None:
            for c in plugin.complete(rest, word):
                out += (c.split("\t", 1)[0] if args[0] == "__completeNoDesc" else c) + "\n"
            directive = _COMPLETE_NO_FILES
        stdout.write(f"{out}:{directive}\n".encode())
        stdout.flush()
        return 0
    if args == ["--describe"]:
        try:
            line = json.dumps(d.to_dict(), separators=(",", ":"), ensure_ascii=False, allow_nan=False)
            stdout.write(line.encode() + b"\n")
            stdout.flush()
        except (TypeError, ValueError, OSError) as e:
            print(f"describe: {e}", file=stderr)
            return 1
        return 0
    return plugin.run(args, stdin, stdout, stderr)


def main(plugin: Plugin) -> NoReturn:
    """The whole of a plugin's main: ``rpt_sdk.main(plugin)``.

    It calls :func:`run` with the process's arguments and streams, flushes stdout, and exits
    with the code it returns. Arguments arrive byte for byte: one that isn't UTF-8 holds
    surrogate escapes, which ``os.fsencode`` turns back into its bytes. When whatever reads
    stdout goes away (a broken pipe), it exits 1 without a traceback.
    """
    try:
        code = run(plugin, sys.argv[1:], sys.stdin.buffer, sys.stdout.buffer, sys.stderr)
        sys.stdout.flush()
    except BrokenPipeError:
        # Python flushes stdout again at exit; point it somewhere that takes the bytes.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        code = 1
    sys.exit(code)


def rpt_bin() -> str:
    """The rpt to call back into: ``$RPT_BIN`` when rpt started the plugin, so it gets the
    same rpt version, otherwise ``rpt`` from ``PATH``. A plugin never requires being started
    by rpt."""
    return os.environ.get("RPT_BIN") or "rpt"
