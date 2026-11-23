"""call against shell scripts standing in for rpt: how it's started, and what outlives it."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import rpt_sdk as sdk


def stand_in(dir: Path, body: str) -> Path:
    p = dir / "rpt"
    p.write_text(f"#!/bin/sh\n{body}\n")
    p.chmod(0o755)
    return p


def pid_in(file: Path) -> int:
    for _ in range(200):
        if file.exists() and file.read_text().strip():
            return int(file.read_text())
        time.sleep(0.01)
    raise AssertionError("the stand-in never wrote its child's pid")


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@unittest.skipUnless(os.name == "posix", "POSIX shell stand-ins")
class Call(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def test_runs_the_rpt_it_is_given(self) -> None:
        bin = stand_in(
            self.dir, """printf '{"kind":"x-env","dir":"%s","x":"%s","home":"%s"}\\n' "$(pwd)" "$X" "${HOME-unset}" """
        )
        work = self.dir / "work"
        work.mkdir()
        res = sdk.call(bin=bin, cwd=work, env={"X": "1"})
        self.assertEqual(
            [r.json() for r in res.records], [{"kind": "x-env", "dir": str(work), "x": "1", "home": "unset"}]
        )

    def test_process_group_kills_what_rpt_started(self) -> None:
        pids = self.dir / "pid"
        bin = stand_in(self.dir, f"sleep 30 &\necho $! > {pids}\nwait")
        start = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            sdk.call("scope", "get", bin=bin, process_group=True, timeout=0.3)
        self.assertLess(time.monotonic() - start, 2)
        pid = pid_in(pids)
        for _ in range(200):
            if not alive(pid):
                break
            time.sleep(0.01)
        self.assertFalse(alive(pid), "the plugin's child outlived the call")

    def test_returns_when_something_rpt_started_holds_the_pipes(self) -> None:
        pids = self.dir / "pid"
        bin = stand_in(self.dir, f'sleep 30 &\necho $! > {pids}\necho \'{{"kind":"x"}}\'')
        start = time.monotonic()
        res = sdk.call(bin=bin)
        os.kill(pid_in(pids), 9)
        self.assertEqual((res.code, len(res.records)), (0, 1))
        self.assertLess(time.monotonic() - start, 5)

    def test_stdin_and_exit_code(self) -> None:
        bin = stand_in(self.dir, "cat\nexit 3")
        res = sdk.call(bin=bin, stdin='{"kind":"note"}\n')
        self.assertEqual((res.code, [r.kind for r in res.records]), (3, ["note"]))


if __name__ == "__main__":
    unittest.main()
