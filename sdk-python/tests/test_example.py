"""An example plugin using every helper, run against rpt built from this repository. Outside it
(the package on its own, or without Go) these tests skip."""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import IO
from unittest import mock

import rpt_sdk as sdk

REPO = Path(__file__).resolve().parents[2]
_tmp = tempfile.TemporaryDirectory(prefix="rpt-sdk-test-")
_rpt: Path | None = None


def setUpModule() -> None:
    global _rpt
    if not (REPO / "cmd" / "rpt").exists() or shutil.which("go") is None:
        return
    out = Path(_tmp.name) / "rpt"
    subprocess.run(["go", "build", "-o", str(out), "./cmd/rpt"], cwd=REPO, check=True, env={**os.environ, "GOWORK": ""})
    _rpt = out


def tearDownModule() -> None:
    _tmp.cleanup()


def work(args: list[str], stdin: IO[bytes], stdout: IO[bytes], stderr: IO[str]) -> int:
    """Tags each finding record on stdin with x-tag-label, from its settings (default
    "triaged"), and ends with a warning counting the report's scope rows."""
    try:
        settings = sdk.settings("tag", {"label": "triaged"})
    except sdk.Error as e:
        print(f"rpt-tag: {e}", file=stderr)
        return 1
    try:
        for item in sdk.records(stdin, stop_at_error=True):
            if isinstance(item, sdk.LineError):
                print(f"rpt-tag: -:{item.line}: {item.reason}", file=stderr)
                return 1
            raw = item.raw
            if item.kind == sdk.KIND_FINDING:
                raw = sdk.set_member(raw, "x-tag-label", settings["label"])
            stdout.write(raw + b"\n")
    except sdk.Stopped as s:
        stdout.write(s.rec.raw + b"\n")  # pass it on; write nothing of our own
        return 1
    res = sdk.call("scope", "get", timeout=30)
    if res.code != 0:
        print(f"rpt-tag: {res.stderr}", file=stderr)
        return 1
    sdk.emit(stdout, sdk.Problem(path=".", rule="tag", level=sdk.WARNING, message=f"{len(res.records)} scope rows"))
    return 0


TAG = sdk.Plugin(
    sdk.Description(
        summary="Tag findings with a label",
        usage="rpt tag < findings.jsonl",
        input="records",
        output="records",
        roles=[sdk.ROLE_FILTER],
        requires=sdk.Requires(schema_version=sdk.Range(min=2)),
        schemas=sdk.Schemas(finding={"x-tag-label": {"type": "string"}}),
    ),
    work,
    lambda args, word: ["--label\tthe label to set"],
)


class Example(unittest.TestCase):
    def setUp(self) -> None:
        if _rpt is None:
            self.skipTest("needs the rpt repository and Go")
        self.dir = Path(tempfile.mkdtemp(dir=_tmp.name)) / "r"
        shutil.copytree(REPO / "testdata" / "fixture", self.dir)
        env = mock.patch.dict(os.environ, {"RPT_BIN": str(_rpt), "RPT_REPORT_DIR": str(self.dir)})
        env.start()
        self.addCleanup(env.stop)

    def rpt(self, *args: str) -> None:
        assert _rpt is not None
        subprocess.run([str(_rpt), "--report", str(self.dir), *args], check=True, capture_output=True)

    def run_tag(self, stdin: bytes, *args: str) -> tuple[int, bytes, str]:
        out, err = io.BytesIO(), io.StringIO()
        code = sdk.run(TAG, list(args), io.BytesIO(stdin), out, err)
        return code, out.getvalue(), err.getvalue()

    def test_example_plugin(self) -> None:
        self.rpt("config", "set", "x-tag.label", "verified")
        code, out, err = self.run_tag(b'{"kind":"finding","id":"F-001"}\n{"kind":"note"}\n')
        want = (
            b'{"kind":"finding","id":"F-001","x-tag-label":"verified"}\n{"kind":"note"}\n'
            b'{"kind":"problem","path":".","rule":"tag","level":"warning","message":"3 scope rows"}\n'
        )
        self.assertEqual((code, out), (0, want), err)

    def test_stops_at_an_error(self) -> None:
        first = b'{"kind":"problem","path":"x","rule":"r","level":"error","message":"m"}\n'
        code, out, _ = self.run_tag(first + b'{"kind":"finding","id":"F-001"}\n')
        self.assertEqual((code, out), (1, first))

    def test_null_settings_keep_the_defaults(self) -> None:
        self.rpt("config", "set", "x-tag", "null")
        _, out, err = self.run_tag(b'{"kind":"finding","id":"F-001"}\n')
        self.assertIn(b'"x-tag-label":"triaged"', out, err)

    def test_call_stale(self) -> None:
        res = sdk.call("finding", "set", "--if-rev", "0000", "F-001", "title", "New")
        self.assertEqual((res.code, res.stale(), len(res.problems())), (1, True, 1), res)

    def test_call_feeds_stdin(self) -> None:
        res = sdk.call("validate", "-", stdin='{"kind":"note"}\n')
        self.assertEqual((res.code, len(res.records)), (0, 1), res)

    def test_call_times_out(self) -> None:
        hang = Path(_tmp.name) / "rpt-hang"
        hang.write_text("#!/bin/sh\nexec sleep 30\n")
        hang.chmod(0o755)
        with mock.patch.dict(os.environ, {"RPT_BIN": str(hang)}), self.assertRaises(subprocess.TimeoutExpired):
            sdk.call("scope", "get", timeout=0.2)

    def test_main_as_a_process(self) -> None:
        """The plugin run as a real program, through rpt, as users run it."""
        bindir = Path(tempfile.mkdtemp(dir=_tmp.name))
        script = bindir / "rpt-tag"
        src = REPO / "sdk-python" / "src"
        script.write_text(
            f"#!{sys.executable}\nimport sys\nsys.path.insert(0, {str(src)!r}); sys.path.insert(0, {str(Path(__file__).parent)!r})\n"
            "import rpt_sdk, test_example\nrpt_sdk.main(test_example.TAG)\n"
        )
        script.chmod(0o755)
        assert _rpt is not None
        env = {**os.environ, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"}
        env.pop("RPT_BIN")
        env.pop("RPT_REPORT_DIR")
        help_ = subprocess.run([str(_rpt), "help", "--json"], env=env, cwd=self.dir, capture_output=True, check=True)
        self.assertIn(b'"name":"tag","source":"plugin"', help_.stdout)
        got = subprocess.run(
            [str(_rpt), "tag"], input=b'{"kind":"finding","id":"F-001"}\n', env=env, cwd=self.dir, capture_output=True
        )
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertTrue(got.stdout.startswith(b'{"kind":"finding","id":"F-001","x-tag-label":"triaged"}\n'), got.stdout)


if __name__ == "__main__":
    unittest.main()
