"""The conformance cases in ../testdata/sdk, shared by every SDK; see the README there."""

from __future__ import annotations

import io
import json
import unittest
from pathlib import Path
from typing import Any

import rpt_sdk as sdk

CASES = Path(__file__).resolve().parents[2] / "testdata" / "sdk"

TYPES: dict[str, type[sdk.Wire]] = {
    "finding": sdk.Finding,
    "page": sdk.Page,
    "scope": sdk.ScopeRow,
    "config": sdk.Config,
    "evidence": sdk.Evidence,
    "problem": sdk.Problem,
    "report": sdk.Report,
    "location": sdk.Location,
    "command": sdk.Command,
    "version": sdk.Version,
    "description": sdk.Description,
}


def load(name: str) -> Any:
    path = CASES / name
    if not path.exists():
        raise unittest.SkipTest("needs the rpt repository's testdata/sdk folder")
    return json.loads(path.read_text(encoding="utf-8"))


def rec_json(r: sdk.Rec) -> dict[str, Any]:
    return {"kind": r.kind, "raw": r.raw.decode(), "line": r.line}


class Conformance(unittest.TestCase):
    def test_stream(self) -> None:
        for c in load("stream.json"):
            with self.subTest(c["name"]):
                got: list[dict[str, Any]] = []
                try:
                    for item in sdk.records(
                        io.BytesIO(c["input"].encode()), stop_at_error=c.get("stop_at_error", False)
                    ):
                        if isinstance(item, sdk.LineError):
                            got.append({"error_line": item.line})
                        else:
                            got.append(rec_json(item))
                except sdk.Stopped as s:
                    got.append({"stopped": rec_json(s.rec)})
                self.assertEqual(got, c["want"])

    def test_set_member(self) -> None:
        for c in load("set_member.json"):
            with self.subTest(c["name"]):
                if c.get("error"):
                    with self.assertRaises(sdk.Error):
                        sdk.set_member(c["in"], c["member"], c["value"])
                    continue
                self.assertEqual(sdk.set_member(c["in"], c["member"], c["value"]), c["want"])
                self.assertEqual(sdk.set_member(c["in"].encode(), c["member"], c["value"]), c["want"].encode())

    def test_round_trip(self) -> None:
        for c in load("round_trip.json"):
            with self.subTest(c["name"]):
                record = TYPES[c["type"]].from_dict(c["in"])
                out = io.BytesIO()
                sdk.emit(out, record)
                text = out.getvalue().decode()
                self.assertTrue(text.endswith("\n") and text.count("\n") == 1, text)
                self.assertEqual(json.loads(text), c.get("want", c["in"]))

    def test_run(self) -> None:
        suite = load("run.json")
        plugin = suite["plugin"]
        for c in suite["cases"]:
            with self.subTest(c["name"]):
                description = sdk.Description.from_dict(plugin["description"])
                if c.get("no_usage"):
                    description.usage = ""
                ran_with: list[list[str]] = []
                completed: list[tuple[list[str], str]] = []

                def work(args: list[str], stdin: Any, stdout: Any, stderr: Any) -> int:
                    ran_with.append(list(args))
                    return 7

                def complete(args: list[str], word: str) -> list[str]:
                    completed.append((list(args), word))
                    return list(plugin["complete"])

                p = sdk.Plugin(description, work, None if c.get("no_complete") else complete)
                out = io.BytesIO()
                code = sdk.run(p, c["args"], io.BytesIO(), out, io.StringIO())
                if c.get("runs"):
                    self.assertEqual((code, ran_with), (7, [c["args"]]))
                    continue
                self.assertEqual((code, ran_with), (0, []))
                text = out.getvalue().decode()
                if c.get("describe"):
                    self.assertTrue(text.endswith("\n") and text.count("\n") == 1, text)
                    self.assertEqual(json.loads(text), plugin["description"])
                elif "stdout" in c:
                    self.assertEqual(text, c["stdout"])
                if "complete_word" in c:
                    self.assertEqual(completed, [(c["complete_args"], c["complete_word"])])


if __name__ == "__main__":
    unittest.main()
