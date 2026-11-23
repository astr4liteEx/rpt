"""What the conformance cases can't hold: long lines, and decoding typed records."""

from __future__ import annotations

import io
import unittest

import rpt_sdk as sdk


class LongLines(unittest.TestCase):
    def test_long_lines(self) -> None:
        mib = b'{"kind":"finding","title":"' + b"a" * (1 << 20) + b'"}'
        huge = b'{"kind":"finding","title":"' + b"b" * sdk.MAX_LINE + b'"}'
        got = list(sdk.records(io.BytesIO(mib + b"\n" + huge + b'\n{"kind":"scope"}\n' + huge)))
        self.assertEqual(len(got), 4)
        self.assertEqual((got[0].kind, len(got[0].raw)), ("finding", len(mib)))  # type: ignore[union-attr]
        self.assertIsInstance(got[1], sdk.LineError)
        self.assertEqual(got[1].line, 2)
        self.assertTrue(got[1].reason.startswith("line longer"))  # type: ignore[union-attr]
        self.assertEqual(got[2], sdk.Rec("scope", b'{"kind":"scope"}', 3))
        self.assertEqual(got[3], sdk.LineError(4, f"line longer than {sdk.MAX_LINE} bytes"))

    def test_a_line_of_exactly_max_line_is_read(self) -> None:
        line = b'{"t":"' + b"c" * (sdk.MAX_LINE - 8) + b'"}'
        self.assertEqual(len(line), sdk.MAX_LINE)
        got = list(sdk.records(io.BytesIO(line + b"\r\n")))
        self.assertEqual(got, [sdk.Rec("", line, 1)])


class Errors(unittest.TestCase):
    def test_line_errors_say_what_is_wrong(self) -> None:
        for raw, want in [(b"null", "not a record: null"), (b"[1]", "not a record: not a JSON object")]:
            self.assertEqual(list(sdk.records(io.BytesIO(raw))), [sdk.LineError(1, want)])
        (got,) = sdk.records(io.BytesIO(b'{"a":\xff}'))
        self.assertIsInstance(got, sdk.LineError)
        self.assertIn("utf-8", got.reason)  # type: ignore[union-attr]


class Typed(unittest.TestCase):
    def test_decoding_gives_typed_members(self) -> None:
        raw = (
            b'{"kind":"finding","title":"t","severity":"high","targets":[{"scope":"S-1","row":{"id":"S-1","host":"h"}}],'
            b'"lines":{"keys":{"id":{"line":2,"column":1}}},"x":1}'
        )
        f = sdk.Finding.from_json(raw)
        self.assertEqual(f.targets[0].row, sdk.ScopeRow(id="S-1", host="h"))
        self.assertEqual(f.lines.keys["id"].line, 2)  # type: ignore[union-attr]
        self.assertEqual(f.extra, {"x": 1})

    def test_decoding_refuses_the_wrong_type(self) -> None:
        with self.assertRaises(ValueError):
            sdk.Finding.from_dict({"title": 5})
        with self.assertRaises(ValueError):
            sdk.ScopeRow.from_dict({"port": True})

    def test_null_is_empty(self) -> None:
        self.assertEqual(sdk.Finding.from_dict({"title": None}).title, "")

    def test_emit_to_text_and_kind_filled(self) -> None:
        out = io.StringIO()
        sdk.emit(out, sdk.Problem(path=".", rule="r", level=sdk.WARNING, message="m"))
        self.assertEqual(out.getvalue(), '{"kind":"problem","path":".","rule":"r","level":"warning","message":"m"}\n')

    def test_range(self) -> None:
        got = [str(sdk.Range(min=a, max=b)) for a, b in [(0, 0), (2, 0), (0, 1), (2, 2), (2, 3)]]
        self.assertEqual(got, ["any", "2 or later", "up to 1", "2", "2 to 3"])
        self.assertTrue(sdk.Requires().fits(3, 2))
        self.assertFalse(sdk.Requires(format=sdk.Range(min=1, max=1)).fits(3, 2))


def load_tests(loader: unittest.TestLoader, tests: unittest.TestSuite, pattern: str | None) -> unittest.TestSuite:
    import doctest

    from rpt_sdk import _member

    tests.addTests(doctest.DocTestSuite(_member))
    return tests


if __name__ == "__main__":
    unittest.main()
