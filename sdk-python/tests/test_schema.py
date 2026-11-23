"""Checks that each published JSON Schema in ../schema names exactly the members the Python type
declares, and requires exactly the ones it always writes, so the two can't drift apart."""

from __future__ import annotations

import dataclasses
import json
import unittest
from pathlib import Path
from typing import Any

import rpt_sdk as sdk

SCHEMAS = Path(__file__).resolve().parents[2] / "schema"

CHECKS: list[tuple[str, list[str], type[sdk.Wire]]] = [
    ("finding.schema.json", [], sdk.Finding),
    ("finding.schema.json", ["$defs", "target"], sdk.Target),
    ("finding.schema.json", ["$defs", "lines"], sdk.Lines),
    ("finding.schema.json", ["$defs", "sectionLines"], sdk.SectionLines),
    ("finding.schema.json", ["$defs", "position"], sdk.Position),
    ("finding.schema.json", ["$defs", "asset"], sdk.Asset),
    ("page.schema.json", [], sdk.Page),
    ("scope.schema.json", [], sdk.ScopeRow),
    ("config.schema.json", [], sdk.Config),
    ("evidence.schema.json", [], sdk.Evidence),
    ("problem.schema.json", [], sdk.Problem),
    ("report.schema.json", [], sdk.Report),
    ("report.schema.json", ["$defs", "section"], sdk.Section),
    ("location.schema.json", [], sdk.Location),
    ("version.schema.json", [], sdk.Version),
    ("command.schema.json", [], sdk.Command),
    ("command.schema.json", ["$defs", "description"], sdk.Description),
    ("command.schema.json", ["$defs", "requires"], sdk.Requires),
    ("command.schema.json", ["$defs", "range"], sdk.Range),
    ("command.schema.json", ["$defs", "schemas"], sdk.Schemas),
]


class SchemasMatchTypes(unittest.TestCase):
    def test_schemas_match_types(self) -> None:
        if not SCHEMAS.exists():
            self.skipTest("needs the rpt repository's schema folder")
        for file, path, cls in CHECKS:
            with self.subTest(f"{file} {path}"):
                node: Any = json.loads((SCHEMAS / file).read_text(encoding="utf-8"))
                for key in path:
                    node = node[key]
                fields = [f for f in dataclasses.fields(cls) if f.name != "extra"]
                self.assertEqual(sorted(f.name for f in fields), sorted(node["properties"]))
                required = sorted(f.name for f in fields if f.metadata.get("required"))
                self.assertEqual(required, sorted(node.get("required", [])))
                self.assertIs(node["additionalProperties"], True, "records pass through unknown members")
                # An empty value writes exactly the required members.
                self.assertEqual(sorted(cls().to_dict()), required)


if __name__ == "__main__":
    unittest.main()
