from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_oracle.records import (  # noqa: E402
    ASSERTION_SCHEMA_VERSION,
    RESULT_SCHEMA_VERSION,
    UnknownReason,
    Verdict,
)

SCHEMAS = ROOT / "oracle" / "schemas"


class SchemaContractTests(unittest.TestCase):
    def test_schemas_are_json_and_pin_expected_versions(self) -> None:
        expectations = json.loads(
            (SCHEMAS / "expectations-v1.schema.json").read_text(encoding="utf-8")
        )
        results = json.loads(
            (SCHEMAS / "results-v1.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            expectations["properties"]["schema_version"]["const"],
            ASSERTION_SCHEMA_VERSION,
        )
        self.assertEqual(
            results["properties"]["schema_version"]["const"], RESULT_SCHEMA_VERSION
        )
        self.assertEqual(expectations["$schema"], results["$schema"])

    def test_result_schema_has_three_state_verdict(self) -> None:
        results = json.loads(
            (SCHEMAS / "results-v1.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            set(results["$defs"]["verdict"]["enum"]),
            {item.value for item in Verdict},
        )

    def test_schema_unknown_reasons_match_runtime_model(self) -> None:
        results = json.loads(
            (SCHEMAS / "results-v1.schema.json").read_text(encoding="utf-8")
        )
        unknown = results["$defs"]["typed_value"]["oneOf"][1]
        self.assertEqual(
            set(unknown["properties"]["reason"]["enum"]),
            {item.value for item in UnknownReason},
        )

    def test_assertion_result_requires_applicability(self) -> None:
        results = json.loads(
            (SCHEMAS / "results-v1.schema.json").read_text(encoding="utf-8")
        )
        assertion = results["$defs"]["assertion_result"]
        self.assertIn("applicability", assertion["required"])
        self.assertEqual(
            set(assertion["properties"]["applicability"]["enum"]),
            {"applicable", "not_applicable", "unknown"},
        )

    def test_result_schema_requires_dialog_and_stream_evidence_collections(self) -> None:
        results = json.loads(
            (SCHEMAS / "results-v1.schema.json").read_text(encoding="utf-8")
        )
        self.assertIn("dialogs", results["required"])
        self.assertIn("streams", results["required"])
        self.assertIn("evidence", results["$defs"]["dialog"]["required"])
        self.assertIn("evidence", results["$defs"]["stream"]["required"])


if __name__ == "__main__":
    unittest.main()
