from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "oracle"))

from test_dialogs import scenario_frames

from sippycup_learn import (
    canonicalize_dialog,
    compare_behavior_packs,
    normalize_behavior_pack,
    render_diff_human,
    render_diff_json,
    render_diff_junit,
)
from sippycup_oracle.dialogs import reconstruct_dialogs


CLI = ROOT / "bin" / "sippycup-diff"


def evidence(frame: int, timestamp: str) -> dict:
    return {
        "frame_number": {"state": "known", "value": frame},
        "timestamp_epoch": {"state": "known", "value": timestamp},
    }


def known(value):
    return {"state": "known", "value": value}


def oracle_result(*, call_id: str = "golden@example.invalid") -> dict:
    return {
        "schema_version": "sippycup.results/v1",
        "verdict": "pass",
        "summary": {"pass": 3, "fail": 0, "unknown": 0},
        "dialogs": [
            {
                "id": "dialog[0]",
                "call_id": call_id,
                "state": "terminated",
                "complete": known(True),
                "evidence": evidence(1, "1000.100"),
            }
        ],
        "streams": [
            {
                "id": "dialog[0].stream[0]",
                "dialog_id": "dialog[0]",
                "direction": "caller_to_callee",
                "correlation": "negotiated",
                "flow": {
                    "source_address": "192.0.2.10",
                    "source_port": 40000,
                    "destination_address": "198.51.100.20",
                    "destination_port": 50000,
                    "transport": "udp",
                    "ssrc": 8675309,
                },
                "encrypted": False,
                "metrics": {
                    "packets": known(40),
                    "loss_fraction": known("0"),
                    "jitter_ms": known("1.25"),
                },
                "evidence": [evidence(10, "1000.500")],
            },
            {
                "id": "dialog[0].stream[1]",
                "dialog_id": "dialog[0]",
                "direction": "callee_to_caller",
                "correlation": "negotiated",
                "flow": {
                    "source_address": "198.51.100.20",
                    "source_port": 50000,
                    "destination_address": "192.0.2.10",
                    "destination_port": 40000,
                    "transport": "udp",
                    "ssrc": 424242,
                },
                "encrypted": False,
                "metrics": {
                    "packets": known(40),
                    "loss_fraction": known("0"),
                    "jitter_ms": known("1.25"),
                },
                "evidence": [evidence(11, "1000.520")],
            },
        ],
        "assertions": [
            {
                "id": "dialog[0].media.directionality",
                "verdict": "pass",
                "applicability": "applicable",
                "message": "bidirectional media",
                "evidence": [evidence(10, "1000.500"), evidence(11, "1000.520")],
                "observed": known(["caller_to_callee", "callee_to_caller"]),
            },
            {
                "id": "dialog[0].media.timing",
                "verdict": "pass",
                "applicability": "applicable",
                "message": "setup timing is within bounds",
                "evidence": [evidence(1, "1000.100"), evidence(10, "1000.500")],
                "observed": known("400.0"),
            },
            {
                "id": "dialog[0].media.endpoints",
                "verdict": "pass",
                "applicability": "applicable",
                "message": "endpoints allowed",
                "evidence": [evidence(10, "1000.500")],
                "observed": known(["192.0.2.10", "198.51.100.20"]),
            },
        ],
    }


def model() -> dict:
    frames = scenario_frames("baseline")
    return canonicalize_dialog(
        reconstruct_dialogs(frames),
        frames,
        local_networks=("192.0.2.0/24",),
    )


def write_pack(root: Path, name: str, canonical: dict, oracle: dict) -> Path:
    pack = root / name
    pack.mkdir()
    (pack / "canonical-model.json").write_text(
        json.dumps(canonical, indent=2, sort_keys=True) + "\n"
    )
    (pack / "oracle-result.json").write_text(
        json.dumps(oracle, indent=2, sort_keys=True) + "\n"
    )
    return pack


def rewrite_nondeterminism(value):
    if isinstance(value, list):
        for item in value:
            rewrite_nondeterminism(item)
    elif isinstance(value, dict):
        if set(value) == {"type", "name"}:
            value["name"] = "candidate-" + value["name"]
        for key, item in value.items():
            if key in {"requestFrame", "frame"} and type(item) is int:
                value[key] += 1000
            rewrite_nondeterminism(item)


def shift_evidence(value):
    if isinstance(value, list):
        for item in value:
            shift_evidence(item)
    elif isinstance(value, dict):
        if value.get("state") == "known" and isinstance(value.get("value"), int):
            return
        if "frame_number" in value and "timestamp_epoch" in value:
            value["frame_number"]["value"] += 1000
            value["timestamp_epoch"]["value"] = str(
                float(value["timestamp_epoch"]["value"]) + 9000
            )
        for item in value.values():
            shift_evidence(item)


class GoldenDiffTests(unittest.TestCase):
    def packs(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        baseline_model, baseline_oracle = model(), oracle_result()
        candidate_model, candidate_oracle = copy.deepcopy(baseline_model), copy.deepcopy(baseline_oracle)
        return (
            root,
            baseline_model,
            baseline_oracle,
            candidate_model,
            candidate_oracle,
        )

    def compare(self, mutate=lambda _model, _oracle: None, *, tolerance=20):
        root, baseline_model, baseline_oracle, candidate_model, candidate_oracle = self.packs()
        mutate(candidate_model, candidate_oracle)
        baseline = write_pack(root, "baseline", baseline_model, baseline_oracle)
        candidate = write_pack(root, "candidate", candidate_model, candidate_oracle)
        return compare_behavior_packs(
            baseline, candidate, timing_tolerance_ms=tolerance
        ), baseline, candidate

    def test_identifier_ports_frames_and_time_origin_only_compare_equal(self):
        def mutate(candidate_model, candidate_oracle):
            rewrite_nondeterminism(candidate_model)
            for transaction in candidate_model["transactions"]:
                for field in ("earliest", "latest"):
                    if transaction["timingWindowMs"][field] is not None:
                        transaction["timingWindowMs"][field] += 50_000
            candidate_oracle["dialogs"][0]["call_id"] = "new-call-id@example.invalid"
            for stream in candidate_oracle["streams"]:
                stream["flow"]["source_port"] += 10000
                stream["flow"]["destination_port"] += 10000
                stream["flow"]["ssrc"] += 777
            shift_evidence(candidate_oracle)

        result, baseline, candidate = self.compare(mutate)
        self.assertEqual("equal", result["verdict"], result["changes"])
        self.assertEqual(
            normalize_behavior_pack(baseline),
            normalize_behavior_pack(candidate),
        )

    def test_codec_and_endpoint_changes_remain_semantic_and_evidence_linked(self):
        def mutate(candidate_model, candidate_oracle):
            candidate_model["sdpRevisions"][0]["media"][0]["codecs"][0]["encoding"] = "OPUS"
            candidate_oracle["streams"][0]["flow"]["source_address"] = "203.0.113.9"

        result, _baseline, _candidate = self.compare(mutate)
        categories = {item["category"] for item in result["changes"]}
        self.assertIn("codec", categories)
        self.assertIn("endpoint-topology", categories)
        self.assertTrue(
            all(set(item["evidence"]) == {"baseline", "candidate"} for item in result["changes"])
        )

    def test_dialog_transition_sdp_and_media_metric_changes_are_preserved(self):
        def mutate(candidate_model, candidate_oracle):
            candidate_model["dialog"]["state"] = "rejected"
            candidate_model["transactions"][0]["responses"][-1]["status"] = 488
            candidate_model["sdpRevisions"][0]["media"][0]["direction"] = "sendonly"
            candidate_oracle["streams"][0]["metrics"]["jitter_ms"] = known("9.75")

        result, _baseline, _candidate = self.compare(mutate)
        paths = {item["path"] for item in result["changes"]}
        self.assertIn("dialog.state", paths)
        self.assertTrue(any(".responses" in path and path.endswith(".status") for path in paths))
        self.assertTrue(any(path.endswith(".direction") and "sdpRevisions" in path for path in paths))
        self.assertTrue(any("streams" in path and "jitter_ms" in path for path in paths))

    def test_one_way_setup_latency_assertion_and_post_bye_changes_are_focused(self):
        def mutate(candidate_model, candidate_oracle):
            candidate_oracle["streams"].pop()
            direction = candidate_oracle["assertions"][0]
            direction["verdict"] = "fail"
            direction["observed"] = known(["caller_to_callee"])
            candidate_oracle["assertions"][1]["observed"] = known("525.0")
            bye = next(
                item for item in candidate_model["transactions"] if item["method"] == "BYE"
            )
            extra = copy.deepcopy(bye)
            extra["method"] = "OPTIONS"
            candidate_model["transactions"].append(extra)

        result, _baseline, _candidate = self.compare(mutate)
        self.assertEqual("different", result["verdict"])
        categories = {item["category"] for item in result["changes"]}
        self.assertTrue({"media", "assertion", "response-timing", "post-bye"} <= categories)
        self.assertLessEqual(result["summary"]["changeCount"], 8)

    def test_timing_tolerance_is_explicit_and_does_not_hide_large_drift(self):
        within, _baseline, _candidate = self.compare(
            lambda _model, oracle: oracle["assertions"][1].update(
                {"observed": known("415.0")}
            ),
            tolerance=20,
        )
        self.assertEqual("equal", within["verdict"])
        outside, _baseline, _candidate = self.compare(
            lambda _model, oracle: oracle["assertions"][1].update(
                {"observed": known("421.0")}
            ),
            tolerance=20,
        )
        self.assertEqual("different", outside["verdict"])
        self.assertEqual("response-timing", outside["changes"][0]["category"])

        missing, _baseline, _candidate = self.compare(
            lambda model, _oracle: model["transactions"][0][
                "timingWindowMs"
            ].update({"latest": None}),
            tolerance=5000,
        )
        self.assertEqual("different", missing["verdict"])

    def test_rtp_identifiers_normalize_but_packet_semantics_do_not(self):
        root, baseline_model, baseline_oracle, candidate_model, candidate_oracle = self.packs()
        packet = {
            "frame": 20,
            "ssrc": {"type": "ssrc", "name": "ssrc-original"},
            "sequence": {"type": "rtp-sequence", "name": "sequence-original"},
            "timestamp": {"type": "rtp-timestamp", "name": "timestamp-original"},
            "payloadType": 0,
            "offsetMs": 1000,
        }
        baseline_model["mediaPackets"] = [copy.deepcopy(packet)]
        candidate_model["mediaPackets"] = [copy.deepcopy(packet)]
        rewrite_nondeterminism(candidate_model["mediaPackets"])
        candidate_model["mediaPackets"][0]["frame"] = 2020
        candidate_model["mediaPackets"][0]["offsetMs"] = 9000
        baseline = write_pack(root, "baseline", baseline_model, baseline_oracle)
        candidate = write_pack(root, "candidate", candidate_model, candidate_oracle)
        self.assertEqual(
            "equal", compare_behavior_packs(baseline, candidate)["verdict"]
        )
        candidate_model["mediaPackets"][0]["payloadType"] = 111
        (candidate / "canonical-model.json").write_text(json.dumps(candidate_model))
        changed = compare_behavior_packs(baseline, candidate)
        self.assertEqual("different", changed["verdict"])
        self.assertEqual("media", changed["changes"][0]["category"])

    def test_human_json_junit_and_cli_derive_from_one_result(self):
        result, baseline, candidate = self.compare(
            lambda _model, oracle: oracle["assertions"][0].update({"verdict": "fail"})
        )
        self.assertEqual(result, json.loads(render_diff_json(result)))
        human = render_diff_human(result)
        junit = ET.fromstring(render_diff_junit(result))
        count = str(result["summary"]["changeCount"])
        self.assertIn(f"({count} changes)", human)
        self.assertIn(count, junit.find("testcase/failure").get("message"))
        for output_format in ("json", "human", "junit"):
            run = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    str(baseline),
                    str(candidate),
                    "--format",
                    output_format,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(1, run.returncode, run.stderr)
            self.assertTrue(run.stdout)


if __name__ == "__main__":
    unittest.main()
