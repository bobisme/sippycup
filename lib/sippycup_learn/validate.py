"""Zero-INET learned-pack reference execution and semantic diff."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import socket
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

from sippycup_oracle.cli import load_expectations

from .canonical import CanonicalizationError


def validate_pack(
    pack: Path,
    output: Path,
    *,
    image_identity: str,
    tool_versions: dict[str, str] | None = None,
    timing_tolerance_ms: int = 250,
) -> dict[str, object]:
    pack, output = pack.resolve(), output.resolve()
    if output.exists():
        raise CanonicalizationError("output-exists", "validation output must not exist")
    if not 0 <= timing_tolerance_ms <= 5000:
        raise CanonicalizationError("timing", "timing tolerance must be in 0..5000 ms")
    before_manifest = hashlib.sha256((pack / "manifest.yaml").read_bytes()).hexdigest()
    manifest = yaml.safe_load((pack / "manifest.yaml").read_text())
    if manifest["review"]["reviewed"] or manifest["review"]["sourcePeerApproved"]:
        raise CanonicalizationError("authorization", "offline validation requires an unreviewed pack")
    if manifest["target"]["host"] != "REPLACE_WITH_REVIEWED_TARGET.invalid":
        raise CanonicalizationError("authorization", "offline validation refuses a concrete target")
    model = json.loads((pack / "canonical-model.json").read_text())
    load_expectations(pack / "expectations.yaml")

    observed, capture = _run_isolated(pack / "scenario.xml")
    differences = _semantic_diff(model, observed, timing_tolerance_ms)
    after_manifest = hashlib.sha256((pack / "manifest.yaml").read_bytes()).hexdigest()
    if before_manifest != after_manifest:
        raise CanonicalizationError("mutation", "validation modified the source manifest")

    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        (temporary / "validation-capture.jsonl").write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in capture),
            encoding="utf-8",
        )
        result = {
            "schema": "sippycup.learned-validation/v1",
            "verdict": "pass" if not differences else "fail",
            "networkIsolation": {
                "family": "AF_UNIX",
                "externalTraffic": 0,
                "inetSocketsCreated": 0,
            },
            "semanticDiff": differences,
            "timingToleranceMs": timing_tolerance_ms,
            "expectations": {
                "loaded": True,
                "allowedEndpoints": ["127.0.0.1"],
                "callPath": "pass" if not differences else "fail",
            },
            "versions": {
                "image": image_identity,
                "python": platform.python_version(),
                **(tool_versions or {}),
            },
            "authorizationChanged": False,
            "sourceManifestSha256": before_manifest,
            "capture": "validation-capture.jsonl",
        }
        (temporary / "result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(temporary, output)
        return result
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _run_isolated(xml_path: Path):
    root = ET.parse(xml_path).getroot()
    observed = []
    capture = []
    uac, uas = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        clock_ms = 0
        for node in root:
            if node.tag == "pause":
                clock_ms += int(node.get("milliseconds"))
                continue
            if node.tag not in {"send", "recv"}:
                continue
            if node.tag == "send":
                text = node.text or ""
                first = text.splitlines()[0] if text.splitlines() else ""
                response = re.match(r"SIP/2.0\s+(\d{3})", first)
                if response:
                    event = {"direction": "agent-to-reference", "status": int(response.group(1))}
                else:
                    method = first.split(" ", 1)[0]
                    event = {
                        "direction": "agent-to-reference",
                        "method": method,
                        "hasSdp": "m=audio " in text,
                        "codecs": _sdp_codecs(text),
                    }
                encoded = json.dumps(event, sort_keys=True).encode()
                uac.send(encoded)
                exact = uas.recv(65536)
            elif node.get("request"):
                event = {
                    "direction": "reference-to-agent",
                    "method": node.get("request"),
                    "hasSdp": False,
                    "codecs": [],
                }
                encoded = json.dumps(event, sort_keys=True).encode()
                uas.send(encoded)
                exact = uac.recv(65536)
            else:
                event = {
                    "direction": "reference-to-agent",
                    "status": int(node.get("response")),
                }
                encoded = json.dumps(event, sort_keys=True).encode()
                uas.send(encoded)
                exact = uac.recv(65536)
            if exact != encoded:
                raise CanonicalizationError("reference", "isolated reference transport altered bytes")
            event["offsetMs"] = clock_ms
            clock_ms += 20
            capture.append({"frame": len(capture) + 1, **event})
            if "method" in event:
                observed.append({**event, "responses": []})
            elif not observed:
                raise CanonicalizationError("reference", "orphan response in generated scenario")
            else:
                observed[-1]["responses"].append(event["status"])
    finally:
        uac.close()
        uas.close()
    return observed, capture


def _semantic_diff(model, observed, tolerance):
    expected = model["transactions"]
    differences = []
    if len(expected) != len(observed):
        differences.append(_diff("transactions.count", len(expected), len(observed)))
    for index, (wanted, actual) in enumerate(zip(expected, observed)):
        prefix = f"transactions[{index}]"
        for field, actual_field in (("method", "method"), ("requestHasSdp", "hasSdp")):
            if wanted.get(field) != actual.get(actual_field):
                differences.append(_diff(f"{prefix}.{field}", wanted.get(field), actual.get(actual_field)))
        expected_direction = (
            "agent-to-reference" if wanted["direction"] == "local-to-remote"
            else "reference-to-agent"
        )
        if expected_direction != actual["direction"]:
            differences.append(_diff(f"{prefix}.direction", expected_direction, actual["direction"]))
        expected_classes = [
            response["status"] // 100 for response in wanted["responses"]
            if response["status"] is not None
        ]
        actual_classes = [status // 100 for status in actual["responses"]]
        if expected_classes != actual_classes:
            differences.append(_diff(f"{prefix}.responseClasses", expected_classes, actual_classes))
        expected_codecs = _source_request_codecs(model, wanted)
        if expected_codecs != actual["codecs"]:
            differences.append(_diff(f"{prefix}.sdpCodecs", expected_codecs, actual["codecs"]))
        window = wanted["timingWindowMs"]
        earliest = window["earliest"]
        latest = window["latest"]
        if earliest is not None and latest is not None:
            observed_time = actual["offsetMs"]
            if observed_time < earliest - tolerance or observed_time > latest + tolerance:
                differences.append(_diff(
                    f"{prefix}.timingWindowMs",
                    {"earliest": earliest, "latest": latest, "tolerance": tolerance},
                    observed_time,
                ))
    observed_teardown = "none"
    for item in observed:
        if item.get("method") == "BYE":
            observed_teardown = (
                "local" if item["direction"] == "agent-to-reference" else "remote"
            )
    wanted_teardown = model["dialog"]["teardownInitiator"]
    if wanted_teardown != observed_teardown:
        differences.append(_diff("dialog.teardownInitiator", wanted_teardown, observed_teardown))
    return differences


def _source_request_codecs(model, transaction):
    if not transaction.get("requestHasSdp"):
        return []
    for revision in model["sdpRevisions"]:
        if revision["frame"] == transaction["requestFrame"] and revision["role"] == "offer":
            return [
                codec["encoding"] for media in revision["media"] for codec in media["codecs"]
            ]
    return []


def _sdp_codecs(text):
    return re.findall(r"^a=rtpmap:\d+\s+([^/\r\n]+)", text, re.MULTILINE)


def _diff(path, expected, actual):
    return {"path": path, "expected": expected, "actual": actual}
