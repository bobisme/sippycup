"""Versioned normalization and evidence-linked semantic behavior diffs."""

from __future__ import annotations

import copy
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
from typing import Any, Iterable
import xml.etree.ElementTree as ET

from .canonical import CanonicalizationError


NORMALIZATION_VERSION = "sippycup.dev/golden-behavior-normalization/v1"
DIFF_VERSION = "sippycup.dev/golden-behavior-diff/v1"
MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
_PLACEHOLDER_TYPES = {
    "address",
    "branch",
    "call-id",
    "contact",
    "cseq",
    "length",
    "media-address",
    "media-port",
    "port",
    "rtp-sequence",
    "rtp-timestamp",
    "ssrc",
    "tag",
}


def _load_json(path: Path, description: str) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            raise CanonicalizationError("pack", f"{description} must be a regular file")
        if path.stat().st_size > MAX_DOCUMENT_BYTES:
            raise CanonicalizationError("pack", f"{description} exceeds 32 MiB")
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise CanonicalizationError("pack", f"cannot read {description}: {error}") from error
    except json.JSONDecodeError as error:
        raise CanonicalizationError("pack", f"invalid {description} JSON: {error}") from error
    if not isinstance(value, dict):
        raise CanonicalizationError("pack", f"{description} must contain an object")
    return value


def load_behavior_pack(path: str | Path) -> dict[str, Any]:
    """Load the learned model and oracle result that form a golden behavior pack."""
    root = Path(path).resolve(strict=True)
    if not root.is_dir():
        raise CanonicalizationError("pack", "behavior pack must be a directory")
    model = _load_json(root / "canonical-model.json", "canonical model")
    result_path = root / "oracle-result.json"
    if not result_path.exists():
        fallback = root / "result.json"
        if fallback.exists():
            result_path = fallback
    oracle = _load_json(result_path, "oracle result")
    if model.get("schema") != "sippycup.learned-dialog/v1":
        raise CanonicalizationError("schema", "unsupported learned dialog model")
    if oracle.get("schema_version") != "sippycup.results/v1":
        raise CanonicalizationError("schema", "unsupported oracle result")
    for field in ("dialog", "transactions", "sdpRevisions"):
        if field not in model:
            raise CanonicalizationError("schema", f"canonical model is missing {field}")
    for field in ("dialogs", "streams", "assertions", "verdict"):
        if field not in oracle:
            raise CanonicalizationError("schema", f"oracle result is missing {field}")
    if not all(isinstance(oracle[field], list) for field in ("dialogs", "streams", "assertions")):
        raise CanonicalizationError("schema", "oracle result collections must be arrays")
    return {"root": root, "model": model, "oracle": oracle}


class _PlaceholderNormalizer:
    def __init__(self) -> None:
        self._values: dict[str, dict[str, str]] = {}

    def normalize(self, value: Any, *, field: str = "") -> Any:
        if isinstance(value, list):
            return [self.normalize(item, field=field) for item in value]
        if not isinstance(value, dict):
            if field.lower().endswith("port") and type(value) is int and value > 1023:
                return "<ephemeral-port>"
            return value
        if set(value) == {"type", "name"} and value.get("type") in _PLACEHOLDER_TYPES:
            kind = value["type"]
            raw = value["name"]
            if not isinstance(raw, str):
                raise CanonicalizationError("schema", "placeholder name must be a string")
            mapping = self._values.setdefault(kind, {})
            if raw not in mapping:
                mapping[raw] = f"{kind}-{len(mapping) + 1}"
            return {"type": kind, "name": mapping[raw]}
        return {
            key: self.normalize(item, field=key)
            for key, item in sorted(value.items())
        }


def _integer(value: Any, field: str) -> int:
    if type(value) is not int:
        raise CanonicalizationError("schema", f"{field} must be an integer")
    return value


def _normalize_timing(transactions: list[dict[str, Any]]) -> None:
    starts = []
    for index, transaction in enumerate(transactions):
        window = transaction.get("timingWindowMs")
        if not isinstance(window, dict):
            raise CanonicalizationError(
                "schema", f"transactions[{index}].timingWindowMs must be an object"
            )
        for field in ("earliest", "latest"):
            value = window.get(field)
            if value is not None:
                starts.append(_integer(value, f"transactions[{index}].timingWindowMs.{field}"))
    origin = min(starts, default=0)
    for transaction in transactions:
        window = transaction["timingWindowMs"]
        for field in ("earliest", "latest"):
            if window.get(field) is not None:
                window[field] -= origin


def _semantic_model(model: dict[str, Any]) -> dict[str, Any]:
    normalized = _PlaceholderNormalizer()
    dialog = model["dialog"]
    if not isinstance(dialog, dict):
        raise CanonicalizationError("schema", "canonical model dialog must be an object")
    transactions = copy.deepcopy(model["transactions"])
    revisions = copy.deepcopy(model["sdpRevisions"])
    media_packets = copy.deepcopy(model.get("mediaPackets", []))
    if not isinstance(transactions, list) or not all(isinstance(item, dict) for item in transactions):
        raise CanonicalizationError("schema", "canonical model transactions must be objects")
    if not isinstance(revisions, list) or not all(isinstance(item, dict) for item in revisions):
        raise CanonicalizationError("schema", "canonical model SDP revisions must be objects")
    if not isinstance(media_packets, list) or not all(isinstance(item, dict) for item in media_packets):
        raise CanonicalizationError("schema", "canonical model media packets must be objects")
    _normalize_timing(transactions)
    semantic_transactions = []
    for index, transaction in enumerate(transactions):
        responses = transaction.get("responses", [])
        if not isinstance(responses, list) or not all(
            isinstance(response, dict) for response in responses
        ):
            raise CanonicalizationError(
                "schema", f"transactions[{index}].responses must contain objects"
            )
        semantic_transactions.append(
            normalized.normalize(
                {
                    "method": transaction.get("method"),
                    "direction": transaction.get("direction"),
                    "flow": transaction.get("flow"),
                    "timingWindowMs": transaction.get("timingWindowMs"),
                    "requestHasSdp": transaction.get("requestHasSdp"),
                    "responses": [
                        {
                            "status": response.get("status"),
                            "optional": response.get("optional"),
                        }
                        for response in responses
                    ],
                }
            )
        )
    semantic_revisions = []
    for revision in revisions:
        semantic_revisions.append(
            normalized.normalize(
                {
                    "role": revision.get("role"),
                    "method": revision.get("method"),
                    "status": revision.get("status"),
                    "media": revision.get("media"),
                }
            )
        )
    media_origin = min(
        (
            _integer(item["offsetMs"], "mediaPackets.offsetMs")
            for item in media_packets
            if item.get("offsetMs") is not None
        ),
        default=0,
    )
    semantic_media = [
        normalized.normalize(
            {
                "ssrc": item.get("ssrc"),
                "sequence": item.get("sequence"),
                "timestamp": item.get("timestamp"),
                "payloadType": item.get("payloadType"),
                "offsetMs": (
                    item.get("offsetMs") - media_origin
                    if item.get("offsetMs") is not None
                    else None
                ),
            }
        )
        for item in media_packets
    ]
    return {
        "dialog": {
            "state": dialog.get("state"),
            "teardownInitiator": dialog.get("teardownInitiator"),
        },
        "transactions": semantic_transactions,
        "sdpRevisions": semantic_revisions,
        "mediaPackets": semantic_media,
    }


def _strip_evidence(value: Any, *, field: str = "") -> Any:
    if isinstance(value, list):
        return [_strip_evidence(item, field=field) for item in value]
    if not isinstance(value, dict):
        if field.lower().endswith("port") and type(value) is int and value > 1023:
            return "<ephemeral-port>"
        if field.lower() in {"ssrc", "sender_ssrc"} and type(value) is int:
            return "<ssrc>"
        return value
    return {
        key: _strip_evidence(item, field=key)
        for key, item in sorted(value.items())
        if key not in {"evidence", "message", "call_id", "id"}
    }


def _semantic_oracle(oracle: dict[str, Any]) -> dict[str, Any]:
    if not all(isinstance(item, dict) for item in oracle["dialogs"]):
        raise CanonicalizationError("schema", "oracle dialogs must contain objects")
    if not all(isinstance(item, dict) for item in oracle["streams"]):
        raise CanonicalizationError("schema", "oracle streams must contain objects")
    if not all(isinstance(item, dict) for item in oracle["assertions"]):
        raise CanonicalizationError("schema", "oracle assertions must contain objects")
    dialogs = [
        {
            "state": item.get("state"),
            "complete": _strip_evidence(item.get("complete")),
        }
        for item in oracle["dialogs"]
    ]
    dialogs.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    streams = [
        {
            "direction": item.get("direction"),
            "correlation": item.get("correlation"),
            "flow": _strip_evidence(item.get("flow")),
            "encrypted": item.get("encrypted"),
            "metrics": _strip_evidence(item.get("metrics")),
        }
        for item in oracle["streams"]
    ]
    streams.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    assertions = {
        item.get("id"): {
            "verdict": item.get("verdict"),
            "applicability": item.get("applicability"),
            "observed": _strip_evidence(item.get("observed")),
        }
        for item in oracle["assertions"]
        if isinstance(item.get("id"), str)
    }
    if len(assertions) != len(oracle["assertions"]):
        raise CanonicalizationError("schema", "oracle assertion IDs must be unique strings")
    return {
        "verdict": oracle["verdict"],
        "dialogs": dialogs,
        "streams": streams,
        "assertions": assertions,
    }


def normalize_behavior_pack(path: str | Path) -> dict[str, Any]:
    """Return the versioned semantic identity of a behavior pack."""
    loaded = load_behavior_pack(path)
    return {
        "apiVersion": NORMALIZATION_VERSION,
        "kind": "NormalizedGoldenBehavior",
        "model": _semantic_model(loaded["model"]),
        "oracle": _semantic_oracle(loaded["oracle"]),
    }


def _frame(value: Any) -> Any:
    if isinstance(value, dict) and value.get("state") == "known":
        return value.get("value")
    return None


def _evidence_refs(pack: dict[str, Any], section: str, index: int | str) -> list[dict[str, Any]]:
    model, oracle = pack["model"], pack["oracle"]
    if section == "transaction":
        try:
            item = model["transactions"][int(index)]
        except (IndexError, TypeError, ValueError):
            return []
        frames = [item.get("requestFrame")]
        frames.extend(response.get("frame") for response in item.get("responses", []))
        return [{"frame": frame} for frame in frames if frame is not None]
    if section == "sdp":
        try:
            frame = model["sdpRevisions"][int(index)].get("frame")
        except (IndexError, TypeError, ValueError):
            return []
        return [{"frame": frame}] if frame is not None else []
    if section == "media":
        try:
            frame = model.get("mediaPackets", [])[int(index)].get("frame")
        except (IndexError, TypeError, ValueError):
            return []
        return [{"frame": frame}] if frame is not None else []
    if section == "dialog":
        try:
            evidence = oracle["dialogs"][int(index)].get("evidence")
        except (IndexError, TypeError, ValueError):
            return []
        return [evidence] if isinstance(evidence, dict) else []
    if section == "stream":
        try:
            evidence = oracle["streams"][int(index)].get("evidence", [])
        except (IndexError, TypeError, ValueError):
            return []
        return evidence if isinstance(evidence, list) else []
    if section == "assertion":
        for item in oracle["assertions"]:
            if item.get("id") == index:
                evidence = item.get("evidence", [])
                return evidence if isinstance(evidence, list) else []
    return []


def _stream_evidence(pack: dict[str, Any], direction: str) -> list[dict[str, Any]]:
    evidence = []
    for item in pack["oracle"]["streams"]:
        if item.get("direction") == direction and isinstance(item.get("evidence"), list):
            evidence.extend(item["evidence"])
    return evidence


def _numeric(value: Any) -> Decimal | None:
    if isinstance(value, dict) and value.get("state") == "known":
        value = value.get("value")
    if isinstance(value, bool):
        return None
    try:
        result = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None
    return result if result.is_finite() else None


def _equal_with_tolerance(left: Any, right: Any, tolerance: int) -> bool:
    first, second = _numeric(left), _numeric(right)
    return first is not None and second is not None and abs(first - second) <= tolerance


def _category(path: str) -> str:
    if "timingWindowMs" in path or ".media.timing.observed" in path:
        return "response-timing"
    if "assertions" in path:
        return "assertion"
    if "codecs" in path or "payloadTypes" in path:
        return "codec"
    if "flow" in path or "address" in path.lower() or "port" in path.lower():
        return "endpoint-topology"
    if "streams" in path or "mediaPackets" in path or "directionality" in path:
        return "media"
    if "sdpRevisions" in path:
        return "sdp"
    if "teardown" in path:
        return "post-bye"
    return "dialog"


def _change(
    path: str,
    baseline: Any,
    candidate: Any,
    baseline_evidence: Iterable[Any],
    candidate_evidence: Iterable[Any],
    *,
    category: str | None = None,
) -> dict[str, Any]:
    return {
        "category": category or _category(path),
        "path": path,
        "baseline": baseline,
        "candidate": candidate,
        "evidence": {
            "baseline": list(baseline_evidence),
            "candidate": list(candidate_evidence),
        },
    }


def _walk_changes(
    path: str,
    left: Any,
    right: Any,
    left_evidence: Iterable[Any],
    right_evidence: Iterable[Any],
) -> list[dict[str, Any]]:
    if left == right:
        return []
    if isinstance(left, dict) and isinstance(right, dict):
        changes = []
        for key in sorted(set(left) | set(right)):
            changes.extend(
                _walk_changes(
                    f"{path}.{key}", left.get(key), right.get(key),
                    left_evidence, right_evidence,
                )
            )
        return changes
    if isinstance(left, list) and isinstance(right, list) and len(left) == len(right):
        changes = []
        for index, (before, after) in enumerate(zip(left, right)):
            changes.extend(
                _walk_changes(
                    f"{path}[{index}]", before, after,
                    left_evidence, right_evidence,
                )
            )
        return changes
    return [_change(path, left, right, left_evidence, right_evidence)]


def compare_behavior_packs(
    baseline: str | Path,
    candidate: str | Path,
    *,
    timing_tolerance_ms: int = 20,
) -> dict[str, Any]:
    """Compare two packs and return the sole result model used by every renderer."""
    if type(timing_tolerance_ms) is not int or not 0 <= timing_tolerance_ms <= 5000:
        raise CanonicalizationError("timing", "timing tolerance must be an integer in 0..5000 ms")
    raw_left, raw_right = load_behavior_pack(baseline), load_behavior_pack(candidate)
    left = {
        "model": _semantic_model(raw_left["model"]),
        "oracle": _semantic_oracle(raw_left["oracle"]),
    }
    right = {
        "model": _semantic_model(raw_right["model"]),
        "oracle": _semantic_oracle(raw_right["oracle"]),
    }
    changes: list[dict[str, Any]] = []

    changes.extend(
        _walk_changes(
            "dialog", left["model"]["dialog"], right["model"]["dialog"],
            _evidence_refs(raw_left, "dialog", 0), _evidence_refs(raw_right, "dialog", 0),
        )
    )
    changes.extend(
        _walk_changes(
            "oracle.dialogs", left["oracle"]["dialogs"], right["oracle"]["dialogs"],
            [ref for index in range(len(raw_left["oracle"]["dialogs"])) for ref in _evidence_refs(raw_left, "dialog", index)],
            [ref for index in range(len(raw_right["oracle"]["dialogs"])) for ref in _evidence_refs(raw_right, "dialog", index)],
        )
    )
    if left["oracle"]["verdict"] != right["oracle"]["verdict"]:
        changes.append(
            _change(
                "oracle.verdict",
                left["oracle"]["verdict"],
                right["oracle"]["verdict"],
                [
                    ref
                    for item in raw_left["oracle"]["assertions"]
                    for ref in item.get("evidence", [])
                ],
                [
                    ref
                    for item in raw_right["oracle"]["assertions"]
                    for ref in item.get("evidence", [])
                ],
                category="assertion",
            )
        )
    left_transactions, right_transactions = left["model"]["transactions"], right["model"]["transactions"]
    if len(left_transactions) != len(right_transactions):
        changes.append(
            _change(
                "transactions.count", len(left_transactions), len(right_transactions),
                _evidence_refs(raw_left, "transaction", max(len(left_transactions) - 1, 0)),
                _evidence_refs(raw_right, "transaction", max(len(right_transactions) - 1, 0)),
            )
        )
    bye_index = min(
        (
            index for index, item in enumerate(left_transactions)
            if item.get("method") == "BYE"
        ),
        default=len(left_transactions),
    )
    for index, (before, after) in enumerate(zip(left_transactions, right_transactions)):
        left_refs = _evidence_refs(raw_left, "transaction", index)
        right_refs = _evidence_refs(raw_right, "transaction", index)
        for field in sorted(set(before) | set(after)):
            path = f"transactions[{index}].{field}"
            if field == "timingWindowMs":
                if before[field] != after[field]:
                    missing_mismatch = any(
                        (before[field].get(name) is None)
                        != (after[field].get(name) is None)
                        for name in ("earliest", "latest")
                    )
                    deltas = [
                        abs(before[field][name] - after[field][name])
                        for name in ("earliest", "latest")
                        if before[field].get(name) is not None and after[field].get(name) is not None
                    ]
                    if missing_mismatch or not deltas or max(deltas) > timing_tolerance_ms:
                        changes.append(
                            _change(path, before[field], after[field], left_refs, right_refs)
                        )
                continue
            field_changes = _walk_changes(path, before.get(field), after.get(field), left_refs, right_refs)
            if index > bye_index:
                for item in field_changes:
                    item["category"] = "post-bye"
            changes.extend(field_changes)
    for index in range(min(len(left_transactions), len(right_transactions)), max(len(left_transactions), len(right_transactions))):
        before = left_transactions[index] if index < len(left_transactions) else None
        after = right_transactions[index] if index < len(right_transactions) else None
        changes.append(
            _change(
                f"transactions[{index}]", before, after,
                _evidence_refs(raw_left, "transaction", index),
                _evidence_refs(raw_right, "transaction", index),
                category="post-bye" if index > bye_index else "dialog",
            )
        )

    left_sdp, right_sdp = left["model"]["sdpRevisions"], right["model"]["sdpRevisions"]
    if len(left_sdp) != len(right_sdp):
        changes.append(
            _change(
                "sdpRevisions.count",
                len(left_sdp),
                len(right_sdp),
                _evidence_refs(raw_left, "sdp", max(len(left_sdp) - 1, 0)),
                _evidence_refs(raw_right, "sdp", max(len(right_sdp) - 1, 0)),
                category="sdp",
            )
        )
    for index, (before, after) in enumerate(zip(left_sdp, right_sdp)):
        changes.extend(
            _walk_changes(
                f"sdpRevisions[{index}]", before, after,
                _evidence_refs(raw_left, "sdp", index), _evidence_refs(raw_right, "sdp", index),
            )
        )

    left_media, right_media = left["model"]["mediaPackets"], right["model"]["mediaPackets"]
    if len(left_media) != len(right_media):
        changes.append(
            _change(
                "mediaPackets.count",
                len(left_media),
                len(right_media),
                _evidence_refs(raw_left, "media", max(len(left_media) - 1, 0)),
                _evidence_refs(raw_right, "media", max(len(right_media) - 1, 0)),
                category="media",
            )
        )
    for index, (before, after) in enumerate(zip(left_media, right_media)):
        changes.extend(
            _walk_changes(
                f"mediaPackets[{index}]",
                before,
                after,
                _evidence_refs(raw_left, "media", index),
                _evidence_refs(raw_right, "media", index),
            )
        )

    left_streams, right_streams = left["oracle"]["streams"], right["oracle"]["streams"]
    left_by_direction: dict[str, list[dict[str, Any]]] = {}
    right_by_direction: dict[str, list[dict[str, Any]]] = {}
    for item in left_streams:
        left_by_direction.setdefault(str(item.get("direction")), []).append(item)
    for item in right_streams:
        right_by_direction.setdefault(str(item.get("direction")), []).append(item)
    for direction in sorted(set(left_by_direction) | set(right_by_direction)):
        before_items = left_by_direction.get(direction, [])
        after_items = right_by_direction.get(direction, [])
        left_refs = _stream_evidence(raw_left, direction)
        right_refs = _stream_evidence(raw_right, direction)
        if len(before_items) != len(after_items):
            changes.append(
                _change(
                    f"streams.{direction}.count",
                    len(before_items),
                    len(after_items),
                    left_refs,
                    right_refs,
                    category="media",
                )
            )
        for index, (before, after) in enumerate(zip(before_items, after_items)):
            changes.extend(
                _walk_changes(
                    f"streams.{direction}[{index}]",
                    before,
                    after,
                    left_refs,
                    right_refs,
                )
            )
    assertion_ids = sorted(set(left["oracle"]["assertions"]) | set(right["oracle"]["assertions"]))
    for identifier in assertion_ids:
        before = left["oracle"]["assertions"].get(identifier)
        after = right["oracle"]["assertions"].get(identifier)
        if before == after:
            continue
        if (
            identifier.endswith(".media.timing")
            and before is not None
            and after is not None
            and before.get("verdict") == after.get("verdict")
            and before.get("applicability") == after.get("applicability")
            and _equal_with_tolerance(
                before.get("observed"), after.get("observed"), timing_tolerance_ms
            )
        ):
            continue
        changes.extend(
            _walk_changes(
                f"assertions.{identifier}", before, after,
                _evidence_refs(raw_left, "assertion", identifier),
                _evidence_refs(raw_right, "assertion", identifier),
            )
        )
    changes.sort(key=lambda item: (item["path"], item["category"]))
    categories = {
        category: sum(item["category"] == category for item in changes)
        for category in sorted({item["category"] for item in changes})
    }
    return {
        "apiVersion": DIFF_VERSION,
        "kind": "GoldenBehaviorDiff",
        "normalizationVersion": NORMALIZATION_VERSION,
        "verdict": "equal" if not changes else "different",
        "summary": {"changeCount": len(changes), "categories": categories},
        "timingToleranceMs": timing_tolerance_ms,
        "changes": changes,
    }


def render_diff_json(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def render_diff_human(result: dict[str, Any]) -> str:
    lines = [
        f"BEHAVIOR {result['verdict'].upper()} ({result['summary']['changeCount']} changes)",
        f"normalization={result['normalizationVersion']} timing-tolerance={result['timingToleranceMs']}ms",
    ]
    for item in result["changes"]:
        left_frames = [_frame(ref.get("frame_number")) or ref.get("frame") for ref in item["evidence"]["baseline"]]
        right_frames = [_frame(ref.get("frame_number")) or ref.get("frame") for ref in item["evidence"]["candidate"]]
        lines.append(
            f"{item['category']:17} {item['path']}: "
            f"{json.dumps(item['baseline'], sort_keys=True)} -> "
            f"{json.dumps(item['candidate'], sort_keys=True)} "
            f"(frames baseline={left_frames} candidate={right_frames})"
        )
    return "\n".join(lines) + "\n"


def render_diff_junit(result: dict[str, Any]) -> str:
    suite = ET.Element(
        "testsuite",
        {
            "name": "sippycup.golden-behavior",
            "tests": "1",
            "failures": "0" if result["verdict"] == "equal" else "1",
        },
    )
    case = ET.SubElement(suite, "testcase", {"name": "baseline-vs-candidate"})
    if result["changes"]:
        failure = ET.SubElement(
            case,
            "failure",
            {
                "message": f"{result['summary']['changeCount']} semantic behavior changes",
                "type": "GoldenBehaviorDiff",
            },
        )
        failure.text = render_diff_human(result)
    properties = ET.SubElement(suite, "properties")
    ET.SubElement(
        properties,
        "property",
        {"name": "normalizationVersion", "value": result["normalizationVersion"]},
    )
    return ET.tostring(suite, encoding="unicode", xml_declaration=True) + "\n"
