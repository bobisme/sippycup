"""Explicit adapters from producer records into the UI event envelope."""

from __future__ import annotations

from typing import Mapping

from .state import Event, EventError


CAMPAIGN_KINDS = {
    "campaign.started": "run.started",
    "campaign.stop_requested": "stop.requested",
    "campaign.succeeded": "run.completed",
    "campaign.failed": "run.failed",
    "campaign.timed_out": "run.failed",
    "campaign.cancelled": "run.failed",
    "step.output_truncated": "run.warning",
    "step.start_failed": "run.warning",
    "step.failed": "run.warning",
    "step.timed_out": "run.warning",
}


def adapt_campaign(record: Mapping[str, object]) -> Event | None:
    """Map one validated campaign JSONL record without consuming tool text."""
    if record.get("apiVersion") != "sippycup.dev/events/v1":
        raise EventError("unsupported campaign event schema")
    sequence, campaign, producer_kind = (
        record.get("sequence"), record.get("campaign"), record.get("event")
    )
    if type(sequence) is not int or sequence < 1:
        raise EventError("campaign sequence must be a positive integer")
    if not isinstance(campaign, str) or not campaign:
        raise EventError("campaign name is required")
    if not isinstance(producer_kind, str):
        raise EventError("campaign event kind is required")
    kind = CAMPAIGN_KINDS.get(producer_kind)
    if kind is None:
        # Step progress/output does not change mission state. In particular,
        # step.output text is intentionally not forwarded or ANSI-parsed.
        return None
    safe_fields = {
        name: record[name]
        for name in (
            "state", "step", "completedSteps", "stepCount", "case",
            "retainedBytes", "droppedBytes", "exitCode", "reason",
        )
        if name in record
    }
    if kind == "run.warning":
        safe_fields["message"] = producer_kind
    safe_fields["producerEvent"] = producer_kind
    return Event(sequence, f"campaign:{campaign}", kind, safe_fields)


def adapt_assertion(record: Mapping[str, object], *, sequence: int) -> Event:
    """Map an oracle result using verdict and aggregate summary only."""
    if record.get("schema_version") != "sippycup.results/v1":
        raise EventError("unsupported assertion result schema")
    if type(sequence) is not int or sequence < 1:
        raise EventError("assertion sequence must be a positive integer")
    verdict, summary = record.get("verdict"), record.get("summary")
    if verdict not in {"pass", "fail", "unknown"} or not isinstance(summary, dict):
        raise EventError("assertion verdict and summary are required")
    kind = "assertions.passed" if verdict == "pass" else "assertions.failed"
    counts = {}
    for name in ("pass", "fail", "unknown"):
        value = summary.get(name, 0)
        if type(value) is not int or value < 0:
            raise EventError("assertion summary counts must be non-negative integers")
        counts[name] = value
    return Event(sequence, "oracle", kind, {"verdict": verdict, "summary": counts})
