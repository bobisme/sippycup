"""SIP overload, retry discipline, and fairness oracle."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .common import (
    ResilienceError,
    bounded_int,
    exact_keys,
    nonempty_string,
    require_mapping,
    verdict,
)

REPORT_VERSION = "sippycup.dev/overload-report/v1"
MAX_TRANSACTIONS = 1_000_000
MAX_DURATION_MS = 3_600_000


def analyze_overload(
    transactions_value: Any,
    *,
    max_attempts: int = 2,
    fairness_tolerance_percent: int = 20,
) -> dict[str, Any]:
    if not isinstance(transactions_value, list) or not transactions_value:
        raise ResilienceError("transactions must be a non-empty array")
    if len(transactions_value) > MAX_TRANSACTIONS:
        raise ResilienceError(f"transactions exceed {MAX_TRANSACTIONS}")
    attempt_limit = bounded_int(max_attempts, "maxAttempts", 1, 5)
    fairness = bounded_int(
        fairness_tolerance_percent, "fairnessTolerancePercent", 0, 100
    )
    attempts: dict[str, list[dict[str, Any]]] = defaultdict(list)
    findings: list[dict[str, Any]] = []
    previous_time = -1
    for index, raw in enumerate(transactions_value):
        item = require_mapping(raw, f"transactions[{index}]")
        exact_keys(
            item,
            ("atMs", "client", "requestId", "attempt", "response", "retryAfterMs"),
            name=f"transactions[{index}]",
        )
        at_ms = bounded_int(item["atMs"], "atMs", 0, MAX_DURATION_MS)
        if at_ms < previous_time:
            raise ResilienceError("transactions must be ordered by atMs")
        previous_time = at_ms
        client = nonempty_string(item["client"], "client", 64)
        request_id = nonempty_string(item["requestId"], "requestId", 128)
        attempt = bounded_int(item["attempt"], "attempt", 1, 32)
        response = bounded_int(item["response"], "response", 100, 699)
        retry_after = item["retryAfterMs"]
        if retry_after is not None:
            bounded_int(retry_after, "retryAfterMs", 1, MAX_DURATION_MS)
        if response != 503 and retry_after is not None:
            raise ResilienceError("Retry-After is only accepted with response 503")
        record = {
            "atMs": at_ms,
            "client": client,
            "requestId": request_id,
            "attempt": attempt,
            "response": response,
            "retryAfterMs": retry_after,
            "index": index,
        }
        attempts[request_id].append(record)
    client_totals: dict[str, int] = defaultdict(int)
    client_success: dict[str, int] = defaultdict(int)
    for request_id, records in attempts.items():
        clients = {item["client"] for item in records}
        if len(clients) != 1:
            raise ResilienceError(f"{request_id} changes client identity")
        client = records[0]["client"]
        client_totals[client] += 1
        if any(200 <= item["response"] < 300 for item in records):
            client_success[client] += 1
        numbers = [item["attempt"] for item in records]
        if numbers != list(range(1, len(records) + 1)):
            raise ResilienceError(f"{request_id} attempts must be contiguous from one")
        if len(records) > attempt_limit:
            findings.append(
                {
                    "severity": "fail",
                    "code": "retry_amplification",
                    "requestId": request_id,
                    "attempts": len(records),
                    "limit": attempt_limit,
                }
            )
        for prior, current in zip(records, records[1:]):
            if prior["response"] != 503:
                findings.append(
                    {
                        "severity": "fail",
                        "code": "retry_after_non_overload",
                        "requestId": request_id,
                        "attempt": current["attempt"],
                    }
                )
                continue
            retry_after = prior["retryAfterMs"]
            if retry_after is None:
                findings.append(
                    {
                        "severity": "fail",
                        "code": "unbounded_retry_after_503",
                        "requestId": request_id,
                        "attempt": current["attempt"],
                    }
                )
            elif current["atMs"] < prior["atMs"] + retry_after:
                findings.append(
                    {
                        "severity": "fail",
                        "code": "retry_before_retry_after",
                        "requestId": request_id,
                        "attempt": current["attempt"],
                    }
                )
    rates = {
        client: client_success[client] * 100.0 / total
        for client, total in client_totals.items()
    }
    if len(rates) >= 2 and max(rates.values()) - min(rates.values()) > fairness:
        findings.append(
            {
                "severity": "fail",
                "code": "client_unfairness",
                "successPercent": {key: round(value, 3) for key, value in sorted(rates.items())},
                "tolerancePercent": fairness,
            }
        )
    return {
        "apiVersion": REPORT_VERSION,
        "status": verdict(findings),
        "transactions": len(transactions_value),
        "logicalRequests": len(attempts),
        "maximumAttempts": max(len(value) for value in attempts.values()),
        "clientSuccessPercent": {
            key: round(value, 3) for key, value in sorted(rates.items())
        },
        "findings": findings,
        "capacityClaim": None,
    }


def synthetic_transactions(
    clients: int = 2,
    requests_per_client: int = 4,
    accepted_per_client: int = 2,
) -> list[dict[str, Any]]:
    client_count = bounded_int(clients, "clients", 2, 64)
    request_count = bounded_int(requests_per_client, "requestsPerClient", 1, 1000)
    accepted = bounded_int(
        accepted_per_client, "acceptedPerClient", 0, request_count
    )
    records: list[dict[str, Any]] = []
    for request in range(request_count):
        for client in range(client_count):
            records.append(
                {
                    "atMs": request * 10,
                    "client": f"peer-{client + 1}",
                    "requestId": f"peer-{client + 1}-request-{request + 1}",
                    "attempt": 1,
                    "response": 200 if request < accepted else 503,
                    "retryAfterMs": None if request < accepted else 1000,
                }
            )
    return records
