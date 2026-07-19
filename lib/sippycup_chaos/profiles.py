"""Strict, deterministic compilation of reviewed chaos profiles.

This module deliberately does not execute the commands it emits.  Applying and
rolling back an impairment plan is a separate, ownership-aware lifecycle.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
from typing import Any

import yaml


PROFILE_API_VERSION = "sippycup.dev/chaos-profile/v1"
PROFILE_KIND = "ChaosProfile"
PLAN_API_VERSION = "sippycup.dev/chaos-impairment-plan/v1"
PLAN_KIND = "ChaosImpairmentPlan"
TOPOLOGY_API_VERSION = "sippycup.dev/chaos-topology-plan/v1"
TOPOLOGY_KIND = "ChaosTopologyPlan"

_PROFILE_KEYS = {
    "apiVersion",
    "kind",
    "metadata",
    "seed",
    "durationSeconds",
    "direction",
    "directions",
}
_IMPAIRMENT_KEYS = {
    "delay",
    "loss",
    "reorder",
    "duplicate",
    "corrupt",
    "queuePackets",
    "rate",
    "mtu",
}
_DIRECTIONS = {"egress", "ingress"}
_PROFILE_DIRECTIONS = {"egress", "ingress", "bidirectional", "asymmetric"}
_NAMESPACE_RE = re.compile(r"[a-z][a-z0-9-]{0,30}")
_INTERFACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}")
_MAX_PROFILE_BYTES = 1024 * 1024


class _StrictSafeLoader(yaml.SafeLoader):
    """Safe YAML with aliases and duplicate mapping keys forbidden."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise yaml.constructor.ConstructorError(
                None, None, "YAML aliases are not permitted in chaos profiles", None
            )
        return super().compose_node(parent, index)


def _construct_unique_mapping(
    loader: _StrictSafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "mapping keys must be scalar",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


class ProfileError(ValueError):
    """Raised when a profile or its topology binding is unsafe or ambiguous."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _expect_mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise ProfileError(f"{field} must be a mapping with string keys")
    return value


def _exact_keys(
    value: dict[str, Any],
    *,
    field: str,
    allowed: set[str],
    required: set[str] | None = None,
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ProfileError(f"{field} contains unknown keys: {', '.join(unknown)}")
    missing = sorted((required or set()) - set(value))
    if missing:
        raise ProfileError(f"{field} is missing required keys: {', '.join(missing)}")


def _integer(
    value: Any, field: str, *, minimum: int, maximum: int
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProfileError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise ProfileError(f"{field} must be between {minimum} and {maximum}")
    return value


def _decimal(
    value: Any,
    field: str,
    *,
    minimum: Decimal = Decimal(0),
    maximum: Decimal = Decimal(100),
) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProfileError(f"{field} must be a finite number")
    if isinstance(value, float) and not math.isfinite(value):
        raise ProfileError(f"{field} must be a finite number")
    try:
        result = Decimal(str(value))
    except InvalidOperation as error:
        raise ProfileError(f"{field} must be a finite number") from error
    if not result.is_finite() or not minimum <= result <= maximum:
        raise ProfileError(f"{field} must be between {minimum} and {maximum}")
    return result


def _json_number(value: Decimal) -> int | float:
    if value == value.to_integral_value():
        return int(value)
    return float(value)


def _render_number(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _render_percent(value: Decimal) -> str:
    return f"{_render_number(value)}%"


def _normalize_delay(value: Any, field: str) -> dict[str, Any]:
    delay = _expect_mapping(value, field)
    _exact_keys(
        delay,
        field=field,
        allowed={
            "milliseconds",
            "jitterMilliseconds",
            "correlationPercent",
            "distribution",
        },
        required={"milliseconds"},
    )
    milliseconds = _decimal(
        delay["milliseconds"], f"{field}.milliseconds", maximum=Decimal(60000)
    )
    if milliseconds <= 0:
        raise ProfileError(f"{field}.milliseconds must be greater than zero")
    normalized: dict[str, Any] = {"milliseconds": milliseconds}
    if "jitterMilliseconds" in delay:
        jitter = _decimal(
            delay["jitterMilliseconds"],
            f"{field}.jitterMilliseconds",
            maximum=Decimal(60000),
        )
        if jitter <= 0 or jitter > milliseconds:
            raise ProfileError(
                f"{field}.jitterMilliseconds must be greater than zero and no "
                "larger than milliseconds"
            )
        normalized["jitterMilliseconds"] = jitter
    elif "correlationPercent" in delay or "distribution" in delay:
        raise ProfileError(
            f"{field} correlation/distribution requires jitterMilliseconds"
        )
    if "correlationPercent" in delay:
        normalized["correlationPercent"] = _decimal(
            delay["correlationPercent"], f"{field}.correlationPercent"
        )
    if "distribution" in delay:
        distribution = delay["distribution"]
        if distribution not in {"uniform", "normal", "pareto", "paretonormal"}:
            raise ProfileError(f"{field}.distribution is not supported")
        normalized["distribution"] = distribution
    return normalized


def _normalize_loss(value: Any, field: str) -> dict[str, Any]:
    loss = _expect_mapping(value, field)
    model = loss.get("model")
    if model == "random":
        _exact_keys(
            loss,
            field=field,
            allowed={"model", "percent", "correlationPercent"},
            required={"model", "percent"},
        )
        percent = _decimal(loss["percent"], f"{field}.percent")
        if percent <= 0:
            raise ProfileError(f"{field}.percent must be greater than zero")
        normalized: dict[str, Any] = {"model": model, "percent": percent}
        if "correlationPercent" in loss:
            normalized["correlationPercent"] = _decimal(
                loss["correlationPercent"], f"{field}.correlationPercent"
            )
        return normalized
    if model == "gemodel":
        _exact_keys(
            loss,
            field=field,
            allowed={
                "model",
                "startPercent",
                "recoveryPercent",
                "badLossPercent",
                "goodLossPercent",
            },
            required={
                "model",
                "startPercent",
                "recoveryPercent",
                "badLossPercent",
                "goodLossPercent",
            },
        )
        result = {"model": model}
        for key in (
            "startPercent",
            "recoveryPercent",
            "badLossPercent",
            "goodLossPercent",
        ):
            result[key] = _decimal(loss[key], f"{field}.{key}")
        if result["startPercent"] <= 0 or result["recoveryPercent"] <= 0:
            raise ProfileError(
                f"{field} startPercent and recoveryPercent must be greater than zero"
            )
        return result
    raise ProfileError(f"{field}.model must be random or gemodel")


def _normalize_percent_effect(value: Any, field: str) -> dict[str, Any]:
    effect = _expect_mapping(value, field)
    _exact_keys(
        effect,
        field=field,
        allowed={"percent", "correlationPercent"},
        required={"percent"},
    )
    percent = _decimal(effect["percent"], f"{field}.percent")
    if percent <= 0:
        raise ProfileError(f"{field}.percent must be greater than zero")
    result: dict[str, Any] = {"percent": percent}
    if "correlationPercent" in effect:
        result["correlationPercent"] = _decimal(
            effect["correlationPercent"], f"{field}.correlationPercent"
        )
    return result


def _normalize_reorder(value: Any, field: str) -> dict[str, Any]:
    original = _expect_mapping(value, field)
    _exact_keys(
        original,
        field=field,
        allowed={"percent", "correlationPercent", "gap"},
        required={"percent"},
    )
    percent = _decimal(original["percent"], f"{field}.percent")
    if percent <= 0:
        raise ProfileError(f"{field}.percent must be greater than zero")
    reorder: dict[str, Any] = {"percent": percent}
    if "correlationPercent" in original:
        reorder["correlationPercent"] = _decimal(
            original["correlationPercent"], f"{field}.correlationPercent"
        )
    if "gap" in original:
        reorder["gap"] = _integer(
            original["gap"], f"{field}.gap", minimum=1, maximum=1_000_000
        )
    return reorder


def _normalize_rate(value: Any, field: str) -> dict[str, Any]:
    rate = _expect_mapping(value, field)
    _exact_keys(
        rate,
        field=field,
        allowed={"kbit", "burstBytes", "latencyMilliseconds", "limitBytes"},
        required={"kbit", "burstBytes"},
    )
    bounds = {"latencyMilliseconds", "limitBytes"} & set(rate)
    if len(bounds) != 1:
        raise ProfileError(
            f"{field} requires exactly one of latencyMilliseconds or limitBytes"
        )
    result = {
        "kbit": _integer(rate["kbit"], f"{field}.kbit", minimum=8, maximum=10_000_000),
        "burstBytes": _integer(
            rate["burstBytes"],
            f"{field}.burstBytes",
            minimum=256,
            maximum=16_777_216,
        ),
    }
    if "latencyMilliseconds" in rate:
        result["latencyMilliseconds"] = _integer(
            rate["latencyMilliseconds"],
            f"{field}.latencyMilliseconds",
            minimum=1,
            maximum=60_000,
        )
    else:
        result["limitBytes"] = _integer(
            rate["limitBytes"],
            f"{field}.limitBytes",
            minimum=result["burstBytes"],
            maximum=1_073_741_824,
        )
    return result


def _normalize_impairment(value: Any, field: str) -> dict[str, Any]:
    impairment = _expect_mapping(value, field)
    _exact_keys(impairment, field=field, allowed=_IMPAIRMENT_KEYS)
    result: dict[str, Any] = {}
    if "delay" in impairment:
        result["delay"] = _normalize_delay(impairment["delay"], f"{field}.delay")
    if "loss" in impairment:
        result["loss"] = _normalize_loss(impairment["loss"], f"{field}.loss")
    if "reorder" in impairment:
        if "delay" not in result:
            raise ProfileError(f"{field}.reorder requires a non-zero delay")
        result["reorder"] = _normalize_reorder(
            impairment["reorder"], f"{field}.reorder"
        )
    for key in ("duplicate", "corrupt"):
        if key in impairment:
            result[key] = _normalize_percent_effect(
                impairment[key], f"{field}.{key}"
            )
    if "queuePackets" in impairment:
        if not any(
            key in result for key in ("delay", "loss", "reorder", "duplicate", "corrupt")
        ):
            raise ProfileError(
                f"{field}.queuePackets requires a netem impairment; it cannot "
                "stand alone or ambiguously replace a rate queue"
            )
        result["queuePackets"] = _integer(
            impairment["queuePackets"],
            f"{field}.queuePackets",
            minimum=1,
            maximum=1_000_000,
        )
    if "rate" in impairment:
        result["rate"] = _normalize_rate(impairment["rate"], f"{field}.rate")
    if "mtu" in impairment:
        result["mtu"] = _integer(
            impairment["mtu"], f"{field}.mtu", minimum=1280, maximum=9000
        )
    return result


def load_profile(path: str | Path) -> tuple[dict[str, Any], str]:
    """Load a profile without YAML's unsafe object constructors."""

    profile_path = Path(path)
    try:
        with profile_path.open("rb") as source:
            raw = source.read(_MAX_PROFILE_BYTES + 1)
        if len(raw) > _MAX_PROFILE_BYTES:
            raise ProfileError(f"profile {profile_path} exceeds 1 MiB")
        loaded = yaml.load(raw, Loader=_StrictSafeLoader)
    except (OSError, yaml.YAMLError) as error:
        raise ProfileError(f"cannot load profile {profile_path}: {error}") from error
    return _expect_mapping(loaded, "profile"), hashlib.sha256(raw).hexdigest()


def validate_profile(profile: Any) -> dict[str, Any]:
    """Validate and normalize a profile, rejecting all ambiguous input."""

    document = _expect_mapping(profile, "profile")
    _exact_keys(
        document,
        field="profile",
        allowed=_PROFILE_KEYS,
        required=_PROFILE_KEYS,
    )
    if document["apiVersion"] != PROFILE_API_VERSION:
        raise ProfileError(f"profile.apiVersion must be {PROFILE_API_VERSION}")
    if document["kind"] != PROFILE_KIND:
        raise ProfileError(f"profile.kind must be {PROFILE_KIND}")

    metadata = _expect_mapping(document["metadata"], "profile.metadata")
    _exact_keys(
        metadata,
        field="profile.metadata",
        allowed={"name", "description"},
        required={"name"},
    )
    name = metadata["name"]
    if (
        not isinstance(name, str)
        or not 1 <= len(name) <= 63
        or not name[0].isalnum()
        or any(not (char.isalnum() or char in "-.") for char in name)
    ):
        raise ProfileError("profile.metadata.name is not a safe profile identifier")
    if "description" in metadata and (
        not isinstance(metadata["description"], str)
        or not 1 <= len(metadata["description"]) <= 240
    ):
        raise ProfileError("profile.metadata.description must be 1-240 characters")

    seed = _integer(
        document["seed"], "profile.seed", minimum=1, maximum=2_147_483_647
    )
    duration = _integer(
        document["durationSeconds"],
        "profile.durationSeconds",
        minimum=1,
        maximum=3600,
    )
    direction = document["direction"]
    if direction not in _PROFILE_DIRECTIONS:
        raise ProfileError(
            "profile.direction must be egress, ingress, bidirectional, or asymmetric"
        )
    directions = _expect_mapping(document["directions"], "profile.directions")
    if not set(directions) <= _DIRECTIONS:
        raise ProfileError("profile.directions may only contain egress and ingress")
    expected = {
        "egress": {"egress"},
        "ingress": {"ingress"},
        "bidirectional": _DIRECTIONS,
        "asymmetric": _DIRECTIONS,
    }[direction]
    if set(directions) != expected:
        raise ProfileError(
            f"profile.direction {direction} requires directions "
            f"{', '.join(sorted(expected))}"
        )
    normalized_directions = {
        key: _normalize_impairment(value, f"profile.directions.{key}")
        for key, value in sorted(directions.items())
    }
    if direction == "bidirectional" and (
        normalized_directions["egress"] != normalized_directions["ingress"]
    ):
        raise ProfileError(
            "bidirectional profiles require identical egress and ingress settings; "
            "use asymmetric for different settings"
        )
    if direction == "asymmetric" and (
        normalized_directions["egress"] == normalized_directions["ingress"]
    ):
        raise ProfileError(
            "asymmetric profiles require different egress and ingress settings"
        )

    result = {
        "apiVersion": PROFILE_API_VERSION,
        "kind": PROFILE_KIND,
        "metadata": dict(metadata),
        "seed": seed,
        "durationSeconds": duration,
        "direction": direction,
        "directions": normalized_directions,
    }
    return result


def _validate_topology(topology: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    plan = _expect_mapping(topology, "topology plan")
    if plan.get("apiVersion") != TOPOLOGY_API_VERSION:
        raise ProfileError("topology plan has an unsupported apiVersion")
    if plan.get("kind") != TOPOLOGY_KIND:
        raise ProfileError("topology plan has an unsupported kind")
    if plan.get("noChange") is not True or plan.get("mutationCommands") != []:
        raise ProfileError(
            "topology plan must be a no-change plan with no mutation commands"
        )
    topology_kind = plan.get("topology")
    dangerous = plan.get("dangerous")
    if (topology_kind, dangerous) not in {
        ("disposable-router", False),
        ("dangerous-host-network", True),
    }:
        raise ProfileError("topology kind and dangerous flag are inconsistent")
    snapshot = _expect_mapping(
        plan.get("preMutationSnapshot"), "topology.preMutationSnapshot"
    )
    if plan.get("snapshotSha256") != _sha256(snapshot):
        raise ProfileError("topology pre-mutation snapshot digest does not match")
    capabilities = _expect_mapping(
        plan.get("capabilities"), "topology.capabilities"
    )
    features = _expect_mapping(
        capabilities.get("features"), "topology.capabilities.features"
    )
    required_features = ["iproute2", "tc", "netAdmin", "netem", "classifier"]
    if topology_kind == "disposable-router":
        required_features.extend(("sysAdmin", "pasta"))
    for feature in required_features:
        if features.get(feature) != "available":
            raise ProfileError(f"topology capability {feature} is not available")

    attachments = _expect_mapping(plan.get("attachments"), "topology.attachments")
    filters = plan.get("targetFilters")
    if not isinstance(filters, list) or not filters:
        raise ProfileError("topology plan has no frozen target filters")

    validated_filters: list[dict[str, Any]] = []
    networks: set[str] = set()
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(filters):
        target = _expect_mapping(item, f"topology.targetFilters[{index}]")
        _exact_keys(
            target,
            field=f"topology.targetFilters[{index}]",
            allowed={"direction", "family", "network", "tcProtocol", "match"},
            required={"direction", "family", "network", "tcProtocol", "match"},
        )
        direction = target["direction"]
        if direction not in _DIRECTIONS or direction not in attachments:
            raise ProfileError("target filter direction has no topology attachment")
        try:
            network = ipaddress.ip_network(target["network"], strict=True)
        except (TypeError, ValueError) as error:
            raise ProfileError("target filter network is not canonical CIDR") from error
        family = "ipv4" if network.version == 4 else "ipv6"
        protocol = "ip" if network.version == 4 else "ipv6"
        match = f"{'dst_ip' if direction == 'egress' else 'src_ip'} {network}"
        if (
            target["network"] != str(network)
            or target["family"] != family
            or target["tcProtocol"] != protocol
            or target["match"] != match
        ):
            raise ProfileError("target filter was widened or is internally inconsistent")
        marker = (direction, str(network))
        if marker in seen:
            raise ProfileError("topology plan contains duplicate target filters")
        seen.add(marker)
        networks.add(str(network))
        validated_filters.append(dict(target))

    expected_scope = _sha256(sorted(networks))
    if plan.get("targetScopeSha256") != expected_scope:
        raise ProfileError("topology target scope digest does not match its filters")
    for direction, attachment in attachments.items():
        if direction not in _DIRECTIONS:
            raise ProfileError("topology contains an unsupported attachment direction")
        value = _expect_mapping(attachment, f"topology.attachments.{direction}")
        _exact_keys(
            value,
            field=f"topology.attachments.{direction}",
            allowed={"namespace", "interface", "hook"},
            required={"namespace", "interface", "hook"},
        )
        if (
            not isinstance(value["namespace"], str)
            or not value["namespace"]
            or not isinstance(value["interface"], str)
            or not value["interface"]
            or value["hook"]
            not in {"egress", "ingress", "egress-after-ingress-redirect"}
        ):
            raise ProfileError("topology attachment is malformed")
        if value["namespace"] != "host" and not _NAMESPACE_RE.fullmatch(
            value["namespace"]
        ):
            raise ProfileError("topology attachment namespace is unsafe")
        if not _INTERFACE_RE.fullmatch(value["interface"]):
            raise ProfileError("topology attachment interface is unsafe")

    expected_filter_pairs = {
        (direction, network)
        for direction in attachments
        for network in networks
    }
    if seen != expected_filter_pairs:
        raise ProfileError(
            "topology target filters are not complete for every attachment and target"
        )

    if topology_kind == "disposable-router":
        namespaces = _expect_mapping(plan.get("namespaces"), "topology.namespaces")
        impairment_namespace = namespaces.get("impairment")
        if (
            not isinstance(impairment_namespace, str)
            or not _NAMESPACE_RE.fullmatch(impairment_namespace)
        ):
            raise ProfileError("disposable topology impairment namespace is malformed")
        expected_attachments = {
            "egress": (impairment_namespace, "imp-uplink0", "egress"),
            "ingress": (impairment_namespace, "imp-test0", "egress"),
        }
        for direction, attachment in attachments.items():
            if (
                attachment["namespace"],
                attachment["interface"],
                attachment["hook"],
            ) != expected_attachments[direction]:
                raise ProfileError("disposable topology attachment was modified")
        namespace_snapshots = snapshot.get("namespaces")
        if not isinstance(namespace_snapshots, list):
            raise ProfileError("disposable topology namespace snapshot is malformed")
        snapshot_names = {
            item.get("name")
            for item in namespace_snapshots
            if isinstance(item, dict) and item.get("exists") is False
        }
        if impairment_namespace not in snapshot_names:
            raise ProfileError(
                "disposable impairment namespace is not proven absent in snapshot"
            )
    else:
        for direction, attachment in attachments.items():
            if attachment["namespace"] != "host":
                raise ProfileError("host topology attachment must remain in host")
            if direction == "ingress" and (
                attachment["interface"] != "ifb-sippycup"
                or attachment["hook"] != "egress-after-ingress-redirect"
            ):
                raise ProfileError("host ingress attachment was modified")
            if direction == "egress":
                host = _expect_mapping(snapshot.get("host"), "topology.snapshot.host")
                qdiscs = host.get("qdiscs")
                if not isinstance(qdiscs, list):
                    raise ProfileError("host qdisc snapshot is malformed")
                devices = {
                    item.get("dev")
                    for item in qdiscs
                    if isinstance(item, dict)
                }
                if (
                    attachment["hook"] != "egress"
                    or attachment["interface"] not in devices
                ):
                    raise ProfileError(
                        "host egress attachment is absent from the frozen snapshot"
                    )
    return plan, validated_filters


def _derived_seed(seed: int, direction: str) -> int:
    digest = hashlib.sha256(f"{seed}:{direction}".encode("ascii")).digest()
    return int.from_bytes(digest[:4], "big") % 2_147_483_646 + 1


def _netem_args(impairment: dict[str, Any], seed: int) -> list[str]:
    args: list[str] = []
    if "queuePackets" in impairment:
        args.extend(("limit", str(impairment["queuePackets"])))
    if "delay" in impairment:
        delay = impairment["delay"]
        args.extend(("delay", f"{_render_number(delay['milliseconds'])}ms"))
        if "jitterMilliseconds" in delay:
            args.append(f"{_render_number(delay['jitterMilliseconds'])}ms")
            if "correlationPercent" in delay:
                args.append(_render_percent(delay["correlationPercent"]))
            if "distribution" in delay:
                args.extend(("distribution", delay["distribution"]))
    if "loss" in impairment:
        loss = impairment["loss"]
        if loss["model"] == "random":
            args.extend(("loss", "random", _render_percent(loss["percent"])))
            if "correlationPercent" in loss:
                args.append(_render_percent(loss["correlationPercent"]))
        else:
            args.extend(
                (
                    "loss",
                    "gemodel",
                    _render_percent(loss["startPercent"]),
                    _render_percent(loss["recoveryPercent"]),
                    _render_percent(loss["badLossPercent"]),
                    _render_percent(loss["goodLossPercent"]),
                )
            )
    for key in ("corrupt", "duplicate"):
        if key in impairment:
            effect = impairment[key]
            args.extend((key, _render_percent(effect["percent"])))
            if "correlationPercent" in effect:
                args.append(_render_percent(effect["correlationPercent"]))
    if "reorder" in impairment:
        reorder = impairment["reorder"]
        args.extend(("reorder", _render_percent(reorder["percent"])))
        if "correlationPercent" in reorder:
            args.append(_render_percent(reorder["correlationPercent"]))
        if "gap" in reorder:
            args.extend(("gap", str(reorder["gap"])))
    if args:
        args.extend(("seed", str(seed)))
    return args


def _wrap(namespace: str, argv: list[str]) -> list[str]:
    if namespace == "host":
        return argv
    # ip-netns-exec also creates a mount namespace and remounts /sys.  Rootless
    # Podman cannot perform that remount even with SYS_ADMIN, while entering the
    # already-owned network namespace directly is sufficient for tc.
    return ["nsenter", f"--net=/run/netns/{namespace}", *argv]


def _json_impairment(value: Any) -> Any:
    if isinstance(value, Decimal):
        return _json_number(value)
    if isinstance(value, dict):
        return {key: _json_impairment(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_impairment(item) for item in value]
    return value


def compile_profile(
    topology: Any,
    profile: Any,
    *,
    source_sha256: str | None = None,
) -> dict[str, Any]:
    """Compile a reviewed profile into a deterministic, non-executed command plan."""

    topology_plan, target_filters = _validate_topology(topology)
    normalized = validate_profile(profile)
    available_directions = set(topology_plan["attachments"])
    requested_directions = set(normalized["directions"])
    if not requested_directions <= available_directions:
        raise ProfileError(
            "profile direction is not covered by the frozen topology attachments"
        )

    topology_kind = topology_plan.get("topology")
    dangerous = topology_plan.get("dangerous")
    if not isinstance(dangerous, bool):
        raise ProfileError("topology dangerous flag is malformed")
    features = (
        topology_plan.get("capabilities", {})
        .get("features", {})
    )
    commands: list[dict[str, Any]] = []
    compiled_directions: list[dict[str, Any]] = []
    topology_sha = _sha256(topology_plan)
    owner = f"sippycup-{topology_sha[:8]}-{_sha256(_json_impairment(normalized))[:8]}"

    for direction in sorted(requested_directions):
        impairment = normalized["directions"][direction]
        attachment = topology_plan["attachments"][direction]
        namespace = attachment["namespace"]
        interface = attachment["interface"]
        seed = _derived_seed(normalized["seed"], direction)
        netem_args = _netem_args(impairment, seed)
        rate = impairment.get("rate")
        mtu = impairment.get("mtu")
        direction_filters = [
            target for target in target_filters if target["direction"] == direction
        ]
        if not direction_filters:
            raise ProfileError(f"topology has no target filters for {direction}")

        if mtu is not None:
            if dangerous or topology_kind != "disposable-router":
                raise ProfileError(
                    "MTU impairments are only permitted on disposable-router "
                    "interfaces dedicated to the run"
                )
            if features.get("mtu") != "available":
                raise ProfileError("topology did not prove MTU capability")
            argv = _wrap(
                namespace,
                ["ip", "link", "set", "dev", interface, "mtu", str(mtu)],
            )
            commands.append(
                {
                    "id": f"{direction}-set-mtu",
                    "direction": direction,
                    "namespace": namespace,
                    "argv": argv,
                    "owns": f"{owner}:{direction}:mtu",
                }
            )

        if netem_args or rate:
            root = _wrap(
                namespace,
                ["tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "prio", "bands", "3"],
            )
            commands.append(
                {
                    "id": f"{direction}-root",
                    "direction": direction,
                    "namespace": namespace,
                    "argv": root,
                    "owns": f"{owner}:{direction}:1:",
                }
            )
            for index, target in enumerate(direction_filters):
                selector, network = target["match"].split(" ", 1)
                filter_argv = _wrap(
                    namespace,
                    [
                        "tc",
                        "filter",
                        "add",
                        "dev",
                        interface,
                        "protocol",
                        target["tcProtocol"],
                        "parent",
                        "1:",
                        "prio",
                        str(100 + index),
                        "flower",
                        selector,
                        network,
                        "flowid",
                        "1:1",
                    ],
                )
                commands.append(
                    {
                        "id": f"{direction}-filter-{index + 1}",
                        "direction": direction,
                        "namespace": namespace,
                        "argv": filter_argv,
                        "owns": f"{owner}:{direction}:filter:{100 + index}",
                    }
                )
            netem_parent = "1:1"
            if rate:
                tbf = [
                    "tc",
                    "qdisc",
                    "add",
                    "dev",
                    interface,
                    "parent",
                    "1:1",
                    "handle",
                    "10:",
                    "tbf",
                    "rate",
                    f"{rate['kbit']}kbit",
                    "burst",
                    str(rate["burstBytes"]),
                ]
                if "latencyMilliseconds" in rate:
                    tbf.extend(("latency", f"{rate['latencyMilliseconds']}ms"))
                else:
                    tbf.extend(("limit", str(rate["limitBytes"])))
                commands.append(
                    {
                        "id": f"{direction}-rate",
                        "direction": direction,
                        "namespace": namespace,
                        "argv": _wrap(namespace, tbf),
                        "owns": f"{owner}:{direction}:10:",
                    }
                )
                netem_parent = "10:1"
            if netem_args:
                netem = _wrap(
                    namespace,
                    [
                        "tc",
                        "qdisc",
                        "add",
                        "dev",
                        interface,
                        "parent",
                        netem_parent,
                        "handle",
                        "20:",
                        "netem",
                        *netem_args,
                    ],
                )
                commands.append(
                    {
                        "id": f"{direction}-netem",
                        "direction": direction,
                        "namespace": namespace,
                        "argv": netem,
                        "owns": f"{owner}:{direction}:20:",
                    }
                )

        compiled_directions.append(
            {
                "direction": direction,
                "attachment": dict(attachment),
                "derivedSeed": seed if netem_args else None,
                "impairment": _json_impairment(impairment),
                "targetFilters": direction_filters,
                "commandIds": [
                    command["id"]
                    for command in commands
                    if command["direction"] == direction
                ],
            }
        )

    normalized_json = _json_impairment(normalized)
    profile_sha = source_sha256 or _sha256(normalized_json)
    if (
        not isinstance(profile_sha, str)
        or len(profile_sha) != 64
        or any(character not in "0123456789abcdef" for character in profile_sha)
    ):
        raise ProfileError("profile source SHA-256 is malformed")
    return {
        "apiVersion": PLAN_API_VERSION,
        "kind": PLAN_KIND,
        "noChange": True,
        "profile": {
            "name": normalized["metadata"]["name"],
            "sourceSha256": profile_sha,
            "seed": normalized["seed"],
            "durationSeconds": normalized["durationSeconds"],
            "direction": normalized["direction"],
        },
        "topology": {
            "planSha256": topology_sha,
            "targetScopeSha256": topology_plan["targetScopeSha256"],
            "snapshotSha256": topology_plan["snapshotSha256"],
            "dangerous": dangerous,
        },
        "owner": owner,
        "directions": compiled_directions,
        "commands": commands,
        "execution": {
            "performed": False,
            "requiresLifecycleApply": True,
            "expiresAfterSeconds": normalized["durationSeconds"],
        },
    }
