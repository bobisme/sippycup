"""Generate a review-gated SIPp pack from the canonical dialog model."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

from .canonical import CanonicalizationError

REFERENCE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


def generate_pack(
    model: dict[str, object],
    destination: Path,
    *,
    auth_username_ref: str | None = None,
    auth_secret_ref: str | None = None,
) -> dict[str, object]:
    _validate_model(model)
    auth = _auth_policy(model, auth_username_ref, auth_secret_ref)
    destination = destination.resolve()
    if destination.exists():
        raise CanonicalizationError("output-exists", "pack destination must not exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
    try:
        root, dispositions = _scenario(model, auth)
        ET.indent(root, space="  ")
        xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        ET.fromstring(xml_bytes)
        (temporary / "scenario.xml").write_bytes(xml_bytes)
        (temporary / "canonical-model.json").write_text(
            json.dumps(model, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        injection_fields = ["username", "auth_secret"] if auth else []
        (temporary / "injection-schema.csv").write_text(
            "field,source,required,sensitive\n"
            + "".join(
                f"{field},secret-reference,true,true\n" for field in injection_fields
            ),
            encoding="utf-8",
        )
        template = "SEQUENTIAL\n"
        if auth:
            template += (
                f"${{secret:{auth_username_ref}}};"
                f"${{secret:{auth_secret_ref}}}\n"
            )
        (temporary / "injection-template.csv").write_text(template, encoding="utf-8")

        expectations = {
            "schema_version": "sippycup.expectations/v1",
            "capture": {"allowed_endpoints": ["127.0.0.1"]},
            "expectations": [
                {
                    "id": "learned-call-path",
                    "type": "call_path",
                    "on_unknown": "inconclusive",
                    "parameters": {
                        "require_bidirectional": True,
                        "expected_codecs": _codecs(model),
                        "require_dtmf": False,
                        "allow_symmetric_rtp": True,
                        "max_setup_ms": 5000,
                        "max_loss_fraction": 0.01,
                        "max_duplicates": 0,
                        "max_reordered": 0,
                        "max_jitter_ms": 30,
                        "timestamp_jump_tolerance_ms": 200,
                    },
                }
            ],
        }
        (temporary / "expectations.yaml").write_text(
            yaml.safe_dump(expectations, sort_keys=True), encoding="utf-8"
        )
        manifest = {
            "apiVersion": "sippycup.dev/learned-pack/v1",
            "review": {
                "reviewed": False,
                "reviewer": None,
                "reviewedAt": None,
                "sourcePeerApproved": False,
            },
            "target": {
                "host": "REPLACE_WITH_REVIEWED_TARGET.invalid",
                "port": 5060,
                "transport": "udp",
            },
            "limits": {"calls": 1, "concurrency": 1, "durationSeconds": 30},
            "scenario": "scenario.xml",
            "injection": "injection-template.csv",
            "expectations": "expectations.yaml",
        }
        (temporary / "manifest.yaml").write_text(
            yaml.safe_dump(manifest, sort_keys=True), encoding="utf-8"
        )
        canonical = json.dumps(model, sort_keys=True, separators=(",", ":")).encode()
        provenance = {
            "schema": "sippycup.learned-pack-provenance/v1",
            "canonicalModelSha256": hashlib.sha256(canonical).hexdigest(),
            "sourceFrames": model["provenance"]["sourceFrames"],
            "generatedFiles": {},
        }
        disposition = {
            "schema": "sippycup.field-disposition/v1",
            "kept": sorted(dispositions["kept"]),
            "parameterized": sorted(dispositions["parameterized"]),
            "removed": [
                "absolute timestamps", "captured endpoint addresses", "captured endpoint ports",
                "Call-ID", "tags", "branches", "CSeq numbers", "message lengths",
                "SIP identity headers", "Authorization and Proxy-Authorization values",
            ],
            "unsupported": sorted(dispositions["unsupported"]),
        }
        (temporary / "field-disposition.json").write_text(
            json.dumps(disposition, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (temporary / "README.md").write_text(_readme(bool(auth)), encoding="utf-8")
        media_source = _media_source()
        shutil.copytree(media_source, temporary / "media")
        (temporary / "media-assets.json").write_text(
            json.dumps({
                "schema": "sippycup.learned-media-references/v1",
                "authoritativeManifest": "media/manifest.json",
                "copyIntoPack": True,
            }, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        for path in sorted(temporary.rglob("*")):
            if path.is_file() and path.name != "provenance.json":
                name = path.relative_to(temporary).as_posix()
                provenance["generatedFiles"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
        (temporary / "provenance.json").write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        _lint_pack(temporary)
        os.replace(temporary, destination)
        return provenance
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _scenario(model, auth):
    root = ET.Element("scenario", {"name": "Sippycup learned dialog — REVIEW REQUIRED"})
    dispositions = {"kept": set(), "parameterized": set(), "unsupported": set()}
    challenge_seen = False
    virtual_clock_ms = 0
    for transaction in model["transactions"]:
        method, direction = transaction["method"], transaction["direction"]
        responses = transaction["responses"]
        desired = transaction.get("timingWindowMs", {}).get("earliest")
        if isinstance(desired, int) and desired > virtual_clock_ms:
            ET.SubElement(root, "pause", {"milliseconds": str(desired - virtual_clock_ms)})
            virtual_clock_ms = desired
        root.append(ET.Comment(
            f" {transaction['id']} source-frame={transaction.get('requestFrame')} "
            f"direction={direction} "
        ))
        if direction == "local-to-remote":
            send = ET.SubElement(root, "send", {"retrans": "500"})
            send.text = _request(
                method,
                include_auth=bool(auth and challenge_seen and method in {"INVITE", "REGISTER"}),
                media=_request_media(model, transaction),
            )
            virtual_clock_ms += 20
            for response in responses:
                status = response["status"]
                if status is None:
                    dispositions["unsupported"].add(f"{method} response with unknown status")
                    continue
                attributes = {"response": str(status), "timeout": "5000"}
                if response["optional"]:
                    attributes["optional"] = "true"
                if status in {401, 407}:
                    attributes["auth"] = "true"
                    challenge_seen = True
                ET.SubElement(root, "recv", attributes)
                virtual_clock_ms += 20
        else:
            ET.SubElement(root, "recv", {"request": method, "timeout": "5000"})
            virtual_clock_ms += 20
            for response in responses:
                if response["status"] is not None:
                    send = ET.SubElement(root, "send")
                    send.text = _response(int(response["status"]), method)
                    virtual_clock_ms += 20
        dispositions["kept"].update(("method", "response status/order", "direction"))
        dispositions["parameterized"].update(
            ("Call-ID", "tags", "branch", "CSeq", "Content-Length", "addresses", "ports")
        )
    ET.SubElement(root, "ResponseTimeRepartition", {"value": "10,20,50,100,150,500,1000,5000"})
    return root, dispositions


def _request(method: str, *, include_auth: bool, media: dict | None) -> str:
    lines = [
        f"{method} sip:[service]@[remote_ip]:[remote_port] SIP/2.0",
        "Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=z9hG4bK-[branch]",
        "From: <sip:sippycup@[local_ip]>;tag=[pid]-[call_number]",
        "To: <sip:[service]@[remote_ip]>",
        "Call-ID: [call_id]",
        f"CSeq: [cseq] {method}",
        "Contact: <sip:sippycup@[local_ip]:[local_port]>",
        "Max-Forwards: 70",
    ]
    if include_auth:
        lines.append("[authentication username=[field0] password=[field1]]")
    if media is not None:
        payloads = " ".join(str(value) for value in media["payloadTypes"])
        lines += [
            "Content-Type: application/sdp",
            "Content-Length: [len]",
            "",
            "v=0",
            "o=sippycup [pid] [call_number] IN IP4 [local_ip]",
            "s=sippycup",
            "c=IN IP4 [media_ip]",
            "t=0 0",
            f"m=audio [media_port] RTP/AVP {payloads}",
        ]
        for codec in media["codecs"]:
            lines.append(
                f"a=rtpmap:{codec['payloadType']} {codec['encoding']}/{codec['clockRate']}"
            )
            if str(codec["encoding"]).lower() == "telephone-event":
                lines.append(f"a=fmtp:{codec['payloadType']} 0-16")
        lines.append(f"a={media.get('direction') or 'sendrecv'}")
        if media.get("packetTimeMs") is not None:
            lines.append(f"a=ptime:{media['packetTimeMs']}")
    else:
        lines += ["Content-Length: [len]", ""]
    return "\r\n".join(lines) + "\r\n"


def _response(status: int, method: str) -> str:
    reason = {200: "OK", 481: "Call/Transaction Does Not Exist"}.get(status, "Response")
    return "\r\n".join((
        f"SIP/2.0 {status} {reason}",
        "Via: [last_Via:]",
        "From: [last_From:]",
        "To: [last_To:];tag=[pid]-remote",
        "Call-ID: [last_Call-ID:]",
        f"CSeq: [last_CSeq:]",
        "Content-Length: [len]",
        "", "",
    ))


def _auth_policy(model, username, secret):
    challenged = any(
        response.get("status") in {401, 407}
        for transaction in model["transactions"]
        for response in transaction["responses"]
    )
    if (username is None) != (secret is None):
        raise CanonicalizationError("auth", "both username and secret references are required")
    if username is not None:
        if not challenged:
            raise CanonicalizationError("auth", "authentication references require a learned challenge")
        if not REFERENCE.fullmatch(username) or not REFERENCE.fullmatch(secret):
            raise CanonicalizationError("auth", "secret references have an invalid name")
        return True
    return False


def _validate_model(model):
    if model.get("schema") != "sippycup.learned-dialog/v1":
        raise CanonicalizationError("schema", "unsupported canonical model")
    if not isinstance(model.get("transactions"), list) or not model["transactions"]:
        raise CanonicalizationError("schema", "canonical model has no transactions")
    if "provenance" not in model:
        raise CanonicalizationError("schema", "canonical model has no provenance")


def _codecs(model) -> list[str]:
    values = []
    for revision in model.get("sdpRevisions", []):
        for media in revision.get("media", []):
            for codec in media.get("codecs", []):
                encoding = codec.get("encoding")
                if encoding and encoding.lower() != "telephone-event" and encoding not in values:
                    values.append(encoding)
    return values or ["PCMU"]


def _request_media(model, transaction) -> dict | None:
    if not transaction.get("requestHasSdp"):
        return None
    for revision in model.get("sdpRevisions", []):
        if (
            revision.get("frame") == transaction.get("requestFrame")
            and revision.get("role") == "offer"
            and revision.get("media")
        ):
            return revision["media"][0]
    raise CanonicalizationError(
        "sdp", f"{transaction['id']} has SDP without a canonical offer revision"
    )


def _lint_pack(directory):
    root = ET.parse(directory / "scenario.xml").getroot()
    for wait in root.findall(".//recv"):
        if not wait.get("timeout"):
            raise CanonicalizationError("lint", "every receive must have a timeout")
    for pause in root.findall(".//pause"):
        value = pause.get("milliseconds")
        if value is None or not value.isdigit() or not 1 <= int(value) <= 5000:
            raise CanonicalizationError("lint", "every pause must be finite and bounded")
    text = ET.tostring(root, encoding="unicode")
    for forbidden in ("192.0.2.", "198.51.100.", "Authorization:", "Proxy-Authorization:"):
        if forbidden in text:
            raise CanonicalizationError("lint", f"scenario retained forbidden value: {forbidden}")
    for send in root.findall(".//send"):
        if send.text and "Content-Length:" in send.text and "Content-Length: [len]" not in send.text:
            raise CanonicalizationError("lint", "Content-Length is not dynamic")
    manifest = yaml.safe_load((directory / "manifest.yaml").read_text())
    if manifest["review"]["reviewed"] is not False or manifest["review"]["sourcePeerApproved"]:
        raise CanonicalizationError("lint", "generated manifest must begin unreviewed")


def _readme(auth: bool) -> str:
    auth_text = (
        "Digest is generated by SIPp from the received challenge. The CSV contains only "
        "named secret references; resolve them locally at execution time."
        if auth else
        "No authentication action was generated. If the target challenges, regenerate "
        "with reviewed named secret references."
    )
    return f"""# REVIEW REQUIRED — learned SIPp pack

This pack cannot run against the captured peer as generated. Edit
`manifest.yaml`, select an explicitly authorized target, review every field
disposition and traffic limit, then set the review fields in a frozen campaign
manifest. Defaults are one call, concurrency one, and 30 seconds.

Dynamic Call-ID, tags, branches, CSeq, message length, signaling/media
addresses, and ports are regenerated by SIPp. {auth_text}

Files:
- `scenario.xml`: annotated, finite-timeout SIPp flow.
- `canonical-model.json`: privacy-safe source behavior for offline semantic diff.
- `injection-schema.csv` / `injection-template.csv`: secret-reference contract.
- `expectations.yaml`: offline oracle expectations.
- `media-assets.json`: deterministic canary reference.
- `provenance.json`: source frames, model identity, and file hashes.
- `field-disposition.json`: kept, parameterized, removed, unsupported values.
"""


def _media_source() -> Path:
    candidates = (
        Path(__file__).resolve().parents[2] / "media" / "canary-v1",
        Path("/usr/local/share/sippycup/media/canary-v1"),
    )
    for candidate in candidates:
        if (candidate / "manifest.json").is_file():
            return candidate
    raise CanonicalizationError("media", "deterministic canary assets are not installed")
