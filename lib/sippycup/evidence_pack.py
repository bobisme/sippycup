"""Portable evidence packs, external signing/encryption, and safe CI export."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
from typing import Any, Iterable
import xml.etree.ElementTree as ET

from .evidence import MANIFEST_NAME, MANIFEST_VERSION


PACK_VERSION = "sippycup.dev/evidence-pack/v1"
VERIFY_VERSION = "sippycup.dev/evidence-pack-verification/v1"
CI_VERSION = "sippycup.dev/evidence-ci-export/v1"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_MEMBERS = 10_000
CHUNK_BYTES = 1024 * 1024
IMAGE_DIGEST_PREFIX = "sha256:"


class EvidencePackError(ValueError):
    """Invalid pack input, output, or external-tool configuration."""


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, separators=(",", ": "))
        + "\n"
    ).encode()


def _safe_relative(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise EvidencePackError(f"unsafe artifact path {value!r}")
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise EvidencePackError(f"unsafe artifact path {value!r}")
    parsed = PurePosixPath(value)
    if parsed.is_absolute():
        raise EvidencePackError(f"unsafe artifact path {value!r}")
    return parsed.as_posix()


def _sha256_file(path: Path) -> tuple[int, str]:
    size = 0
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_BYTES):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _read_evidence_manifest(root: Path) -> tuple[dict[str, Any], bytes]:
    path = root / MANIFEST_NAME
    try:
        if path.is_symlink() or not path.is_file():
            raise EvidencePackError("evidence manifest must be a regular file")
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise EvidencePackError("evidence manifest exceeds 4 MiB")
        raw = path.read_bytes()
        value = json.loads(raw)
    except OSError as error:
        raise EvidencePackError(f"cannot read evidence manifest: {error}") from error
    except json.JSONDecodeError as error:
        raise EvidencePackError(f"invalid evidence manifest JSON: {error}") from error
    if not isinstance(value, dict) or value.get("apiVersion") != MANIFEST_VERSION:
        raise EvidencePackError("unsupported evidence manifest")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) > MAX_MEMBERS - 2:
        raise EvidencePackError("evidence manifest artifacts are invalid or excessive")
    return value, raw


def _validated_source_artifacts(
    root: Path, manifest: dict[str, Any], manifest_raw: bytes
) -> list[dict[str, Any]]:
    records = [
        {
            "path": MANIFEST_NAME,
            "mediaType": "application/json",
            "size": len(manifest_raw),
            "sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "provenance": "evidence-inventory",
            "sensitivity": "internal",
        }
    ]
    seen = {MANIFEST_NAME}
    for index, item in enumerate(manifest["artifacts"]):
        if not isinstance(item, dict) or set(item) != {
            "path",
            "mediaType",
            "size",
            "sha256",
            "provenance",
            "sensitivity",
        }:
            raise EvidencePackError(f"artifact {index} must be an object")
        relative = _safe_relative(item.get("path"))
        if relative in seen:
            raise EvidencePackError(f"duplicate declared artifact {relative}")
        seen.add(relative)
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise EvidencePackError(f"declared artifact is missing or not regular: {relative}")
        size, digest = _sha256_file(path)
        if size != item.get("size") or digest != item.get("sha256"):
            raise EvidencePackError(f"declared artifact content differs: {relative}")
        sensitivity = item.get("sensitivity")
        if sensitivity not in {"public", "internal", "confidential", "restricted"}:
            raise EvidencePackError(f"artifact sensitivity is invalid: {relative}")
        if (
            not isinstance(item.get("mediaType"), str)
            or not item["mediaType"]
            or not isinstance(item.get("provenance"), str)
            or not item["provenance"]
        ):
            raise EvidencePackError(f"artifact metadata is invalid: {relative}")
        records.append(
            {
                "path": relative,
                "mediaType": item.get("mediaType"),
                "size": size,
                "sha256": digest,
                "provenance": item.get("provenance"),
                "sensitivity": sensitivity,
            }
        )
    return records


def _pack_manifest(
    evidence: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    image_digest: str,
) -> dict[str, Any]:
    if (
        not isinstance(image_digest, str)
        or not image_digest.startswith(IMAGE_DIGEST_PREFIX)
        or len(image_digest) != len(IMAGE_DIGEST_PREFIX) + 64
        or any(character not in "0123456789abcdef" for character in image_digest[7:])
    ):
        raise EvidencePackError("image digest must be sha256:<64 lowercase hex>")
    return {
        "apiVersion": PACK_VERSION,
        "kind": "PortableEvidencePack",
        "contentIdentity": evidence.get("contentIdentity"),
        "artifacts": records,
        "supplyChain": {
            "imageDigest": image_digest,
            "sbom": {
                "format": "SPDX",
                "spdxVersion": "SPDX-2.3",
                "name": "sippycup-evidence-pack",
                "packages": [
                    {
                        "name": "sippycup",
                        "versionInfo": "workspace",
                        "downloadLocation": "NOASSERTION",
                    }
                ],
            },
        },
    }


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o600
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    return info


def _write_plain_pack(root: Path, output: Path, image_digest: str) -> dict[str, Any]:
    evidence, evidence_raw = _read_evidence_manifest(root)
    records = _validated_source_artifacts(root, evidence, evidence_raw)
    pack_manifest = _pack_manifest(evidence, records, image_digest=image_digest)
    encoded = _canonical_bytes(pack_manifest)
    with tarfile.open(output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(_tar_info("pack-manifest.json", len(encoded)), io.BytesIO(encoded))
        for item in records:
            source = root / item["path"]
            with source.open("rb") as data:
                archive.addfile(_tar_info(item["path"], item["size"]), data)
    return pack_manifest


def _run_external(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def create_evidence_pack(
    root: str | Path,
    output: str | Path,
    *,
    image_digest: str,
    recipients: Iterable[str] = (),
    age_executable: str = "age",
    runner=_run_external,
) -> dict[str, Any]:
    """Create a deterministic plain pack or recipient-encrypted age output."""
    root = Path(root).resolve(strict=True)
    output = Path(output).resolve()
    if not root.is_dir():
        raise EvidencePackError("evidence root must be a directory")
    if output.exists():
        raise EvidencePackError("pack output must not exist")
    output.parent.mkdir(parents=True, exist_ok=True)
    recipient_list = list(recipients)
    if any(not isinstance(item, str) or not item.strip() for item in recipient_list):
        raise EvidencePackError("age recipients must be non-empty strings")
    temporary_root = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent)
    )
    temporary_root.chmod(0o700)
    try:
        plain = temporary_root / "plaintext-pack.tar"
        manifest = _write_plain_pack(root, plain, image_digest)
        if recipient_list:
            encrypted = temporary_root / "encrypted.age"
            command = [age_executable]
            for recipient in recipient_list:
                command.extend(["-r", recipient])
            command.extend(["-o", str(encrypted), str(plain)])
            try:
                completed = runner(command)
            except OSError as error:
                raise EvidencePackError(f"cannot execute age: {error}") from error
            if completed.returncode != 0 or not encrypted.is_file():
                raise EvidencePackError(
                    "age encryption failed: " + completed.stderr.strip()
                )
            os.replace(encrypted, output)
        else:
            os.replace(plain, output)
        output.chmod(0o600)
        return {
            "apiVersion": PACK_VERSION,
            "contentIdentity": manifest["contentIdentity"],
            "output": str(output),
            "encrypted": bool(recipient_list),
            "recipientCount": len(recipient_list),
        }
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)


def sign_evidence_pack(
    pack: str | Path,
    secret_key: str | Path,
    signature: str | Path | None = None,
    *,
    minisign_executable: str = "minisign",
    runner=_run_external,
) -> Path:
    """Ask external minisign to sign an existing pack; never read or create keys."""
    pack = Path(pack).resolve(strict=True)
    key = Path(secret_key).resolve(strict=True)
    destination = (
        Path(signature).resolve()
        if signature is not None
        else Path(str(pack) + ".minisig")
    )
    if not pack.is_file() or not key.is_file():
        raise EvidencePackError("pack and minisign secret key must be regular files")
    if destination.exists():
        raise EvidencePackError("signature output must not exist")
    try:
        completed = runner(
            [
                minisign_executable,
                "-S",
                "-s",
                str(key),
                "-m",
                str(pack),
                "-x",
                str(destination),
            ]
        )
    except OSError as error:
        raise EvidencePackError(f"cannot execute minisign: {error}") from error
    if completed.returncode != 0 or not destination.is_file():
        destination.unlink(missing_ok=True)
        raise EvidencePackError("minisign signing failed: " + completed.stderr.strip())
    destination.chmod(0o600)
    return destination


def _manifest_from_archive(
    archive: tarfile.TarFile, members: list[tarfile.TarInfo]
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    names: set[str] = set()
    for member in members:
        try:
            name = _safe_relative(member.name)
        except EvidencePackError as error:
            errors.append(str(error))
            continue
        if name in names:
            errors.append(f"duplicate archive member: {name}")
        names.add(name)
        if not member.isfile():
            errors.append(f"archive member is not a regular file: {name}")
        if (
            member.mode != 0o600
            or member.uid != 0
            or member.gid != 0
            or member.uname != ""
            or member.gname != ""
            or member.mtime != 0
        ):
            errors.append(f"archive member metadata is non-canonical: {name}")
    matches = [item for item in members if item.name == "pack-manifest.json"]
    if len(matches) != 1 or not matches[0].isfile():
        errors.append("archive must contain one regular pack-manifest.json")
        return None, errors
    if matches[0].size > MAX_MANIFEST_BYTES:
        errors.append("pack manifest exceeds 4 MiB")
        return None, errors
    source = archive.extractfile(matches[0])
    try:
        value = json.load(source) if source is not None else None
    except json.JSONDecodeError as error:
        errors.append(f"invalid pack manifest JSON: {error}")
        return None, errors
    if not isinstance(value, dict) or value.get("apiVersion") != PACK_VERSION:
        errors.append("unsupported pack manifest")
        return None, errors
    if set(value) != {
        "apiVersion",
        "kind",
        "contentIdentity",
        "artifacts",
        "supplyChain",
    } or value.get("kind") != "PortableEvidencePack":
        errors.append("pack manifest has invalid fields")
    artifact_values = value.get("artifacts")
    if isinstance(artifact_values, list) and all(
        isinstance(item, dict) and isinstance(item.get("path"), str)
        for item in artifact_values
    ):
        expected_order = [
            "pack-manifest.json",
            *(item["path"] for item in artifact_values),
        ]
        if [item.name for item in members] != expected_order:
            errors.append("archive member order differs from canonical pack")
    identity = value.get("contentIdentity")
    if (
        not isinstance(identity, str)
        or not identity.startswith("sha256:")
        or len(identity) != 71
        or any(character not in "0123456789abcdef" for character in identity[7:])
    ):
        errors.append("pack content identity is invalid")
    supply_chain = value.get("supplyChain")
    if not isinstance(supply_chain, dict) or set(supply_chain) != {
        "imageDigest",
        "sbom",
    }:
        errors.append("pack supply-chain record is invalid")
    else:
        digest = supply_chain.get("imageDigest")
        sbom = supply_chain.get("sbom")
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or len(digest) != 71
            or any(character not in "0123456789abcdef" for character in digest[7:])
        ):
            errors.append("pack image digest is invalid")
        if (
            not isinstance(sbom, dict)
            or sbom.get("format") != "SPDX"
            or sbom.get("spdxVersion") != "SPDX-2.3"
            or not isinstance(sbom.get("packages"), list)
            or not sbom["packages"]
        ):
            errors.append("pack SBOM record is invalid")
    return value, errors


def _verify_content(pack: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        with tarfile.open(pack, mode="r:*") as archive:
            members = archive.getmembers()
            if len(members) > MAX_MEMBERS:
                return None, ["archive contains too many members"]
            manifest, errors = _manifest_from_archive(archive, members)
            if manifest is None:
                return None, sorted(set(errors))
            artifacts = manifest.get("artifacts")
            if not isinstance(artifacts, list):
                errors.append("pack manifest artifacts must be an array")
                return manifest, sorted(set(errors))
            declared: dict[str, dict[str, Any]] = {}
            for item in artifacts:
                if not isinstance(item, dict) or set(item) != {
                    "path",
                    "mediaType",
                    "size",
                    "sha256",
                    "provenance",
                    "sensitivity",
                }:
                    errors.append("declared artifact must be an object")
                    continue
                try:
                    relative = _safe_relative(item.get("path"))
                except EvidencePackError as error:
                    errors.append(str(error))
                    continue
                if relative == "pack-manifest.json" or relative in declared:
                    errors.append(f"duplicate or reserved declared artifact: {relative}")
                    continue
                if (
                    not isinstance(item.get("mediaType"), str)
                    or not item["mediaType"]
                    or not isinstance(item.get("provenance"), str)
                    or not item["provenance"]
                    or item.get("sensitivity")
                    not in {"public", "internal", "confidential", "restricted"}
                ):
                    errors.append(f"invalid declared metadata: {relative}")
                declared[relative] = item
            actual = {
                member.name: member
                for member in members
                if member.name != "pack-manifest.json" and member.isfile()
            }
            for missing in sorted(set(declared) - set(actual)):
                errors.append(f"missing declared artifact: {missing}")
            for extra in sorted(set(actual) - set(declared)):
                errors.append(f"undeclared archive member: {extra}")
            for relative in sorted(set(declared) & set(actual)):
                item, member = declared[relative], actual[relative]
                expected_size, expected_digest = item.get("size"), item.get("sha256")
                if type(expected_size) is not int or expected_size < 0:
                    errors.append(f"invalid declared size: {relative}")
                    continue
                if member.size != expected_size:
                    errors.append(f"artifact size differs: {relative}")
                    continue
                source = archive.extractfile(member)
                digest, size = hashlib.sha256(), 0
                if source is None:
                    errors.append(f"artifact cannot be read: {relative}")
                    continue
                while chunk := source.read(CHUNK_BYTES):
                    size += len(chunk)
                    digest.update(chunk)
                if size != expected_size or digest.hexdigest() != expected_digest:
                    errors.append(f"artifact hash differs: {relative}")
            evidence_member = actual.get(MANIFEST_NAME)
            if evidence_member is None or evidence_member.size > MAX_MANIFEST_BYTES:
                errors.append("embedded evidence manifest is missing or excessive")
            else:
                source = archive.extractfile(evidence_member)
                try:
                    evidence_raw = source.read() if source is not None else b""
                    evidence = json.loads(evidence_raw)
                except json.JSONDecodeError as error:
                    errors.append(f"invalid embedded evidence manifest: {error}")
                else:
                    if (
                        not isinstance(evidence, dict)
                        or evidence.get("apiVersion") != MANIFEST_VERSION
                        or not isinstance(evidence.get("artifacts"), list)
                        or not isinstance(evidence.get("missingExpected"), list)
                    ):
                        errors.append("embedded evidence manifest has invalid structure")
                    else:
                        identity_input = {
                            "schema": MANIFEST_VERSION,
                            "artifacts": evidence["artifacts"],
                            "missingExpected": evidence["missingExpected"],
                        }
                        identity = "sha256:" + hashlib.sha256(
                            json.dumps(
                                identity_input,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode()
                        ).hexdigest()
                        if evidence.get("contentIdentity") != identity:
                            errors.append("embedded evidence content identity differs")
                        if manifest.get("contentIdentity") != identity:
                            errors.append("pack content identity differs")
                        expected_records = [
                            {
                                "path": MANIFEST_NAME,
                                "mediaType": "application/json",
                                "size": len(evidence_raw),
                                "sha256": hashlib.sha256(evidence_raw).hexdigest(),
                                "provenance": "evidence-inventory",
                                "sensitivity": "internal",
                            },
                            *evidence["artifacts"],
                        ]
                        if artifacts != expected_records:
                            errors.append(
                                "pack artifact inventory differs from embedded evidence"
                            )
            return manifest, sorted(set(errors))
    except (OSError, tarfile.TarError) as error:
        return None, [f"invalid evidence archive: {error}"]


def verify_evidence_pack(
    pack: str | Path,
    *,
    signature: str | Path | None = None,
    public_key: str | Path | None = None,
    minisign_executable: str = "minisign",
    runner=_run_external,
) -> dict[str, Any]:
    """Verify content offline and optionally verify an external minisign signature."""
    pack = Path(pack).resolve(strict=True)
    if not pack.is_file():
        raise EvidencePackError("pack must be a regular file")
    if (signature is None) != (public_key is None):
        raise EvidencePackError("signature and public key must be supplied together")
    signature_status = "not-checked"
    signature_error = None
    if signature is not None and public_key is not None:
        signature_path = Path(signature).resolve(strict=True)
        key_path = Path(public_key).resolve(strict=True)
        if not signature_path.is_file() or not key_path.is_file():
            raise EvidencePackError("signature and public key must be regular files")
        try:
            completed = runner(
                [
                    minisign_executable,
                    "-V",
                    "-p",
                    str(key_path),
                    "-m",
                    str(pack),
                    "-x",
                    str(signature_path),
                ]
            )
        except OSError as error:
            raise EvidencePackError(f"cannot execute minisign: {error}") from error
        if completed.returncode == 0:
            signature_status = "valid"
        else:
            signature_status = "invalid"
            signature_error = completed.stderr.strip() or "minisign rejected signature"
    manifest, errors = _verify_content(pack)
    content_status = "valid" if not errors else "invalid"
    if content_status == "invalid":
        verdict = "content-failure"
    elif signature_status == "invalid":
        verdict = "signature-failure"
    else:
        verdict = "pass"
    return {
        "apiVersion": VERIFY_VERSION,
        "kind": "EvidencePackVerification",
        "verdict": verdict,
        "content": {"status": content_status, "errors": errors},
        "signature": {
            "status": signature_status,
            "error": signature_error,
        },
        "contentIdentity": manifest.get("contentIdentity") if manifest else None,
        "supplyChain": manifest.get("supplyChain") if manifest else None,
    }


def render_verification_json(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def render_verification_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Sippycup evidence verification",
        "",
        f"- Verdict: **{result['verdict']}**",
        f"- Content: `{result['content']['status']}`",
        f"- Signature: `{result['signature']['status']}`",
        f"- Content identity: `{result['contentIdentity'] or 'unavailable'}`",
    ]
    for error in result["content"]["errors"]:
        lines.append(f"- Content error: `{error}`")
    if result["signature"]["error"]:
        lines.append(f"- Signature error: `{result['signature']['error']}`")
    return "\n".join(lines) + "\n"


def render_verification_junit(result: dict[str, Any]) -> str:
    suite = ET.Element(
        "testsuite",
        {
            "name": "sippycup.evidence-pack",
            "tests": "1",
            "failures": "0" if result["verdict"] == "pass" else "1",
        },
    )
    case = ET.SubElement(suite, "testcase", {"name": "portable-pack-verification"})
    if result["verdict"] != "pass":
        failure = ET.SubElement(
            case,
            "failure",
            {"type": result["verdict"], "message": result["verdict"]},
        )
        failure.text = render_verification_markdown(result)
    return ET.tostring(suite, encoding="unicode", xml_declaration=True) + "\n"


def _archive_artifact(pack: Path, relative: str, destination: Path) -> None:
    with tarfile.open(pack, mode="r:*") as archive:
        matches = [item for item in archive.getmembers() if item.name == relative]
        if len(matches) != 1 or not matches[0].isfile():
            raise EvidencePackError(f"selected artifact is unavailable: {relative}")
        source = archive.extractfile(matches[0])
        if source is None:
            raise EvidencePackError(f"selected artifact cannot be read: {relative}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as output:
            shutil.copyfileobj(source, output, CHUNK_BYTES)
        destination.chmod(0o600)


def _embedded_privacy_status(pack: Path) -> str:
    with tarfile.open(pack, mode="r:*") as archive:
        matches = [
            item
            for item in archive.getmembers()
            if item.name == MANIFEST_NAME and item.isfile()
        ]
        if len(matches) != 1 or matches[0].size > MAX_MANIFEST_BYTES:
            raise EvidencePackError("embedded evidence manifest is unavailable")
        source = archive.extractfile(matches[0])
        try:
            value = json.load(source) if source is not None else None
        except json.JSONDecodeError as error:
            raise EvidencePackError(
                f"invalid embedded evidence manifest: {error}"
            ) from error
    privacy = value.get("privacy") if isinstance(value, dict) else None
    status = privacy.get("status") if isinstance(privacy, dict) else None
    if status not in {"pass", "blocked"}:
        raise EvidencePackError("embedded privacy status is invalid")
    return status


def export_ci(
    pack: str | Path,
    output: str | Path,
    *,
    include_artifacts: Iterable[str] = (),
    allow_privacy_findings: bool = False,
) -> dict[str, Any]:
    """Write portable CI reports and only explicitly selected source artifacts."""
    pack = Path(pack).resolve(strict=True)
    output = Path(output).resolve()
    if output.exists():
        raise EvidencePackError("CI export output must not exist")
    output.parent.mkdir(parents=True, exist_ok=True)
    result = verify_evidence_pack(pack)
    if result["verdict"] != "pass":
        raise EvidencePackError("cannot export CI reports from an invalid pack")
    privacy_status = _embedded_privacy_status(pack)
    if privacy_status == "blocked" and not allow_privacy_findings:
        raise EvidencePackError(
            "privacy findings block default CI export; explicit acknowledgement required"
        )
    manifest, errors = _verify_content(pack)
    if manifest is None or errors:
        raise EvidencePackError("cannot read verified pack manifest")
    declared = {item["path"]: item for item in manifest["artifacts"]}
    selected = []
    seen = set()
    for value in include_artifacts:
        relative = _safe_relative(value)
        if relative in seen:
            raise EvidencePackError(f"duplicate selected artifact: {relative}")
        if relative not in declared:
            raise EvidencePackError(f"selected artifact is undeclared: {relative}")
        seen.add(relative)
        selected.append(declared[relative])
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        (temporary / "verification.json").write_text(render_verification_json(result))
        (temporary / "verification.md").write_text(render_verification_markdown(result))
        (temporary / "verification.junit.xml").write_text(render_verification_junit(result))
        for item in selected:
            _archive_artifact(
                pack, item["path"], temporary / "artifacts" / item["path"]
            )
        export_manifest = {
            "apiVersion": CI_VERSION,
            "kind": "EvidenceCiExport",
            "verificationVerdict": result["verdict"],
            "privacyStatus": privacy_status,
            "privacyFindingsAcknowledged": bool(
                privacy_status == "blocked" and allow_privacy_findings
            ),
            "includedArtifacts": [
                {
                    "path": item["path"],
                    "sha256": item["sha256"],
                    "sensitivity": item["sensitivity"],
                    "explicitlySelected": True,
                }
                for item in selected
            ],
        }
        (temporary / "ci-export.json").write_bytes(_canonical_bytes(export_manifest))
        os.replace(temporary, output)
        return export_manifest
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
