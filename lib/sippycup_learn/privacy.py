"""Pack-level exact-value and credential-header privacy scan."""

from __future__ import annotations

import re
from pathlib import Path


CREDENTIAL = re.compile(
    rb"(?:Proxy-)?Authorization\s*:\s*(?!\[(?:authentication|field))[^\r\n]{1,4096}",
    re.IGNORECASE,
)


def scan_pack_privacy(pack: Path, *, forbidden_values: tuple[bytes, ...]) -> list[dict[str, object]]:
    findings = []
    for path in sorted(pack.rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        for value in forbidden_values:
            if value and value in data:
                findings.append({
                    "file": path.relative_to(pack).as_posix(),
                    "type": "captured-value",
                    "valueSha256": __import__("hashlib").sha256(value).hexdigest(),
                })
        if CREDENTIAL.search(data):
            findings.append({
                "file": path.relative_to(pack).as_posix(),
                "type": "credential-header-value",
            })
    return findings
