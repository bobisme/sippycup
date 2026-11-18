"""Privacy controls for the owner-facing engagement report.

Two layers, both offline:

1. ``Sanitizer.text`` cleans every string that came from a run artifact
   before it enters the report model: control and bidi-override characters
   are stripped, credential material, Digest parameters, Call-ID headers, SIP
   URIs, phone numbers, long digit runs, and high-entropy tokens are replaced
   with labels, and every literal address that is not an approved target is
   replaced with ``unapproved-address-N`` and recorded as an integrity
   exception.
2. ``lint_model`` and ``lint_text`` re-check the finished model and every
   rendering with the evidence privacy patterns from
   ``sippycup.evidence``. Any hit fails the whole report closed; the caller
   writes nothing and names the offending field path (never the value).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable

from sippycup.evidence import (
    ASCII_ADDRESS,
    AUTHORIZATION,
    CALL_ID,
    PHONE_IDENTIFIER,
    SIP_USER,
)

MAX_TEXT_CHARS = 600

# Characters that reorder or hide text without being visible themselves.
_BIDI_AND_INVISIBLE = {
    "؜",
    "​",
    "‌",
    "‍",
    "‎",
    "‏",
    "‪",
    "‫",
    "‬",
    "‭",
    "‮",
    "⁠",
    "⁦",
    "⁧",
    "⁨",
    "⁩",
    "﻿",
}

_AUTH_LINE = re.compile(
    r"(?i)\b(?:proxy-)?(?:www-)?auth(?:orization|enticate)\b\s*[:=]\s*.*"
)
_DIGEST = re.compile(
    r"(?i)\bdigest\s+(?=[A-Za-z]+\s*=).*"
    r"|\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"
    r"|\bbasic\s+[A-Za-z0-9+/]{8,}={0,2}"
)
_DIGEST_PARAM = re.compile(
    r"(?i)\b(response|nonce|cnonce|opaque|nc|qop|username|realm|uri)\s*=\s*"
    r"(?:\"[^\"]*\"?|[^\s,;]+)"
)
_SECRET_KV = re.compile(
    r"(?i)\b(password|passwd|passphrase|pwd|secret|token|api[_-]?key|"
    r"credential|private[_-]?key)\b(\s*[:=]\s*)(\"[^\"]*\"?|'[^']*'?|\S+)"
)
_CALL_ID_TEXT = re.compile(r"(?i)\bcall-?id\b\s*[:=]\s*\S+")
_SIP_URI = re.compile(r"(?i)\b(?:sips?|tel):[^\s<>\"'|,;)]+")
_PHONE_TEXT = re.compile(r"(?<![0-9])\+[0-9][0-9() .-]{5,}[0-9](?![0-9])")
_LONG_DIGITS = re.compile(r"(?<![0-9.:])[0-9]{7,}(?![0-9.:])")
_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{16,}")
_IDENTIFIER = re.compile(r"[^A-Za-z0-9._:\[\]/-]")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")

# Rendered-output lint (str patterns mirroring sippycup.evidence and the
# sanitizer's credential rules).
_LINT_DIGEST_PARAM = re.compile(
    r"(?i)\b(?:response|nonce|cnonce|opaque)\s*=\s*\"?(?!\\?\[redacted)[A-Za-z0-9+/=_-]{4,}"
)
_LINT_SECRET_KV = re.compile(
    r"(?i)\b(?:password|passwd|passphrase|secret|api[_-]?key)\b\s*[:=]\s*"
    r"(?!\\?\[redacted)[\"']?[^\s\"'<&|]{3,}"
)
_LINT_DIGEST = re.compile(r"(?i)\bdigest\s+(?:username|realm|nonce|response)\s*=")


def strip_controls(value: str) -> str:
    """Remove control, bidi-override, and invisible format characters."""
    output = []
    for character in value:
        if character in "\t\r\n":
            output.append(" ")
            continue
        if character in _BIDI_AND_INVISIBLE:
            continue
        category = unicodedata.category(character)
        if category in {"Cc", "Cs", "Co", "Cn"}:
            continue
        output.append(character)
    return re.sub(r" {2,}", " ", "".join(output)).strip()


def short_hash(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:length]


def _high_entropy(token: str) -> bool:
    if _HEX_DIGEST.fullmatch(token.lower()) and token == token.lower():
        return False
    classes = sum(
        (
            any(c.islower() for c in token),
            any(c.isupper() for c in token),
            any(c.isdigit() for c in token),
        )
    )
    if classes < 3:
        # Lowercase words joined by dashes, or long hex digests, are not
        # secrets; a mixed-case-and-digit token of this length usually is.
        return False
    return True


@dataclass
class AddressBook:
    """Approved literal addresses and networks, plus pseudonyms for the rest."""

    networks: list[Any] = field(default_factory=list)
    assessor: set[str] = field(default_factory=set)
    pseudonyms: dict[str, str] = field(default_factory=dict)

    def add_network(self, value: str) -> bool:
        try:
            network = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError:
            return False
        if network not in self.networks:
            self.networks.append(network)
        return True

    def approved(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(
            address.version == network.version and address in network
            for network in self.networks
        )

    def label(self, value: str) -> str:
        """Approved addresses are shown; everything else gets a stable label."""
        try:
            canonical = str(ipaddress.ip_address(value))
        except ValueError:
            return value
        if self.approved(canonical):
            return canonical
        if canonical in self.assessor:
            return "assessor-address"
        if canonical not in self.pseudonyms:
            self.pseudonyms[canonical] = f"unapproved-address-{len(self.pseudonyms) + 1}"
        return self.pseudonyms[canonical]


@dataclass
class Sanitizer:
    addresses: AddressBook
    run_names: set[str] = field(default_factory=set)
    forbidden: tuple[str, ...] = ()
    # (field path, address label) pairs for addresses outside the approved set.
    unapproved_hits: list[tuple[str, str]] = field(default_factory=list)
    redactions: int = 0

    def _replace_addresses(self, value: str, path: str) -> str:
        def replace(match: re.Match[str]) -> str:
            text = match.group()
            try:
                canonical = str(ipaddress.ip_address(text))
            except ValueError:
                return text
            label = self.addresses.label(canonical)
            if label.startswith("unapproved-address-"):
                self.unapproved_hits.append((path, label))
            return label

        pattern = re.compile(ASCII_ADDRESS.pattern.decode("ascii"))
        return pattern.sub(replace, value)

    def text(self, value: Any, path: str, *, limit: int = MAX_TEXT_CHARS) -> str | None:
        """Clean one artifact-derived string for the report model."""
        if value is None:
            return None
        if not isinstance(value, str):
            value = str(value)
        original = value
        value = strip_controls(value)
        # Run directory names are report identifiers, not secrets: shield them
        # from the digit and entropy rules and restore them afterwards.
        shielded: dict[str, str] = {}
        for index, name in enumerate(sorted(self.run_names, key=len, reverse=True)):
            if name and name in value:
                marker = f"RUNREF{index:04d}MARK"
                shielded[marker] = name
                value = value.replace(name, marker)
        for secret in self.forbidden:
            if secret and secret in value:
                value = value.replace(secret, "[secret redacted]")
        value = _AUTH_LINE.sub("[authorization redacted]", value)
        value = _DIGEST.sub("[credential redacted]", value)
        value = _DIGEST_PARAM.sub(lambda m: f"{m.group(1)}=[redacted]", value)
        value = _SECRET_KV.sub(lambda m: f"{m.group(1)}=[redacted]", value)
        value = _CALL_ID_TEXT.sub("Call-ID=[redacted]", value)
        value = _SIP_URI.sub("[sip-uri]", value)
        value = _PHONE_TEXT.sub("[phone]", value)
        value = self._replace_addresses(value, path)
        value = _LONG_DIGITS.sub("[number]", value)

        def token(match: re.Match[str]) -> str:
            text = match.group()
            if "RUNREF" in text and re.fullmatch(r"(?:[A-Za-z0-9+/=_-]*RUNREF[0-9]{4}MARK[A-Za-z0-9+/=_-]*)", text):
                parts = re.split(r"RUNREF[0-9]{4}MARK", text)
                if all(not part or not _high_entropy(part) for part in parts):
                    return text
            return "[token]" if _high_entropy(text) else text

        value = _TOKEN.sub(token, value)
        for marker, name in shielded.items():
            value = value.replace(marker, name)
        if len(value) > limit:
            value = value[: limit - 1].rstrip() + "…"
        if value != strip_controls(original):
            self.redactions += 1
        return value

    def identifier(self, value: Any, path: str, *, limit: int = 128) -> str | None:
        """A short machine identifier: keep only a safe character set."""
        if value is None:
            return None
        cleaned = self.text(value, path, limit=limit)
        if cleaned is None:
            return None
        return _IDENTIFIER.sub("_", cleaned)[:limit] or "_"


# --------------------------------------------------------------------------
# Lint (fail closed)


@dataclass(frozen=True)
class LintHit:
    path: str
    code: str

    def as_dict(self) -> dict[str, str]:
        return {"path": self.path, "code": self.code}


def lint_string(
    value: str,
    *,
    addresses: AddressBook,
    forbidden: Iterable[str] = (),
    allow_call_ids: bool = False,
) -> list[str]:
    codes: list[str] = []
    data = value.encode("utf-8", "replace")
    if AUTHORIZATION.search(data) or _LINT_DIGEST.search(value):
        codes.append("authorization-material")
    if _LINT_DIGEST_PARAM.search(value):
        codes.append("digest-parameter")
    if _LINT_SECRET_KV.search(value):
        codes.append("credential-assignment")
    if not allow_call_ids and CALL_ID.search(data):
        codes.append("call-id")
    if SIP_USER.search(data) or PHONE_IDENTIFIER.search(data):
        codes.append("subscriber-identifier")
    for match in ASCII_ADDRESS.finditer(data):
        try:
            canonical = str(ipaddress.ip_address(match.group().decode()))
        except ValueError:
            continue
        if not addresses.approved(canonical):
            codes.append("unapproved-address")
            break
    for secret in forbidden:
        if secret and secret in value:
            codes.append("forbidden-secret")
            break
    if any(character in _BIDI_AND_INVISIBLE for character in value) or any(
        unicodedata.category(character) == "Cc" and character not in "\n\t"
        for character in value
    ):
        codes.append("control-character")
    return codes


def lint_model(
    value: Any,
    *,
    addresses: AddressBook,
    forbidden: Iterable[str] = (),
    allow_call_ids: bool = False,
    path: str = "$",
) -> list[LintHit]:
    forbidden = tuple(forbidden)
    hits: list[LintHit] = []
    if isinstance(value, dict):
        for key in sorted(value):
            child = f"{path}.{key}"
            for code in lint_string(
                str(key), addresses=addresses, forbidden=forbidden, allow_call_ids=allow_call_ids
            ):
                hits.append(LintHit(child + "(key)", code))
            hits.extend(
                lint_model(
                    value[key],
                    addresses=addresses,
                    forbidden=forbidden,
                    allow_call_ids=allow_call_ids,
                    path=child,
                )
            )
    elif isinstance(value, list):
        for index, item in enumerate(value):
            hits.extend(
                lint_model(
                    item,
                    addresses=addresses,
                    forbidden=forbidden,
                    allow_call_ids=allow_call_ids,
                    path=f"{path}[{index}]",
                )
            )
    elif isinstance(value, str):
        for code in lint_string(
            value, addresses=addresses, forbidden=forbidden, allow_call_ids=allow_call_ids
        ):
            hits.append(LintHit(path, code))
    return hits


def lint_text(
    name: str,
    text: str,
    *,
    addresses: AddressBook,
    forbidden: Iterable[str] = (),
    allow_call_ids: bool = False,
) -> list[LintHit]:
    forbidden = tuple(forbidden)
    hits: list[LintHit] = []
    for number, line in enumerate(text.split("\n"), 1):
        for code in lint_string(
            line, addresses=addresses, forbidden=forbidden, allow_call_ids=allow_call_ids
        ):
            hits.append(LintHit(f"{name}:line {number}", code))
    # Multi-line patterns (headers) are anchored per line above; also scan the
    # whole text once for anything a line split could hide.
    data = text.encode("utf-8", "replace")
    if AUTHORIZATION.search(data) and not any(h.code == "authorization-material" for h in hits):
        hits.append(LintHit(f"{name}:document", "authorization-material"))
    return hits
