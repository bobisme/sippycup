"""Privacy-safe scenario learning from packet-oracle records."""

from .canonical import CanonicalizationError, canonicalize_dialog
from .diff import (
    compare_behavior_packs,
    load_behavior_pack,
    normalize_behavior_pack,
    render_diff_human,
    render_diff_json,
    render_diff_junit,
)
from .generate import generate_pack
from .validate import validate_pack
from .privacy import scan_pack_privacy

__all__ = [
    "CanonicalizationError",
    "canonicalize_dialog",
    "compare_behavior_packs",
    "generate_pack",
    "load_behavior_pack",
    "normalize_behavior_pack",
    "render_diff_human",
    "render_diff_json",
    "render_diff_junit",
    "scan_pack_privacy",
    "validate_pack",
]
