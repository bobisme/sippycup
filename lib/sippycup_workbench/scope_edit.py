"""Change answers in a scope file's YAML text while keeping everything else.

PyYAML (the only YAML library here) cannot round-trip comments: loading and
dumping a document drops them. This module therefore edits the TEXT: it uses
PyYAML's node positions (``yaml.compose``) to find the value of one key and
replaces only that span, or inserts one new key. Comments, blank lines, key
order, and every answer that is not being changed stay byte for byte.

Every edit is verified: the new text is parsed again and must equal the
intended document exactly. When the text edit cannot produce that (an unusual
layout), ``apply_edits`` falls back to dumping the whole document, which
loses comments; the caller is told so (``comments_kept`` is False) and keeps a
backup of the old file.

Values are written in YAML flow style for scalars, lists of scalars, and small
mappings (``[udp, tls]``, ``{start: 20000, end: 20019}``), and in block style
for lists of mappings (``targets``, ``destinations``), like the examples.
"""

from __future__ import annotations

import copy
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

INLINE_WIDTH = 100


class EditError(ValueError):
    """The text edit cannot be made safely; the caller falls back."""


def render_inline(value: Any) -> str:
    """One value in flow style, safe inside a flow collection or after ``key:``."""
    dumped = yaml.safe_dump(
        [value], default_flow_style=True, width=1 << 20, allow_unicode=True, sort_keys=False
    ).strip()
    if not (dumped.startswith("[") and dumped.endswith("]")):
        raise EditError("unexpected flow rendering")
    return dumped[1:-1].strip()


def _scalar(value: Any) -> bool:
    return not isinstance(value, (dict, list))


def is_inline(value: Any) -> bool:
    if _scalar(value):
        return True
    if isinstance(value, list):
        return all(_scalar(item) for item in value) and len(render_inline(value)) <= INLINE_WIDTH
    return all(
        _scalar(item) or (isinstance(item, list) and all(_scalar(sub) for sub in item))
        for item in value.values()
    ) and len(render_inline(value)) <= INLINE_WIDTH


def render_block(value: Any, indent: int) -> list[str]:
    """Block-style lines for a list of mappings or a nested mapping."""
    pad = " " * indent
    lines: list[str] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and item:
                first = True
                for key, sub in item.items():
                    lead = f"{pad}- " if first else f"{pad}  "
                    first = False
                    if is_inline(sub):
                        lines.append(f"{lead}{render_inline(key)}: {render_inline(sub)}")
                    else:
                        lines.append(f"{lead}{render_inline(key)}:")
                        lines.extend(render_block(sub, indent + 4))
            else:
                lines.append(f"{pad}- {render_inline(item)}")
        return lines
    if isinstance(value, dict):
        for key, sub in value.items():
            if is_inline(sub):
                lines.append(f"{pad}{render_inline(key)}: {render_inline(sub)}")
            else:
                lines.append(f"{pad}{render_inline(key)}:")
                lines.extend(render_block(sub, indent + 2))
        return lines
    return [f"{pad}{render_inline(value)}"]


def _empty_scalar(node: Node) -> bool:
    return isinstance(node, ScalarNode) and node.value == "" and node.style is None


def _colon_after(text: str, key_node: Node) -> int:
    index = key_node.end_mark.index
    while index < len(text) and text[index] in " \t":
        index += 1
    if index >= len(text) or text[index] != ":":
        raise EditError("key is not followed by a colon")
    return index


def _content_end(text: str, node: Node) -> int:
    """Index just after the last character of a node's own content."""
    if isinstance(node, ScalarNode):
        end = node.end_mark.index
        if node.style in ("|", ">"):
            while end > 0 and text[end - 1] in " \t\r\n":
                end -= 1
        return end
    if getattr(node, "flow_style", False):
        return node.end_mark.index
    if isinstance(node, MappingNode):
        if not node.value:
            return node.end_mark.index
        key, value = node.value[-1]
        if _empty_scalar(value):
            return _colon_after(text, key) + 1
        return _content_end(text, value)
    if isinstance(node, SequenceNode):
        if not node.value:
            return node.end_mark.index
        return _content_end(text, node.value[-1])
    raise EditError("unsupported node")


def _line_end(text: str, index: int) -> int:
    end = text.find("\n", index)
    return len(text) if end < 0 else end


def _find(mapping: MappingNode, key: str) -> tuple[Node, Node] | None:
    for key_node, value_node in mapping.value:
        if isinstance(key_node, ScalarNode) and key_node.value == key:
            return key_node, value_node
    return None


def _nest(path: tuple[str, ...], value: Any) -> Any:
    for key in reversed(path):
        value = {key: value}
    return value


def _comment(segment: str) -> str:
    stripped = segment.strip()
    return stripped if stripped.startswith("#") else ""


def _replace(text: str, key_node: Node, value_node: Node, value: Any) -> str:
    column = key_node.start_mark.column
    colon = _colon_after(text, key_node)
    inline = is_inline(value)
    if _empty_scalar(value_node):
        start = end = colon + 1
        same_line = True
    else:
        start = value_node.start_mark.index
        end = _content_end(text, value_node)
        same_line = "\n" not in text[colon:start]
    if same_line:
        # key: OLD   # comment  -> the comment after the value stays where it is
        if inline:
            return text[:colon] + ": " + render_inline(value) + text[end:]
        line_end = _line_end(text, end)
        comment = _comment(text[end:line_end])
        if text[end:line_end].strip() and not comment:
            raise EditError("unexpected text after the value")
        head = ":" + (f"  {comment}" if comment else "")
        return text[:colon] + head + "\n" + "\n".join(render_block(value, column + 2)) + text[line_end:]
    # key:   # comment
    #   OLD BLOCK          -> the comment on the key line is kept
    key_line_end = _line_end(text, colon)
    comment = _comment(text[colon + 1:key_line_end])
    # the old value's own trailing comment and its indented comment lines go with it
    end = _line_end(text, end)
    while True:
        following = _line_end(text, end + 1) if end < len(text) else end
        line = text[end + 1:following]
        if end < len(text) and line.strip().startswith("#") and len(line) - len(line.lstrip()) > column:
            end = following
            continue
        break
    if inline:
        body = ": " + render_inline(value) + (f"  {comment}" if comment else "")
    else:
        body = ":" + (f"  {comment}" if comment else "") + "\n" + "\n".join(render_block(value, column + 2))
    return text[:colon] + body + text[end:]


def _insert(text: str, mapping: MappingNode, root: bool, key: str, value: Any) -> str:
    if root:
        column = 0
        position = len(text.rstrip("\n"))
    else:
        column = mapping.value[0][0].start_mark.column
        position = _line_end(text, _content_end(text, mapping))
    if is_inline(value):
        entry = f"{' ' * column}{render_inline(key)}: {render_inline(value)}"
    else:
        entry = "\n".join([f"{' ' * column}{render_inline(key)}:", *render_block(value, column + 2)])
    tail = text[position:]
    return text[:position] + "\n" + entry + (tail if tail else "\n")


def set_value(text: str, path: tuple[str, ...], value: Any) -> str:
    """Return ``text`` with the value at ``path`` (mapping keys) replaced."""
    root = yaml.compose(text, Loader=yaml.SafeLoader)
    if not isinstance(root, MappingNode) or root.flow_style:
        raise EditError("the document is not a block mapping")
    node: MappingNode = root
    parent: tuple[Node, Node] | None = None
    for depth, key in enumerate(path):
        pair = _find(node, key)
        rest = path[depth + 1:]
        if pair is None:
            if node.flow_style:
                if parent is None:
                    raise EditError("flow-style document")
                # rebuild this small flow mapping as a whole
                current = yaml.safe_load(text[parent[1].start_mark.index:parent[1].end_mark.index])
                if not isinstance(current, dict):
                    raise EditError("flow mapping did not parse")
                merged = copy.deepcopy(current)
                cursor = merged
                for part in path[depth:-1]:
                    cursor = cursor.setdefault(part, {})
                cursor[path[-1]] = value
                return _replace(text, parent[0], parent[1], merged)
            return _insert(text, node, node is root, key, _nest(rest, value))
        key_node, value_node = pair
        if not rest:
            return _replace(text, key_node, value_node, value)
        if isinstance(value_node, MappingNode):
            parent = pair
            node = value_node
            continue
        return _replace(text, key_node, value_node, _nest(rest, value))
    raise EditError("empty path")


def set_in(document: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    cursor: Any = document
    for key in path[:-1]:
        child = cursor.get(key)
        if not isinstance(child, dict):
            child = {}
            cursor[key] = child
        cursor = child
    cursor[path[-1]] = value


def get_in(document: Any, path: tuple[str, ...]) -> Any:
    cursor = document
    for key in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(key)
    return cursor


def apply_edits(
    text: str,
    document: dict[str, Any],
    edits: list[tuple[tuple[str, ...], Any]],
    loader: Any,
) -> tuple[str, dict[str, Any], bool]:
    """Apply edits; return (new text, new document, comments kept).

    ``loader`` is the strict loader ``scope check`` reads with. The new text
    always parses to exactly the intended document, or this raises.
    """
    expected = copy.deepcopy(document)
    for path, value in edits:
        set_in(expected, path, copy.deepcopy(value))
    try:
        updated = text
        for path, value in edits:
            updated = set_value(updated, path, value)
        if yaml.load(updated, Loader=loader) == expected:
            return updated, expected, True
    except (EditError, yaml.YAMLError, ValueError, IndexError):
        pass
    dumped = yaml.safe_dump(expected, default_flow_style=None, sort_keys=False, allow_unicode=True, width=4096)
    if yaml.load(dumped, Loader=loader) != expected:
        raise EditError("the answer cannot be written as YAML that reads back the same")
    return dumped, expected, False
