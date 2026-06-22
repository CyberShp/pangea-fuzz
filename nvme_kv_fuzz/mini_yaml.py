from __future__ import annotations

import json
from typing import Any


def load_catalog_yaml(text: str) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
    for line in text.splitlines():
        stripped = _strip_comment(line).strip()
        if not stripped:
            continue
        if stripped.startswith("- {") and stripped.endswith("}"):
            fields.append(_parse_flow_mapping(stripped[2:].strip()))
        elif ":" in stripped and not stripped.startswith("fields:"):
            key, value = stripped.split(":", 1)
            metadata[key.strip()] = _parse_scalar_or_list(value.strip())
    if not fields:
        raise ValueError("catalog YAML did not contain any flow-map field entries")
    metadata["fields"] = fields
    return metadata


def load_simple_yaml(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if not stripped:
        return {}
    if stripped.startswith("{"):
        return json.loads(stripped)

    result: dict[str, Any] = {}
    for line in text.splitlines():
        clean = _strip_comment(line).strip()
        if not clean or ":" not in clean:
            continue
        key, raw = clean.split(":", 1)
        result[key.strip()] = _parse_scalar_or_list(raw.strip())
    return result


def dump_json_yaml(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def _parse_flow_mapping(raw: str) -> dict[str, Any]:
    body = raw.strip()
    if not body.startswith("{") or not body.endswith("}"):
        raise ValueError(f"expected flow mapping, got {raw!r}")
    result: dict[str, Any] = {}
    for item in _split_top_level(body[1:-1], ","):
        if not item.strip():
            continue
        key, value = _split_key_value(item)
        result[key.strip()] = _parse_scalar_or_list(value.strip())
    return result


def _split_key_value(item: str) -> tuple[str, str]:
    parts = _split_top_level(item, ":", maxsplit=1)
    if len(parts) != 2:
        raise ValueError(f"expected key/value item, got {item!r}")
    return parts[0], parts[1]


def _parse_scalar_or_list(raw: str) -> Any:
    raw = raw.strip()
    if raw == "":
        return ""
    if raw.startswith("[") and raw.endswith("]"):
        body = raw[1:-1].strip()
        if not body:
            return []
        return [_parse_scalar_or_list(item.strip()) for item in _split_top_level(body, ",")]
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    if raw in {"true", "false"}:
        return raw == "true"
    if raw in {"null", "~"}:
        return None
    try:
        return int(raw, 0)
    except ValueError:
        return raw


def _split_top_level(text: str, delimiter: str, maxsplit: int = -1) -> list[str]:
    result: list[str] = []
    depth = 0
    in_quote: str | None = None
    start = 0
    splits = 0
    for index, char in enumerate(text):
        if in_quote:
            if char == in_quote:
                in_quote = None
            continue
        if char in {"'", '"'}:
            in_quote = char
            continue
        if char in "[{(":
            depth += 1
            continue
        if char in "]})":
            depth -= 1
            continue
        if char == delimiter and depth == 0 and (maxsplit < 0 or splits < maxsplit):
            result.append(text[start:index])
            start = index + 1
            splits += 1
    result.append(text[start:])
    return result


def _strip_comment(line: str) -> str:
    in_quote: str | None = None
    for index, char in enumerate(line):
        if in_quote:
            if char == in_quote:
                in_quote = None
            continue
        if char in {"'", '"'}:
            in_quote = char
            continue
        if char == "#":
            return line[:index]
    return line
