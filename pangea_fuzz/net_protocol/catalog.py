from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pangea_fuzz.config import load_simple_yaml


@dataclass(frozen=True)
class NetField:
    path: str
    protocol: str
    strategies: tuple[str, ...]


class NetFieldCatalog:
    def __init__(self, fields: list[NetField]):
        self.fields = fields

    @classmethod
    def from_yaml(cls, path: str | Path) -> "NetFieldCatalog":
        data = load_catalog(Path(path).read_text(encoding="utf-8"))
        fields = [
            NetField(
                path=str(item["path"]),
                protocol=str(item["protocol"]),
                strategies=tuple(str(value) for value in item.get("strategies", [])),
            )
            for item in data["fields"]
        ]
        return cls(fields)

    def protocols(self) -> list[str]:
        return sorted({field.protocol for field in self.fields})

    def by_protocol(self, protocol: str) -> list[NetField]:
        return [field for field in self.fields if field.protocol == protocol]


def load_catalog(text: str) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("- {") and line.endswith("}"):
            body = line[2:].strip()
            fields.append(_parse_flow_mapping(body))
    if not fields:
        raise ValueError("net field catalog has no fields")
    return {"fields": fields}


def _parse_flow_mapping(raw: str) -> dict[str, Any]:
    body = raw.strip()[1:-1]
    result: dict[str, Any] = {}
    for part in _split_top_level(body):
        key, value = part.split(":", 1)
        result[key.strip()] = load_simple_yaml(f"value: {value.strip()}")["value"]
    return result


def _split_top_level(text: str) -> list[str]:
    result: list[str] = []
    depth = 0
    in_quote: str | None = None
    start = 0
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
        elif char in "]})":
            depth -= 1
        elif char == "," and depth == 0:
            result.append(text[start:index])
            start = index + 1
    result.append(text[start:])
    return result
