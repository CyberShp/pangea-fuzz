from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .mini_yaml import load_catalog_yaml


@dataclass(frozen=True)
class FieldSpec:
    path: str
    name: str
    operation: str
    phase: str
    bit_width: int
    strategies: tuple[str, ...]
    legal_values: tuple[Any, ...] = ()
    invalid_values: tuple[Any, ...] = ()
    boundary_values: tuple[Any, ...] = ()
    oracle: str = "must_reject_or_recover"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FieldSpec":
        return cls(
            path=str(data["path"]),
            name=str(data.get("name", data["path"].split(".")[-1])),
            operation=str(data.get("operation", "any")),
            phase=str(data.get("phase", "command")),
            bit_width=int(data.get("bit_width", 32)),
            strategies=tuple(str(item) for item in data.get("strategies", [])),
            legal_values=tuple(data.get("legal_values", [])),
            invalid_values=tuple(data.get("invalid_values", [])),
            boundary_values=tuple(data.get("boundary_values", [])),
            oracle=str(data.get("oracle", "must_reject_or_recover")),
        )


class FieldCatalog:
    def __init__(self, fields: list[FieldSpec], metadata: dict[str, Any] | None = None):
        if not fields:
            raise ValueError("field catalog must contain at least one field")
        self.fields = fields
        self.metadata = metadata or {}

    @classmethod
    def from_yaml(cls, path: str | Path) -> "FieldCatalog":
        source = Path(path)
        parsed = load_catalog_yaml(source.read_text(encoding="utf-8"))
        fields = [FieldSpec.from_dict(item) for item in parsed["fields"]]
        metadata = {key: value for key, value in parsed.items() if key != "fields"}
        return cls(fields, metadata)

    def matching(self, *, operation: str | None = None, strategy: str | None = None) -> list[FieldSpec]:
        result: list[FieldSpec] = []
        for field in self.fields:
            if operation and field.operation not in {operation, "any"}:
                continue
            if strategy and strategy not in field.strategies:
                continue
            result.append(field)
        return result

    def operations(self) -> list[str]:
        return sorted({field.operation for field in self.fields if field.operation != "any"})

    def strategies(self) -> list[str]:
        return sorted({strategy for field in self.fields for strategy in field.strategies})

    def field_paths(self) -> list[str]:
        return sorted(field.path for field in self.fields)
