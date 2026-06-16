from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .mini_yaml import load_catalog_yaml


Direction = str


@dataclass(frozen=True)
class FieldSpec:
    name: str
    pdu_type: str
    direction: Direction
    path: str
    bit_width: int
    endian: str = "le"
    legal_values: tuple[Any, ...] = ()
    boundary_values: tuple[Any, ...] = ()
    invalid_values: tuple[Any, ...] = ()
    strategies: frozenset[str] = frozenset()
    dependencies: dict[str, Any] = field(default_factory=dict)
    oracle: str = "reject_or_disconnect"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "FieldSpec":
        return cls(
            name=str(raw["name"]),
            pdu_type=str(raw["pdu_type"]),
            direction=str(raw.get("direction", "both")),
            path=str(raw["path"]),
            bit_width=int(raw["bit_width"]),
            endian=str(raw.get("endian", "le")),
            legal_values=tuple(raw.get("legal_values", []) or []),
            boundary_values=tuple(raw.get("boundary_values", []) or []),
            invalid_values=tuple(raw.get("invalid_values", []) or []),
            strategies=frozenset(raw.get("strategies", []) or []),
            dependencies=dict(raw.get("dependencies", {}) or {}),
            oracle=str(raw.get("oracle", "reject_or_disconnect")),
        )


@dataclass(frozen=True)
class FieldCatalog:
    fields: tuple[FieldSpec, ...]
    source: Path | None = None

    @classmethod
    def from_yaml(cls, path: str | Path) -> "FieldCatalog":
        catalog_path = Path(path)
        raw = load_catalog_yaml(catalog_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or "fields" not in raw:
            raise ValueError("field catalog must contain a top-level 'fields' list")
        return cls(tuple(FieldSpec.from_dict(item) for item in raw["fields"]), catalog_path)

    def pdu_types(self) -> list[str]:
        return sorted({field.pdu_type for field in self.fields})

    def strategies(self) -> set[str]:
        strategies: set[str] = set()
        for field in self.fields:
            strategies.update(field.strategies)
        return strategies

    def matching(
        self,
        *,
        direction: str | None = None,
        pdu_type: str | None = None,
        strategy: str | None = None,
    ) -> list[FieldSpec]:
        result: list[FieldSpec] = []
        for item in self.fields:
            if direction and direction != "both" and item.direction not in {direction, "both"}:
                continue
            if pdu_type and item.pdu_type != pdu_type:
                continue
            if strategy and strategy not in item.strategies:
                continue
            result.append(item)
        return result
