from __future__ import annotations

from dataclasses import dataclass
import hashlib
import random
from typing import Any

from .catalog import FieldCatalog, FieldSpec


KV_OPCODES = {
    "store": 0x01,
    "retrieve": 0x02,
    "list": 0x06,
    "delete": 0x10,
    "exist": 0x14,
}

BASE_FORBIDDEN = ("FAIL_SAFETY", "FAIL_HANG", "FAIL_CLEANUP", "FAIL_ORACLE", "FAIL_INFRA")


@dataclass(frozen=True)
class ExpectedOutcome:
    allowed: tuple[str, ...]
    forbidden: tuple[str, ...] = BASE_FORBIDDEN


@dataclass(frozen=True)
class FieldMutation:
    field: FieldSpec
    strategy: str
    original_value: Any
    mutated_value: Any
    injection_phase: str


@dataclass(frozen=True)
class FuzzCase:
    seed: int
    operation: str
    opcode: int
    nsid: int
    key: bytes
    value: bytes
    cdw: dict[str, int]
    data_direction: str
    mutation: FieldMutation
    expected: ExpectedOutcome

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "operation": self.operation,
            "opcode": self.opcode,
            "opcode_hex": f"0x{self.opcode:02x}",
            "nsid": self.nsid,
            "key_hex": self.key.hex(),
            "key_ascii": _safe_ascii(self.key),
            "key_length": len(self.key),
            "value_hex": self.value.hex(),
            "value_length": len(self.value),
            "value_sha256": hashlib.sha256(self.value).hexdigest(),
            "cdw": dict(sorted(self.cdw.items())),
            "data_direction": self.data_direction,
            "mutation": {
                "field": self.mutation.field.path,
                "field_name": self.mutation.field.name,
                "strategy": self.mutation.strategy,
                "original_value": self.mutation.original_value,
                "mutated_value": self.mutation.mutated_value,
                "injection_phase": self.mutation.injection_phase,
            },
            "expected": {
                "allowed": list(self.expected.allowed),
                "forbidden": list(self.expected.forbidden),
            },
        }


class CaseGenerator:
    def __init__(self, catalog: FieldCatalog, *, key_prefix: str = "kvfuzz-", nsid: int = 1):
        self.catalog = catalog
        self.key_prefix = key_prefix
        self.nsid = nsid

    def generate(
        self,
        *,
        seed: int,
        operation: str | None = None,
        strategy: str | None = None,
        field_path: str | None = None,
    ) -> FuzzCase:
        rng = random.Random(seed)
        op = operation or rng.choice(self.catalog.operations() or list(KV_OPCODES))
        if op not in KV_OPCODES:
            raise ValueError(f"unknown KV operation: {op}")

        catalog_strategy = None if strategy == "random_value" else strategy
        candidates = self.catalog.matching(operation=op, strategy=catalog_strategy)
        if field_path:
            candidates = [field for field in candidates if field.path == field_path]
        if not candidates:
            candidates = self.catalog.matching(operation=None, strategy=catalog_strategy)
        if not candidates:
            raise ValueError(f"no fields match operation={op!r}, strategy={strategy!r}")

        field = rng.choice(candidates)
        chosen_strategy = strategy or rng.choice(sorted(field.strategies))
        original = self._pick_original(field, rng)
        mutated = self._pick_mutated(field, chosen_strategy, rng)
        key = self._make_key(rng, chosen_strategy)
        value = self._make_value(rng, op, chosen_strategy)
        opcode = KV_OPCODES[op]
        nsid = self.nsid
        if field.path == "kv.opcode" and isinstance(mutated, int):
            opcode = mutated
        if field.path == "kv.nsid" and isinstance(mutated, int):
            nsid = mutated
        cdw = self._make_cdw(op, key, value)
        self._apply_field_mutation(cdw, field, chosen_strategy, mutated)
        cdw["operation_id"] = opcode

        return FuzzCase(
            seed=seed,
            operation=op,
            opcode=opcode,
            nsid=nsid,
            key=key,
            value=value,
            cdw=cdw,
            data_direction=self._direction_for(op),
            mutation=FieldMutation(field, chosen_strategy, original, mutated, field.phase),
            expected=ExpectedOutcome(allowed=self._allowed_for(field, chosen_strategy)),
        )

    def _make_key(self, rng: random.Random, strategy: str) -> bytes:
        if strategy == "invalid_key_size":
            return (self.key_prefix + "x" * rng.choice([0, 256, 512])).encode("ascii", errors="ignore")
        suffix = f"{rng.randrange(0, 2**48):012x}"
        return f"{self.key_prefix}{suffix}".encode("ascii")

    def _make_value(self, rng: random.Random, operation: str, strategy: str) -> bytes:
        if operation in {"delete", "exist", "list"}:
            return b""
        size = rng.choice([0, 1, 16, 4096, 8192]) if strategy == "legal_boundary" else rng.randrange(1, 257)
        return bytes(rng.randrange(0, 256) for _ in range(size))

    def _make_cdw(self, operation: str, key: bytes, value: bytes) -> dict[str, int]:
        return {
            "cdw2": 0,
            "cdw3": 0,
            "cdw10": len(key),
            "cdw11": len(value),
            "cdw12": 0,
            "cdw13": 0,
            "cdw14": 0,
            "cdw15": 0,
            "option_bits": 0,
            "reserved_bits": 0,
            "operation_id": KV_OPCODES[operation],
        }

    def _apply_field_mutation(self, cdw: dict[str, int], field: FieldSpec, strategy: str, mutated: Any) -> None:
        leaf = field.path.split(".")[-1]
        if leaf in cdw and isinstance(mutated, int):
            cdw[leaf] = mutated
        elif leaf == "key_length" and isinstance(mutated, int):
            cdw["cdw10"] = mutated
        elif leaf in {"value_length", "host_buffer_size"} and isinstance(mutated, int):
            cdw["cdw11"] = mutated
        elif leaf == "reserved_bits" and isinstance(mutated, int):
            cdw["reserved_bits"] = mutated
        elif strategy == "reserved_nonzero":
            cdw["reserved_bits"] = int(mutated) if isinstance(mutated, int) else 1

    def _pick_original(self, field: FieldSpec, rng: random.Random) -> Any:
        return rng.choice(list(field.legal_values or field.boundary_values or (0,)))

    def _pick_mutated(self, field: FieldSpec, strategy: str, rng: random.Random) -> Any:
        if strategy == "legal_boundary":
            return rng.choice(list(field.boundary_values or field.legal_values or (0,)))
        if strategy == "random_value":
            return rng.randrange(0, 2 ** min(field.bit_width, 31))
        if strategy in {"reserved_nonzero", "length_mismatch", "invalid_key_size", "buffer_too_small"}:
            return rng.choice(list(field.invalid_values or field.boundary_values or (1,)))
        if strategy in {"option_conflict", "key_not_exist", "duplicate_store", "delete_race", "list_prefix_boundary"}:
            return strategy
        return rng.choice(list(field.invalid_values or field.boundary_values or field.legal_values or (0,)))

    def _allowed_for(self, field: FieldSpec, strategy: str) -> tuple[str, ...]:
        if strategy == "legal_boundary" and field.oracle == "must_succeed":
            return ("PASS_VALID",)
        if strategy in {"key_not_exist", "invalid_key_size", "length_mismatch", "reserved_nonzero", "buffer_too_small"}:
            return ("PASS_REJECTED", "PASS_RECOVERED")
        if strategy in {"delete_race"}:
            return ("PASS_VALID", "PASS_REJECTED", "PASS_RECOVERED")
        return ("PASS_VALID", "PASS_REJECTED", "PASS_RECOVERED")

    def _direction_for(self, operation: str) -> str:
        if operation == "store":
            return "host_to_controller"
        if operation in {"retrieve", "list", "exist"}:
            return "controller_to_host"
        return "none"


def _safe_ascii(data: bytes) -> str:
    return data.decode("ascii", errors="replace")
