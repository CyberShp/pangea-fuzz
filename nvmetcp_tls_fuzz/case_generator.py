from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Any

from .catalog import FieldCatalog, FieldSpec


BASE_FORBIDDEN = (
    "FAIL_SAFETY",
    "FAIL_HANG",
    "FAIL_CLEANUP",
    "FAIL_ORACLE",
)


@dataclass(frozen=True)
class ExpectedOutcome:
    allowed: tuple[str, ...]
    forbidden: tuple[str, ...] = BASE_FORBIDDEN

    @property
    def allows_rejection(self) -> bool:
        return "PASS_REJECTED" in self.allowed


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
    direction: str
    pdu_type: str
    command: str
    mutation: FieldMutation
    expected: ExpectedOutcome

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "direction": self.direction,
            "pdu_type": self.pdu_type,
            "command": self.command,
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
    def __init__(self, catalog: FieldCatalog):
        self.catalog = catalog

    def generate(
        self,
        *,
        seed: int,
        direction: str = "both",
        pdu_type: str | None = None,
        command: str = "read",
        strategy: str | None = None,
    ) -> FuzzCase:
        rng = random.Random(seed)
        catalog_strategy = None if strategy == "random_value" else strategy
        candidates = self.catalog.matching(direction=direction, pdu_type=pdu_type, strategy=catalog_strategy)
        if not candidates:
            raise ValueError(
                f"no fields match direction={direction!r}, pdu_type={pdu_type!r}, strategy={strategy!r}"
            )

        field = rng.choice(candidates)
        chosen_strategy = strategy or rng.choice(sorted(field.strategies))
        original = self._pick_original(field, rng)
        mutated = self._pick_mutated(field, chosen_strategy, rng)
        allowed = self._allowed_for(field, chosen_strategy)

        return FuzzCase(
            seed=seed,
            direction=direction,
            pdu_type=field.pdu_type,
            command=command,
            mutation=FieldMutation(
                field=field,
                strategy=chosen_strategy,
                original_value=original,
                mutated_value=mutated,
                injection_phase=self._phase_for(field),
            ),
            expected=ExpectedOutcome(allowed=allowed),
        )

    def _pick_original(self, field: FieldSpec, rng: random.Random) -> Any:
        values = field.legal_values or field.boundary_values or (0,)
        return rng.choice(list(values))

    def _pick_mutated(self, field: FieldSpec, strategy: str, rng: random.Random) -> Any:
        if strategy in {"invalid_enum", "reserved_nonzero", "offset_out_of_range", "length_mismatch"}:
            values = field.invalid_values or field.boundary_values or (2**min(field.bit_width, 31) - 1,)
            return rng.choice(list(values))
        if strategy == "legal_boundary":
            values = field.boundary_values or field.legal_values or (0,)
            return rng.choice(list(values))
        if strategy == "bit_flip":
            return {"bit": rng.randrange(max(1, min(field.bit_width, 32)))}
        if strategy == "endian_swap":
            return "endian_swap"
        if strategy in {"duplicate", "drop", "delay", "sequence_error", "digest_flag_mismatch"}:
            return strategy
        if strategy == "random_value":
            return rng.randrange(0, 2 ** min(field.bit_width, 63))
        return rng.choice(list(field.invalid_values or field.boundary_values or field.legal_values or (0,)))

    def _allowed_for(self, field: FieldSpec, strategy: str) -> tuple[str, ...]:
        if strategy == "legal_boundary" and field.oracle == "must_succeed":
            return ("PASS_VALID",)
        if field.pdu_type == "tls_key":
            return ("PASS_REJECTED",)
        if strategy in {"drop", "delay", "sequence_error"}:
            return ("PASS_REJECTED", "PASS_DISCONNECTED")
        return ("PASS_REJECTED", "PASS_DISCONNECTED")

    def _phase_for(self, field: FieldSpec) -> str:
        if field.pdu_type in {"icreq", "icresp", "tls_key"}:
            return "connect"
        if field.pdu_type in {"capsule_cmd", "response_capsule"}:
            return "command"
        if field.pdu_type in {"h2cdata", "c2hdata", "r2t"}:
            return "data_transfer"
        if field.pdu_type == "termreq":
            return "termination"
        return "frame_decode"
