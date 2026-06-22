from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Any

from .catalog import NetFieldCatalog


PROTOCOLS = ("ethernet", "arp", "ipv4", "ipv6", "icmp", "icmpv6", "tcp", "udp")
STRATEGIES = ("legal_boundary", "invalid_length", "checksum_error", "reserved_nonzero", "sequence_error", "random_value")


@dataclass(frozen=True)
class NetFuzzCase:
    seed: int
    protocol: str
    field: str
    strategy: str
    target: dict[str, Any]
    expected: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "mode": "net_protocol",
            "protocol": self.protocol,
            "mutation": {"field": self.field, "strategy": self.strategy},
            "target": self.target,
            "expected": self.expected,
        }


class NetCaseGenerator:
    def __init__(self, catalog: NetFieldCatalog):
        self.catalog = catalog

    def generate(
        self,
        *,
        seed: int,
        protocol: str | None = None,
        strategy: str | None = None,
        target: dict[str, Any] | None = None,
    ) -> NetFuzzCase:
        rng = random.Random(seed)
        protocol = protocol or rng.choice(self.catalog.protocols() or list(PROTOCOLS))
        fields = self.catalog.by_protocol(protocol)
        if not fields:
            raise ValueError(f"unknown protocol {protocol}")
        field = rng.choice(fields)
        chosen_strategy = strategy or rng.choice(field.strategies or STRATEGIES)
        return NetFuzzCase(
            seed=seed,
            protocol=protocol,
            field=field.path,
            strategy=chosen_strategy,
            target=target or default_target(),
            expected={"allowed": ["PASS_VALID", "PASS_REJECTED", "PASS_DISCONNECTED"]},
        )


def default_target() -> dict[str, Any]:
    return {
        "src_mac": "02:00:00:00:00:01",
        "dst_mac": "02:00:00:00:00:02",
        "src_ipv4": "192.0.2.1",
        "dst_ipv4": "192.0.2.10",
        "src_ipv6": "2001:db8::1",
        "dst_ipv6": "2001:db8::10",
        "tcp_port": 4420,
        "udp_port": 4420,
    }
