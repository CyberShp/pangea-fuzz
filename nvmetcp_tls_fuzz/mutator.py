from __future__ import annotations

from dataclasses import dataclass
import struct


@dataclass(frozen=True)
class Mutation:
    field_path: str
    value: int | bytes | None = None
    strategy: str | None = None
    bit: int | None = None


class MutationEngine:
    """Byte-level mutation engine for parsed grammar fields.

    The first implementation intentionally supports common-header fields because
    every NVMe/TCP PDU starts there. Deeper PDU fields are addressed by the same
    Mutation object and can be added by extending FIELD_LAYOUT.
    """

    FIELD_LAYOUT = {
        "common.type": (0, 1, "u8"),
        "common.flags": (1, 1, "u8"),
        "common.hlen": (2, 1, "u8"),
        "common.pdo": (3, 1, "u8"),
        "common.plen": (4, 4, "le32"),
    }

    def apply(self, pdu: bytes, mutation: Mutation) -> bytes:
        if mutation.field_path not in self.FIELD_LAYOUT:
            raise KeyError(f"unsupported mutation field path: {mutation.field_path}")

        offset, width, encoding = self.FIELD_LAYOUT[mutation.field_path]
        if len(pdu) < offset + width:
            raise ValueError(f"PDU too short for field {mutation.field_path}")

        result = bytearray(pdu)
        current = self._read(result[offset : offset + width], encoding)

        if mutation.strategy == "bit_flip":
            bit = 0 if mutation.bit is None else mutation.bit
            new_value = current ^ (1 << bit)
        elif mutation.strategy == "endian_swap":
            result[offset : offset + width] = bytes(result[offset : offset + width])[::-1]
            return bytes(result)
        elif mutation.value is not None:
            new_value = mutation.value
        else:
            raise ValueError("mutation requires either a value, bit_flip, or endian_swap")

        self._write(result, offset, encoding, new_value)
        return bytes(result)

    def _read(self, raw: bytes | bytearray, encoding: str) -> int:
        if encoding == "u8":
            return int(raw[0])
        if encoding == "le32":
            return struct.unpack("<I", bytes(raw))[0]
        raise ValueError(f"unsupported field encoding {encoding}")

    def _write(self, buf: bytearray, offset: int, encoding: str, value: int | bytes) -> None:
        if isinstance(value, bytes):
            buf[offset : offset + len(value)] = value
            return
        if encoding == "u8":
            buf[offset] = value & 0xFF
            return
        if encoding == "le32":
            buf[offset : offset + 4] = struct.pack("<I", value & 0xFFFFFFFF)
            return
        raise ValueError(f"unsupported field encoding {encoding}")
