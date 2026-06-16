from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import struct


class PduType(IntEnum):
    ICREQ = 0x00
    ICRESP = 0x01
    H2C_TERM_REQ = 0x02
    C2H_TERM_REQ = 0x03
    CAPSULE_CMD = 0x04
    RESPONSE_CAPSULE = 0x05
    H2CDATA = 0x06
    C2HDATA = 0x07
    R2T = 0x09

    @classmethod
    def from_byte(cls, value: int) -> "PduType | int":
        try:
            return cls(value)
        except ValueError:
            return value


class PduFlag(IntEnum):
    HDGST = 0x01
    DDGST = 0x02
    DATA_LAST = 0x04
    DATA_SUCCESS = 0x08


HEADER_SIZE = 8
_HEADER = struct.Struct("<BBBBI")


@dataclass(frozen=True)
class NvmeTcpHeader:
    pdu_type: PduType | int
    flags: int
    hlen: int
    pdo: int
    plen: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "NvmeTcpHeader":
        if len(data) < HEADER_SIZE:
            raise ValueError(f"NVMe/TCP header requires {HEADER_SIZE} bytes, got {len(data)}")
        pdu_type, flags, hlen, pdo, plen = _HEADER.unpack(data[:HEADER_SIZE])
        return cls(PduType.from_byte(pdu_type), flags, hlen, pdo, plen)

    def to_bytes(self) -> bytes:
        pdu_value = int(self.pdu_type)
        return _HEADER.pack(pdu_value, self.flags & 0xFF, self.hlen & 0xFF, self.pdo & 0xFF, self.plen)

    @property
    def frame_length(self) -> int:
        return self.plen


@dataclass(frozen=True)
class NvmeTcpFrame:
    header: NvmeTcpHeader
    payload: bytes = b""

    @classmethod
    def from_bytes(cls, data: bytes) -> "NvmeTcpFrame":
        header = NvmeTcpHeader.from_bytes(data)
        if len(data) < header.plen:
            raise ValueError(f"incomplete PDU: plen={header.plen}, actual={len(data)}")
        return cls(header, data[HEADER_SIZE : header.plen])

    def to_bytes(self) -> bytes:
        expected_payload = max(0, self.header.plen - HEADER_SIZE)
        payload = self.payload[:expected_payload].ljust(expected_payload, b"\x00")
        return self.header.to_bytes() + payload
