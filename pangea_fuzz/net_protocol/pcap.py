from __future__ import annotations

from pathlib import Path
import struct
import time


PCAP_GLOBAL_HEADER = struct.pack("!IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


class PcapWriter:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("wb")
        self.handle.write(PCAP_GLOBAL_HEADER)

    def write_packet(self, packet: bytes, timestamp: float | None = None) -> None:
        ts = timestamp if timestamp is not None else time.time()
        seconds = int(ts)
        micros = int((ts - seconds) * 1_000_000)
        self.handle.write(struct.pack("!IIII", seconds, micros, len(packet), len(packet)))
        self.handle.write(packet)

    def close(self) -> None:
        self.handle.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *args) -> None:
        self.close()


def read_pcap_records(path: str | Path) -> list[bytes]:
    data = Path(path).read_bytes()
    if len(data) < 24:
        return []
    offset = 24
    records: list[bytes] = []
    while offset + 16 <= len(data):
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack("!IIII", data[offset : offset + 16])
        offset += 16
        records.append(data[offset : offset + incl_len])
        offset += incl_len
    return records
