from __future__ import annotations

import ipaddress
import struct
from typing import Any


def build_packet(case: dict[str, Any]) -> bytes:
    target = case.get("target", {}) or {}
    protocol = str(case.get("protocol", "tcp"))
    dst_mac = _mac(target.get("dst_mac", "02:00:00:00:00:02"))
    src_mac = _mac(target.get("src_mac", "02:00:00:00:00:01"))
    if protocol == "arp":
        return dst_mac + src_mac + struct.pack("!H", 0x0806) + _arp_payload(target)
    if protocol == "ipv6" or protocol == "icmpv6":
        return dst_mac + src_mac + struct.pack("!H", 0x86DD) + _ipv6_packet(target, protocol)
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + _ipv4_packet(target, protocol)


def _arp_payload(target: dict[str, Any]) -> bytes:
    src_mac = _mac(target.get("src_mac", "02:00:00:00:00:01"))
    dst_mac = _mac(target.get("dst_mac", "02:00:00:00:00:02"))
    src_ip = ipaddress.IPv4Address(target.get("src_ipv4", "192.0.2.1")).packed
    dst_ip = ipaddress.IPv4Address(target.get("dst_ipv4", "192.0.2.10")).packed
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + src_mac + src_ip + dst_mac + dst_ip


def _ipv4_packet(target: dict[str, Any], protocol_name: str) -> bytes:
    if protocol_name == "udp":
        proto = 17
        payload = _udp_segment(target)
    elif protocol_name == "icmp":
        proto = 1
        payload = _icmp_payload()
    else:
        proto = 6
        payload = _tcp_segment(target)
    src = ipaddress.IPv4Address(target.get("src_ipv4", "192.0.2.1")).packed
    dst = ipaddress.IPv4Address(target.get("dst_ipv4", "192.0.2.10")).packed
    total_length = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, 1, 0, 64, proto, 0, src, dst)
    checksum = _checksum(header)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, 1, 0, 64, proto, checksum, src, dst)
    return header + payload


def _ipv6_packet(target: dict[str, Any], protocol_name: str) -> bytes:
    next_header = 58 if protocol_name == "icmpv6" else 6
    payload = _icmpv6_payload() if protocol_name == "icmpv6" else _tcp_segment(target)
    src = ipaddress.IPv6Address(target.get("src_ipv6", "2001:db8::1")).packed
    dst = ipaddress.IPv6Address(target.get("dst_ipv6", "2001:db8::10")).packed
    header = struct.pack("!IHBB16s16s", 6 << 28, len(payload), next_header, 64, src, dst)
    return header + payload


def _tcp_segment(target: dict[str, Any]) -> bytes:
    sport = int(target.get("src_port", 40000))
    dport = int(target.get("tcp_port", 4420))
    return struct.pack("!HHIIHHHH", sport, dport, 1, 0, (5 << 12) | 0x02, 64240, 0, 0) + b"pangea"


def _udp_segment(target: dict[str, Any]) -> bytes:
    sport = int(target.get("src_port", 40000))
    dport = int(target.get("udp_port", 4420))
    payload = b"pangea"
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _icmp_payload() -> bytes:
    body = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"pangea"
    checksum = _checksum(body)
    return struct.pack("!BBHHH", 8, 0, checksum, 1, 1) + b"pangea"


def _icmpv6_payload() -> bytes:
    return struct.pack("!BBHHH", 128, 0, 0, 1, 1) + b"pangea"


def _mac(value: str) -> bytes:
    return bytes(int(part, 16) for part in value.split(":"))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF
