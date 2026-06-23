from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_CONFIG: dict[str, Any] = {
    "active_mode": "nvmetcp_tls",
    "global": {
        "artifacts_dir": "artifacts",
        "workers": 1,
        "shard_count": 1,
        "shard_index": 0,
    },
    "artifact_policy": {
        "max_total_gb": 200,
        "stop_when_free_space_below_gb": 20,
        "compression": {
            "enabled": True,
            "format": "gzip",
        },
        "pass": {
            "keep_full": False,
            "keep_stdout_tail_kb": 16,
            "keep_stderr_tail_kb": 16,
            "keep_trace": True,
            "keep_payload": False,
            "keep_pcap": False,
        },
        "fail": {
            "keep_full": True,
            "keep_first_n_per_bucket": 5,
            "keep_every_n_after": 100,
            "keep_pcap": "on_new_bucket",
            "max_pcap_mb": 64,
            "keep_payload": True,
        },
        "buckets": {
            "key_fields": ["mode", "verdict", "reason", "operation_or_protocol_or_pdu", "field", "strategy"],
        },
        "pruning": {
            "enabled": True,
            "prune_pass_first": True,
            "preserve_core": True,
        },
    },
    "modes": {
        "nvmetcp_tls": {
            "catalog": "field_catalog.yaml",
            "engine": "fio",
            "device": "",
            "runtime_s": 5,
            "timeout_s": 120,
            "allow_write": False,
            "tool_paths": {
                "nvme": "nvme",
                "fio": "fio",
                "vdbench": "vdbench",
                "keyctl": "keyctl",
            },
            "transport": "tcp",
            "target_traddr": "",
            "target_trsvcid": "4420",
            "subsysnqn": "",
            "hostnqn": "",
            "connect_extra_args": [],
            "disconnect_extra_args": [],
            "connection_lifecycle": "none",
            "discover_before_connect": False,
            "disconnect_after_case": True,
            "tls_key": {
                "source": "none",
                "env": "",
                "file": "",
                "identity": "",
                "keyring": "@u",
                "import": False,
            },
        },
        "nvme_kv": {
            "catalog": "kv_field_catalog.yaml",
            "allow_live_target": False,
        },
        "net_protocol": {
            "catalog": "net_field_catalog.yaml",
            "iface": "",
            "target_mac": "02:00:00:00:00:02",
            "target_ipv4": "192.0.2.10",
            "target_ipv6": "2001:db8::10",
            "tcp_ports": [4420],
            "udp_ports": [4420],
            "packet_engine": "stdlib",
            "pcap_only": True,
            "max_pps": 100,
            "max_duration_s": 30,
            "iface_allowlist": [],
            "forbid_default_route_iface": True,
            "allow_disruptive": False,
            "allow_broadcast": False,
            "allow_multicast": False,
        },
    },
}


def load_pangea_config(path: str | Path | None = None) -> dict[str, Any]:
    data = _deep_copy(DEFAULT_CONFIG)
    if path is None:
        return data
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(config_path)
    loaded = load_simple_yaml(config_path.read_text(encoding="utf-8"))
    _deep_merge(data, loaded)
    _normalize(data)
    return data


def load_simple_yaml(text: str) -> dict[str, Any]:
    text = text.lstrip("\ufeff")
    stripped = text.strip()
    if not stripped:
        return {}
    if stripped.startswith("{"):
        return json.loads(stripped)
    result: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, result)]
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = _strip_comment(raw_line).strip()
        if not line or ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if raw_value == "":
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            _set_dotted(parent, key, _parse_scalar_or_list(raw_value))
    return result


def _normalize(config: dict[str, Any]) -> None:
    global_config = config.setdefault("global", {})
    for key in ("workers", "shard_count", "shard_index"):
        if key in global_config:
            global_config[key] = int(global_config[key])
    net = config.setdefault("modes", {}).setdefault("net_protocol", {})
    for key in ("max_pps", "max_duration_s"):
        if key in net:
            net[key] = int(net[key])


def _set_dotted(root: dict[str, Any], key: str, value: Any) -> None:
    parts = key.split(".")
    current = root
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = value


def _deep_merge(base: dict[str, Any], update: dict[str, Any]) -> None:
    for key, value in update.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _deep_copy(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value))


def _parse_scalar_or_list(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        body = raw[1:-1].strip()
        if not body:
            return []
        return [_parse_scalar_or_list(item.strip()) for item in _split_top_level(body, ",")]
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    if raw in {"true", "false"}:
        return raw == "true"
    if raw in {"null", "~"}:
        return None
    try:
        return int(raw, 0)
    except ValueError:
        return raw


def _split_top_level(text: str, delimiter: str) -> list[str]:
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
            continue
        if char in "]})":
            depth -= 1
            continue
        if char == delimiter and depth == 0:
            result.append(text[start:index])
            start = index + 1
    result.append(text[start:])
    return result


def _strip_comment(line: str) -> str:
    in_quote: str | None = None
    for index, char in enumerate(line):
        if in_quote:
            if char == in_quote:
                in_quote = None
            continue
        if char in {"'", '"'}:
            in_quote = char
            continue
        if char == "#":
            return line[:index]
    return line
