from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .mini_yaml import load_simple_yaml


REQUIRED_KEYS = ("device_path", "nsid", "target_nqn", "allowed_model_or_serial", "key_prefix", "max_qps", "timeout_ms")


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    data = load_simple_yaml(config_path.read_text(encoding="utf-8"))
    missing = [key for key in REQUIRED_KEYS if key not in data]
    if missing:
        raise ValueError(f"config missing required keys: {', '.join(missing)}")
    data["nsid"] = int(data["nsid"])
    data["max_qps"] = int(data["max_qps"])
    data["timeout_ms"] = int(data["timeout_ms"])
    if isinstance(data["allowed_model_or_serial"], str):
        data["allowed_model_or_serial"] = [data["allowed_model_or_serial"]]
    validate_config(data)
    return data


def validate_config(config: dict[str, Any]) -> None:
    if not re.match(r"^/dev/nvme\d+n\d+$", str(config["device_path"])):
        raise ValueError("device_path must look like /dev/nvmeXnY")
    if int(config["nsid"]) <= 0:
        raise ValueError("nsid must be positive")
    if not str(config["target_nqn"]).startswith("nqn."):
        raise ValueError("target_nqn must start with nqn.")
    if not config["allowed_model_or_serial"]:
        raise ValueError("allowed_model_or_serial must not be empty")
    if not str(config["key_prefix"]):
        raise ValueError("key_prefix must not be empty")
    if int(config["max_qps"]) <= 0:
        raise ValueError("max_qps must be positive")
    if int(config["timeout_ms"]) <= 0:
        raise ValueError("timeout_ms must be positive")
