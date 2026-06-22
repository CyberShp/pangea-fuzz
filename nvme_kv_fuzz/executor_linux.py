from __future__ import annotations

from dataclasses import dataclass
import subprocess
import time
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ExecutorResult:
    returncode: int | None
    stdout: str
    stderr: str
    latency_ms: float
    timed_out: bool = False
    infra_error: str | None = None


class NvmeCliExecutor:
    def __init__(self, *, timeout_ms: int):
        self.timeout_ms = timeout_ms

    def run(self, command: list[str], *, cwd: Path) -> ExecutorResult:
        start = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=max(self.timeout_ms / 1000.0, 0.001),
                check=False,
            )
        except FileNotFoundError as exc:
            return ExecutorResult(None, "", str(exc), _elapsed_ms(start), infra_error=f"tool not found: {command[0]}")
        except subprocess.TimeoutExpired as exc:
            return ExecutorResult(
                None,
                _decode(exc.stdout),
                _decode(exc.stderr),
                _elapsed_ms(start),
                timed_out=True,
            )
        return ExecutorResult(completed.returncode, completed.stdout, completed.stderr, _elapsed_ms(start))


def build_io_passthru(case: dict[str, Any], config: dict[str, Any], payload_file: Path | None) -> dict[str, Any]:
    device = str(config["device_path"])
    nsid = int(case.get("nsid") or config.get("nsid", 1))
    opcode = int(case["opcode"])
    cdw = case.get("cdw", {}) or {}
    direction = case.get("data_direction", "none")
    data_len = int(case.get("value_length", 0) or 0)

    argv = [
        "nvme",
        "io-passthru",
        device,
        f"--opcode=0x{opcode:02x}",
        f"--namespace-id={nsid}",
        "--raw-binary",
    ]
    for name in ("cdw2", "cdw3", "cdw10", "cdw11", "cdw12", "cdw13", "cdw14", "cdw15"):
        if name in cdw:
            argv.append(f"--{name}={int(cdw[name])}")
    if direction == "host_to_controller":
        argv.append("--write")
        if payload_file is not None:
            argv.append(f"--input-file={payload_file.name}")
        argv.append(f"--data-len={data_len}")
    elif direction == "controller_to_host":
        argv.append("--read")
        argv.append(f"--data-len={max(data_len, int(cdw.get('cdw11', 4096) or 4096))}")

    return {
        "argv": argv,
        "device_path": device,
        "nsid": nsid,
        "opcode": f"0x{opcode:02x}",
        "cdw": cdw,
        "data_direction": direction,
        "payload_file": payload_file.name if payload_file else None,
    }


def _elapsed_ms(start: float) -> float:
    return round((time.monotonic() - start) * 1000.0, 3)


def _decode(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
