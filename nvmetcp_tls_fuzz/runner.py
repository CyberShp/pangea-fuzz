from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import subprocess
from typing import Sequence

from .artifacts import ArtifactWriter


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class HostCommandRunner:
    def __init__(self, timeout_s: float = 15.0):
        self.timeout_s = timeout_s

    def run(self, command: Sequence[str], *, timeout_s: float | None = None) -> CommandResult:
        try:
            proc = subprocess.run(
                list(command),
                text=True,
                capture_output=True,
                timeout=timeout_s or self.timeout_s,
                check=False,
            )
            return CommandResult(tuple(command), proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                tuple(command),
                returncode=124,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                timed_out=True,
            )


class HostArtifactCollector:
    """Collect host-side artifacts without making mutating changes."""

    SNAPSHOT_COMMANDS = {
        "nvme-list.json": ("nvme", "list", "-o", "json"),
        "nvme-list-subsys.json": ("nvme", "list-subsys", "-o", "json"),
        "ss-tcp.txt": ("ss", "-tnpi"),
    }

    def __init__(self, runner: HostCommandRunner | None = None):
        self.runner = runner or HostCommandRunner()

    def collect_snapshots(self, writer: ArtifactWriter, prefix: str) -> list[CommandResult]:
        results: list[CommandResult] = []
        for name, command in self.SNAPSHOT_COMMANDS.items():
            result = self.runner.run(command)
            results.append(result)
            artifact_name = f"{prefix}-{name}"
            if name.endswith(".json") and result.stdout.strip():
                try:
                    writer.write_json(artifact_name, json.loads(result.stdout))
                    continue
                except json.JSONDecodeError:
                    pass
            writer.write_text(artifact_name.replace(".json", ".txt"), result.stdout + result.stderr)
        writer.write_json(f"{prefix}-commands.json", {"commands": [asdict(item) for item in results]})
        return results

    def collect_dmesg_delta(self, writer: ArtifactWriter, name: str = "dmesg.log") -> CommandResult:
        result = self.runner.run(("dmesg", "--ctime", "--color=never"))
        writer.write_text(name, result.stdout + result.stderr)
        return result
