from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import time
from typing import Any, Iterator

from .artifacts import ArtifactWriter, KvTraceEntry
from .config import load_config
from .executor_linux import ExecutorResult, NvmeCliExecutor, build_io_passthru
from .oracle import OracleAnalyzer, OracleResult, Verdict


@dataclass(frozen=True)
class RunConfig:
    campaign_path: Path
    config_path: Path
    artifacts_dir: Path
    dry_run: bool = False
    allow_live_target: bool = False
    limit: int | None = None
    shard_index: int = 0
    shard_count: int = 1
    stop_on_failure: bool = False
    max_consecutive_timeouts: int = 3

    def __post_init__(self) -> None:
        if self.shard_count < 1:
            raise ValueError("shard_count must be >= 1")
        if not 0 <= self.shard_index < self.shard_count:
            raise ValueError("shard_index must be in [0, shard_count)")
        if self.limit is not None and self.limit < 1:
            raise ValueError("limit must be positive")


class RunOrchestrator:
    def __init__(self, config: RunConfig):
        self.config = config
        self.oracle = OracleAnalyzer()

    def run(self) -> dict[str, Any]:
        kv_config = load_config(self.config.config_path)
        if not self.config.dry_run and not self.config.allow_live_target:
            raise ValueError("live target execution requires --allow-live-target")
        if not self.config.dry_run:
            _live_precheck(kv_config)

        run_id = datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
        writer = ArtifactWriter(self.config.artifacts_dir, run_id=run_id)
        self.config.artifacts_dir.mkdir(parents=True, exist_ok=True)
        executor = NvmeCliExecutor(timeout_ms=int(kv_config["timeout_ms"]))

        planned = 0
        selected = 0
        executed = 0
        verdict_counts: dict[str, int] = {}
        consecutive_timeouts = 0
        fuse_reason: str | None = None
        next_allowed_start = 0.0

        for ordinal, case in enumerate(_read_campaign(self.config.campaign_path)):
            planned += 1
            case_index = int(case.get("campaign_index", ordinal))
            if case_index % self.config.shard_count != self.config.shard_index:
                continue
            if self.config.limit is not None and selected >= self.config.limit:
                continue
            if fuse_reason:
                continue

            selected += 1
            now = time.monotonic()
            if now < next_allowed_start:
                time.sleep(next_allowed_start - now)
            summary = self._run_one_case(case, kv_config, writer, executor)
            next_allowed_start = time.monotonic() + (1.0 / max(int(kv_config["max_qps"]), 1))
            executed += 1
            verdict = str(summary["verdict"])
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            if verdict == "FAIL_HANG":
                consecutive_timeouts += 1
            else:
                consecutive_timeouts = 0
            if consecutive_timeouts >= self.config.max_consecutive_timeouts:
                fuse_reason = f"fuse opened after {consecutive_timeouts} consecutive timeouts"
            if verdict in {"FAIL_SAFETY", "FAIL_CLEANUP"} or (self.config.stop_on_failure and verdict.startswith("FAIL_")):
                fuse_reason = f"fuse opened on {verdict}"

        return {
            "run_schema": "nvme_kv_fuzz_run.v1",
            "campaign_path": str(self.config.campaign_path),
            "config_path": str(self.config.config_path),
            "artifacts_dir": str(self.config.artifacts_dir),
            "run_id": run_id,
            "planned_cases": planned,
            "selected_cases": selected,
            "executed_cases": executed,
            "dry_run": self.config.dry_run,
            "allow_live_target": self.config.allow_live_target,
            "fuse_reason": fuse_reason,
            "verdict_counts": dict(sorted(verdict_counts.items())),
        }

    def _run_one_case(
        self,
        case: dict[str, Any],
        kv_config: dict[str, Any],
        writer: ArtifactWriter,
        executor: NvmeCliExecutor,
    ) -> dict[str, Any]:
        writer.start_case(case)
        mutation = _mutation(case)
        field = str(mutation.get("field", "<unknown>"))
        strategy = str(mutation.get("strategy", "<unknown>"))
        operation = str(case.get("operation", "<unknown>"))
        expected_allowed = tuple((case.get("expected", {}) or {}).get("allowed", ("PASS_VALID",)))

        self._trace(writer, 0, case, "precheck", {"device_path": kv_config["device_path"], "nsid": kv_config["nsid"]})
        value = bytes.fromhex(str(case.get("value_hex", "")))
        payload_file = writer.write_bytes("payload.bin", value) if value else None
        command = build_io_passthru(case, kv_config, payload_file)
        writer.write_json("command.json", command)
        if self.config.dry_run:
            writer.write_text("nvme-before.json", "{}\n")
            writer.write_text("dmesg-before.log", "")
        else:
            writer.write_text("nvme-before.json", _capture_command(["nvme", "list", "-v", "-o", "json"]))
            writer.write_text("dmesg-before.log", _capture_command(["dmesg", "--ctime", "--color=never"]))

        self._trace(writer, 1, case, "send", {"argv": command["argv"], "dry_run": self.config.dry_run})
        if self.config.dry_run:
            result = ExecutorResult(0, "dry-run command planned\n", "", 0.0)
        else:
            result = executor.run(command["argv"], cwd=writer.case_dir or self.config.artifacts_dir)

        writer.write_text("stdout.log", result.stdout)
        writer.write_text("stderr.log", result.stderr)
        if self.config.dry_run:
            writer.write_text("nvme-after.json", "{}\n")
            writer.write_text("dmesg-after.log", "")
            writer.write_text("journal-kernel.log", "")
        else:
            writer.write_text("nvme-after.json", _capture_command(["nvme", "list", "-v", "-o", "json"]))
            writer.write_text("dmesg-after.log", _capture_command(["dmesg", "--ctime", "--color=never"]))
            writer.write_text("journal-kernel.log", _capture_command(["journalctl", "-k", "-n", "300", "--no-pager"]))

        self._trace(
            writer,
            2,
            case,
            "completion",
            {"returncode": result.returncode, "timed_out": result.timed_out, "latency_ms": result.latency_ms},
        )
        if self.config.dry_run:
            oracle_result = OracleResult(Verdict.PASS_VALID, "dry-run command planned", nvme_status="dry-run")
        else:
            oracle_result = self.oracle.analyze(
                dmesg=result.stderr,
                timed_out=result.timed_out,
                infra_error=result.infra_error,
                expected_allowed=expected_allowed,
                command_returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        self._trace(writer, 3, case, "semantic_verify", {"verdict": str(oracle_result.verdict)})
        self._trace(writer, 4, case, "cleanup", {"status": "not-required" if self.config.dry_run else "caller-managed"})

        summary = {
            "verdict": str(oracle_result.verdict),
            "reason": oracle_result.reason,
            "reasons": [oracle_result.reason],
            "bucket_key": _bucket_key(
                str(oracle_result.verdict),
                oracle_result.reason,
                operation,
                field,
                strategy,
                oracle_result.nvme_status,
            ),
            "operation": operation,
            "field": field,
            "strategy": strategy,
            "nvme_status": oracle_result.nvme_status,
            "errno": oracle_result.errno,
            "latency_ms": result.latency_ms,
            "returncode": result.returncode,
            "device_state_delta": "not-collected-in-dry-run" if self.config.dry_run else "see nvme-before/after artifacts",
            "replay_command": f"python -m nvme_kv_fuzz.cli replay {writer.case_dir / 'case.yaml'} --config {self.config.config_path}",
            "dry_run": self.config.dry_run,
        }
        writer.write_json("summary.json", summary)
        return summary

    def _trace(self, writer: ArtifactWriter, ordinal: int, case: dict[str, Any], stage: str, detail: dict[str, Any]) -> None:
        mutation = _mutation(case)
        writer.append_trace(
            KvTraceEntry(
                stage=stage,
                ordinal=ordinal,
                operation=str(case.get("operation", "<unknown>")),
                field=str(mutation.get("field", "<unknown>")),
                strategy=str(mutation.get("strategy", "<unknown>")),
                detail=detail,
            )
        )


def collect_env(config_path: Path, output_dir: Path) -> dict[str, Any]:
    kv_config = load_config(config_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    commands = {
        "nvme-list-v.json": ["nvme", "list", "-v", "-o", "json"],
        "nvme-id-ctrl.txt": ["nvme", "id-ctrl", str(kv_config["device_path"])],
        "nvme-id-ns.txt": ["nvme", "id-ns", str(kv_config["device_path"])],
        "nvme-list-subsys.txt": ["nvme", "list-subsys"],
        "dmesg.log": ["dmesg", "--ctime", "--color=never"],
        "modinfo-nvme-tcp.txt": ["modinfo", "nvme_tcp"],
        "modinfo-nvme-fabrics.txt": ["modinfo", "nvme_fabrics"],
        "ip-link.txt": ["ip", "-d", "link"],
    }
    results: dict[str, Any] = {}
    for name, argv in commands.items():
        started = time.monotonic()
        try:
            completed = subprocess.run(argv, text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=10)
            text = completed.stdout + completed.stderr
            rc = completed.returncode
        except Exception as exc:  # noqa: BLE001 - env collection should be best effort.
            text = str(exc)
            rc = None
        (output_dir / name).write_text(text, encoding="utf-8", errors="replace")
        results[name] = {"argv": argv, "returncode": rc, "latency_ms": round((time.monotonic() - started) * 1000, 3)}
    (output_dir / "summary.json").write_text(json.dumps(results, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return results


def _live_precheck(kv_config: dict[str, Any]) -> None:
    nvme_list = _capture_command(["nvme", "list", "-v", "-o", "json"], timeout_s=10)
    subsys = _capture_command(["nvme", "list-subsys"], timeout_s=10)
    combined = f"{nvme_list}\n{subsys}"
    device = str(kv_config["device_path"])
    if device not in combined:
        raise ValueError(f"live precheck failed: {device} not found in nvme list output")
    allowed = [str(item) for item in kv_config["allowed_model_or_serial"]]
    if not any(item and item in combined for item in allowed):
        raise ValueError("live precheck failed: no allowed model/serial matched nvme list output")
    target_nqn = str(kv_config["target_nqn"])
    if target_nqn not in combined:
        raise ValueError(f"live precheck failed: target NQN {target_nqn!r} not found")


def _capture_command(argv: list[str], timeout_s: int = 5) -> str:
    try:
        completed = subprocess.run(
            argv,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001 - diagnostics must not hide the primary case result.
        return f"$ {' '.join(argv)}\n<collection failed: {exc}>\n"
    return f"$ {' '.join(argv)}\n# returncode={completed.returncode}\n{completed.stdout}{completed.stderr}"


def _read_campaign(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                yield json.loads(stripped)


def _mutation(case: dict[str, Any]) -> dict[str, Any]:
    mutation = case.get("mutation", {})
    return mutation if isinstance(mutation, dict) else {}


def _bucket_key(verdict: str, reason: str, operation: str, field: str, strategy: str, nvme_status: str | None) -> str:
    return "|".join([verdict, reason, operation, field, strategy, nvme_status or "<none>"])
